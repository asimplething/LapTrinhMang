from flask import Flask, render_template_string, request, redirect, url_for, abort
import os
from threading import Thread
import time
import json
from collections import defaultdict

app = Flask(__name__)

# Đường dẫn đến file log và config
LOG_DIR = "log"
MAIN_LOG_FILE = os.path.join(LOG_DIR, "network_analysis_log.txt")
CONFIG_FILE = "config/system_config.txt"
VIEWABLE_LOG_FILES = {
    "capture": "capture_log.txt",
    "gemini": "gemini_log.txt",
    "deepseek": "deepseek_log.txt",
    "qwen": "qwen_log.txt",
    "network_analysis": "network_analysis_log.txt" # Main log also viewable here
}

def parse_log_file():
    """Phân tích file log để lấy thông tin trạng thái và log mới nhất"""
    try:
        with open(MAIN_LOG_FILE, 'r', encoding='utf-8') as f:
            content = f.read()

        log_parts = content.split('=== ĐÁNH GIÁ TỔNG HỢP - ')[1:]

        if not log_parts:
            return {
                'current_status': 'Chưa có dữ liệu',
                'latest_evaluation': 'Chưa có đánh giá',
                'full_log_summary': content # Changed for clarity on dashboard
            }

        latest_eval_session = log_parts[-1]
        current_status = 'Đang phân tích' # Default

        # Trích xuất trạng thái hiện tại từ phần kết luận tổng thể của phiên đánh giá mới nhất
        if '=== KẾT LUẬN TỔNG THỂ - ' in latest_eval_session:
            conclusion_part = latest_eval_session.split('=== KẾT LUẬN TỔNG THỂ - ')[1]
            status_lines = [line for line in conclusion_part.split('\n') if line.startswith('Hệ thống ở trạng thái')]
            if status_lines:
                current_status = status_lines[0].split('Hệ thống ở trạng thái ')[1].strip('.')

        latest_evaluation_display = '=== ĐÁNH GIÁ TỔNG HỢP - ' + latest_eval_session

        return {
            'current_status': current_status,
            'latest_evaluation': latest_evaluation_display, # For the "latest evaluation" card
            'full_log_summary': content # The main log for the "full log" card on dashboard
        }

    except FileNotFoundError:
        return {
            'current_status': 'Chưa có dữ liệu',
            'latest_evaluation': 'File log chính chưa được tạo',
            'full_log_summary': 'Chờ dữ liệu...'
        }

def parse_config_file():
    """Phân tích file config để lấy các tham số"""
    config = {}
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip().strip('"')
    except FileNotFoundError:
        pass # Handled by C++ part creating default
    return config

def write_config_file(config_data): # Renamed param to avoid conflict
    """Ghi các tham số mới vào file config"""
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        f.write("# Giao diện bắt gói tin\n")
        f.write(f"capture_interface=\"{config_data['capture_interface']}\"\n\n")
        f.write("# Thời gian bắt gói tin để lưu thành pcapng\n")
        f.write(f"capture_duration={config_data['capture_duration']}\n\n")
        f.write("# Số lượng gói tin bắt được trong capture_duration, tránh tình trạng bắt quá nhiều gói tin\n")
        f.write(f"maximum_packets_capture={config_data['maximum_packets_capture']}\n\n")
        f.write("# Đường dẫn file bắt được\n")
        f.write(f"output_capture_file=\"{config_data['output_capture_file']}\"\n\n")
        f.write("# Quy định giới hạn băng thông mạng của hệ thống\n")
        f.write(f"minimum_network_limit=\"{config_data['minimum_network_limit']}\"\n")
        f.write(f"maximum_network_limit=\"{config_data['maximum_network_limit']}\"\n")

# HTML template cho dashboard
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Network Analysis Dashboard</title>
    <meta http-equiv="refresh" content="10"> <!-- Increased refresh to 10s -->
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .dashboard { display: grid; grid-template-areas: "header header" "status latest" "logs-links logs-links" "full-log full-log"; grid-gap: 20px; }
        .card { background-color: white; padding: 15px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .header { grid-area: header; background-color: #4285f4; color: white; text-align: center; }
        .status-card { grid-area: status; }
        .latest-card { grid-area: latest; }
        .logs-links-card { grid-area: logs-links; }
        .full-log-card { grid-area: full-log; } /* Renamed for consistency */
        .status-indicator { font-size: 1.5em; font-weight: bold; padding: 10px; border-radius: 5px; text-align: center; margin-top: 10px; }
        .good { background-color: #34a853; color: white; }
        .suspicious { background-color: #fbbc05; color: black; }
        .attack { background-color: #ea4335; color: white; }
        .normal { background-color: #4285f4; color: white; } /* Default/unknown */
        pre { white-space: pre-wrap; word-wrap: break-word; background-color: #f8f9fa; padding: 15px; border-radius: 3px; max-height: 300px; overflow-y: auto; }
        h2 { margin-top: 0; border-bottom: 1px solid #eee; padding-bottom: 10px; }
        .timestamp { color: white; font-size: 0.9em; text-align: right; }
        .nav-button { margin: 5px; padding: 10px 15px; background-color: #34a853; color: white; border: none; border-radius: 5px; cursor: pointer; font-size: 1em; text-decoration: none; display: inline-block; }
        .nav-button:hover { background-color: #2e8b57; }
        .log-link-button { background-color: #5bc0de; }
        .log-link-button:hover { background-color: #31b0d5; }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header card">
            <h1>Network Analysis Dashboard</h1>
            <div class="timestamp">Last updated: {{ timestamp }}</div>
            <a href="{{ url_for('configuration') }}" class="nav-button">Configuration</a>
        </div>

        <div class="status-card card">
            <h2>Trạng thái hiện tại</h2>
            <div class="status-indicator {{ status_class }}">
                {{ current_status }}
            </div>
        </div>

        <div class="latest-card card">
            <h2>Đánh giá mới nhất (từ network_analysis_log.txt)</h2>
            <pre>{{ latest_evaluation }}</pre>
        </div>

        <div class="logs-links-card card">
            <h2>Xem chi tiết Logs</h2>
            <a href="{{ url_for('view_specific_log', log_key='network_analysis') }}" class="nav-button log-link-button">Network Analysis Log</a>
            <a href="{{ url_for('view_specific_log', log_key='capture') }}" class="nav-button log-link-button">Capture Log</a>
            <a href="{{ url_for('view_specific_log', log_key='gemini') }}" class="nav-button log-link-button">Gemini Log</a>
            <a href="{{ url_for('view_specific_log', log_key='deepseek') }}" class="nav-button log-link-button">Deepseek Log</a>
            <a href="{{ url_for('view_specific_log', log_key='qwen') }}" class="nav-button log-link-button">Qwen Log</a>
        </div>

        <div class="full-log-card card"> <!-- Renamed class -->
            <h2>Toàn bộ nhật ký chính (network_analysis_log.txt)</h2>
            <pre>{{ full_log_summary }}</pre>
        </div>
    </div>
</body>
</html>
"""

# HTML template cho trang xem log chi tiết
LOG_VIEW_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>View Log: {{ log_title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        pre { white-space: pre-wrap; word-wrap: break-word; background-color: #f8f9fa; padding: 15px; border-radius: 3px; max-height: 80vh; overflow-y: auto; }
        a { color: #007bff; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Log: {{ log_title }}</h2>
        <p><a href="{{ url_for('view_main_dashboard') }}">Back to Dashboard</a></p>
        <pre>{{ log_content }}</pre>
    </div>
</body>
</html>
"""

# HTML template cho trang configuration (giữ nguyên, chỉ rút gọn display)
CONFIG_TEMPLATE = """
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Configuration</title>
<style>
    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
    .config-form { background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); max-width: 600px; margin: auto; }
    label { display: block; margin-bottom: 5px; font-weight: bold; }
    input[type="text"], input[type="number"], select { width: calc(100% - 18px); padding: 8px; margin-bottom: 15px; border: 1px solid #ccc; border-radius: 3px; box-sizing: border-box; }
    .form-group { margin-bottom: 15px; }
    .button-container { display: flex; justify-content: space-between; margin-top: 20px; }
    .button { padding: 10px 20px; color: white; border: none; border-radius: 3px; cursor: pointer; transition: background-color 0.3s; text-decoration: none; }
    .save-button { background-color: #34a853; } .save-button:hover { background-color: #2e8b57; }
    .dashboard-button { background-color: #4285f4; } .dashboard-button:hover { background-color: #3367d6; }
</style></head><body><div class="config-form"><h2>System Configuration</h2><form method="POST">
    <div class="form-group"><label for="capture_interface">Giao diện bắt gói tin:</label><input type="text" id="capture_interface" name="capture_interface" value="{{ capture_interface }}" required></div>
    <div class="form-group"><label for="capture_duration">Thời gian bắt gói tin (giây):</label><input type="number" id="capture_duration" name="capture_duration" value="{{ capture_duration }}" required></div>
    <div class="form-group"><label for="maximum_packets_capture">Số lượng gói tin tối đa:</label><input type="number" id="maximum_packets_capture" name="maximum_packets_capture" value="{{ maximum_packets_capture }}" required></div>
    <div class="form-group"><label for="output_capture_file">Đường dẫn file bắt được:</label><input type="text" id="output_capture_file" name="output_capture_file" value="{{ output_capture_file }}" required></div>
    <div class="form-group"><label for="minimum_network_limit">Giới hạn băng thông tối thiểu:</label><input type="number" step="any" id="minimum_network_limit" name="minimum_network_limit" value="{{ minimum_network_limit }}" required> <select name="min_unit"><option value="Mbs" {% if min_unit == 'Mbs' %}selected{% endif %}>Mbs</option><option value="Kbs" {% if min_unit == 'Kbs' %}selected{% endif %}>Kbs</option></select></div>
    <div class="form-group"><label for="maximum_network_limit">Giới hạn băng thông tối đa:</label><input type="number" step="any" id="maximum_network_limit" name="maximum_network_limit" value="{{ maximum_network_limit }}" required> <select name="max_unit"><option value="Mbs" {% if max_unit == 'Mbs' %}selected{% endif %}>Mbs</option><option value="Kbs" {% if max_unit == 'Kbs' %}selected{% endif %}>Kbs</option></select></div>
    <div class="button-container"><button type="submit" class="button save-button">Save</button><a href="{{ url_for('view_main_dashboard') }}" class="button dashboard-button">Dashboard</a></div>
</form></div></body></html>
"""


def get_status_class(status):
    """Xác định class CSS dựa trên trạng thái"""
    status_lower = status.lower()
    if 'tốt' in status_lower:
        return 'good'
    elif 'đáng ngờ' in status_lower:
        return 'suspicious'
    elif 'bị tấn công' in status_lower or 'nghẽn mạng' in status_lower or 'mạng sập' in status_lower:
        return 'attack'
    return 'normal' # Default for "Chưa có dữ liệu", "Đang phân tích", etc.

@app.route('/')
def view_main_dashboard(): # Renamed for clarity
    log_data = parse_log_file()
    current_time = time.strftime('%Y-%m-%d %H:%M:%S')

    return render_template_string(
        DASHBOARD_TEMPLATE,
        current_status=log_data['current_status'],
        latest_evaluation=log_data['latest_evaluation'],
        full_log_summary=log_data['full_log_summary'], # Pass the main log content
        timestamp=current_time,
        status_class=get_status_class(log_data['current_status'])
    )

@app.route('/logs/<log_key>')
def view_specific_log(log_key):
    if log_key not in VIEWABLE_LOG_FILES:
        abort(404, description="Log file key not recognized.")

    log_filename = VIEWABLE_LOG_FILES[log_key]
    log_file_path = os.path.join(LOG_DIR, log_filename)
    log_content = f"Nội dung log cho {log_filename}:\n\n"

    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            log_content += f.read()
    except FileNotFoundError:
        log_content += "File log không tìm thấy."
    except Exception as e:
        log_content += f"Lỗi khi đọc file log: {str(e)}"

    return render_template_string(LOG_VIEW_TEMPLATE, log_title=log_filename, log_content=log_content)

@app.route('/configuration/', methods=['GET', 'POST'])
def configuration():
    if request.method == 'POST':
        # Ensure all form fields are present before creating the new_config_data dict
        required_fields = ['capture_interface', 'capture_duration', 'maximum_packets_capture',
                           'output_capture_file', 'minimum_network_limit', 'min_unit',
                           'maximum_network_limit', 'max_unit']
        if not all(field in request.form for field in required_fields):
            # Handle missing fields, perhaps return an error message or redirect
            return "Error: Missing form fields.", 400

        new_config_data = {
            'capture_interface': request.form['capture_interface'],
            'capture_duration': request.form['capture_duration'],
            'maximum_packets_capture': request.form['maximum_packets_capture'],
            'output_capture_file': request.form['output_capture_file'],
            'minimum_network_limit': f"{request.form['minimum_network_limit']} {request.form['min_unit']}",
            'maximum_network_limit': f"{request.form['maximum_network_limit']} {request.form['max_unit']}"
        }
        write_config_file(new_config_data)
        return redirect(url_for('configuration')) # Redirect to refresh the page with new values
    else:
        current_config = parse_config_file()
        # Provide default values if not found in config or if config is empty
        capture_interface = current_config.get('capture_interface', 'wlp3s0')
        capture_duration = current_config.get('capture_duration', '5')
        maximum_packets_capture = current_config.get('maximum_packets_capture', '2000')
        output_capture_file = current_config.get('output_capture_file', 'content/captured_network.pcapng')

        min_limit_full = current_config.get('minimum_network_limit', '100 Mbs')
        min_parts = min_limit_full.split()
        min_limit_val = min_parts[0] if min_parts else '100'
        min_unit_val = min_parts[1] if len(min_parts) > 1 else 'Mbs'

        max_limit_full = current_config.get('maximum_network_limit', '100 Mbs')
        max_parts = max_limit_full.split()
        max_limit_val = max_parts[0] if max_parts else '100'
        max_unit_val = max_parts[1] if len(max_parts) > 1 else 'Mbs'

        return render_template_string(
            CONFIG_TEMPLATE,
            capture_interface=capture_interface,
            capture_duration=capture_duration,
            maximum_packets_capture=maximum_packets_capture,
            output_capture_file=output_capture_file,
            minimum_network_limit=min_limit_val,
            min_unit=min_unit_val,
            maximum_network_limit=max_limit_val,
            max_unit=max_unit_val
        )

def run_flask_app():
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)

if __name__ == '__main__':
    flask_thread = Thread(target=run_flask_app)
    flask_thread.daemon = True
    flask_thread.start()

    print("Dashboard is running at http://localhost:5000")
    print("Configuration page is at http://localhost:5000/configuration/")
    print("View logs at /logs/<log_key> (e.g., /logs/capture, /logs/gemini)")
    print("Auto-refreshing dashboard every 10 seconds...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down dashboard...")
