# -*- coding: utf-8 -*-
from flask import Flask, render_template_string, request, redirect, url_for, abort
import os
from threading import Thread
import time
import json # Giữ lại nếu các phần của web_viewer sử dụng, mặc dù không trực tiếp trong logic C++
from collections import defaultdict # Giữ lại nếu được sử dụng
import subprocess # Để chạy các tiến trình bên ngoài (thay thế system() của C++)
import sys # Để có thể truy cập sys.getdefaultencoding() nếu cần
sys.stdout.reconfigure(encoding='utf-8')
# ----- Các hằng số và biến toàn cục -----
LOG_DIR = "log"
MAIN_LOG_FILE = os.path.join(LOG_DIR, "network_analysis_log.txt")
CONFIG_FILE = "config/system_config.txt" # Giống C++
VIEWABLE_LOG_FILES = {
    "capture": "capture_log.txt",
    "gemini": "gemini_log.txt",
    "deepseek": "deepseek_log.txt",
    "qwen": "qwen_log.txt",
    "network_analysis": "network_analysis_log.txt" # Log chính cũng có thể xem ở đây
}

# Khởi tạo ứng dụng Flask (từ web_viewer.py)
app = Flask(__name__)

# ----- Các hàm tiện ích và Templates từ web_viewer.py -----

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
                'full_log_summary': content
            }

        latest_eval_session = log_parts[-1]
        current_status = 'Đang phân tích' # Mặc định

        if '=== KẾT LUẬN TỔNG THỂ - ' in latest_eval_session:
            conclusion_part = latest_eval_session.split('=== KẾT LUẬN TỔNG THỂ - ')[1]
            status_lines = [line for line in conclusion_part.split('\n') if line.startswith('Hệ thống ở trạng thái')]
            if status_lines:
                current_status = status_lines[0].split('Hệ thống ở trạng thái ')[1].strip('.')

        latest_evaluation_display = '=== ĐÁNH GIÁ TỔNG HỢP - ' + latest_eval_session

        return {
            'current_status': current_status,
            'latest_evaluation': latest_evaluation_display,
            'full_log_summary': content
        }
    except FileNotFoundError:
        return {
            'current_status': 'Chưa có dữ liệu',
            'latest_evaluation': 'File log chính chưa được tạo',
            'full_log_summary': 'Chờ dữ liệu...'
        }
    except Exception as e:
        print(f"[ERROR] Lỗi khi phân tích file log: {e}")
        return {
            'current_status': 'Lỗi đọc log',
            'latest_evaluation': f'Lỗi: {e}',
            'full_log_summary': f'Không thể đọc file log: {MAIN_LOG_FILE}'
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
                    # Loại bỏ dấu ngoặc kép nếu có ở đầu và cuối giá trị
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    config[key.strip()] = value.strip()
    except FileNotFoundError:
        print(f"[WARNING] File cấu hình {CONFIG_FILE} không tìm thấy. Sử dụng giá trị mặc định nếu có.")
    except Exception as e:
        print(f"[ERROR] Lỗi khi đọc file cấu hình {CONFIG_FILE}: {e}")
    return config

def write_config_file(config_data):
    """Ghi các tham số mới vào file config"""
    try:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
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
        print(f"[INFO] Đã ghi cấu hình vào {CONFIG_FILE}")
    except Exception as e:
        print(f"[ERROR] Lỗi khi ghi file cấu hình {CONFIG_FILE}: {e}")

DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>Network Analysis Dashboard</title>
    <meta http-equiv="refresh" content="10">
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .dashboard { display: grid; grid-template-areas: "header header" "status latest" "logs-links logs-links" "full-log full-log"; grid-gap: 20px; }
        .card { background-color: white; padding: 15px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .header { grid-area: header; background-color: #4285f4; color: white; text-align: center; }
        .status-card { grid-area: status; }
        .latest-card { grid-area: latest; }
        .logs-links-card { grid-area: logs-links; }
        .full-log-card { grid-area: full-log; }
        .status-indicator { font-size: 1.5em; font-weight: bold; padding: 10px; border-radius: 5px; text-align: center; margin-top: 10px; }
        .good { background-color: #34a853; color: white; }
        .suspicious { background-color: #fbbc05; color: black; }
        .attack { background-color: #ea4335; color: white; }
        .normal { background-color: #4285f4; color: white; }
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
        <div class="full-log-card card">
            <h2>Toàn bộ nhật ký chính (network_analysis_log.txt)</h2>
            <pre>{{ full_log_summary }}</pre>
        </div>
    </div>
</body>
</html>
"""

LOG_VIEW_TEMPLATE = """
<!DOCTYPE html>
<html lang="vi">
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

CONFIG_TEMPLATE = """
<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8"><title>Configuration</title>
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
    <div class="form-group"><label for="minimum_network_limit_val">Giới hạn băng thông tối thiểu:</label><input type="text" id="minimum_network_limit_val" name="minimum_network_limit_val" value="{{ minimum_network_limit_val }}" required> <select name="min_unit"><option value="Mbs" {% if min_unit == 'Mbs' %}selected{% endif %}>Mbs</option><option value="Kbs" {% if min_unit == 'Kbs' %}selected{% endif %}>Kbs</option></select></div>
    <div class="form-group"><label for="maximum_network_limit_val">Giới hạn băng thông tối đa:</label><input type="text" id="maximum_network_limit_val" name="maximum_network_limit_val" value="{{ maximum_network_limit_val }}" required> <select name="max_unit"><option value="Mbs" {% if max_unit == 'Mbs' %}selected{% endif %}>Mbs</option><option value="Kbs" {% if max_unit == 'Kbs' %}selected{% endif %}>Kbs</option></select></div>
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
    return 'normal'

# ----- Các route Flask (từ web_viewer.py) -----
@app.route('/')
def view_main_dashboard():
    log_data = parse_log_file()
    current_time = time.strftime('%Y-%m-%d %H:%M:%S')
    return render_template_string(
        DASHBOARD_TEMPLATE,
        current_status=log_data['current_status'],
        latest_evaluation=log_data['latest_evaluation'],
        full_log_summary=log_data['full_log_summary'],
        timestamp=current_time,
        status_class=get_status_class(log_data['current_status'])
    )

@app.route('/logs/<log_key>')
def view_specific_log(log_key):
    if log_key not in VIEWABLE_LOG_FILES:
        abort(404, description="Log file key not recognized.")

    log_filename = VIEWABLE_LOG_FILES[log_key]
    log_file_path = os.path.join(LOG_DIR, log_filename)
    log_content_display = f"Nội dung log cho {log_filename}:\n\n"

    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            log_content_display += f.read()
    except FileNotFoundError:
        log_content_display += "File log không tìm thấy."
    except Exception as e:
        log_content_display += f"Lỗi khi đọc file log: {str(e)}"

    return render_template_string(LOG_VIEW_TEMPLATE, log_title=log_filename, log_content=log_content_display)

@app.route('/configuration/', methods=['GET', 'POST'])
def configuration():
    if request.method == 'POST':
        required_fields = ['capture_interface', 'capture_duration', 'maximum_packets_capture',
                           'output_capture_file', 'minimum_network_limit_val', 'min_unit',
                           'maximum_network_limit_val', 'max_unit']
        if not all(field in request.form for field in required_fields):
            return "Lỗi: Thiếu trường dữ liệu trong form.", 400

        new_config_data = {
            'capture_interface': request.form['capture_interface'],
            'capture_duration': request.form['capture_duration'],
            'maximum_packets_capture': request.form['maximum_packets_capture'],
            'output_capture_file': request.form['output_capture_file'],
            'minimum_network_limit': f"{request.form['minimum_network_limit_val']} {request.form['min_unit']}",
            'maximum_network_limit': f"{request.form['maximum_network_limit_val']} {request.form['max_unit']}"
        }
        write_config_file(new_config_data)
        return redirect(url_for('configuration'))
    else:
        current_config = parse_config_file()
        # Cung cấp giá trị mặc định nếu không tìm thấy trong config hoặc config trống
        capture_interface = current_config.get('capture_interface', 'eth0') # Thay 'eth0' bằng default phù hợp
        capture_duration = current_config.get('capture_duration', '5')
        maximum_packets_capture = current_config.get('maximum_packets_capture', '2000')
        output_capture_file = current_config.get('output_capture_file', 'content/captured_network.pcapng')

        min_limit_full = current_config.get('minimum_network_limit', '100 Mbs')
        min_parts = min_limit_full.split(maxsplit=1)
        min_limit_val = min_parts[0] if min_parts else '100'
        min_unit_val = min_parts[1] if len(min_parts) > 1 else 'Mbs'

        max_limit_full = current_config.get('maximum_network_limit', '100 Mbs')
        max_parts = max_limit_full.split(maxsplit=1)
        max_limit_val = max_parts[0] if max_parts else '100'
        max_unit_val = max_parts[1] if len(max_parts) > 1 else 'Mbs'

        return render_template_string(
            CONFIG_TEMPLATE,
            capture_interface=capture_interface,
            capture_duration=capture_duration,
            maximum_packets_capture=maximum_packets_capture,
            output_capture_file=output_capture_file,
            minimum_network_limit_val=min_limit_val,
            min_unit=min_unit_val,
            maximum_network_limit_val=max_limit_val,
            max_unit=max_unit_val
        )

# ----- Logic được chuyển từ C++ (network_analyze.cpp) -----

def load_and_validate_config_python():
    """
    Đọc file cấu hình và xác thực các tham số cần thiết.
    Tương tự loadConfigFile và một phần read_config_file của C++.
    Trả về một dictionary chứa dữ liệu cấu hình hoặc None nếu có lỗi.
    """
    print("[INFO] Python: Đang kiểm tra lại cấu hình...")
    config_data = parse_config_file() # Sử dụng hàm parse_config_file hiện có

    if not config_data: # Trường hợp file không tồn tại hoặc lỗi đọc nghiêm trọng
        print(f"[ERROR] Python: Không thể đọc file cấu hình: {CONFIG_FILE}. Vui lòng kiểm tra file.")
        return None

    required_keys = [
        "capture_interface", "capture_duration", "maximum_packets_capture",
        "output_capture_file", "minimum_network_limit", "maximum_network_limit"
    ]

    # In các tham số đã đọc (giống C++)
    for key, value in config_data.items():
        print(f"[INFO] Python: Đã đọc tham số: {key} = {value}")

    all_keys_present = True
    for key in required_keys:
        if key not in config_data or not config_data[key]:
            print(f"[ERROR] Python: Tham số '{key}' chưa được thiết lập hoặc trống trong file cấu hình: {CONFIG_FILE}")
            all_keys_present = False
            
    if not all_keys_present:
        return None
        
    return config_data

def run_ai_agent_periodically():
    """
    Vòng lặp chính định kỳ chạy script AI agent.
    Tương tự vòng lặp while(true) trong main() của C++.
    """
    sleep_time_seconds = 5  # Thời gian chờ giữa các lần thử lại (giây)

    while True:
        # \033[K xóa phần còn lại của dòng, \r đưa con trỏ về đầu dòng
        print("\r\033[K---------------------------------------------------------")
        print("[INFO] Python: Bắt đầu vòng lặp chính, tải cấu hình...")

        current_config = load_and_validate_config_python()
        if not current_config:
            print(f"[ERROR] Python: Không thể tải file cấu hình, thử lại sau {sleep_time_seconds} giây.")
            time.sleep(sleep_time_seconds)
            continue

        capture_duration = current_config["capture_duration"]
        maximum_packets_capture = current_config["maximum_packets_capture"]
        output_capture_file = current_config["output_capture_file"]
        minimum_network_limit = current_config["minimum_network_limit"] 
        maximum_network_limit = current_config["maximum_network_limit"] 
        capture_interface = current_config["capture_interface"]

        ai_agent_command_parts = [
            "python3", "AI_agent.py",
            f'"{minimum_network_limit}"', 
            f'"{maximum_network_limit}"',
            f'"{output_capture_file}"',   
            f'"{capture_interface}"',     
            capture_duration,
            maximum_packets_capture
        ]
        ai_agent_command_str = " ".join(str(part) for part in ai_agent_command_parts)
        
        print(f"[INFO] Python: Đang chuẩn bị chạy script AI agent: {ai_agent_command_str}")

        try:
            # print(f"[DEBUG] Đang chạy lệnh: {ai_agent_command_str}") # Bỏ comment nếu cần debug lệnh
            ai_result = subprocess.run(
                ai_agent_command_str,
                shell=True,
                check=False,   # Tiếp tục cố gắng với UTF-8
            )

            if ai_result.returncode != 0:
                print(f"[ERROR] Python: AI_agent.py gặp lỗi (exit code {ai_result.returncode}). Đang thử lại...")
                if ai_result.stdout:
                    print(f"Stdout:\n{ai_result.stdout.strip()}")
                if ai_result.stderr:
                    print(f"Stderr:\n{ai_result.stderr.strip()}")
                time.sleep(sleep_time_seconds)
            else:
                print("[INFO] Python: AI_agent.py đã chạy thành công.")
                if ai_result.stdout:
                    print(f"Stdout từ AI_agent.py:\n{ai_result.stdout.strip()}")
                if ai_result.stderr:
                    print(f"Stderr từ AI_agent.py (có thể là warnings):\n{ai_result.stderr.strip()}")
            
        except FileNotFoundError:
            print(f"[ERROR] Python: Lệnh 'python3' hoặc script 'AI_agent.py' không tìm thấy. Hãy đảm bảo chúng có trong PATH hoặc thư mục hiện tại.")
            print(f"Đang thử lại sau {sleep_time_seconds} giây...")
            time.sleep(sleep_time_seconds)
        except Exception as e:
            print(f"[ERROR] Python: Lỗi không xác định khi chạy AI_agent.py: {e}")
            print(f"Đang thử lại sau {sleep_time_seconds} giây...")
            time.sleep(sleep_time_seconds)
        
        print("\n") 

# ----- Hàm chạy Flask và khối thực thi chính -----
def run_flask_app_in_thread():
    """Chạy ứng dụng Flask trong một luồng riêng biệt."""
    if not os.path.exists(LOG_DIR):
        try:
            os.makedirs(LOG_DIR)
            print(f"[INFO] Đã tạo thư mục log: {LOG_DIR}")
        except OSError as e:
            print(f"[ERROR] Không thể tạo thư mục log {LOG_DIR}: {e}")
            return 

    print("[INFO] Khởi chạy Flask web server...")
    try:
        app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
    except Exception as e:
        print(f"[ERROR] Không thể khởi chạy Flask web server: {e}")

if __name__ == '__main__':
    print("Đây là màn hình debug của chương trình phân tích mạng (Phiên bản Python tổng hợp).")
    print("Thầy có thể xem trạng thái mạng ở giao diện web: http://localhost:5000")
    print("[INFO] Python: Bắt đầu chương trình phân tích mạng...")

    flask_thread = Thread(target=run_flask_app_in_thread)
    flask_thread.daemon = True 
    flask_thread.start()

    print("Dashboard đang chạy tại http://localhost:5000")
    print("Trang cấu hình tại http://localhost:5000/configuration/")
    print("Xem logs tại /logs/<log_key> (ví dụ: /logs/capture, /logs/gemini)")

    try:
        run_ai_agent_periodically()
    except KeyboardInterrupt:
        print("\n[INFO] Nhận tín hiệu KeyboardInterrupt, đang tắt chương trình...")
    except Exception as e:
        print(f"[ERROR] Lỗi không mong muốn trong vòng lặp chính: {e}")
    finally:
        print("[INFO] Chương trình đã kết thúc.")