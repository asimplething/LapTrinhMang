from flask import Flask, render_template_string, request, redirect, url_for
import os
from threading import Thread
import time
import json
from collections import defaultdict

app = Flask(__name__)

# Đường dẫn đến file log và config
LOG_FILE = "log/network_analysis_log.txt"
CONFIG_FILE = "config/system_config.txt"

def parse_log_file():
    """Phân tích file log để lấy thông tin trạng thái và log mới nhất"""
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            content = f.read()

        # Tách phần log thành các phần đánh giá
        log_parts = content.split('=== ĐÁNH GIÁ TỔNG HỢP - ')[1:]

        if not log_parts:
            return {
                'current_status': 'Chưa có dữ liệu',
                'latest_evaluation': 'Chưa có đánh giá',
                'full_log': content
            }

        # Lấy phần đánh giá mới nhất
        latest_eval = log_parts[-1]

        # Trích xuất trạng thái hiện tại từ phần kết luận tổng thể
        if '=== KẾT LUẬN TỔNG THỂ - ' in latest_eval:
            conclusion_part = latest_eval.split('=== KẾT LUẬN TỔNG THỂ - ')[1]
            status_line = [line for line in conclusion_part.split('\n')
                          if line.startswith('Hệ thống ở trạng thái')][0]
            current_status = status_line.split('Hệ thống ở trạng thái ')[1].strip('.')
        else:
            current_status = 'Đang phân tích'

        # Lấy toàn bộ phần đánh giá mới nhất, bao gồm ĐÁNH GIÁ TỔNG HỢP + KẾT LUẬN
        latest_eval_full = '=== ĐÁNH GIÁ TỔNG HỢP - ' + log_parts[-1]

        return {
            'current_status': current_status,
            'latest_evaluation': latest_eval_full,
            'full_log': content
        }

    except FileNotFoundError:
        return {
            'current_status': 'Chưa có dữ liệu',
            'latest_evaluation': 'File log chưa được tạo',
            'full_log': 'Chờ dữ liệu...'
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
        pass
    return config

def write_config_file(config):
    """Ghi các tham số mới vào file config"""
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        f.write("# Giao diện bắt gói tin\n")
        f.write(f"capture_interface=\"{config['capture_interface']}\"\n\n")
        f.write("# Thời gian bắt gói tin để lưu thành pcapng\n")
        f.write(f"capture_duration={config['capture_duration']}\n\n")
        f.write("# Số lượng gói tin bắt được trong capture_duration, tránh tình trạng bắt quá nhiều gói tin\n")
        f.write(f"maximum_packets_capture={config['maximum_packets_capture']}\n\n")
        f.write("# Đường dẫn file bắt được\n")
        f.write(f"output_capture_file=\"{config['output_capture_file']}\"\n\n")
        f.write("# Quy định giới hạn băng thông mạng của hệ thống\n")
        f.write(f"minimum_network_limit=\"{config['minimum_network_limit']}\"\n")
        f.write(f"maximum_network_limit=\"{config['maximum_network_limit']}\"\n")

# HTML template cho dashboard
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Network Analysis Dashboard</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .dashboard {
            display: grid;
            grid-template-areas:
                "header header"
                "status latest"
                "full-log full-log";
            grid-gap: 20px;
        }
        .header {
            grid-area: header;
            background-color: #4285f4;
            color: white;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }
        .status-card {
            grid-area: status;
            background-color: white;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .latest-card {
            grid-area: latest;
            background-color: white;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .full-log {
            grid-area: full-log;
            background-color: white;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .status-indicator {
            font-size: 1.5em;
            font-weight: bold;
            padding: 10px;
            border-radius: 5px;
            text-align: center;
            margin-top: 10px;
        }
        .good {
            background-color: #34a853;
            color: white;
        }
        .suspicious {
            background-color: #fbbc05;
            color: black;
        }
        .attack {
            background-color: #ea4335;
            color: white;
        }
        .normal {
            background-color: #4285f4;
            color: white;
        }
        pre {
            white-space: pre-wrap;
            word-wrap: break-word;
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 3px;
            max-height: 300px;
            overflow-y: auto;
        }
        h2 {
            margin-top: 0;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        .timestamp {
            color: white;
            font-size: 0.9em;
            text-align: right;
        }
        .config-button {
            margin-top: 10px;
            padding: 10px 20px;
            background-color: #34a853;
            color: white;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 1em;
            transition: background-color 0.3s;
        }
        .config-button:hover {
            background-color: #2e8b57;
        }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <h1>Network Analysis Dashboard</h1>
            <div class="timestamp">Last updated: {{ timestamp }}</div>
            <button class="config-button" onclick="window.location.href='/configuration/'">Configuration</button>
        </div>

        <div class="status-card">
            <h2>Trạng thái hiện tại</h2>
            <div class="status-indicator {{ status_class }}">
                {{ current_status }}
            </div>
        </div>

        <div class="latest-card">
            <h2>Đánh giá mới nhất</h2>
            <pre>{{ latest_evaluation }}</pre>
        </div>

        <div class="full-log">
            <h2>Toàn bộ nhật ký</h2>
            <pre>{{ full_log }}</pre>
        </div>
    </div>
</body>
</html>
"""

# HTML template cho trang configuration
CONFIG_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Configuration</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .config-form {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        label {
            display: block;
            margin-bottom: 5px;
        }
        input[type="text"], input[type="number"] {
            width: 100%;
            padding: 8px;
            margin-bottom: 15px;
            border: 1px solid #ccc;
            border-radius: 3px;
        }
        select {
            padding: 8px;
            border: 1px solid #ccc;
            border-radius: 3px;
        }
        .button-container {
            display: flex;
            justify-content: space-between;
            margin-top: 20px;
        }
        .save-button, .dashboard-button {
            padding: 10px 20px;
            background-color: #34a853;
            color: white;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        .save-button:hover, .dashboard-button:hover {
            background-color: #2e8b57;
        }
        .dashboard-button {
            background-color: #4285f4;
        }
        .dashboard-button:hover {
            background-color: #3367d6;
        }
    </style>
</head>
<body>
    <div class="config-form">
        <h2>System Configuration</h2>
        <form method="POST">
            <label for="capture_interface">Giao diện bắt gói tin:</label>
            <input type="text" id="capture_interface" name="capture_interface" value="{{ capture_interface }}" required>

            <label for="capture_duration">Thời gian bắt gói tin (giây):</label>
            <input type="number" id="capture_duration" name="capture_duration" value="{{ capture_duration }}" required>

            <label for="maximum_packets_capture">Số lượng gói tin tối đa:</label>
            <input type="number" id="maximum_packets_capture" name="maximum_packets_capture" value="{{ maximum_packets_capture }}" required>

            <label for="output_capture_file">Đường dẫn file bắt được:</label>
            <input type="text" id="output_capture_file" name="output_capture_file" value="{{ output_capture_file }}" required>

            <label for="minimum_network_limit">Giới hạn băng thông tối thiểu của hệ thống:</label>
            <input type="number" step="any" id="minimum_network_limit" name="minimum_network_limit" value="{{ minimum_network_limit }}" required>
            <select name="min_unit">
                <option value="Mbs" {% if min_unit == 'Mbs' %}selected{% endif %}>Mbs</option>
                <option value="Kbs" {% if min_unit == 'Kbs' %}selected{% endif %}>Kbs</option>
            </select>

            <label for="maximum_network_limit">Giới hạn băng thông tối đa của hệ thống:</label>
            <input type="number" step="any" id="maximum_network_limit" name="maximum_network_limit" value="{{ maximum_network_limit }}" required>
            <select name="max_unit">
                <option value="Mbs" {% if max_unit == 'Mbs' %}selected{% endif %}>Mbs</option>
                <option value="Kbs" {% if max_unit == 'Kbs' %}selected{% endif %}>Kbs</option>
            </select>

            <br><br>
            <div class="button-container">
                <button type="submit" class="save-button">Save</button>
                <button type="button" class="dashboard-button" onclick="window.location.href='/'">Dashboard</button>
            </div>
        </form>
    </div>
</body>
</html>
"""

def get_status_class(status):
    """Xác định class CSS dựa trên trạng thái"""
    if 'Tốt' in status:
        return 'good'
    elif 'Đáng ngờ' in status:
        return 'suspicious'
    elif 'Bị tấn công' in status or 'Nghẽn mạng' in status or 'Mạng sập' in status:
        return 'attack'
    return 'normal'

@app.route('/')
def view_log():
    log_data = parse_log_file()
    current_time = time.strftime('%Y-%m-%d %H:%M:%S')

    return render_template_string(
        DASHBOARD_TEMPLATE,
        current_status=log_data['current_status'],
        latest_evaluation=log_data['latest_evaluation'],
        full_log=log_data['full_log'],
        timestamp=current_time,
        status_class=get_status_class(log_data['current_status'])
    )

@app.route('/configuration/', methods=['GET', 'POST'])
def configuration():
    if request.method == 'POST':
        capture_interface = request.form['capture_interface']
        capture_duration = request.form['capture_duration']
        maximum_packets_capture = request.form['maximum_packets_capture']
        output_capture_file = request.form['output_capture_file']
        minimum_network_limit = f"{request.form['minimum_network_limit']} {request.form['min_unit']}"
        maximum_network_limit = f"{request.form['maximum_network_limit']} {request.form['max_unit']}"

        config = {
            'capture_interface': capture_interface,
            'capture_duration': capture_duration,
            'maximum_packets_capture': maximum_packets_capture,
            'output_capture_file': output_capture_file,
            'minimum_network_limit': minimum_network_limit,
            'maximum_network_limit': maximum_network_limit
        }
        write_config_file(config)
        return redirect(url_for('configuration'))
    else:
        config = parse_config_file()
        capture_interface = config.get('capture_interface', 'Wi-Fi')
        capture_duration = config.get('capture_duration', '20')
        maximum_packets_capture = config.get('maximum_packets_capture', '5000')
        output_capture_file = config.get('output_capture_file', 'content/wifi_capture.pcapng')
        min_limit, min_unit = config.get('minimum_network_limit', '20 Mbs').split()
        max_limit, max_unit = config.get('maximum_network_limit', '10 Mbs').split()

        return render_template_string(
            CONFIG_TEMPLATE,
            capture_interface=capture_interface,
            capture_duration=capture_duration,
            maximum_packets_capture=maximum_packets_capture,
            output_capture_file=output_capture_file,
            minimum_network_limit=min_limit,
            min_unit=min_unit,
            maximum_network_limit=max_limit,
            max_unit=max_unit
        )

def run_flask_app():
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)

if __name__ == '__main__':
    # Khởi chạy Flask trong một thread riêng
    flask_thread = Thread(target=run_flask_app)
    flask_thread.daemon = True
    flask_thread.start()

    print("Dashboard is running at http://localhost:5000")
    print("Configuration page is at http://localhost:5000/configuration/")
    print("Auto-refreshing every 5 seconds...")

    # Giữ chương trình chạy
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down dashboard...")