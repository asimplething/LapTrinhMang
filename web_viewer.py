from flask import Flask, render_template_string
import os
from threading import Thread
import time
import json
from collections import defaultdict

app = Flask(__name__)

# Đường dẫn đến file log
LOG_FILE = "log/network_analysis_log.txt"

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

# HTML template với 3 khu vực
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
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
            color: #666;
            font-size: 0.9em;
            text-align: right;
        }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <h1>Network Analysis Dashboard</h1>
            <div class="timestamp">Last updated: {{ timestamp }}</div>
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
        HTML_TEMPLATE,
        current_status=log_data['current_status'],
        latest_evaluation=log_data['latest_evaluation'],
        full_log=log_data['full_log'],
        timestamp=current_time,
        status_class=get_status_class(log_data['current_status'])
    )

def run_flask_app():
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)

if __name__ == '__main__':
    # Khởi chạy Flask trong một thread riêng
    flask_thread = Thread(target=run_flask_app)
    flask_thread.daemon = True
    flask_thread.start()

    print("Dashboard is running at http://localhost:5000")
    print("Auto-refreshing every 5 seconds...")

    # Giữ chương trình chạy
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down dashboard...")
