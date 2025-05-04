from flask import Flask, render_template_string
import os
from threading import Thread
import time

app = Flask(__name__)

# Đường dẫn đến file log
LOG_FILE = "log/network_analysis_log.txt"

def read_log_file():
    #Đọc nội dung file log
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return "Log file not found yet. Please wait..."

# HTML template với auto-refresh
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Network Analysis Log Viewer</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        pre {
            white-space: pre-wrap;
            word-wrap: break-word;
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 3px;
            border-left: 4px solid #4285f4;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .timestamp {
            color: #666;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Network Analysis Log</h1>
            <div class="timestamp">Last updated: {{ timestamp }}</div>
        </div>
        <pre>{{ log_content }}</pre>
    </div>
</body>
</html>
"""

@app.route('/')
def view_log():
    log_content = read_log_file()
    current_time = time.strftime('%Y-%m-%d %H:%M:%S')
    return render_template_string(HTML_TEMPLATE,
                               log_content=log_content,
                               timestamp=current_time)

def run_flask_app():
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)

if __name__ == '__main__':
    # Khởi chạy Flask trong một thread riêng
    flask_thread = Thread(target=run_flask_app)
    flask_thread.daemon = True
    flask_thread.start()

    print("Log viewer is running at http://localhost:5000")
    print("Auto-refreshing every 5 seconds...")

    # Giữ chương trình chạy
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down log viewer...")
