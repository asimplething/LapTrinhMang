from flask import Flask, render_template_string, request, redirect, url_for, abort
from markupsafe import Markup
import os
from threading import Thread
import time
import json
from collections import defaultdict 
import subprocess
import sys 
import markdown 
import re
sys.stdout.reconfigure(encoding='utf-8')
# ----- Các hằng số và biến toàn cục -----
LOG_DIR = "log"
MAIN_LOG_FILE = os.path.join(LOG_DIR, "network_analysis_log.txt")
CONFIG_FILE = "config/system_config.txt" # Giống C++
ANALYSIS_TIMESTAMP_FILE = os.path.join(LOG_DIR, "analysis_timestamp.txt")
VIEWABLE_LOG_FILES = {
    "capture": "capture_log.txt",
    "gemini": "gemini_log.txt",
    "deepseek": "deepseek_log.txt",
    "llama": "llama_log.txt",
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

        # Tìm các khối đánh giá tổng hợp
        log_parts = []
        
        # Thử nhiều định dạng khác nhau
        if '## ĐÁNH GIÁ TỔNG HỢP' in content:  # Định dạng mới nhất
            log_parts = content.split('## ĐÁNH GIÁ TỔNG HỢP')[1:]
        elif '=== ĐÁNH GIÁ TỔNG HỢP' in content:  # Định dạng cũ
            log_parts = content.split('=== ĐÁNH GIÁ TỔNG HỢP')[1:]

        if not log_parts:
            return {
                'current_status': 'Chưa có dữ liệu',
                'latest_evaluation': 'Chưa có đánh giá',
                'full_log_summary': content
            }

        # Lấy đánh giá mới nhất
        latest_eval_session = log_parts[-1]
        
        # Trích xuất kết luận tổng thể từ đánh giá mới nhất
        conclusion_part = ""
        
        # Kiểm tra nhiều định dạng kết luận có thể có
        conclusion_markers = [
            '## KẾT LUẬN TỔNG THỂ', 
            '=== KẾT LUẬN TỔNG THỂ',
            '## KẾT LUẬN:', 
            '## KẾT LUẬN TỔNG THỂ -'
        ]
        
        # Tìm đoạn báo cáo từ assistant_writer (giữa ĐÁNH GIÁ TỔNG HỢP và KẾT LUẬN TỔNG THỂ)
        report_part = latest_eval_session
        for marker in conclusion_markers:
            if marker in report_part:
                report_part = report_part.split(marker)[0]
        
        # Tìm phần kết luận
        for marker in conclusion_markers:
            if marker in latest_eval_session:
                conclusion_part = latest_eval_session.split(marker)[1]
                break

        current_status = 'Đang phân tích'  # Mặc định
        
        # Tìm dòng kết luận chứa trạng thái
        if conclusion_part:
            status_lines = [line for line in conclusion_part.split('\n') if 'Hệ thống ở trạng thái' in line]
            if status_lines:
                current_status = status_lines[0].split('Hệ thống ở trạng thái ')[1].strip('.')

        # Hiển thị chỉ báo cáo tổng hợp từ assistant_writer thay vì chi tiết phần
        formatted_latest_eval = report_part.strip()
        
        # Nếu không có định dạng Markdown thích hợp, thêm định dạng mặc định
        if not formatted_latest_eval or all(marker not in formatted_latest_eval for marker in ['### TÓM TẮT NHANH', '### PHÁT HIỆN CHÍNH']):
            # Hiển thị thông tin trạng thái
            formatted_latest_eval = "### Không tìm thấy báo cáo từ phân tích chi tiết\n\n"
            if current_status:
                formatted_latest_eval += f"**Trạng thái hiện tại:** {current_status}\n\n"
            
            # Nếu vẫn cần hiển thị các phần chi tiết như mã cũ, có thể thêm lại phần đó ở đây

        return {
            'current_status': current_status,
            'latest_evaluation': formatted_latest_eval,
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
    <script>
        // Lưu timestamp hiện tại để kiểm tra cập nhật
        let lastAnalysisTime = "{{ analysis_timestamp }}";
        
        // Hàm kiểm tra nếu có phân tích mới và tải lại trang nếu cần
        function checkForUpdates() {
            fetch('/analysis-timestamp')
                .then(response => response.text())
                .then(timestamp => {
                    if (timestamp !== lastAnalysisTime) {
                        console.log("Phát hiện phân tích mới, đang tải lại trang");
                        window.location.reload();
                    } else {
                        console.log("Không có phân tích mới, đang chờ...");
                        setTimeout(checkForUpdates, 5000); // Kiểm tra mỗi 5 giây
                    }
                })
                .catch(error => {
                    console.error("Lỗi khi kiểm tra cập nhật:", error);
                    setTimeout(checkForUpdates, 5000); // Thử lại sau 5 giây
                });
        }

        // Bắt đầu kiểm tra cập nhật khi trang tải xong
        window.onload = function() {
            setTimeout(checkForUpdates, 5000);
        }
    </script>
    <style>
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background-color: #f8f9fa; 
            color: #333; 
        }
        .dashboard { 
            display: grid; 
            grid-template-areas: 
                "header header" 
                "status latest" 
                "logs-links logs-links" 
                "full-log full-log"; 
            grid-gap: 20px; 
            max-width: 1200px;
            margin: 0 auto;
        }
        .card { 
            background-color: white; 
            padding: 20px; 
            border-radius: 8px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            transition: box-shadow 0.3s ease;
        }
        .card:hover {
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        .header { 
            grid-area: header; 
            background: linear-gradient(135deg, #4285f4, #34a853); 
            color: white; 
            text-align: center;
            padding: 25px 20px;
        }
        .status-card { grid-area: status; }
        .latest-card { grid-area: latest; }
        .logs-links-card { grid-area: logs-links; }
        .full-log-card { grid-area: full-log; }
        .status-indicator { 
            font-size: 1.8em; 
            font-weight: bold; 
            padding: 15px; 
            border-radius: 8px; 
            text-align: center; 
            margin: 15px 0;
            transition: all 0.3s ease;
        }
        .good { background-color: #34a853; color: white; }
        .suspicious { background-color: #fbbc05; color: black; }
        .attack { background-color: #ea4335; color: white; }
        .normal { background-color: #4285f4; color: white; }
        pre { white-space: pre-wrap; word-wrap: break-word; background-color: #f8f9fa; padding: 15px; border-radius: 3px; max-height: 300px; overflow-y: auto; }
        .markdown-content { 
            background-color: #f8f9fa; 
            padding: 20px; 
            border-radius: 6px; 
            max-height: 500px; 
            overflow-y: auto;
            line-height: 1.6;
            box-shadow: inset 0 0 5px rgba(0,0,0,0.05);
        }
        h1 { 
            margin-top: 0; 
            font-size: 2.5em;
            text-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        h2 { 
            margin-top: 0; 
            border-bottom: 2px solid #eee; 
            padding-bottom: 10px; 
            color: #4285f4;
            font-size: 1.5em;
        }
        h3 {
            color: #34a853;
            margin-top: 20px;
            margin-bottom: 10px;
        }
        .timestamp { 
            color: rgba(255,255,255,0.8); 
            font-size: 0.9em; 
            margin-top: 10px;
        }
        .nav-button { 
            margin: 10px 5px; 
            padding: 12px 20px; 
            background-color: #34a853; 
            color: white; 
            border: none; 
            border-radius: 30px; 
            cursor: pointer; 
            font-size: 1em; 
            text-decoration: none; 
            display: inline-block;
            transition: all 0.3s ease;
            font-weight: bold;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
        }
        .nav-button:hover { 
            background-color: #2e8b57; 
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }
        .log-link-button { 
            background-color: #5bc0de;
            font-weight: normal; 
        }
        .log-link-button:hover { 
            background-color: #31b0d5; 
        }
        /* Định dạng cho phần tử markdown */
        .markdown-content p { margin: 1em 0; }
        .markdown-content strong { 
            font-weight: bold; 
            color: #0d6efd;
        }
        .markdown-content ul { 
            margin-left: 20px;
            padding-left: 20px;
        }
        .markdown-content li {
            margin-bottom: 5px;
        }
        .markdown-content .list-item {
            padding: 4px 0;
            margin-left: 20px;
            display: block;
        }
        .markdown-content h1, .markdown-content h2, .markdown-content h3, .markdown-content h4 { 
            margin-top: 1em; 
            margin-bottom: 0.5em; 
        }
        .markdown-content h4 {
            font-size: 1.1em;
            margin-top: 0.8em;
            margin-bottom: 0.3em;
        }
        .markdown-content code {
            background-color: #f0f0f0;
            padding: 2px 4px;
            border-radius: 4px;
            font-family: Consolas, Monaco, 'Courier New', monospace;
            font-size: 0.9em;
        }
        .markdown-content pre {
            background-color: #f0f0f0;
            padding: 12px;
            border-radius: 4px;
            margin: 12px 0;
            border-left: 4px solid #34a853;
            overflow-x: auto;
        }
        .markdown-content pre code {
            background-color: transparent;
            padding: 0;
        }
        /* Responsive Design */
        @media (max-width: 768px) {
            .dashboard {
                grid-template-areas:
                    "header"
                    "status"
                    "latest"
                    "logs-links"
                    "full-log";
            }
        }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header card">
            <h1>Network Analysis Dashboard</h1>
            <div class="timestamp">Cập nhật cuối: {{ timestamp }}</div>
            <a href="{{ url_for('configuration') }}" class="nav-button">Cấu hình hệ thống</a>
        </div>
        <div class="status-card card">
            <h2>Trạng thái mạng hiện tại</h2>
            <div class="status-indicator {{ status_class }}">
                {{ current_status }}
            </div>
        </div>
        <div class="latest-card card">
            <h2>Đánh giá mới nhất</h2>
            <div class="markdown-content">
                {{ latest_evaluation|safe }}
            </div>
        </div>
        <div class="logs-links-card card">
            <h2>Xem chi tiết nhật ký</h2>
            <div style="text-align: center;">
                <a href="{{ url_for('view_specific_log', log_key='network_analysis') }}" class="nav-button log-link-button">Network Analysis</a>
                <a href="{{ url_for('view_specific_log', log_key='capture') }}" class="nav-button log-link-button">Capture</a>
                <a href="{{ url_for('view_specific_log', log_key='gemini') }}" class="nav-button log-link-button">Gemini</a>
                <a href="{{ url_for('view_specific_log', log_key='deepseek') }}" class="nav-button log-link-button">Deepseek</a>
                <a href="{{ url_for('view_specific_log', log_key='llama') }}" class="nav-button log-link-button">Llama</a>
            </div>
        </div>
        <div class="full-log-card card">
            <h2>Lịch sử đánh giá</h2>
            <div class="markdown-content">
                {{ full_log_summary|safe }}
            </div>
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
        /* Base styles */
        body { 
            font-family: 'Segoe UI', Arial, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background-color: #f8f9fa;
            color: #333;
        }
        .container { 
            background-color: white; 
            padding: 25px; 
            border-radius: 8px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            flex-direction: column;
            height: calc(100vh - 40px);
        }
        
        /* Header and layout */
        .header {
            margin-bottom: 20px;
        }
        .content-area {
            flex: 1;
            overflow: hidden;
            position: relative;
            display: flex;
            flex-direction: column;
        }
        .log-content { 
            background-color: #f8f9fa; 
            padding: 20px; 
            border-radius: 6px; 
            line-height: 1.6;
            box-shadow: inset 0 0 5px rgba(0,0,0,0.05);
            overflow-y: auto;
            flex: 1;
        }
        
        /* Links and buttons */
        a { 
            color: #4285f4; 
            text-decoration: none; 
            transition: all 0.3s;
            font-weight: bold;
        }
        a:hover { 
            text-decoration: underline;
            color: #34a853; 
        }
        .back-button {
            display: inline-block;
            margin: 10px 0 20px;
            padding: 10px 20px;
            background-color: #4285f4;
            color: white;
            border-radius: 30px;
            text-decoration: none;
            font-weight: bold;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
            transition: all 0.3s;
        }
        .back-button:hover {
            background-color: #3367d6;
            text-decoration: none;
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }
        
        /* Typography */
        h2 { 
            color: #4285f4; 
            margin-top: 0;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }
        .log-content p { margin: 1em 0; }
        .log-content strong { font-weight: bold; color: #0d6efd; }
        .log-content ul { 
            margin-left: 20px; 
            padding-left: 20px;
        }
        .log-content li {
            margin-bottom: 5px;
        }
        .log-content .list-item {
            padding: 4px 0;
            margin-left: 20px;
            display: block;
        }
        .log-content h1, .log-content h2, .log-content h3, .log-content h4 { 
            margin-top: 1em; 
            margin-bottom: 0.5em;
            color: #34a853;
        }
        .log-content h4 {
            font-size: 1.1em;
            margin-top: 0.8em;
            margin-bottom: 0.3em;
        }
        
        /* Code blocks */
        .log-content code {
            background-color: #f0f0f0;
            padding: 2px 4px;
            border-radius: 4px;
            font-family: Consolas, Monaco, 'Courier New', monospace;
            font-size: 0.9em;
        }
        pre { 
            white-space: pre-wrap; 
            word-wrap: break-word; 
            background-color: #f0f0f0; 
            padding: 12px; 
            border-radius: 4px; 
            margin: 12px 0;
            border-left: 4px solid #34a853;
            color: #333;
            font-family: Consolas, Monaco, 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
        }
        pre code {
            background-color: transparent;
            padding: 0;
        }
        
        /* Log entries */
        .log-entry {
            margin-bottom: 25px;
            padding-bottom: 20px;
            border-bottom: 1px solid #ddd;
            background-color: #fff;
            padding: 15px;
            border-radius: 6px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }
        .log-entry:hover {
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            transition: box-shadow 0.3s ease;
        }
        
        /* Timestamps */
        .timestamp {
            color: #666;
            font-size: 0.9em;
            font-style: italic;
            margin-bottom: 8px;
            padding-bottom: 5px;
            border-bottom: 1px dashed #eee;
            display: block;
        }
        
        /* Evaluation sections */
        .evaluation-section {
            margin-top: 15px;
            padding: 12px;
            background-color: rgba(52, 168, 83, 0.05);
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>Nhật ký: {{ log_title }}</h2>
            <a href="{{ url_for('view_main_dashboard') }}" class="back-button">← Quay lại Dashboard</a>
        </div>
        <div class="content-area">
            <div class="log-content">
                {{ log_content|safe }}
            </div>
        </div>
    </div>
</body>
</html>
"""

CONFIG_TEMPLATE = """
<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8"><title>Cấu hình Hệ thống</title>
<style>
    body { 
        font-family: 'Segoe UI', Arial, sans-serif; 
        margin: 0; 
        padding: 20px; 
        background-color: #f8f9fa;
        color: #333;
    }
    .config-form { 
        background-color: white; 
        padding: 30px; 
        border-radius: 8px; 
        box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        max-width: 700px; 
        margin: 20px auto;
    }
    h2 {
        color: #4285f4;
        margin-top: 0;
        border-bottom: 2px solid #eee;
        padding-bottom: 15px;
        text-align: center;
    }
    label { 
        display: block; 
        margin-bottom: 8px; 
        font-weight: bold;
        color: #555;
    }
    input[type="text"], input[type="number"], select { 
        width: calc(100% - 18px); 
        padding: 12px; 
        margin-bottom: 20px; 
        border: 1px solid #ddd; 
        border-radius: 6px; 
        box-sizing: border-box;
        font-size: 16px;
        transition: all 0.3s;
    }
    input:focus, select:focus {
        outline: none;
        border-color: #4285f4;
        box-shadow: 0 0 0 2px rgba(66,133,244,0.2);
    }
    .form-group { 
        margin-bottom: 25px; 
    }
    .form-row {
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .form-row input {
        flex: 1;
        margin-bottom: 0;
    }
    .form-row select {
        width: 100px;
        margin-bottom: 0;
    }
    .button-container { 
        display: flex; 
        justify-content: center;
        gap: 20px;
        margin-top: 30px; 
    }
    .button { 
        padding: 12px 24px; 
        color: white; 
        border: none; 
        border-radius: 30px; 
        cursor: pointer; 
        transition: all 0.3s; 
        text-decoration: none;
        font-weight: bold;
        font-size: 16px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.2);
    }
    .button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0,0,0,0.2);
    }
    .save-button { 
        background-color: #34a853; 
    } 
    .save-button:hover { 
        background-color: #2e8b57; 
    }
    .dashboard-button { 
        background-color: #4285f4; 
    } 
    .dashboard-button:hover { 
        background-color: #3367d6; 
    }
    .section-header {
        font-size: 18px;
        color: #4285f4;
        margin: 30px 0 15px;
        padding-bottom: 5px;
        border-bottom: 1px solid #eee;
    }
</style></head><body><div class="config-form"><h2>Cấu hình Hệ Thống</h2><form method="POST">
    <div class="section-header">Cấu hình thu thập dữ liệu</div>
    <div class="form-group"><label for="capture_interface">Giao diện bắt gói tin:</label><input type="text" id="capture_interface" name="capture_interface" value="{{ capture_interface }}" required></div>
    <div class="form-group"><label for="capture_duration">Thời gian bắt gói tin (giây):</label><input type="number" id="capture_duration" name="capture_duration" value="{{ capture_duration }}" required></div>
    <div class="form-group"><label for="maximum_packets_capture">Số lượng gói tin tối đa:</label><input type="number" id="maximum_packets_capture" name="maximum_packets_capture" value="{{ maximum_packets_capture }}" required></div>
    <div class="form-group"><label for="output_capture_file">Đường dẫn file bắt được:</label><input type="text" id="output_capture_file" name="output_capture_file" value="{{ output_capture_file }}" required></div>
    
    <div class="section-header">Cấu hình giới hạn băng thông</div>
    <div class="form-group"><label for="minimum_network_limit_val">Giới hạn băng thông tối thiểu:</label>
        <div class="form-row">
            <input type="text" id="minimum_network_limit_val" name="minimum_network_limit_val" value="{{ minimum_network_limit_val }}" required>
            <select name="min_unit">
                <option value="Mbs" {% if min_unit == 'Mbs' %}selected{% endif %}>Mbs</option>
                <option value="Kbs" {% if min_unit == 'Kbs' %}selected{% endif %}>Kbs</option>
            </select>
        </div>
    </div>
    <div class="form-group"><label for="maximum_network_limit_val">Giới hạn băng thông tối đa:</label>
        <div class="form-row">
            <input type="text" id="maximum_network_limit_val" name="maximum_network_limit_val" value="{{ maximum_network_limit_val }}" required>
            <select name="max_unit">
                <option value="Mbs" {% if max_unit == 'Mbs' %}selected{% endif %}>Mbs</option>
                <option value="Kbs" {% if max_unit == 'Kbs' %}selected{% endif %}>Kbs</option>
            </select>
        </div>
    </div>
    <div class="button-container">
        <a href="{{ url_for('view_main_dashboard') }}" class="button dashboard-button">← Trở về Dashboard</a>
        <button type="submit" class="button save-button">Lưu cấu hình</button>
    </div>
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

def render_markdown(text):
    """Chuyển đổi văn bản có định dạng markdown thành HTML"""
    # Đảm bảo text là chuỗi và không phải None
    if text is None:
        return Markup("")
    
    # Tiền xử lý văn bản để đảm bảo các dòng danh sách được giữ nguyên
    # Xử lý các dòng bắt đầu bằng "- **" bằng cách thêm hai dòng trống trước mỗi dòng
    text = re.sub(r'(?m)^- \*\*(.*?)\*\*: (.*?)$', r'\n\n- **\1**: \2', text)
    
    # Xử lý định dạng markdown tiêu đề trước khi chuyển đổi
    lines = text.split('\n')
    processed_lines = []
    
    in_log_entry = False
    in_evaluation_section = False
    
    for i, line in enumerate(lines):
        line_trimmed = line.strip()
        
        # Xử lý tiêu đề ## thành h2 và ### thành h3
        if line_trimmed.startswith('## '):
            # Đánh dấu đây là một timestamp mới
            if re.match(r'^## \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$', line_trimmed):
                # Đóng evaluation section nếu đang mở
                if in_evaluation_section:
                    processed_lines.append('</div>')
                    in_evaluation_section = False
                
                # Đóng log-entry trước đó nếu có
                if in_log_entry:
                    processed_lines.append('</div>')
                    
                # Mở log-entry mới
                processed_lines.append('<div class="log-entry">')
                processed_lines.append(f'<div class="timestamp">{line_trimmed[3:]}</div>')
                in_log_entry = True
            elif line_trimmed == '## ĐÁNH GIÁ TỔNG HỢP':
                # Mở evaluation section
                if in_evaluation_section:
                    processed_lines.append('</div>')
                processed_lines.append('<div class="evaluation-section">')
                processed_lines.append(f'<h2>{line_trimmed[3:]}</h2>')
                in_evaluation_section = True
            elif line_trimmed == '## KẾT LUẬN TỔNG THỂ' or line_trimmed.startswith('## KẾT LUẬN'):
                # Đóng evaluation section trước khi mở một section mới
                if in_evaluation_section:
                    processed_lines.append('</div>')
                processed_lines.append('<div class="evaluation-section">')
                processed_lines.append(f'<h2>{line_trimmed[3:]}</h2>')
                in_evaluation_section = True
            else:
                # Tiêu đề h2 bình thường
                processed_lines.append(f'<h2>{line_trimmed[3:]}</h2>')
        elif line_trimmed.startswith('### '):
            # Xử lý tiêu đề h3
            processed_lines.append(f'<h3>{line_trimmed[4:]}</h3>')
        elif line_trimmed.startswith('#### '):
            # Xử lý tiêu đề h4
            processed_lines.append(f'<h4>{line_trimmed[5:]}</h4>')
        elif line_trimmed.startswith('---'):
            # Xử lý dấu phân cách
            processed_lines.append('<hr>')
        else:
            # Xử lý các dòng bình thường
            # Đặc biệt xử lý các dòng danh sách để đảm bảo chúng được tách riêng
            if line_trimmed.startswith('- '):
                # Thêm một thẻ đánh dấu đặc biệt cho các dòng danh sách
                processed_lines.append('<list-item>' + line + '</list-item>')
            else:
                processed_lines.append(line)
    
    # Đóng các thẻ mở nếu cần
    if in_evaluation_section:
        processed_lines.append('</div>')
    if in_log_entry:
        processed_lines.append('</div>')
    
    # Ghép lại text đã xử lý
    text = '\n'.join(processed_lines)
    
    # Xử lý danh sách các mục trong phần đánh giá mạng
    # Tìm và thay thế các dòng như: "- **Các mối đe dọa đã xác định**: Không có... - **Điểm yếu tiềm ẩn**:"
    text = re.sub(r'- \*\*(.*?)\*\*: (.*?) -', r'- **\1**: \2\n-', text)
    
    # Xử lý đặc biệt cho phần ĐÁNH GIÁ BẢO MẬT và các phần tương tự
    # Tìm dạng "- **Tiêu đề**: Nội dung - **Tiêu đề khác**:"
    security_section_pattern = r'(ĐÁNH GIÁ BẢO MẬT|HIỆU SUẤT MẠNG|KHUYẾN NGHỊ)\n+(.*?)(?=\n\n|$)'
    
    def format_security_section(match):
        section_title = match.group(1)
        content = match.group(2)
        
        # Tìm và định dạng lại các dòng có dạng "- **Tiêu đề**: Nội dung"
        content = re.sub(r'- \*\*(.*?)\*\*: (.*?)(?= - \*\*|\n|$)', r'- **\1**: \2\n', content)
        
        return f"{section_title}\n{content}"
    
    text = re.sub(security_section_pattern, format_security_section, text, flags=re.DOTALL)
    
    # Chuyển đổi markdown thành HTML với các extensions phụ trợ
    html = markdown.markdown(text, extensions=[
        'tables', 
        'nl2br',
        'fenced_code',
        'smarty',
        'attr_list',
        'def_list'
    ])
    
    # Thay thế các thẻ danh sách tạm thời bằng các mục danh sách HTML thực sự
    html = re.sub(r'<p><list-item>(.*?)</list-item></p>', r'<div class="list-item">\1</div>', html)
    
    # Xử lý các dòng danh sách bắt đầu bằng dấu gạch đầu dòng
    html = html.replace('<div class="list-item">- ', '<div class="list-item">• ')
    
    # Đảm bảo các dòng bắt đầu bằng "- **" được định dạng đúng
    html = re.sub(r'<p>- \*\*(.*?)\*\*: (.*?)</p>', r'<div class="list-item">• <strong>\1</strong>: \2</div>', html)
    
    # Xử lý các bullet points (dấu gạch đầu dòng) trong đoạn văn
    html = re.sub(r'<p>- ', r'<p>• ', html)
    html = re.sub(r'<br />- ', r'<br />• ', html)
    
    # Đảm bảo các đoạn văn bản được xuống dòng đúng
    html = re.sub(r'<p>(.*?)\s*-\s*\*\*(.*?)\*\*:\s*(.*?)\s*-\s*', r'<p>\1<br/>• <strong>\2</strong>: \3<br/>', html)
    
    # Chuyển đổi các định dạng đặc biệt 
    html = html.replace("**Tình trạng:**", "<strong>Tình trạng:</strong>")
    html = html.replace("**Đánh giá:**", "<strong>Đánh giá:</strong>")
    
    # Đảm bảo các đoạn văn bản được xuống dòng đúng trong các phần đánh giá
    html = re.sub(r'<p>(.*?)\*\*(.*?)\*\*:(.*?)<\/p>', r'<p>\1<strong>\2</strong>:\3</p>', html)
    
    # Xử lý các khối code được bao bởi ```
    code_pattern = r'```(.*?)```'
    code_blocks = re.findall(code_pattern, html, re.DOTALL)
    for block in code_blocks:
        formatted_block = block.strip() 
        html = html.replace(f'```{block}```', f'<pre><code>{formatted_block}</code></pre>')
    
    # Xử lý backtick đơn
    inline_code_pattern = r'`([^`]+)`'
    html = re.sub(inline_code_pattern, r'<code>\1</code>', html)
    
    # Tìm tất cả các dòng dạng [timestamp]
    timestamp_pattern = r'\[([\d\-]{10} [\d:]{8})\]'
    html = re.sub(timestamp_pattern, r'<span class="timestamp">[\1]</span>', html)
    
    # Xóa khoảng trống thừa trong các thẻ pre
    html = re.sub(r'<pre>\s*', '<pre>', html)
    html = re.sub(r'\s*</pre>', '</pre>', html)
    
    return Markup(html)

# ----- Các route Flask (từ web_viewer.py) -----
@app.route('/')
def view_main_dashboard():
    log_data = parse_log_file()
    current_time = time.strftime('%Y-%m-%d %H:%M:%S')
    
    # Chuyển đổi nội dung log từ markdown thành HTML
    latest_evaluation_html = render_markdown(log_data['latest_evaluation'])
    full_log_summary_html = render_markdown(log_data['full_log_summary'])
    
    # Get the current analysis timestamp
    analysis_timestamp = get_analysis_timestamp()
    
    return render_template_string(
        DASHBOARD_TEMPLATE,
        current_status=log_data['current_status'],
        latest_evaluation=latest_evaluation_html,
        full_log_summary=full_log_summary_html,
        timestamp=current_time,
        status_class=get_status_class(log_data['current_status']),
        analysis_timestamp=analysis_timestamp
    )

@app.route('/analysis-timestamp')
def get_timestamp():
    """Trả về timestamp phân tích mới nhất"""
    return get_analysis_timestamp()

def get_analysis_timestamp():
    """Đọc timestamp phân tích mới nhất từ file"""
    try:
        if os.path.exists(ANALYSIS_TIMESTAMP_FILE):
            with open(ANALYSIS_TIMESTAMP_FILE, 'r', encoding='utf-8') as f:
                return f.read().strip()
        return str(int(time.time()))  # Sử dụng thời gian hiện tại nếu file không tồn tại
    except Exception as e:
        print(f"[ERROR] Lỗi khi đọc timestamp phân tích: {e}")
        return str(int(time.time()))  # Fallback to current time

def update_analysis_timestamp():
    """Cập nhật timestamp phân tích mới nhất vào file"""
    try:
        os.makedirs(os.path.dirname(ANALYSIS_TIMESTAMP_FILE), exist_ok=True)
        timestamp = str(int(time.time()))
        with open(ANALYSIS_TIMESTAMP_FILE, 'w', encoding='utf-8') as f:
            f.write(timestamp)
        return timestamp
    except Exception as e:
        print(f"[ERROR] Lỗi khi cập nhật timestamp phân tích: {e}")
        return str(int(time.time()))

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
    
    # Chuyển đổi nội dung log từ markdown thành HTML
    log_content_html = render_markdown(log_content_display)

    return render_template_string(LOG_VIEW_TEMPLATE, log_title=log_filename, log_content=log_content_html)

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