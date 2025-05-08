from graphviz import Digraph

# Tạo một đồ thị có hướng mới
dot = Digraph(comment='Sơ đồ khối phân tích gói tin mạng với Autogen', engine='dot')
dot.attr(rankdir='TB', labelloc="t", label="Sơ đồ khối chi tiết hệ thống phân tích gói tin mạng", fontsize="30")

# Định nghĩa các node chính trong network_analyze.exe (C++)
with dot.subgraph(name='cluster_main_exe') as main_exe_cluster:
    main_exe_cluster.attr(label='network_analyze.exe (C++)', style='filled', color='lightgreen')
    main_exe_cluster.node('start_exe', 'Bắt đầu', fillcolor = 'white', style='filled', color='black')
    main_exe_cluster.node('read_config_exe', 'Đọc tệp config\n(config/system_config.txt)', fillcolor = 'white', style='filled', color='black')
    main_exe_cluster.node('launch_viewer_once', 'Khởi chạy web_viewer.py\n( chạy nền, 1 lần duy nhất)', fillcolor = 'white', style='filled', color='black')
    main_exe_cluster.node('main_loop_exe', 'Vòng lặp chính', fillcolor = 'white', style='filled', color='black')
    main_exe_cluster.node('call_ai_agent_exe', 'Gọi AI_agent.py\nvới các tham số từ config', fillcolor = 'white', style='filled', color='black')

# Định nghĩa các node cho AI_agent.py
with dot.subgraph(name='cluster_ai_agent') as ai_agent_cluster:
    ai_agent_cluster.attr(label='AI_agent.py (Python - Autogen Framework)', style='filled', color='lightblue')
    ai_agent_cluster.node('receive_params_agent', 'Nhận tham số từ\nnetwork_analyze.exe', style='filled', fillcolor='white', color='black')
    
    with ai_agent_cluster.subgraph(name='cluster_capture_extract_agent') as ce_cluster:
        ce_cluster.attr(label='CaptureAgent (gồm 1 AI model API và 2 tool)', fontsize="20", style='filled', color='aliceblue')
        ce_cluster.node('capture_ai_agent', 'CaptureAgent (Gemini API)', style='filled', fillcolor='white', color='black')
        ce_cluster.node('use_network_capture_tool', 'Sử dụng network_capture_tool')
        ce_cluster.node('pcapng_file', '[Tệp .pcapng]', shape='note', style='filled', fillcolor='beige')
        ce_cluster.node('use_pcap_extract_tool', 'Sử dụng pcap_extract_tool')
        ce_cluster.node('data_chunks', '[Data Chunks]', shape='note', style='filled', fillcolor='beige')

    with ai_agent_cluster.subgraph(name='cluster_analysis_models') as analysis_cluster:
        analysis_cluster.attr(label='Phân tích song song (3 AI Models API)', fontsize="20", style='filled', color='lightcyan')
        analysis_cluster.node('loop_chunks', 'Lặp qua từng Data Chunk')
        analysis_cluster.node('send_to_model1', 'Gửi chunk đến AI Model 1\n(Assistant Gemini)')
        analysis_cluster.node('send_to_model2', 'Gửi chunk đến AI Model 2\n(Assistant DeepSeek)')
        analysis_cluster.node('send_to_model3', 'Gửi chunk đến AI Model 3\n(Assistant Qwen)')
        analysis_cluster.node('log_model1', 'Ghi log Model 1\n(gemini_log.txt)')
        analysis_cluster.node('log_model2', 'Ghi log Model 2\n(deepseek_log.txt)')
        analysis_cluster.node('log_model3', 'Ghi log Model 3\n(qwen_log.txt)')
        analysis_cluster.node('wait_3_model', 'Chờ phản hồi từ cả 3 models')
        analysis_cluster.node('collect_3_results', 'Thu thập kết quả\ntừ 3 models cho chunk')
        analysis_cluster.node('log_chunk_eval', 'Lưu đánh giá của chunk\nvào network_analysis_log.txt')

    with ai_agent_cluster.subgraph(name='cluster_evaluation') as eval_cluster:
        eval_cluster.attr(label='Tổng hợp và kết luận', style='filled', fontsize="20", color='lightyellow')
        eval_cluster.node('check_all_chunks_done', 'Tất cả các chunk đã xử lý?')
        eval_cluster.node('overall_conclusion', 'Kết luận trạng thái mạng\n(dựa trên trọng số trạng thái từ các chunk)')
        eval_cluster.node('log_overall_conclusion', 'Ghi trạng thái mạng\nvào network_analysis_log.txt')
        eval_cluster.node('final_log_file', '[log/network_analysis_log.txt]', shape='note', style='filled', fillcolor='lemonchiffon')

    ai_agent_cluster.node('end_ai_agent', 'Kết thúc AI_agent.py', style='filled', fillcolor='white', color='black')

# Định nghĩa các node cho web_viewer.py
with dot.subgraph(name='cluster_web_viewer') as web_viewer_cluster:
    web_viewer_cluster.attr(label='web_viewer.py (Python - Flask)', style='filled', color='lightblue')
    web_viewer_cluster.node('flask_app', 'Chạy ứng dụng Flask Web', style='filled', fillcolor='white', color='black')
    
    with web_viewer_cluster.subgraph(name='cluster_dashboard') as dashboard_cluster:
        dashboard_cluster.attr(label='Trang Dashboard (/) ', fontsize="20", style='filled', color='lightyellow')
        dashboard_cluster.node('start_dashboard_loop', 'Bắt đầu chu kỳ làm mới Dashboard')
        dashboard_cluster.node('read_main_log_viewer', 'Đọc network_analysis_log.txt')
        dashboard_cluster.node('parse_log_viewer', 'Phân tích log:\n- Lấy trạng thái hiện tại\n- Lấy đánh giá mới nhất')
        dashboard_cluster.node('display_on_web', 'Hiển thị thông tin trên web')
        dashboard_cluster.node('web_interface_dashboard', '[Giao diện Web Dashboard]', shape='display', style='filled', fillcolor='aquamarine')
        dashboard_cluster.node('delay_5s', 'Chờ 5 giây')

    with web_viewer_cluster.subgraph(name='cluster_config_page') as config_page_cluster:
        config_page_cluster.attr(label='Trang Configuration (/configuration/)', fontsize="20", style='filled', color='lightcyan')
        config_page_cluster.node('load_config_page', 'Truy cập trang cấu hình')
        config_page_cluster.node('read_config_viewer_initial', 'Đọc config/system_config.txt (lần đầu)')
        config_page_cluster.node('display_config_form', 'Hiển thị form cấu hình\nvới dữ liệu hiện tại')
        config_page_cluster.node('user_modifies_config', 'Người dùng chỉnh sửa & Nhấn SAVE')
        config_page_cluster.node('write_config_viewer', 'Ghi thay đổi vào\nconfig/system_config.txt')
        config_page_cluster.node('read_config_viewer_after_save', 'Đọc lại config/system_config.txt',)
        config_page_cluster.node('config_file_viewer', '[config/system_config.txt]', shape='note', style='filled', fillcolor='beige')

# Kết nối các node trong network_analyze.exe
dot.edge('start_exe', 'read_config_exe')
dot.edge('read_config_exe', 'launch_viewer_once')
dot.edge('launch_viewer_once', 'main_loop_exe')
dot.edge('main_loop_exe', 'call_ai_agent_exe')
dot.edge('call_ai_agent_exe', 'receive_params_agent', lhead='cluster_ai_agent')

# Kết nối các node trong AI_agent.py
dot.edge('receive_params_agent', 'capture_ai_agent')
dot.edge('capture_ai_agent', 'use_network_capture_tool')
dot.edge('use_network_capture_tool', 'pcapng_file')
dot.edge('pcapng_file', 'use_pcap_extract_tool')
dot.edge('use_pcap_extract_tool', 'data_chunks')
dot.edge('data_chunks', 'loop_chunks')
dot.edge('loop_chunks', 'send_to_model1')
dot.edge('loop_chunks', 'send_to_model2')
dot.edge('loop_chunks', 'send_to_model3')
dot.edge('send_to_model1', 'log_model1')
dot.edge('send_to_model2', 'log_model2')
dot.edge('send_to_model3', 'log_model3')
dot.edge('log_model1', 'wait_3_model')
dot.edge('log_model2', 'wait_3_model')
dot.edge('log_model3', 'wait_3_model')
dot.edge('wait_3_model', 'collect_3_results')
dot.edge('collect_3_results', 'log_chunk_eval')
dot.edge('log_chunk_eval', 'check_all_chunks_done')
dot.edge('check_all_chunks_done', 'loop_chunks', label='Còn chunk')
dot.edge('check_all_chunks_done', 'overall_conclusion', label='Hết chunk')
dot.edge('overall_conclusion', 'log_overall_conclusion')
dot.edge('log_overall_conclusion', 'final_log_file')
dot.edge('final_log_file', 'end_ai_agent')
dot.edge('end_ai_agent', 'main_loop_exe', ltail='cluster_ai_agent', label='Lặp lại phân tích')

# Kết nối web_viewer.py với các tệp liên quan
dot.edge('launch_viewer_once', 'flask_app', lhead='cluster_web_viewer')

# Luồng Dashboard (có vòng lặp 5s)
dot.edge('flask_app', 'start_dashboard_loop', label='Truy cập Dashboard (/)')
dot.edge('start_dashboard_loop', 'read_main_log_viewer')
dot.edge('read_main_log_viewer', 'parse_log_viewer')
dot.edge('parse_log_viewer', 'display_on_web')
dot.edge('display_on_web', 'web_interface_dashboard')
dot.edge('web_interface_dashboard', 'delay_5s')
dot.edge('delay_5s', 'start_dashboard_loop', label='5s làm mới')

# Luồng Configuration Page (cập nhật sau khi save)
dot.edge('flask_app', 'load_config_page', label='Truy cập Config (/configuration/) - GET')
dot.edge('load_config_page', 'read_config_viewer_initial')
dot.edge('read_config_viewer_initial', 'display_config_form')
dot.edge('display_config_form', 'user_modifies_config')
dot.edge('user_modifies_config', 'write_config_viewer', label='Nhấn Save (POST)')
dot.edge('write_config_viewer', 'config_file_viewer', arrowhead='normal', style='dashed', label='Ghi vào')
dot.edge('write_config_viewer', 'read_config_viewer_after_save')
dot.edge('read_config_viewer_after_save', 'display_config_form', label='Hiển thị lại\ndữ liệu đã cập nhật')

# Kết nối config file được đọc bởi network_analyze.exe
#dot.edge('read_config_exe', 'config_file_viewer', arrowhead='empty', style='dashed', label='Đọc từ')

# Tạo file output
try:
    dot.render('detailed_project_flowchart_updated', view=True, format='png')
    print("Sơ đồ khối cập nhật đã được tạo: detailed_project_flowchart_updated.png")
except Exception as e:
    print(f"Lỗi khi tạo sơ đồ: {e}")
    print("Hãy đảm bảo bạn đã cài đặt Graphviz và thêm nó vào PATH của hệ thống.")