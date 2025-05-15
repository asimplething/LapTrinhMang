import os
import sys
import json
from scapy.all import rdpcap
from autogen_agentchat.agents import AssistantAgent, UserProxyAgent
from autogen_ext.models.openai import OpenAIChatCompletionClient
# Tool cho AI agent để bắt gói tin và phân tích
from network_capture_tool import network_capture_tool
from pcap_extract_tool import pcap_extract_tool
from autogen_core.tools import FunctionTool
from typing import Literal, Dict, List, Any
from pydantic import BaseModel
import datetime
from dotenv import load_dotenv
from network_evaluation import evaluate_results, STATUS_WEIGHTS
from collections import defaultdict
import asyncio
from write_log import write_log_agents, write_detailed_analysis_report

print("Đang chạy AI agent...")

# Nhận tham số từ command-line
if len(sys.argv) < 7:
    raise ValueError("Thiếu tham số: minimum_network_limit, maximum_network_limit và output_capture_file")
minimum_network_limit = sys.argv[1]
maximum_network_limit = sys.argv[2]
output_capture_file = sys.argv[3]
capture_interface = sys.argv[4]
capture_duration = int(sys.argv[5])
maximum_packets_capture = int(sys.argv[6])

# Đường dẫn tới file PCAPNG
file_path = output_capture_file
json_file_path = "content/extracted_data.json"

# Số lương gói tin tối đa mỗi phần gửi cho AI agent
chunk_size = 100

print("Đang tải API KEY...")
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
if not GEMINI_API_KEY:
    raise ValueError("API_KEY not found in environment variables.")

system_message_analyze_template=f"""Bạn là trợ lý AI chuyên phân tích dữ liệu mạng từ một tệp PCAPNG. Nhiệm vụ của bạn là phân tích từng phần của tệp PCAPNG, với mỗi phần được chia theo số lượng gói tin. Hãy phân tích toàn diện và cung cấp đánh giá chuyên sâu về tình trạng của mạng.

# HƯỚNG DẪN PHÂN TÍCH

## 1. Phân tích giao thức và dịch vụ

### 1.1 Giao thức chính (TCP, UDP, ICMP)
- **TCP**: Truyền tin cậy, handshake 3 bước (SYN, SYN-ACK, ACK)
  + Web (80, 443), Email (25, 143, 993), FTP (20, 21), SSH (22)
  + Kích thước gói tin đa dạng, phụ thuộc vào MSS và MTU
  + Có sequence numbers và flags (SYN, ACK, RST, FIN, PUSH)

- **UDP**: Truyền nhanh, không tin cậy
  + DNS (53), Streaming (443, 19302-19309), Games (variable)
  + Thường có kích thước nhỏ hơn 1500 bytes
  + Không có cơ chế đảm bảo chuyển phát

- **ICMP**: Điều khiển và thông báo lỗi
  + Ping (type 8/0), Traceroute, Unreachable (type 3)
  + Kích thước nhỏ
  + Thường ít khi thấy với số lượng lớn trong mạng bình thường

### 1.2 Dịch vụ và ứng dụng phổ biến
- **Web Browsing**:
  + HTTP/HTTPS (80/443), TCP 3-way handshake
  + Nhiều kết nối đến nhiều domains khác nhau
  + Kích thước gói tin đa dạng, thường có burst traffic

- **Video Streaming**:
  + TCP/UDP 443 (HTTPS/QUIC)
  + Kích thước gói UDP 1000-1500 bytes, tần suất đều đặn
  + Truyền liên tục từ một số máy chủ nhất định (CDN)
  + Domains: Netflix, YouTube, Disney+, etc.
  + IP ranges: Google (142.250.0.0/16), Netflix (108.175.32.0/20)

- **Voice/Video Chat**:
  + UDP với kích thước nhỏ đến trung bình (100-500 bytes)
  + Tần suất đều đặn, hai chiều (upload/download)
  + Zoom, Teams, Meet, etc.

- **Game Online**:
  + UDP với gói tin nhỏ (50-300 bytes)
  + Tần suất cao, đều đặn
  + Độ trễ thấp, nhiều gói tin nhỏ

- **Cập nhật phần mềm**:
  + TCP/443 với kích thước gói lớn
  + Tốc độ download cao, một chiều
  + Từ các máy chủ có tên miền xác định

## 2. Nhận diện lưu lượng bình thường

### 2.1 Web browsing
- Nhiều kết nối TCP/80, TCP/443 đến nhiều domains
- Kích thước gói tin đa dạng
- Có request-response pattern

### 2.2 Video streaming
- Lưu lượng UDP hoặc TCP từ các máy chủ CDN
- Kích thước gói: 1000-1500 bytes
- Tần suất đều đặn
- Các ranges IP của:
  + YouTube/Google (142.250.0.0/16, 172.217.0.0/16, 74.125.0.0/16)
  + Netflix (108.175.32.0/20)
  + Facebook (157.240.0.0/16, 31.13.0.0/16)
  + Amazon Prime (52.84.0.0/15)

### 2.3 Background Services
- Gói tin nhỏ, không thường xuyên
- NTP (123), DNS (53)
- Cập nhật phần mềm tự động
- Heartbeat và health checks

## 3. Nhận diện tấn công mạng

### 3.1 Tấn công DDoS
- **SYN Flood**:
  + Nhiều gói SYN từ nhiều IP khác nhau
  + Không có SYN-ACK, ACK (không hoàn thành handshake)
  + Tần suất cao, không có mẫu thực tế

- **UDP Flood**:
  + Hàng loạt gói UDP kích thước lớn (>1000 bytes)
  + Tần suất cực cao (hàng trăm gói/giây)
  + Đến một cổng cụ thể
  + Thường từ nhiều IP nguồn khác nhau

- **HTTP/HTTPS Flood**:
  + Nhiều kết nối HTTP/HTTPS đến một máy chủ
  + Tần suất cao, không giống với lưu lượng người dùng thực

- **ICMP Flood**:
  + Hàng loạt gói tin ICMP (ping) từ nhiều nguồn
  + Kích thước lớn hoặc số lượng lớn

### 3.2 Scanning và Reconnaissance
- **Port Scan**:
  + Nhiều kết nối đến nhiều cổng khác nhau
  + Từ một IP nguồn (hoặc nhóm IP)
  + Tần suất cao, có mẫu rõ ràng

- **IP Scan**:
  + Gói tin giống nhau đến nhiều IP trong subnet
  + Tần suất cao, có mẫu quét tuần tự hoặc ngẫu nhiên

- **Vulnerability Scan**:
  + Kết nối đến các cổng dịch vụ cụ thể
  + Có payload đặc trưng (ex: SQL injection patterns)

### 3.3 Tấn công ứng dụng
- **DNS Amplification**:
  + UDP từ nhiều máy chủ DNS (53) đến một IP
  + Kích thước gói tin phản hồi lớn hơn nhiều so với request

- **SSL/TLS Attacks**:
  + Nhiều kết nối SSL/TLS không hoàn thành
  + Tần suất cao, từ một hoặc nhiều nguồn

- **Application Exploits**:
  + Có payload đặc trưng trong gói tin
  + Thường nhắm vào cổng dịch vụ cụ thể (80, 443, 22, 23)

## 4. Tiêu chí đánh giá

### 4.1 Lưu lượng bình thường
- **Không phải tấn công nếu**:
  + Lưu lượng từ các IP/domains đã biết (Google, Facebook, etc.)
  + Kích thước gói tin phù hợp với dịch vụ
  + Tần suất đều đặn, phù hợp với hành vi người dùng
  + Có mẫu request-response hoàn chỉnh
  + Có kết nối TCP hoàn chỉnh (SYN, SYN-ACK, ACK)
  + Băng thông nằm trong giới hạn ({minimum_network_limit} - {maximum_network_limit})

### 4.2 Lưu lượng đáng ngờ
- **Cần theo dõi nếu**:
  + Lưu lượng lớn từ IP không xác định
  + Kích thước gói tin khác thường nhưng không rõ ràng là tấn công
  + Tần suất cao hơn bình thường
  + Băng thông gần với giới hạn trên ({maximum_network_limit})
  + Có hành vi không thường xuyên nhưng chưa rõ ràng là tấn công

### 4.3 Lưu lượng tấn công
- **Rõ ràng là tấn công nếu**:
  + Lưu lượng cực lớn từ nhiều IP không xác định
  + Kích thước gói tin bất thường (quá lớn hoặc quá nhỏ)
  + Tần suất cực cao, đột biến
  + Không có mẫu request-response hợp lệ
  + Không có kết nối TCP hoàn chỉnh (chỉ SYN, không có SYN-ACK, ACK)
  + Băng thông vượt quá giới hạn ({maximum_network_limit})
  + Phù hợp với mẫu tấn công đã biết (DDoS, Scan, etc.)

## 5. Định nghĩa trạng thái

- **Tốt**: Lưu lượng mạng bình thường, không có dấu hiệu bất thường
- **Đáng ngờ**: Có lưu lượng bất thường, nhưng chưa đủ để kết luận là tấn công
- **Bị tấn công**: Có dấu hiệu rõ ràng của tấn công (DDoS, Scan, etc.)
- **Nghẽn mạng**: Băng thông sử dụng vượt quá giới hạn, có thể do tấn công hoặc sử dụng quá mức
- **Mạng sập**: Không thể kết nối hoặc băng thông gần như bằng 0

# ĐỊNH DẠNG BÁO CÁO

Tình trạng: [Một trong các giá trị trên]
Đánh giá: [Mô tả ngắn gọn lý do dẫn đến kết luận]

# LƯU Ý QUAN TRỌNG
- Video streaming (YouTube, Netflix) sử dụng nhiều UDP với gói tin kích thước lớn (1000-1500 bytes) và tần suất cao là BÌNH THƯỜNG
- Nhiều kết nối đến các IP Google (142.250.0.0/16, 172.217.0.0/16) là BÌNH THƯỜNG (Google services)
- Lưu lượng UDP lớn đến cổng 443 từ IP của Google/YouTube/Netflix là STREAMING VIDEO, KHÔNG PHẢI TẤN CÔNG
- Chỉ đánh giá là "Bị tấn công" khi có bằng chứng RÕ RÀNG và KHÔNG THỂ TRANH CÃI

Ví dụ:
Tình trạng: Tốt
Đánh giá: Hệ thống mạng hoạt động bình thường, lưu lượng chủ yếu là HTTPS (443) và streaming video từ YouTube (IP 142.250.x.x), kích thước gói tin 1000-1500 bytes, tần suất đều đặn, có kết nối TCP trước đó.

Tình trạng: Đáng ngờ
Đánh giá: Phát hiện lưu lượng UDP lớn từ IP không phải Google/YouTube/CDN, kích thước gói tin < 1500 bytes, tần suất cao nhưng đều đặn. Có thể là streaming video từ nguồn khác, cần theo dõi thêm.

Tình trạng: Bị tấn công
Đánh giá: Phát hiện hàng loạt gói SYN không hoàn thành handshake từ hơn 100 IP khác nhau đến cổng 80, với tần suất >1000 gói/giây, dấu hiệu rõ ràng của SYN Flood DDoS attack.
"""

system_message_report_template = f"""Bạn là một chuyên gia phân tích bảo mật mạng, được yêu cầu viết báo cáo phân tích chi tiết về tình trạng mạng dựa trên dữ liệu đã thu thập. Hãy viết một báo cáo chuyên nghiệp với cấu trúc sau:

1. Tóm tắt (Executive Summary):
   - Tình trạng tổng quan của hệ thống mạng
   - Các vấn đề chính được phát hiện
   - Mức độ nghiêm trọng

2. Phân tích chi tiết:
   - Lưu lượng mạng:
     + Băng thông sử dụng (so với giới hạn {minimum_network_limit} - {maximum_network_limit})
     + Các giao thức chính được sử dụng
     + Mẫu lưu lượng bất thường
   
   - Phân tích bảo mật:
     + Các địa chỉ IP đáng ngờ
     + Các cổng được sử dụng
     + Dấu hiệu của tấn công hoặc hoạt động bất thường

3. Đánh giá rủi ro:
   - Mức độ rủi ro (Thấp/Trung bình/Cao)
   - Tác động tiềm ẩn
   - Khả năng xảy ra

4. Khuyến nghị:
   - Các biện pháp cần thực hiện ngay
   - Các biện pháp phòng ngừa dài hạn
   - Các công cụ hoặc giải pháp đề xuất

5. Kết luận:
   - Tóm tắt các phát hiện chính
   - Đánh giá tổng thể về tình trạng mạng
   - Các bước tiếp theo

Lưu ý:
- Sử dụng ngôn ngữ chuyên nghiệp và dễ hiểu
- Cung cấp dữ liệu cụ thể và ví dụ minh họa
- Đưa ra các khuyến nghị thực tế và khả thi
- Tập trung vào các vấn đề quan trọng nhất
- Sử dụng các thuật ngữ kỹ thuật phù hợp

Báo cáo nên được viết theo định dạng markdown để dễ đọc và trình bày."""

# Custom input function to return one chunk at a time
async def run_AIagent(assistant_deepseek, data_chunks_list):
    current_chunk_index = 0
    results = []
    # Tạo thư mục log nếu chưa tồn tại

    print("Đang phân tích tệp tin PCAPNG...")
    if not isinstance(data_chunks_list, list):
        print(f"Error: Expected data_chunks_list to be a list, but got {type(data_chunks_list)}")
        # Handle the error appropriately, maybe return or raise an exception
        return results # Or raise TypeError("data_chunks_list must be a list")

    while current_chunk_index < len(data_chunks_list):
        chunk = data_chunks_list[current_chunk_index]
        message = f"Phân tích dữ liệu mạng phần {current_chunk_index+1}/{len(data_chunks_list)}:" \
                  f"\n - Chi tiết: \n{json.dumps(chunk, indent=4, ensure_ascii=False)}"

        deepseek_result = await run_models_parallel(assistant_deepseek, message)

        results = write_log_agents(deepseek_result, current_chunk_index, data_chunks_list, results)
        current_chunk_index += 1
    return results

# Chạy song song các model phân tích gói tin
async def run_models_parallel(assistant_deepseek, chunk):
    deepseek_task = assistant_deepseek.run(task=chunk)
    result = await asyncio.gather(deepseek_task)
    # Trả về phần tử đầu tiên của list kết quả
    return result[0] if result else None

async def run_AIagent_capture_packets():
    data = await capture_agent.run(task=f"hãy bắt gói tin và chiết xuất thông tin tệp pcap bằng 2 tool (sử dụng cả 2 tool tôi cung cấp cho bạn) từ interface là {capture_interface} với output là {output_capture_file}, max packets là {maximum_packets_capture}, duration là {capture_duration}, chunk_size là {chunk_size}")
    return data
 #Sau khi có results từ asyncio.run(), thêm phần phân tích:
def analyze_final_results(results):
    print("Đang phân tích kết quả cuối cùng...")
    # Chia results thành các nhóm 3 (gemini, deepseek, qwen)
    grouped_results = [results[i:i+3] for i in range(0, len(results), 3)]
    final_evaluations = []

    # Mở file log tổng hợp để ghi kết quả đánh giá
    log_file = os.path.join("log", "network_analysis_log.txt")

    with open(log_file, "a", encoding="utf-8") as f:
        # Ghi header cho phần đánh giá
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write("\n" + "-"*50 + "\n")
        f.write(f"\n\n=== ĐÁNH GIÁ TỔNG HỢP - {timestamp} ===\n")
        f.write(f"Tổng số phần dữ liệu: {len(grouped_results)}\n")

        for idx, group in enumerate(grouped_results):
            evaluation = evaluate_results(group)
            final_evaluations.append(evaluation)

            # Ghi thông tin phần hiện tại
            part_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"\n[PHẦN {idx+1}/{len(grouped_results)} - {part_timestamp}]\n")

            # Ghi kết quả đánh giá
            f.write(f"Tình trạng: {evaluation['final_status']}\n")
            f.write(f"Đánh giá: {evaluation['final_review']}\n")
    return final_evaluations

# Cấu hình model AI
gemini_model = OpenAIChatCompletionClient(
    model="gemini-2.0-flash",
    api_key=GEMINI_API_KEY,
    model_capabilities={
        "vision": True,
        "function_calling": True,
        "json_output": True,
        "structured_output": True,
    }
    #model="deepseek-chat",
    #base_url="https://api.deepseek.com",
    #api_key=DEEPSEEK_API_KEY,

)

deepseek_model = OpenAIChatCompletionClient(
    model="deepseek-chat",
    base_url="https://api.deepseek.com",
    api_key=DEEPSEEK_API_KEY,
    model_capabilities={
        "vision": True,
        "function_calling": True,
        "json_output": True,
        "structured_output": True,
    },
)

qwen_model = OpenAIChatCompletionClient(
    #model="gemini-2.5-pro-exp-03-25",
    #base_url="https://openrouter.ai/api/v1",
    #api_key=GEMINI_API_KEY,
    model="deepseek-chat",
    base_url="https://api.deepseek.com",
    api_key=DEEPSEEK_API_KEY,
    model_capabilities={
        "vision": True,
        "function_calling": True,
        "json_output": True,
        "structured_output": True,
    },
)


# Thiết lập agent bắt gói tin và chiết xuất thông tin
capture_agent = AssistantAgent(
    name="CaptureAgent",
    model_client=gemini_model,
    #system_message=system_message_network_capture_template,
    tools=[FunctionTool(network_capture_tool, description="Tool to capture network packets", strict=True),
               FunctionTool(pcap_extract_tool, description="Tool to extract information from pcap file", strict=True)],
)

# Thiết lập agent phân tích
assistant_gemini = AssistantAgent(
    name="Assistant",
    model_client=gemini_model,
    system_message=system_message_analyze_template,
)

assistant_deepseek = AssistantAgent(
    name="Assistant",
    model_client=deepseek_model, # Corrected
    system_message=system_message_analyze_template,
)

assistant_qwen= AssistantAgent(
    name="Assistant",
    model_client=qwen_model, # Corrected
    system_message=system_message_analyze_template,

)
# data_chunks = "[[{'time': 1746621874.48171, 'src_ip': '192.168.1.95', 'dst_ip': '140.82.113.21', 'protocol': 6, 'size': 532, 'src_port': 60299, 'dst_port': 443}, {'time': 1746621876.916728, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.2', 'protocol': 2, 'size': 46}, {'time': 1746621876.925393, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.252', 'protocol': 2, 'size': 46}, {'time': 1746621876.926569, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.251', 'protocol': 17, 'size': 78, 'src_port': 5353, 'dst_port': 5353}, {'time': 1746621876.926708, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.251', 'protocol': 17, 'size': 220, 'src_port': 5353, 'dst_port': 5353}, {'time': 1746621876.926826, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.251', 'protocol': 17, 'size': 200, 'src_port': 5353, 'dst_port': 5353}, {'time': 1746621876.927403, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.252', 'protocol': 17, 'size': 72, 'src_port': 53470, 'dst_port': 5355}, {'time': 1746621876.928015, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.2', 'protocol': 2, 'size': 46}, {'time': 1746621876.931735, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.252', 'protocol': 2, 'size': 46}, {'time': 1746621876.932235, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.251', 'protocol': 17, 'size': 78, 'src_port': 5353, 'dst_port': 5353}, {'time': 1746621876.932606, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.251', 'protocol': 17, 'size': 200, 'src_port': 5353, 'dst_port': 5353}, {'time': 1746621876.93299, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.252', 'protocol': 17, 'size': 72, 'src_port': 55602, 'dst_port': 5355}, {'time': 1746621877.231735, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.252', 'protocol': 2, 'size': 46}, {'time': 1746621878.15456, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.251', 'protocol': 17, 'size': 335, 'src_port': 5353, 'dst_port': 5353}, {'time': 1746621878.155154, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.251', 'protocol': 17, 'size': 90, 'src_port': 5353, 'dst_port': 5353}, {'time': 1746621878.405297, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.251', 'protocol': 17, 'size': 90, 'src_port': 5353, 'dst_port': 5353}, {'time': 1746621878.659373, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.251', 'protocol': 17, 'size': 90, 'src_port': 5353, 'dst_port': 5353}]]"
data_chunks_from_tool = None # Renamed from data_chunks to avoid confusion before parsing
is_network_captured = False

# Bắt gói tin và chiết xuất thông tin từ tệp PCAPNG
while True:
    results_capture_extract = asyncio.run(run_AIagent_capture_packets()) # Renamed 'results'
    # Tìm ToolCallExecutionEvent
    for message in results_capture_extract.messages:
        if message.type == 'ToolCallExecutionEvent':
            for tool_result in message.content:
                print(tool_result.name)
                if tool_result.name == 'network_capture_tool' and not tool_result.is_error: # Removed 'is_network_captured is False' here as it's set below
                    # We should check tool_result.content['success'] if possible,
                    # but for now, just being called without error is the trigger.
                    print(f"network_capture_tool output: {tool_result.content}")
                    # Attempt to interpret the tool_result.content to set is_network_captured
                    capture_successful = False
                    if isinstance(tool_result.content, dict) and tool_result.content.get("success") is True:
                        capture_successful = True
                    elif isinstance(tool_result.content, str): # If content is a string, try to parse as JSON
                        try:
                            parsed_content = json.loads(tool_result.content)
                            if isinstance(parsed_content, dict) and parsed_content.get("success") is True:
                                 capture_successful = True
                            else:
                                print("network_capture_tool output was parsable JSON but did not indicate success.")
                        except json.JSONDecodeError:
                            print("network_capture_tool output was a string but not valid JSON.")
                    else:
                        print(f"network_capture_tool output was not in expected format (dict or JSON string). Type: {type(tool_result.content)}")

                    if capture_successful:
                        is_network_captured = True
                        print("Network capture reported success.")
                    else:
                        print("Network capture did NOT report success.")
                        is_network_captured = False # Explicitly set to false if not successful

                if tool_result.name == 'pcap_extract_tool' and not tool_result.is_error and is_network_captured is True:
                    print(f"pcap_extract_tool output: {tool_result.content}")
                    data_chunks_from_tool = tool_result.content

    if data_chunks_from_tool is None or is_network_captured is False:
        print(f"AI không bắt được gói tin thành công hoặc không chiết xuất được thông tin. Capture success status: {is_network_captured}, Extracted data: {data_chunks_from_tool}")
        # C++ wrapper handles retry and sleep, so Python script should exit to signal failure for this attempt.
        print("Exiting AI_agent.py to allow the main program to retry.")
        sys.exit(1)
    else:
        print("Successfully captured and extracted data. Proceeding to analysis.")
        break

# Initialize data_chunks_parsed to a default value (e.g., None or an empty list)
# to ensure it's defined in case of early exit.
data_chunks_parsed = None

if data_chunks_from_tool is None: # This check is somewhat redundant given the loop exit condition but kept for safety
    print(f"Error: data_chunks_from_tool is None after capture loop. Cannot proceed.")
    print("This implies an issue with the capture/extraction logic or tool responses.")
    print("Exiting AI_agent.py.")
    sys.exit(1)

elif isinstance(data_chunks_from_tool, str):
    if data_chunks_from_tool.strip().lower() == "none":
        print(f"Error: data_chunks_from_tool is the literal string 'None'. Cannot parse JSON.")
        print("This indicates pcap_extract_tool likely failed or returned None, which was then stringified by the framework.")
        print("Check logs for pcap_extract_tool and network_capture_tool for more details.")
        print("Exiting AI_agent.py.")
        sys.exit(1)
    elif not data_chunks_from_tool.strip():
        print(f"Error: data_chunks_from_tool is an empty or whitespace-only string: '{data_chunks_from_tool}'. Cannot parse JSON.")
        print("pcap_extract_tool might have returned an empty string unexpectedly.")
        print("Exiting AI_agent.py.")
        sys.exit(1)

    try:
        data_chunks_parsed = json.loads(data_chunks_from_tool)
        print(f"Successfully parsed JSON string from pcap_extract_tool.")
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from data_chunks_from_tool string: {e}")
        print(f"Content of data_chunks_from_tool string that failed to parse: >>>{data_chunks_from_tool}<<<")
        print("This could be due to malformed JSON output from pcap_extract_tool.")
        print("Exiting AI_agent.py.")
        sys.exit(1)
elif isinstance(data_chunks_from_tool, (list, dict)):
    print("data_chunks_from_tool is already a Python object (list/dict). Assuming it's the parsed data.")
    data_chunks_parsed = data_chunks_from_tool
else:
    print(f"Error: data_chunks_from_tool is of an unexpected type: {type(data_chunks_from_tool)}. Content: {data_chunks_from_tool}")
    print("Expected a JSON string, or a list/dict if already parsed by the framework.")
    print("Exiting AI_agent.py.")
    sys.exit(1)

if data_chunks_parsed is None:
    print("Critical Error: data_chunks_parsed is None after all processing attempts.")
    print(f"Original data_chunks_from_tool content was: >>>{data_chunks_from_tool}<<<")
    print("This points to a flaw in the data handling or tool output interpretation logic.")
    print("Exiting AI_agent.py.")
    sys.exit(1)

if not isinstance(data_chunks_parsed, list):
    print(f"Critical Error: data_chunks_parsed is not a list as expected by run_AIagent. Type: {type(data_chunks_parsed)}")
    print(f"Content: {data_chunks_parsed}")
    print("The pcap_extract_tool should return a list of chunks (even if it's a JSON string representing that list).")
    print("Exiting AI_agent.py.")
    sys.exit(1)

analysis_results = asyncio.run(run_AIagent(assistant_deepseek, data_chunks_parsed))

final_evaluations = analyze_final_results(analysis_results)

overall_status = defaultdict(int)
for eval_item in final_evaluations:
    overall_status[eval_item["final_status"]] += 1

print("Đang tạo báo cáo phân tích chi tiết...")
write_detailed_analysis_report(analysis_results, overall_status)
