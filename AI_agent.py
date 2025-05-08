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

system_message_analyze_template=f"""Bạn là trợ lý AI chuyên phân tích dữ liệu mạng từ một tệp PCAPNG. Nhiệm vụ của bạn là phân tích từng phần của tệp PCAPNG, với mỗi phần được chia theo số lượng gói tin (không theo thời gian 1 giây). Hãy đọc và xử lý thông tin từ các phần này. Khi đạt đến phần cuối cùng, hãy đánh giá tổng quan toàn bộ dữ liệu và trả về kết quả theo định dạng đã định sẵn.
                             Hãy tuân thủ các quy tắc sau:"
                             - Dựa vào giới hạn tốc độ mạng của hệ thống, với băng thông tối đa là {maximum_network_limit} và tối thiểu là {minimum_network_limit}."
                             - Phân tích các địa chỉ IP, lưu lượng mạng, và các dấu hiệu bất thường trong gói tin để đưa ra kết luận chính xác."
                             - Kết quả cuối cùng phải bao gồm:"
                                 Tình trạng: Một trong các giá trị: 'Tốt', 'Đáng ngờ', 'Bị tấn công', 'Nghẽn mạng', hoặc 'Mạng sập'.
                                 Đánh giá: Một mô tả ngắn gọn về lý do dẫn đến kết luận.
                             Lưu ý: Ở phần cuối tệp PCAPNG, BẠN CHỈ TRẢ VỀ KẾT QUẢ THEO ĐỊNH DẠNG trên và không thêm bất kỳ thông tin nào khác.
                             Ví dụ:
                             Tình trạng: Tốt/Đáng ngờ/Bị tấn công/Nghẽn mạng/Mạng sập
                             Đánh giá: Hệ thống mạng hoạt động bình thường, không có dấu hiệu bất thường nào./Hệ thống mạng có dấu hiệu bất thường, cần kiểm tra thêm./Hệ thống mạng bị tấn công, cần xử lý ngay lập tức./Hệ thống mạng đang bị nghẽn, cần tối ưu hóa./Hệ thống mạng đã sập, không thể truy cập được.
                         """

# Custom input function to return one chunk at a time
async def run_AIagent(assistant_gemini, assistant_deepseek, assistant_qwen, data_chunks):
    current_chunk_index = 0
    results = []
    # Tạo thư mục log nếu chưa tồn tại
    log_dir = "log"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    gemini_log_file = os.path.join(log_dir, "gemini_log.txt")
    deepseek_log_file = os.path.join(log_dir, "deepseek_log.txt")
    qwen_log_file = os.path.join(log_dir, "qwen_log.txt")

    print("Đang phân tích tệp tin PCAPNG...")
    while current_chunk_index < len(data_chunks):
        chunk = data_chunks[current_chunk_index]
        message = f"Phân tích dữ liệu mạng phần {current_chunk_index+1}/{len(data_chunks)}:" \
                  f"\n - Chi tiết: \n{json.dumps(chunk, indent=4, ensure_ascii=False)}"
        
        gemini_result, deepseek_result, qwen_result = await run_models_parallel(assistant_gemini, assistant_deepseek, assistant_qwen, message)

        # Ghi log vào file log.txt
        with open(gemini_log_file, "a", encoding="utf-8") as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] Phân tích phần {current_chunk_index+1}/{len(data_chunks)}\n")
            for response in gemini_result.messages:
                if response.source == "Assistant":
                    cleaned_content = "\n".join([line for line in response.content.splitlines() if line.strip() != ""])
                    f.write(f"Assistant: {cleaned_content}\n")
                    results.append(cleaned_content)
            f.write("\n")

        with open(deepseek_log_file, "a", encoding="utf-8") as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] Phân tích phần {current_chunk_index+1}/{len(data_chunks)}\n")
            for response in deepseek_result.messages:
                if response.source == "Assistant":
                    cleaned_content = "\n".join([line for line in response.content.splitlines() if line.strip() != ""])
                    f.write(f"Assistant: {cleaned_content}\n")
                    results.append(cleaned_content)
            f.write("\n")

        with open(qwen_log_file, "a", encoding="utf-8") as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] Phân tích phần {current_chunk_index+1}/{len(data_chunks)}\n")
            for response in qwen_result.messages:
                if response.source == "Assistant":
                    cleaned_content = "\n".join([line for line in response.content.splitlines() if line.strip() != ""])
                    f.write(f"Assistant: {cleaned_content}\n")
                    results.append(cleaned_content)
            f.write("\n")
        current_chunk_index += 1
    return results

# Chạy song song các model phân tích gói tin
async def run_models_parallel(assistant_gemini, assistant_deepseek, assistant_qwen, chunk):
    gemini_task = assistant_gemini.run(task=chunk)
    deepseek_task = assistant_deepseek.run(task=chunk)
    qwen_task = assistant_qwen.run(task=chunk)

    result = await asyncio.gather(gemini_task, deepseek_task, qwen_task)
    return result

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
    model_client=gemini_model,
    system_message=system_message_analyze_template,
)

assistant_qwen= AssistantAgent(
    name="Assistant",
    model_client=gemini_model,
    system_message=system_message_analyze_template,

)
# data_chunks = "[[{'time': 1746621874.48171, 'src_ip': '192.168.1.95', 'dst_ip': '140.82.113.21', 'protocol': 6, 'size': 532, 'src_port': 60299, 'dst_port': 443}, {'time': 1746621876.916728, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.2', 'protocol': 2, 'size': 46}, {'time': 1746621876.925393, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.252', 'protocol': 2, 'size': 46}, {'time': 1746621876.926569, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.251', 'protocol': 17, 'size': 78, 'src_port': 5353, 'dst_port': 5353}, {'time': 1746621876.926708, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.251', 'protocol': 17, 'size': 220, 'src_port': 5353, 'dst_port': 5353}, {'time': 1746621876.926826, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.251', 'protocol': 17, 'size': 200, 'src_port': 5353, 'dst_port': 5353}, {'time': 1746621876.927403, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.252', 'protocol': 17, 'size': 72, 'src_port': 53470, 'dst_port': 5355}, {'time': 1746621876.928015, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.2', 'protocol': 2, 'size': 46}, {'time': 1746621876.931735, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.252', 'protocol': 2, 'size': 46}, {'time': 1746621876.932235, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.251', 'protocol': 17, 'size': 78, 'src_port': 5353, 'dst_port': 5353}, {'time': 1746621876.932606, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.251', 'protocol': 17, 'size': 200, 'src_port': 5353, 'dst_port': 5353}, {'time': 1746621876.93299, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.252', 'protocol': 17, 'size': 72, 'src_port': 55602, 'dst_port': 5355}, {'time': 1746621877.231735, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.252', 'protocol': 2, 'size': 46}, {'time': 1746621878.15456, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.251', 'protocol': 17, 'size': 335, 'src_port': 5353, 'dst_port': 5353}, {'time': 1746621878.155154, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.251', 'protocol': 17, 'size': 90, 'src_port': 5353, 'dst_port': 5353}, {'time': 1746621878.405297, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.251', 'protocol': 17, 'size': 90, 'src_port': 5353, 'dst_port': 5353}, {'time': 1746621878.659373, 'src_ip': '192.168.1.95', 'dst_ip': '224.0.0.251', 'protocol': 17, 'size': 90, 'src_port': 5353, 'dst_port': 5353}]]"
data_chunks=None
is_network_captured = False

# Bắt gói tin và chiết xuất thông tin từ tệp PCAPNG
while True:
    results = asyncio.run(run_AIagent_capture_packets())
    # Tìm ToolCallExecutionEvent
    for message in results.messages:
        if message.type == 'ToolCallExecutionEvent':
            for tool_result in message.content:
                print(tool_result.name)
                if tool_result.name == 'network_capture_tool' and not tool_result.is_error and is_network_captured is False:
                    is_network_captured = True
                if tool_result.name == 'pcap_extract_tool' and not tool_result.is_error and is_network_captured is True:
                    data_chunks = tool_result.content
    if data_chunks is None or is_network_captured is False:
        print("AI Không bắt được gói tin hoặc chiết xuất thông tin từ tệp PCAP", data_chunks, is_network_captured   )
    else:
        break
data_chunks = json.loads(data_chunks)

results = asyncio.run(run_AIagent(assistant_gemini, assistant_deepseek, assistant_qwen, data_chunks))

# Gọi hàm phân tích
final_evaluations = analyze_final_results(results)

# Phân tích tổng thể toàn bộ các phần
overall_status = defaultdict(int)
for eval in final_evaluations:
    overall_status[eval["final_status"]] += 1

print("Đang ghi kết quả tổng thể vào file log...")
# Ghi kết quả tổng thể vào file log
with open(os.path.join("log", "network_analysis_log.txt"), "a", encoding="utf-8") as f:
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    f.write(f"\n\n=== KẾT LUẬN TỔNG THỂ - {timestamp} ===\n")

    # Ghi thống kê trạng thái
    f.write("Thống kê trạng thái:\n")
    for status, count in overall_status.items():
        f.write(f"- {status}: {count} phần\n")

     # Chọn trạng thái có trọng số cao nhất
    if overall_status:
        # Sắp xếp các trạng thái theo trọng số giảm dần
        sorted_statuses = sorted(overall_status.keys(),
                                key=lambda x: STATUS_WEIGHTS[x],
                                reverse=True)

        # Lấy trạng thái có trọng số cao nhất
        final_status = sorted_statuses[0]
        conclusion = f"Hệ thống ở trạng thái {final_status}."
    else:
        conclusion = "Không có dữ liệu để đánh giá"

    # Ghi kết luận cuối cùng
    f.write("\nKẾT LUẬN:\n")
    f.write(conclusion + "\n")
