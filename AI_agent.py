import os
import json
from scapy.all import rdpcap
from autogen_agentchat.agents import AssistantAgent, UserProxyAgent
from autogen_ext.models.openai import OpenAIChatCompletionClient
from pydantic import BaseModel
from typing import Literal
import datetime
from dotenv import load_dotenv

load_dotenv()

# Đường dẫn tới file PCAPNG
file_path = "./content/wifi_capture.pcapng"

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
if not GEMINI_API_KEY:
    raise ValueError("API_KEY not found in environment variables.")

# Quy định giới hạn băng thông mạng của hệ thống
minimum_network_limit = "3 Mbs"  # giới hạn băng thông toàn hệ thống mạng
maximum_network_limit = "6 Mbs"

# Giới hạn lưu lượng mạng mà server có thể xử lý
minimum_server_limit = "10 Mbs"
maximum_server_limit = "20 Mbs"

# Danh sách IP server
server_ip_list = ["192.168.1.10", "192.168.1.11"]

# Số lượng gói tin mỗi phần
chunk_size = 100

system_message_template=f"""Bạn là trợ lý AI chuyên phân tích dữ liệu mạng từ một tệp PCAPNG. Nhiệm vụ của bạn là phân tích từng phần của tệp PCAPNG, với mỗi phần được chia theo số lượng gói tin (không theo thời gian 1 giây). Hãy đọc và xử lý thông tin từ các phần này. Khi đạt đến phần cuối cùng, hãy đánh giá tổng quan toàn bộ dữ liệu và trả về kết quả theo định dạng đã định sẵn.
                            Hãy tuân thủ các quy tắc sau:"
                            - Dựa vào giới hạn tốc độ mạng của hệ thống, với băng thông tối đa là {maximum_network_limit} và tối thiểu là {minimum_network_limit}."
                            - Phân tích các địa chỉ IP, lưu lượng mạng, và các dấu hiệu bất thường trong gói tin để đưa ra kết luận chính xác."
                            - Kết quả cuối cùng phải bao gồm:"
                                Tình trạng: Một trong các giá trị: 'Tốt', 'Đáng ngờ', 'Bị tấn công', 'Nghẽn mạng', hoặc 'Mạng sập'.
                                Đánh giá: Một mô tả ngắn gọn về lý do dẫn đến kết luận.
                            Lưu ý: Ở phần cuối tệp PCAPNG, BẠN CHỈ TRẢ VỀ KẾT QUẢ THEO ĐỊNH DẠNG trên và không thêm bất kỳ thông tin nào khác.
                            Ví dụ:
                            Tình trạng: Tốt
                            Đánh giá: Hệ thống mạng hoạt động bình thường, không có dấu hiệu bất thường nào.
                        """

# Hàm chiết xuất thông tin từ file PCAPNG
def extract_pcap_info(pcap_file):
    packets = rdpcap(pcap_file)
    extracted_data = []
    for pkt in packets:
        if pkt.haslayer('IP'):
            ip_layer = pkt.getlayer('IP')
            data = {
                'time': float(pkt.time),
                'src_ip': ip_layer.src,
                'dst_ip': ip_layer.dst,
                'protocol': ip_layer.proto,
                'size': len(pkt),
            }
            if pkt.haslayer('TCP') or pkt.haslayer('UDP'):
                transport = pkt.getlayer('TCP') if pkt.haslayer('TCP') else pkt.getlayer('UDP')
                data['src_port'] = transport.sport
                data['dst_port'] = transport.dport
            extracted_data.append(data)
    return extracted_data

# Chia dữ liệu thành các phần, mỗi phần tối đa 50 gói tin
def split_data(data, max_packets=50):
    chunks = []
    for i in range(0, len(data), max_packets):
        chunks.append(data[i:i + max_packets])
    return chunks

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

    while current_chunk_index < len(data_chunks):
        chunk = data_chunks[current_chunk_index]
        message = f"Phân tích dữ liệu mạng phần {current_chunk_index+1}/{len(data_chunks)}:" \
                  f"\n - Chi tiết: \n{json.dumps(chunk, indent=4, ensure_ascii=False)}"
        print(f"Phân tích dữ liệu mạng phần {current_chunk_index+1}/{len(data_chunks)}...")

        gemini_result, deepseek_result, qwen_result = await run_models_parallel(assistant_gemini, assistant_deepseek, assistant_qwen, message)

         # Lưu kết quả từ cả hai mô hình
        results.append({
            "chunk": current_chunk_index + 1,
            "gemini_result": gemini_result,
            "deepseek_result": deepseek_result,
            "qwen_result": qwen_result
        })

        # Ghi log vào file log.txt
        with open(gemini_log_file, "a", encoding="utf-8") as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] Phân tích phần {current_chunk_index+1}/{len(data_chunks)}\n")
            for response in gemini_result.messages:
                if response.source == "Assistant":
                    f.write(f"Assistant: {response.content}\n")
                    print("Gemini:", response.content)
            f.write("\n")

        with open(deepseek_log_file, "a", encoding="utf-8") as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] Phân tích phần {current_chunk_index+1}/{len(data_chunks)}\n")
            for response in deepseek_result.messages:
                if response.source == "Assistant":
                    f.write(f"Assistant: {response.content}\n")
                    print("Deepseek:", response.content)
            f.write("\n")

        with open(qwen_log_file, "a", encoding="utf-8") as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] Phân tích phần {current_chunk_index+1}/{len(data_chunks)}\n")
            for response in qwen_result.messages:
                if response.source == "Assistant":
                    f.write(f"Assistant: {response.content}\n")
                    print("Qwen:", response.content)
            f.write("\n")

        current_chunk_index += 1
    return results

# Cấu hình model AI
model_client = OpenAIChatCompletionClient(
    model="gemini-2.0-flash",
    api_key=GEMINI_API_KEY,
    model_capabilities={
        "vision": True,
        "function_calling": True,
        "json_output": True,
        "structured_output": True,
    },
)

deepseek_client = OpenAIChatCompletionClient(
    model="deepseek-chat",
    base_url="https://api.deepseek.com",
    api_key=DEEPSEEK_API_KEY,
    model_capabilities={
        "vision": True,
        "function_calling": True,
        "json_output": True,
        #"structured_output": True,
    },
)

qwen_client = OpenAIChatCompletionClient(
    model="opengvlab/internvl3-2b:free",
    base_url="https://openrouter.ai/api/v1",
    api_key=OPENROUTER_API_KEY,
    model_capabilities={
        "vision": True,
        "function_calling": True,
        "json_output": True,
        #"structured_output": True,
    },
)

# Thiết lập agent
assistant_gemini = AssistantAgent(
    name="Assistant",
    model_client=model_client,
    system_message=system_message_template,
)

assistant_deepseek = AssistantAgent(
    name="Assistant",
    model_client=deepseek_client,
    system_message=system_message_template,
)

assistant_qwen= AssistantAgent(
    name="Assistant",
    model_client=qwen_client,
    system_message=system_message_template,

)

# Chiết xuất thông tin và tách ra thành các chunk
print(f"Đang xử lý tệp: \'{file_path}\'...")
extracted_info = extract_pcap_info(file_path)
print(f"Đang chia dữ liệu thành các phần nhỏ ({chunk_size} gói/1 phần)...")
data_chunks = split_data(extracted_info, chunk_size)
print(f"Tổng số phần dữ liệu: {len(data_chunks)}")

# Start the conversation
import asyncio

async def run_models_parallel(assistant_gemini, assistant_deepseek, assistant_qwen, chunk):
    gemini_task = assistant_gemini.run(task=chunk)
    deepseek_task = assistant_deepseek.run(task=chunk)
    qwen_task = assistant_qwen.run(task=chunk)

    result = await asyncio.gather(gemini_task, deepseek_task, qwen_task)
    return result

results = asyncio.run(run_AIagent(assistant_gemini, assistant_deepseek, assistant_qwen, data_chunks))
