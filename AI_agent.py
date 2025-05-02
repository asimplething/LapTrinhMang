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

class Response(BaseModel):
    Tình_trạng: Literal["Tốt", "Đáng ngờ", "Bị tấn công", "Nghẽn mạng", "Mạng sập"]
    Đánh_giá: str

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
async def run_AIagent(assistant, data_chunks):
    current_chunk_index = 0
    results = []
    # Tạo thư mục log nếu chưa tồn tại
    log_dir = "log"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    log_file = os.path.join(log_dir, "log.txt")
    
    while current_chunk_index < len(data_chunks):
        chunk = data_chunks[current_chunk_index]
        # chunk_summary = {
        #     "Lượng gói tin": len(chunk),
        #     "Tổng kích cỡ": sum(pkt["size"] for pkt in chunk),
        #     "Số lượng IP": len(set(pkt["src_ip"] for pkt in chunk) | set(pkt["dst_ip"] for pkt in chunk))
        # }
        message = f"Phân tích dữ liệu mạng phần {current_chunk_index+1}/{len(data_chunks)}:" \
                  f"\n - Chi tiết: \n{json.dumps(chunk, indent=4, ensure_ascii=False)}"
        print(f"Phân tích dữ liệu mạng phần {current_chunk_index+1}/{len(data_chunks)}...")
        result = await assistant.run(task=message)
        results.append(result)
        
        # Ghi log vào file log.txt
        with open(log_file, "a", encoding="utf-8") as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] Phân tích phần {current_chunk_index+1}/{len(data_chunks)}\n")
            for response in result.messages:
                if response.source == "Assistant":
                    f.write(f"Assistant: {response.content}\n")
                    print(response.content)
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

# Thiết lập agent
assistant = AssistantAgent(
    name="Assistant",
    model_client=model_client,
    system_message=(
        "Bạn là trợ lý AI chuyên phân tích dữ liệu mạng từ một tệp PCAPNG."
        "Hãy phân tích thông tin được cung cấp và đưa ra kết quả về tình trạng mạng"
        "Bạn sẽ phân tích từng phần của một tệp PCAPNG, mỗi phần được chia ra theo số gói không phải theo 1 giây, hãy đọc thông tin của các phần này và khi đạt tới phần cuối hãy đánh giá tổng quan các phần và đưa ra kết quả"
        "Ở phần cuối tệp tin PCAPNG, BẠN SẼ KHÔNG NÓI GÌ KHÁC ngoài thông báo tình trạng mạng bằng một trong số các từ sau: Tốt, Đáng ngờ, Bị tấn công, Nghẽn mạng, Mạng sập và lý do ngắn gọn" \
        f"Quy định để đánh giá dựa vào giới hạn tốc độ mạng của hệ thống mạng và các địa chỉ IP trong gói tin, băng thông của hệ thống mạng tối đa: {maximum_network_limit} và tổi thiểu: {minimum_network_limit}"
    ),
    output_content_type=Response,
)

# Chiết xuất thông tin và tách ra thành các chunk
print(f"Đang xử lý tệp: \'{file_path}\'...")
extracted_info = extract_pcap_info(file_path)
print(f"Đang chia dữ liệu thành các phần nhỏ ({chunk_size} gói/1 phần)...")
data_chunks = split_data(extracted_info, chunk_size)
print(f"Tổng số phần dữ liệu: {len(data_chunks)}")

# Start the conversation
import asyncio
results = asyncio.run(run_AIagent(assistant, data_chunks))