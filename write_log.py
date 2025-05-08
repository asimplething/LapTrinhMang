import os
import datetime
from network_evaluation import STATUS_WEIGHTS
from scapy.utils import rdpcap

def write_log_capture(pcap_file):
    packet_count = "Không thể xác định"
    with open(os.path.join("log", "capture_log.txt"), "a", encoding="utf-8") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file_size = os.path.getsize(pcap_file)
        try:
            packets = rdpcap(pcap_file)
            packet_count = len(packets)
            print("Ghi log vào capture_log.txt thành công")
        except Exception as e:
            print(f"Ghi log vào capture_log.txt không thành công: {e}")

        string = (f"=== {timestamp} ===\n"
                  f"Kích thước file: {file_size} bytes\n"
                  f"Số lượng gói tin đã bắt: {packet_count}\n")
        f.write(string + "\n")

def write_log_agents(gemini, deepseek, qwen, current_chunk_index, chunks, results):
    log_dir = "log"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    gemini_log_file = os.path.join(log_dir, "gemini_log.txt")
    deepseek_log_file = os.path.join(log_dir, "deepseek_log.txt")
    qwen_log_file = os.path.join(log_dir, "qwen_log.txt")
    #Ghi log Gemini
    with open(gemini_log_file, "a", encoding="utf-8") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] Phân tích phần {current_chunk_index+1}/{len(chunks)}\n")
        for response in gemini.messages:
            if response.source == "Assistant":
                cleaned_content = "\n".join([line for line in response.content.splitlines() if line.strip() != ""])
                f.write(f"Assistant: {cleaned_content}\n")
                results.append(cleaned_content)
        f.write("\n")

    with open(deepseek_log_file, "a", encoding="utf-8") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] Phân tích phần {current_chunk_index+1}/{len(chunks)}\n")
        for response in deepseek.messages:
            if response.source == "Assistant":
                cleaned_content = "\n".join([line for line in response.content.splitlines() if line.strip() != ""])
                f.write(f"Assistant: {cleaned_content}\n")
                results.append(cleaned_content)
        f.write("\n")

    with open(qwen_log_file, "a", encoding="utf-8") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] Phân tích phần {current_chunk_index+1}/{len(chunks)}\n")
        for response in qwen.messages:
            if response.source == "Assistant":
                cleaned_content = "\n".join([line for line in response.content.splitlines() if line.strip() != ""])
                f.write(f"Assistant: {cleaned_content}\n")
                results.append(cleaned_content)
        f.write("\n")

    return results

def write_log_conclusion(overall_status):
    with open(os.path.join("log", "network_analysis_log.txt"), "a", encoding="utf-8") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"\n\n=== KẾT LUẬN TỔNG THỂ - {timestamp} ===\n")

        f.write("Thống kê trạng thái:\n")
        for status, count in overall_status.items():
            f.write(f"- {status}: {count} phần\n")

        if overall_status:
            sorted_statuses = sorted(overall_status.keys(),
                                    key=lambda x: STATUS_WEIGHTS.get(x, 0),
                                    reverse=True)

            if sorted_statuses:
                final_status = sorted_statuses[0]
                conclusion = f"Hệ thống ở trạng thái {final_status}."
            else:
                conclusion = "Không thể xác định trạng thái từ các mục đã xử lý (sorted_statuses was empty)."
        else:
            conclusion = "Không có dữ liệu để đánh giá (overall_status was empty)"

        f.write("\nKẾT LUẬN:\n")
        f.write(conclusion + "\n")
