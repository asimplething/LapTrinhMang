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

        string = (f"## {timestamp}\n"
                  f"Kích thước file: {file_size} bytes\n"
                  f"Số lượng gói tin đã bắt: {packet_count}\n")
        f.write(string + "\n")

def write_log_agents(gemini, deepseek, qwen, current_chunk_index, chunks, results):
    log_dir = "log"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    gemini_log_file = os.path.join(log_dir, "gemini_log.txt")
    deepseek_log_file = os.path.join(log_dir, "deepseek_log.txt")
    llama_log_file = os.path.join(log_dir, "llama_log.txt")

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

    with open(llama_log_file, "a", encoding="utf-8") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] Phân tích phần {current_chunk_index+1}/{len(chunks)}\n")
        for response in qwen.messages:
            if response.source == "Assistant":
                cleaned_content = "\n".join([line for line in response.content.splitlines() if line.strip() != ""])
                f.write(f"Assistant: {cleaned_content}\n")
                results.append(cleaned_content)
        f.write("\n")

    return results

def write_log_conclusion(overall_status, messages):
    with open(os.path.join("log", "network_analysis_log.txt"), "a", encoding="utf-8") as f:
        
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write("\n" + "-"*50 + "\n")
        f.write(f"\n\n## {timestamp}\n")
        f.write(f"## ĐÁNH GIÁ TỔNG HỢP\n\n")

        final_status = "Không xác định"
        writer_content = ""
        
        for message in messages:
            if message.source == "Assistant":
                writer_content = message.content
                f.write(writer_content)
                print("Báo cáo tổng hợp đã được ghi vào file log.")
                
                if "### TÓM TẮT NHANH" in writer_content:
                    status_lines = writer_content.split("### TÓM TẮT NHANH")[1].split("\n")
                    for line in status_lines:
                        if "Trạng thái:" in line:
                            final_status = line.split("Trạng thái:")[1].strip()
                            break
                        if line.strip().startswith("###"):
                            break

        f.write(f"\n\n## KẾT LUẬN TỔNG THỂ\n")
        f.write(f"Hệ thống ở trạng thái {final_status}.\n")
