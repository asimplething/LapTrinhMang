import os
import datetime
from network_evaluation import STATUS_WEIGHTS
from scapy.utils import rdpcap
from collections import defaultdict
import re

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

def write_log_agents(deepseek_result, current_chunk_index, chunks, results):
    log_dir = "log"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    deepseek_log_file = os.path.join(log_dir, "deepseek_log.txt")
   
    with open(deepseek_log_file, "a", encoding="utf-8") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] Phân tích phần {current_chunk_index+1}/{len(chunks)}\n")
        
        # Xử lý kết quả là list
        if isinstance(deepseek_result, list):
            for response in deepseek_result:
                if isinstance(response, str):
                    cleaned_content = "\n".join([line for line in response.splitlines() if line.strip() != ""])
                    f.write(f"Assistant: {cleaned_content}\n")
                    results.append(cleaned_content)
        # Xử lý kết quả là object có thuộc tính messages
        elif hasattr(deepseek_result, 'messages'):
            for response in deepseek_result.messages:
                if response.source == "Assistant":
                    cleaned_content = "\n".join([line for line in response.content.splitlines() if line.strip() != ""])
                    f.write(f"Assistant: {cleaned_content}\n")
                    results.append(cleaned_content)
        # Xử lý kết quả là string
        elif isinstance(deepseek_result, str):
            cleaned_content = "\n".join([line for line in deepseek_result.splitlines() if line.strip() != ""])
            f.write(f"Assistant: {cleaned_content}\n")
            results.append(cleaned_content)
            
        f.write("\n")
    return results


def write_detailed_analysis_report(analysis_results, overall_status):
    """
    Viết báo cáo phân tích chi tiết dựa trên kết quả từ Gemini và trạng thái tổng thể
    """
    report_file = os.path.join("log", "detailed_analysis_report.txt")
    with open(report_file, "a", encoding="utf-8") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"\n\n=== BÁO CÁO PHÂN TÍCH CHI TIẾT - {timestamp} ===\n\n")

        # Đếm trạng thái từ analysis_results
        status_counts = defaultdict(int)
        status_examples = {}
        patterns = defaultdict(list)
        protocols = {"UDP": False, "TCP": False, "ICMP": False, "HTTP": False, "HTTPS": False}
        common_ports = set()
        ip_sources = set()
        ip_destinations = set()

        for result in analysis_results:
            if isinstance(result, str):
                # Tìm dòng chứa "Tình trạng:"
                status = None
                evaluation = None
                
                for line in result.splitlines():
                    if "Tình trạng:" in line:
                        status = line.split("Tình trạng:")[1].strip().replace("*", "")
                        status_counts[status] += 1
                    if "Đánh giá:" in line:
                        evaluation = line.split("Đánh giá:")[1].strip()
                
                # Cải thiện phát hiện giao thức
                if "UDP" in result or "protocol 17" in result.lower():
                    protocols["UDP"] = True
                if "TCP" in result or "protocol 6" in result.lower():
                    protocols["TCP"] = True
                if "ICMP" in result or "protocol 1" in result.lower():
                    protocols["ICMP"] = True
                if "HTTP" in result:
                    protocols["HTTP"] = True
                if "HTTPS" in result or "443" in result:
                    protocols["HTTPS"] = True
                if "QUIC" in result or "HTTP/3" in result:
                    protocols["QUIC/HTTP3"] = True
                
                if status and evaluation:
                    # Lưu một ví dụ cho mỗi loại tình trạng
                    if status not in status_examples:
                        status_examples[status] = evaluation
                    
                    # Thu thập thông tin về giao thức, cổng và IP
                    if "UDP" in evaluation:
                        protocols["UDP"] = True
                    if "TCP" in evaluation:
                        protocols["TCP"] = True
                    if "ICMP" in evaluation:
                        protocols["ICMP"] = True
                    if "HTTP" in evaluation:
                        protocols["HTTP"] = True
                    if "HTTPS" in evaluation or "443" in evaluation:
                        protocols["HTTPS"] = True
                    
                    # Tìm các cổng phổ biến được đề cập - mở rộng regex
                    port_patterns = [r"cổng (\d+)", r"port (\d+)", r"cổng\s+(\d+)", r"port\s+(\d+)"]
                    for pattern in port_patterns:
                        port_matches = re.findall(pattern, result.lower())
                        for port in port_matches:
                            common_ports.add(port)
                    
                    # Tìm các IP - mở rộng phương pháp tìm
                    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                    ip_matches = re.findall(ip_pattern, result)
                    for ip in ip_matches:
                        if "từ IP" in result and ip in result.split("từ IP")[1][:50]:
                            ip_sources.add(ip)
                        elif "đến" in result and ip in result.split("đến")[1][:50]:
                            ip_destinations.add(ip)
                        elif "->" in result and ip in result.split("->")[0][:50]:
                            ip_sources.add(ip)
                        elif "->" in result and ip in result.split("->")[1][:50]:
                            ip_destinations.add(ip)
                        else:
                            # Kiểm tra khoảng cách gần từ khóa
                            if "source" in result.lower() and abs(result.lower().find("source") - result.find(ip)) < 50:
                                ip_sources.add(ip)
                            elif "nguồn" in result.lower() and abs(result.lower().find("nguồn") - result.find(ip)) < 50:
                                ip_sources.add(ip)
                            elif "dest" in result.lower() and abs(result.lower().find("dest") - result.find(ip)) < 50:
                                ip_destinations.add(ip)
                            elif "đích" in result.lower() and abs(result.lower().find("đích") - result.find(ip)) < 50:
                                ip_destinations.add(ip)
                            else:
                                # Nếu không xác định được, thêm vào cả hai
                                ip_sources.add(ip)
                                ip_destinations.add(ip)

        # 1. Tóm tắt
        f.write("1. TÓM TẮT\n")
        f.write("-" * 50 + "\n")
        if status_counts:
            # Tìm trạng thái có trọng số cao nhất
            sorted_statuses = sorted(status_counts.keys(),
                                   key=lambda x: STATUS_WEIGHTS.get(x, 0),
                                   reverse=True)
            final_status = sorted_statuses[0] if sorted_statuses else "Không xác định"
            f.write(f"Tình trạng tổng quan: **{final_status}**\n")
            f.write("Phân bố trạng thái:\n")
            for status, count in status_counts.items():
                f.write(f"  + {status}: {count} phần\n")
        f.write("\n")
        
        # Thông tin chung về giao thức và dịch vụ
        f.write("THÔNG TIN CHUNG VỀ GIAO THỨC VÀ DỊCH VỤ\n")
        f.write("-" * 50 + "\n")
        
        # Hiển thị các giao thức được phát hiện
        detected_protocols = [p for p, detected in protocols.items() if detected]
        if detected_protocols:
            f.write("Các giao thức được phát hiện:\n")
            for protocol in detected_protocols:
                f.write(f"- {protocol}\n")
        else:
            f.write("Không phát hiện giao thức cụ thể trong phân tích.\n")
        f.write("\n")
        
        # Hiển thị các cổng phổ biến
        if common_ports:
            f.write("Các cổng phổ biến được sử dụng:\n")
            for port in sorted(common_ports, key=int):
                f.write(f"- Cổng {port}\n")
            f.write("\n")
        
        # Hiển thị các IP nguồn và đích
        if ip_sources:
            f.write("Các IP nguồn phổ biến:\n")
            for ip in ip_sources:
                f.write(f"- {ip}\n")
            f.write("\n")
        
        if ip_destinations:
            f.write("Các IP đích phổ biến:\n")
            for ip in ip_destinations:
                f.write(f"- {ip}\n")
            f.write("\n")

        # 2. Phân tích chi tiết
        f.write("2. PHÂN TÍCH CHI TIẾT\n")
        f.write("-" * 50 + "\n")
        for idx, result in enumerate(analysis_results, 1):
            f.write(f"\nPhần {idx}:\n")
            f.write(result + "\n")
        f.write("\n")

        # 3. Đánh giá rủi ro
        f.write("3. ĐÁNH GIÁ RỦI RO\n")
        f.write("-" * 50 + "\n")
        if status_counts:
            risk_level = "Cao" if any(status in ["Bị tấn công", "Mạng sập"] for status in status_counts.keys()) else \
                        "Trung bình" if any(status in ["Đáng ngờ", "Nghẽn mạng"] for status in status_counts.keys()) else "Thấp"
            f.write(f"Mức độ rủi ro: {risk_level}\n")
            
            # Thêm phân tích chi tiết về rủi ro
            if risk_level == "Cao":
                f.write("Phân tích: Hệ thống đang gặp nguy cơ bảo mật nghiêm trọng hoặc vấn đề về tính khả dụng.\n")
                f.write("Chi tiết:\n")
                if "Bị tấn công" in status_counts:
                    f.write("- Phát hiện dấu hiệu tấn công mạng rõ ràng\n")
                    f.write("- Cần ưu tiên xử lý ngay lập tức để giảm thiểu tác động\n")
                if "Mạng sập" in status_counts:
                    f.write("- Mất kết nối mạng hoặc dịch vụ đã sập\n")
                    f.write("- Ưu tiên khôi phục các dịch vụ quan trọng\n")
            elif risk_level == "Trung bình":
                f.write("Phân tích: Có một số dấu hiệu đáng ngờ cần được theo dõi, nhưng chưa có bằng chứng rõ ràng về tấn công.\n")
                f.write("Chi tiết:\n")
                if "Đáng ngờ" in status_counts:
                    f.write("- Phát hiện lưu lượng bất thường cần điều tra thêm\n")
                    f.write("- Tăng cường giám sát các địa chỉ IP và cổng đáng ngờ\n")
                if "Nghẽn mạng" in status_counts:
                    f.write("- Hiệu suất mạng đang suy giảm do tải cao\n")
                    f.write("- Xác định nguyên nhân gốc rễ của nghẽn mạng\n")
            else:
                f.write("Phân tích: Hệ thống hoạt động bình thường, không có dấu hiệu bất thường đáng kể.\n")
                if "Tốt" in status_counts:
                    f.write("Chi tiết:\n")
                    f.write("- Tất cả chỉ số mạng đều trong ngưỡng bình thường\n")
                    f.write("- Tốc độ truyền dữ liệu ổn định và dưới ngưỡng băng thông tối đa\n")
                    if len(ip_sources) > 0 or len(ip_destinations) > 0:
                        f.write("- Các địa chỉ IP nguồn và đích có mẫu truy cập bình thường\n")
                    if common_ports:
                        f.write("- Các cổng đang sử dụng đều là cổng tiêu chuẩn hoặc phổ biến\n")
        else:
            f.write("Mức độ rủi ro: Không xác định\n")
            f.write("Phân tích: Không đủ dữ liệu để đánh giá rủi ro.\n")
        f.write("\n")

        # 4. Khuyến nghị
        f.write("4. KHUYẾN NGHỊ\n")
        f.write("-" * 50 + "\n")
        recommendations = []
        
        if status_counts:
            if "Bị tấn công" in status_counts:
                recommendations.extend([
                    "- Cần kiểm tra và xử lý ngay lập tức các dấu hiệu tấn công",
                    "- Tăng cường các biện pháp bảo mật",
                    "- Cách ly hoặc chặn các IP nguồn tấn công",
                    "- Xem xét triển khai giải pháp DDoS mitigation"
                ])
            if "Nghẽn mạng" in status_counts:
                recommendations.extend([
                    "- Tối ưu hóa băng thông mạng",
                    "- Kiểm tra và giảm tải các dịch vụ không cần thiết",
                    "- Xem xét nâng cấp cơ sở hạ tầng mạng"
                ])
            if "Đáng ngờ" in status_counts:
                recommendations.extend([
                    "- Theo dõi và phân tích thêm các hoạt động đáng ngờ",
                    "- Cập nhật các chính sách bảo mật",
                    "- Tăng cường giám sát các địa chỉ IP và cổng đáng ngờ"
                ])
            if "Tốt" in status_counts:
                recommendations.extend([
                    "- Duy trì giám sát thường xuyên",
                    "- Thực hiện các bản cập nhật bảo mật định kỳ",
                    "- Giám sát lưu lượng mạng (burst rate) tránh quá tải",
                    "- Lập kế hoạch sao lưu và khôi phục cho hệ thống mạng"
                ])
        
        # Đảm bảo luôn có khuyến nghị mặc định nếu không có trạng thái nào được xác định
        if not recommendations:
            recommendations = [
                "- Duy trì kiểm tra định kỳ hệ thống mạng",
                "- Cập nhật các bản vá bảo mật thường xuyên",
                "- Tối ưu cấu hình mạng để đảm bảo hiệu suất",
                "- Theo dõi các điểm đáng nghi ngờ trong luồng dữ liệu"
            ]
            
        # Loại bỏ các khuyến nghị trùng lặp
        recommendations = list(set(recommendations))
        for rec in recommendations:
            f.write(f"{rec}\n")
        f.write("\n")

        # 5. Kết luận
        f.write("5. KẾT LUẬN\n")
        f.write("-" * 50 + "\n")
        if status_counts:
            f.write(f"Tình trạng hệ thống: **{final_status}**\n\n")
            
            # Kết luận dựa trên trạng thái
            if final_status == "Bị tấn công":
                f.write("Hệ thống mạng đang phải đối mặt với các dấu hiệu tấn công rõ ràng. Cần có hành động khẩn cấp để giảm thiểu tác động và bảo vệ hạ tầng mạng.\n")
            elif final_status == "Đáng ngờ":
                f.write("Hệ thống mạng có một số hoạt động bất thường cần được theo dõi thêm. Không có bằng chứng rõ ràng về tấn công, nhưng cần cảnh giác.\n")
            elif final_status == "Nghẽn mạng":
                f.write("Hệ thống mạng đang gặp vấn đề về hiệu suất và băng thông. Cần tối ưu hóa cấu hình và có thể xem xét nâng cấp tài nguyên.\n")
            elif final_status == "Tốt":
                f.write("Hệ thống mạng hoạt động bình thường, không có dấu hiệu bất thường. Tiếp tục duy trì giám sát và các biện pháp bảo mật hiện tại.\n")
            
            # Tóm tắt các giao thức và dịch vụ chính
            f.write("\nTóm tắt giao thức và địa chỉ IP chính:\n")
            active_protocols = [p for p, detected in protocols.items() if detected]
            if active_protocols:
                f.write(f"- Giao thức hoạt động: {', '.join(active_protocols)}\n")
            else:
                f.write("- Không phát hiện giao thức cụ thể\n")
            
            if common_ports:
                f.write(f"- Cổng phổ biến: {', '.join(sorted(common_ports, key=int))}\n")
            else:
                f.write("- Không phát hiện cổng đặc biệt\n")
            
            if ip_sources or ip_destinations:
                f.write("- Các IP đáng chú ý:\n")
                for ip in set(ip_sources).union(ip_destinations):
                    f.write(f"  + {ip}\n")
            else:
                f.write("- Không phát hiện IP đáng chú ý\n")
            
            f.write("\nCác bước tiếp theo:\n")
            f.write("1. Theo dõi liên tục tình trạng mạng\n")
            f.write("2. Thực hiện các biện pháp khuyến nghị\n")
            f.write("3. Lên kế hoạch bảo trì và nâng cấp hệ thống\n")
            
            # Thêm lời khuyên cụ thể dựa trên trạng thái
            f.write("\nLời khuyên cụ thể:\n")
            if final_status == "Bị tấn công":
                f.write("- Kích hoạt quy trình phản ứng sự cố bảo mật\n")
                f.write("- Tạm thời cách ly các hệ thống bị ảnh hưởng\n")
                f.write("- Liên hệ đội ứng cứu sự cố (nếu có)\n")
            elif final_status == "Đáng ngờ":
                f.write("- Tăng cường thu thập và phân tích log\n")
                f.write("- Theo dõi các IP đáng ngờ trong danh sách theo dõi\n")
                f.write("- Xem xét cập nhật các quy tắc tường lửa\n")
            elif final_status == "Nghẽn mạng":
                f.write("- Xác định và giảm thiểu tải cho các dịch vụ không thiết yếu\n")
                f.write("- Kiểm tra các cấu hình QoS\n")
                f.write("- Xem xét phân phối lại tài nguyên mạng\n")
            elif final_status == "Tốt":
                f.write("- Lập kế hoạch kiểm tra định kỳ\n")
                f.write("- Cập nhật tài liệu về cấu hình mạng\n")
                f.write("- Duy trì giám sát hệ thống\n")
        else:
            f.write("Tình trạng hệ thống: **Không xác định**\n\n")
            f.write("Không có đủ dữ liệu để đưa ra kết luận chi tiết. Cần thu thập thêm thông tin.\n")
            
            f.write("\nCác bước tiếp theo:\n")
            f.write("1. Thu thập thêm dữ liệu mạng\n")
            f.write("2. Thiết lập hệ thống giám sát\n")
            f.write("3. Thực hiện đánh giá bảo mật cơ bản\n")
        f.write("\n" + "=" * 50 + "\n")
