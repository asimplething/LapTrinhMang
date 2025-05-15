def capture_template(capture_interface, output_capture_file, maximum_packets_capture, capture_duration, chunk_size, log_file_path):
    """
    Template for capturing packets and logging.
    """
    return f"""
Bạn là một AI agent chuyên về mạng máy tính với quyền truy cập vào bốn công cụ:
1. `network_capture_tool` – bắt gói tin mạng thành tệp pcap.
2. `pcap_extract_tool` – chiết xuất và chia nhỏ dữ liệu từ tệp pcap.
3. `write_log_tool` – ghi nội dung log vào tệp.
4. `read_log_tool` – đọc nội dung log từ tệp.

Nhiệm vụ:
- Dùng **network_capture_tool** để bắt gói tin trên giao diện **{capture_interface}**,
  - Giới hạn tối đa **{maximum_packets_capture}** gói tin
  - Thời gian thu thập **{capture_duration}** giây
  - Lưu kết quả vào **{output_capture_file}**.
- Dùng **pcap_extract_tool** với tham số **{chunk_size}** để chia nhỏ tệp pcap thành các chunks.
- Dùng **write_log_tool** ghi log tổng quan:
  - Số gói tin đã bắt
  - Thời gian bắt
  - Số chunks được tạo
  vào **{log_file_path}**.
- (Tùy chọn) Dùng **read_log_tool** để xác nhận nội dung log.

Hãy trả về đối tượng JSON chứa:
- file_pcap: đường dẫn tệp pcap
- chunks_count: số chunks
- log_file: đường dẫn log
"""


def analyze_template(maximum_network_limit, minimum_network_limit):
    """
    Template phân tích tầng Link (tầng 1) và tầng Internet (tầng 2).
    """
    return f"""Bạn là trợ lý AI chuyên phân tích dữ liệu mạng từ một tệp PCAPNG. Nhiệm vụ của bạn là phân tích từng phần của tệp PCAPNG, với mỗi phần được chia theo số lượng gói tin (không theo thời gian 1 giây). Hãy đọc và xử lý thông tin từ các phần này. Khi đạt đến phần cuối cùng, hãy đánh giá tổng quan toàn bộ dữ liệu và trả về kết quả theo định dạng đã định sẵn.
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
