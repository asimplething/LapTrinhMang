# Hệ Thống Phân Tích Mạng Thông Minh

Hệ thống phân tích mạng sử dụng AI để bắt gói tin, phân tích lưu lượng mạng và đưa ra đánh giá về tình trạng mạng. Sử dụng nhiều AI model (Gemini, DeepSeek, Llama) để phân tích và đối chiếu kết quả.

## Yêu Cầu Hệ Thống

- Python 3.8 trở lên
- Wireshark/dumpcap
- Các API key cho các model AI (Gemini, DeepSeek, OpenRouter)
- Hệ điều hành: Linux/Windows

## Cài Đặt

1. Clone repository:
   ```
   git clone <repository-url>
   ```

2. Cài đặt các gói phụ thuộc:
   ```
   pip install -r requirements.txt
   ```

3. Tạo file `.env` trong thư mục gốc với các API key:
   ```
   GEMINI_API_KEY=your_gemini_api_key
   DEEPSEEK_API_KEY=your_deepseek_api_key
   OPENROUTER_API_KEY=your_openrouter_api_key
   ```

4. Đảm bảo Wireshark/dumpcap đã được cài đặt và đường dẫn chính xác trong `tools/network_capture_tool.py`

## Cấu Hình

1. Cấu hình được lưu trong file `config/system_config.txt`
2. Các tham số cấu hình:
   - `capture_interface`: Giao diện mạng để bắt gói tin (ví dụ: eth0, wlan0)
   - `capture_duration`: Thời gian bắt gói tin (giây)
   - `maximum_packets_capture`: Số lượng gói tin tối đa sẽ bắt
   - `output_capture_file`: Đường dẫn lưu file PCAPNG
   - `minimum_network_limit`: Giới hạn băng thông tối thiểu
   - `maximum_network_limit`: Giới hạn băng thông tối đa

## Sử Dụng

### Bắt Đầu Phân Tích

1. Chạy chương trình chính:
   ```
   python run_me.py
   ```

2. Truy cập giao diện web tại địa chỉ:
   ```
   http://localhost:5000
   ```

### Theo Dõi Kết Quả

- **Trang chủ**: Hiển thị thông tin tổng quan về tình trạng mạng
- **Xem Log**: Truy cập vào các log chi tiết của từng model AI
- **Cấu hình**: Thay đổi cấu hình hệ thống

## Cấu Trúc Hệ Thống

- **AI_agent.py**: Module chính cho AI agents phân tích mạng
- **run_me.py**: Chương trình chính, cung cấp giao diện web
- **tools/**: Các công cụ bắt gói tin và chiết xuất thông tin
- **system_message_template/**: Templates hướng dẫn cho các AI agents
- **log/**: Thư mục chứa log phân tích
- **content/**: Thư mục lưu dữ liệu gói tin đã chiết xuất
- **config/**: Cấu hình hệ thống

## Mô Hình Phân Tích

Hệ thống sử dụng 3 model AI để phân tích độc lập:
1. **Gemini**: Model Google Gemini 1.5 Flash
2. **DeepSeek**: Model DeepSeek Chat
3. **Llama**: Model Meta: Llama 3.3 8B Instruct

Kết quả được đối chiếu để đưa ra đánh giá cuối cùng về tình trạng mạng (Tốt, Đáng ngờ, Bị tấn công, Nghẽn mạng, Mạng sập).

## Phân Tích Báo Cáo

Báo cáo phân tích sẽ bao gồm các phần:
1. Tình trạng mạng (Tốt, Đáng ngờ, Bị tấn công, Nghẽn mạng, Mạng sập)
2. Phân tích chi tiết về:
   - Giao thức sử dụng
   - Cổng sử dụng
   - Địa chỉ IP
   - Kích thước và tần suất gói tin
   - Vấn đề an ninh
3. Đánh giá tổng quan

## Xử Lý Sự Cố

- **Lỗi bắt gói tin**: Kiểm tra quyền truy cập và đường dẫn dumpcap
- **Lỗi API**: Xác nhận API key trong file .env
- **Log trống**: Kiểm tra thư mục log/ và quyền ghi file 