import subprocess
import time
import os

# Cấu hình
interface = "Wi-Fi"  # Thay bằng tên giao diện Wi-Fi của bạn (ví dụ: 'Wi-Fi' trên Windows, 'wlan0' trên Linux)
capture_duration = 10  # Thời gian bắt gói tin (giây)
output_file = "content/wifi_capture.pcapng"  # Tên file đầu ra

# Đường dẫn đến dumpcap (thay đổi nếu cần)
# Linux: thường là /usr/bin/dumpcap
# Windows: thường là C:\Program Files\Wireshark\dumpcap.exe
dumpcap_path = "C:/Program Files/Wireshark/dumpcap.exe"  # Để nguyên nếu dumpcap đã được thêm vào PATH

def capture_wifi_packets():
    try:
        print(f"Bắt đầu bắt gói tin trên giao diện {interface} trong {capture_duration} giây...")
        
        # Xóa file đầu ra nếu đã tồn tại
        if os.path.exists(output_file):
            os.remove(output_file)
        
        # Lệnh dumpcap để bắt gói tin
        # -i: giao diện
        # -a duration: thời gian bắt
        # -w: file đầu ra
        # -n: định dạng PCAPNG
        command = [
            dumpcap_path,
            "-i", interface,
            "-a", f"duration:{capture_duration}",
            "-w", output_file,
            "-n"
        ]
        
        # Chạy lệnh dumpcap
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Đợi quá trình hoàn tất
        stdout, stderr = process.communicate()
        
        # Kiểm tra lỗi
        if process.returncode != 0:
            print(f"Lỗi khi chạy dumpcap: {stderr.decode()}")
            return False
        
        print(f"Đã lưu gói tin vào {output_file}")
        if os.path.exists(output_file):
            print(f"Kích thước file: {os.path.getsize(output_file)} bytes")
        return True
        
    except Exception as e:
        print(f"Đã xảy ra lỗi: {str(e)}")
        return False

if __name__ == "__main__":
    # Kiểm tra quyền admin (Linux yêu cầu sudo cho dumpcap)
    if os.name == "posix" and os.geteuid() != 0:
        print("Vui lòng chạy script với quyền root (sudo).")
    else:
        capture_wifi_packets()