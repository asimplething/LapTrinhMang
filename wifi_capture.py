import subprocess
import time
import os
import platform
import sys

# Kiểm tra hệ điều hành đang sử dụng
system_type = platform.system()

if system_type == "Window":
    interface = "Wifi" # Thay bằng tên giao diện Wifi của bạn
    dumpcap_path = "C:/Program Files/Wireshark/dumpcap.exe"  # Để nguyên nếu dumpcap đã được thêm vào PATH
elif system_type == "Linux":
    interface = "wlp3s0"
    dumpcap_path = "/usr/bin/dumpcap"
else:
    raise Exception(f"Hệ điều hành không được hỗ trợ: {system_type}")
    

# Cấu hình
capture_duration = 10  # Thời gian bắt gói tin (giây)
output_file = "content/wifi_capture.pcapng"  # Tên file đầu ra

# Đường dẫn đến dumpcap (thay đổi nếu cần)
# Linux: thường là /usr/bin/dumpcap
# Windows: thường là C:\Program Files\Wireshark\dumpcap.exe

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
            "-F", "pcapng"
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
    if system_type == "Linux" and os.geteuid() != 0:
        print("Vui lòng chạy script với quyền root (sudo).")
        sys.exit(1)
    else:
        capture_wifi_packets()
        if not success:
            sys.exit(1)
