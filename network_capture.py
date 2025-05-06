import subprocess
import time
import os
import platform
import sys

# Nhận tham số từ command-line
if len(sys.argv) < 4:
    raise ValueError("Thiếu tham số: capture_duration, maximum_packets_capture, output_capture_file, capture_interface")
capture_duration = sys.argv[1]
maximum_packets_capture = sys.argv[2]
output_file = sys.argv[3]
capture_interface = sys.argv[4]

# Kiểm tra hệ điều hành đang sử dụng
system_type = platform.system()

if system_type == "Windows":
    interface = capture_interface
    dumpcap_path = "C:/Program Files/Wireshark/dumpcap.exe"
elif system_type == "Linux":
    interface = capture_interface
    dumpcap_path = "/usr/bin/dumpcap"
else:
    print(system_type)
    raise Exception(f"Hệ điều hành không được hỗ trợ: {system_type}")

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
            "-c", f"{maximum_packets_capture}",
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
        success = capture_wifi_packets()
        if not success:
            sys.exit(1)
