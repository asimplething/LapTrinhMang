import subprocess
import os
import platform

async def capture_packets(capture_duration, maximum_packets_capture, output_file, capture_interface):
    """
    Hàm bắt gói tin mạng sử dụng dumpcap.
    
    Args:
        capture_duration (int): Thời gian bắt gói tin (giây)
        maximum_packets_capture (int): Số gói tin tối đa cần bắt
        output_file (str): Đường dẫn file đầu ra
        capture_interface (str): Giao diện mạng để bắt gói tin
    
    Returns:
        dict: Kết quả bao gồm trạng thái thành công và đường dẫn file đầu ra
    """
    system_type = platform.system()
    
    # Xác định đường dẫn dumpcap dựa trên hệ điều hành
    if system_type == "Windows":
        dumpcap_path = "C:/Program Files/Wireshark/dumpcap.exe"
    elif system_type == "Linux":
        dumpcap_path = "/usr/bin/dumpcap"
    else:
        raise Exception(f"Hệ điều hành không được hỗ trợ: {system_type}")
    
    try:
        print(f"Bắt đầu bắt gói tin trên giao diện {capture_interface} trong {capture_duration} giây...")
        
        # Xóa file đầu ra nếu đã tồn tại
        if os.path.exists(output_file):
            os.remove(output_file)
        
        # Lệnh dumpcap để bắt gói tin
        command = [
            dumpcap_path,
            "-i", capture_interface,
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
            return {"success": False, "output_file": None}
        
        print(f"Đã lưu gói tin vào {output_file}")
        if os.path.exists(output_file):
            print(f"Kích thước file: {os.path.getsize(output_file)} bytes")
        return {"success": True, "output_file": output_file}
    
    except Exception as e:
        print(f"Đã xảy ra lỗi: {str(e)}")
        return {"success": False, "output_file": None}

# Đăng ký tool cho Autogen
async def network_capture_tool(duration: int, max_packets: int, output: str, interface: str):
    """
    Tool để bắt gói tin mạng.
    
    Args:
        duration (int): Thời gian bắt gói tin
        max_packets (int): Số gói tin tối đa
        output (str): Đường dẫn file đầu ra
        interface (str): Giao diện mạng
    
    Returns:
        dict: Kết quả capture
    """
    return await capture_packets(duration, max_packets, output, interface)