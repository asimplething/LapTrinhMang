import datetime

def write_log_tool(file_path: str, content: str) -> bool:
    """
    Ghi nội dung vào tệp log.
    
    Args:
        file_path (str): Đường dẫn đến tệp log
        content (str): Nội dung cần ghi vào tệp
    Returns:
        bool: True nếu ghi thành công, False nếu có lỗi
    """
    print(f"Ghi log vào tệp: {file_path}")
    try:
        with open(file_path, 'a', encoding='utf-8') as f:
            f.write(f"{datetime.datetime.now()}:\n{content}\n")
            f.write("-" * 20 + "\n")
            return True
    except Exception as e:
        print(f"Lỗi khi ghi log: {e}")
        return False
        
def read_log_tool(file_path: str) -> str:
    """
    Đọc nội dung từ tệp log.
    
    Args:
        file_path (str): Đường dẫn đến tệp log
    
    Returns:
        str: Nội dung của tệp log
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Tệp log không tồn tại: {file_path}")
        return ""