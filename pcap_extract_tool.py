import json
from scapy.all import rdpcap

def extract_pcap_info(pcap_file):
    """
    Chiết xuất thông tin từ tệp PCAPNG.
    
    Args:
        pcap_file (str): Đường dẫn đến tệp PCAPNG
    
    Returns:
        list: Danh sách các gói tin với thông tin chiết xuất
    """
    packets = rdpcap(pcap_file)
    extracted_data = []
    for pkt in packets:
        if pkt.haslayer('IP'):
            ip_layer = pkt.getlayer('IP')
            data = {
                "time": float(pkt.time),
                "src_ip": ip_layer.src,
                "dst_ip": ip_layer.dst,
                "protocol": ip_layer.proto,
                "size": len(pkt),
            }
            if pkt.haslayer("TCP") or pkt.haslayer("UDP"):
                transport = pkt.getlayer('TCP') if pkt.haslayer('TCP') else pkt.getlayer('UDP')
                data["src_port"] = transport.sport
                data["dst_port"] = transport.dport
            extracted_data.append(data)
    return extracted_data

def split_data(data, chunk_size=50):
    """
    Chia dữ liệu thành các phần, mỗi phần tối đa max_packets gói tin.
    
    Args:
        data (list): Danh sách dữ liệu gói tin
        max_packets (int): Số gói tin tối đa mỗi phần
    
    Returns:
        list: Danh sách các phần dữ liệu
    """
    chunks = []
    for i in range(0, len(data), chunk_size):
        chunks.append(data[i:i + chunk_size])
    chunks = json.dumps(chunks, ensure_ascii=False)
    return chunks


def pcap_extract_tool(pcap_file: str, chunk_size: int):
    """
    Tool để chiết xuất thông tin từ tệp PCAPNG và chia nhỏ thành các phần.
    
    Args:
        pcap_file (str): Đường dẫn đến tệp PCAPNG
        max_packets (int): Số gói tin tối đa mỗi phần (mặc định: 50)
    
    Returns:
        list: Danh sách các phần dữ liệu (chunks), mỗi phần chứa tối đa chunk_size gói tin
    """
    try:
        print(f"Đang chiết xuất thông tin từ tệp {pcap_file}...")
        # Chiết xuất thông tin từ tệp PCAPNG
        extracted_data = extract_pcap_info(pcap_file)
        # Chia dữ liệu thành các phần
        chunks = split_data(extracted_data, chunk_size)
        return chunks
    except Exception as e:
        print(f"Đã xảy ra lỗi: {str(e)}")
        return None