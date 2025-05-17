import json
from scapy.all import rdpcap, PcapReader
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.l2 import ARP, Ether
import time

def extract_pcap_info(pcap_file, max_packets=None, protocols=None):
    """
    Chiết xuất thông tin chi tiết từ tệp PCAPNG với tối ưu hiệu suất.
    
    Args:
        pcap_file (str): Đường dẫn đến tệp PCAPNG
        max_packets (int, optional): Giới hạn số gói tin đọc (None = tất cả)
        protocols (list, optional): Chỉ lấy gói tin có giao thức cụ thể
    
    Returns:
        list: Danh sách các gói tin với thông tin chiết xuất chi tiết
    """
    start_time = time.time()
    extracted_data = []
    packet_count = 0
    
    # Sử dụng PcapReader để đọc từng gói tin một thay vì tải toàn bộ vào bộ nhớ
    with PcapReader(pcap_file) as pcap_reader:
        for pkt in pcap_reader:
            # Giới hạn số lượng gói tin nếu được chỉ định
            if max_packets and packet_count >= max_packets:
                break
                
            packet_count += 1
            
            # Khởi tạo thông tin cơ bản của gói tin
            info = {
                "time": float(pkt.time),
                "length": len(pkt)
            }
            
            # Lọc theo giao thức nếu được chỉ định
            if protocols:
                has_requested_protocol = False
                for protocol in protocols:
                    if pkt.haslayer(protocol):
                        has_requested_protocol = True
                        break
                if not has_requested_protocol:
                    continue

            # Danh sách lớp (layer) của gói - chỉ lấy tên class không phân tích chi tiết để tăng tốc
            layers = []
            layer = pkt
            while layer:
                layers.append(layer.__class__.__name__)
                layer = layer.payload if layer.payload else None
            info["layers"] = layers

            # Ethernet
            if pkt.haslayer(Ether):
                eth = pkt.getlayer(Ether)
                info["ethernet"] = {
                    "src_mac": eth.src,
                    "dst_mac": eth.dst,
                    "type": eth.type
                }

            # ARP
            if pkt.haslayer(ARP):
                arp = pkt.getlayer(ARP)
                info["arp"] = {
                    "hwtype": arp.hwtype,
                    "ptype": arp.ptype,
                    "hwlen": arp.hwlen,
                    "plen": arp.plen,
                    "op": arp.op,  # 1=request, 2=reply
                    "hwsrc": arp.hwsrc,
                    "hwdst": arp.hwdst,
                    "psrc": arp.psrc,
                    "pdst": arp.pdst
                }

            # IP
            if pkt.haslayer(IP):
                ip = pkt.getlayer(IP)
                info["ip"] = {
                    "version": ip.version,
                    "ihl": ip.ihl,
                    "tos": ip.tos,
                    "len": ip.len,
                    "id": ip.id,
                    "flags": str(ip.flags),
                    "frag": ip.frag,
                    "ttl": ip.ttl,
                    "proto": ip.proto,
                    "src": ip.src,
                    "dst": ip.dst
                }

            # TCP/UDP
            if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                trans = pkt.getlayer(TCP) if pkt.haslayer(TCP) else pkt.getlayer(UDP)
                proto = 'TCP' if pkt.haslayer(TCP) else 'UDP'
                info["transport"] = {
                    "proto": proto,
                    "src_port": trans.sport,
                    "dst_port": trans.dport,
                    "seq": getattr(trans, 'seq', None),
                    "ack": getattr(trans, 'ack', None),
                    "flags": str(getattr(trans, 'flags', None))
                }
                
                # HTTP (chỉ phân tích khi có TCP)
                if pkt.haslayer(TCP):
                    if pkt.haslayer(HTTPRequest):
                        http = pkt.getlayer(HTTPRequest)
                        info["http_request"] = {
                            "method": http.Method.decode() if hasattr(http, 'Method') else None,
                            "path": http.Path.decode() if hasattr(http, 'Path') else None,
                            "host": http.Host.decode() if hasattr(http, 'Host') else None,
                            "user_agent": http.User_Agent.decode() if hasattr(http, 'User_Agent') else None
                        }
                    elif pkt.haslayer(HTTPResponse):
                        http = pkt.getlayer(HTTPResponse)
                        info["http_response"] = {
                            "status_code": http.Status_Code if hasattr(http, 'Status_Code') else None,
                            "reason": http.Reason_Phrase.decode() if hasattr(http, 'Reason_Phrase') else None
                        }

            # ICMP
            if pkt.haslayer(ICMP):
                icmp = pkt.getlayer(ICMP)
                info["icmp"] = {
                    "type": icmp.type,
                    "code": icmp.code,
                    "id": getattr(icmp, 'id', None),
                    "seq": getattr(icmp, 'seq', None)
                }
                
            # DNS
            if pkt.haslayer(DNS):
                dns = pkt.getlayer(DNS)
                queries = []
                answers = []
                
                # Xử lý truy vấn DNS
                for i in range(dns.qdcount):
                    qname = dns.qd[i].qname.decode() if dns.qd and hasattr(dns.qd[i], 'qname') else None
                    queries.append({
                        "name": qname,
                        "type": dns.qd[i].qtype if dns.qd and hasattr(dns.qd[i], 'qtype') else None
                    })
                
                # Xử lý câu trả lời DNS
                if dns.an:
                    for i in range(dns.ancount):
                        if dns.an and i < len(dns.an):
                            rdata = None
                            if hasattr(dns.an[i], 'rdata'):
                                try:
                                    if isinstance(dns.an[i].rdata, bytes):
                                        rdata = dns.an[i].rdata.decode('utf-8', errors='replace')
                                    else:
                                        rdata = str(dns.an[i].rdata)
                                except:
                                    rdata = str(dns.an[i].rdata)
                            
                            answers.append({
                                "name": dns.an[i].rrname.decode() if hasattr(dns.an[i], 'rrname') else None,
                                "type": dns.an[i].type if hasattr(dns.an[i], 'type') else None,
                                "data": rdata,
                                "ttl": dns.an[i].ttl if hasattr(dns.an[i], 'ttl') else None
                            })
                
                info["dns"] = {
                    "id": dns.id,
                    "qr": dns.qr,  # 0=query, 1=response
                    "opcode": dns.opcode,
                    "aa": dns.aa,  # Authoritative Answer
                    "tc": dns.tc,  # TrunCation
                    "rd": dns.rd,  # Recursion Desired
                    "ra": dns.ra,  # Recursion Available
                    "z": dns.z,    # Zero (reserved)
                    "rcode": dns.rcode, # Response Code
                    "qdcount": dns.qdcount, # Query Count
                    "ancount": dns.ancount, # Answer Count
                    "nscount": dns.nscount, # Authority Count
                    "arcount": dns.arcount, # Additional Count
                    "queries": queries,
                    "answers": answers
                }

            extracted_data.append(info)
            
            # In tiến trình mỗi 1000 gói tin để theo dõi hiệu suất
            if packet_count % 1000 == 0:
                print(f"Đã xử lý {packet_count} gói tin...")
    
    end_time = time.time()
    print(f"Đã xử lý {packet_count} gói tin trong {end_time - start_time:.2f} giây")
    return extracted_data

def split_data(data, chunk_size=50):
    """
    Chia dữ liệu thành các phần, mỗi phần tối đa chunk_size gói tin.
    
    Args:
        data (list): Danh sách dữ liệu gói tin
        chunk_size (int): Số gói tin tối đa mỗi phần
    
    Returns:
        list: Danh sách các phần dữ liệu
    """
    chunks = []
    for i in range(0, len(data), chunk_size):
        chunks.append(data[i:i + chunk_size])
    chunks = json.dumps(chunks, ensure_ascii=False)
    return chunks


def pcap_extract_tool(pcap_file: str, chunk_size: int, max_packets: int = None, protocols: list = None):
    """
    Tool để chiết xuất thông tin từ tệp PCAPNG và chia nhỏ thành các phần.
    
    Args:
        pcap_file (str): Đường dẫn đến tệp PCAPNG
        chunk_size (int): Số gói tin tối đa mỗi phần
        max_packets (int, optional): Giới hạn số gói tin xử lý (None = không giới hạn)
        protocols (list, optional): Danh sách tên giao thức cần lọc (None = tất cả)
    
    Returns:
        list: Danh sách các phần dữ liệu (chunks), mỗi phần chứa tối đa chunk_size gói tin
    """
    try:
        print(f"Đang chiết xuất thông tin từ tệp {pcap_file}...")
        start_time = time.time()
        
        # Chiết xuất thông tin từ tệp PCAPNG
        extracted_data = extract_pcap_info(pcap_file, max_packets, protocols)
        
        # Chia dữ liệu thành các phần
        chunks = split_data(extracted_data, chunk_size)
        
        end_time = time.time()
        print(f"Hoàn tất chiết xuất và chia dữ liệu trong {end_time - start_time:.2f} giây")
        
        return chunks
    except Exception as e:
        print(f"Đã xảy ra lỗi khi xử lý file pcap: {str(e)}")
        import traceback
        traceback.print_exc()
        return None