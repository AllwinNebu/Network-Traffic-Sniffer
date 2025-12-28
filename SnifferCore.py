import socket
import struct
import textwrap
import os
import ipaddress
import binascii
from datetime import datetime
import threading
import time

# Protocol numbers
PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
    88: "EIGRP",
    89: "OSPF"
}

# Common ports and their services
PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-ALT"
}

def is_admin():
    try:
        return os.getuid() == 0
    except AttributeError:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0

def get_interface_ip():
    try:
        # Get the default interface IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def format_ipv4(addr):
    return '.'.join(map(str, addr))

def format_ipv6(addr):
    return ipaddress.IPv6Address(addr).exploded

def parse_ipv4(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, format_ipv4(src), format_ipv4(target), data[header_length:]

def parse_ipv6(data):
    version_traffic = struct.unpack('! B', data[0:1])[0]
    version = version_traffic >> 4
    traffic_class = ((version_traffic & 0x0F) << 4) | (data[1] >> 4)
    flow_label = struct.unpack('! I', b'\x00' + data[1:4])[0] & 0x0FFFFF
    payload_length, next_header, hop_limit = struct.unpack('! H B B', data[4:8])
    src = data[8:24]
    dst = data[24:40]
    return (version, traffic_class, flow_label, payload_length, 
            next_header, hop_limit, format_ipv6(src), format_ipv6(dst), 
            data[40:])

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp_packet(data):
    src_port, dst_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:10])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dst_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp_packet(data):
    src_port, dst_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dst_port, size, data[8:]

def get_port_service(port):
    return PORTS.get(port, f"Unknown-{port}")

class PacketSniffer:
    def __init__(self):
        self.running = False
        self.socket = None
        self.capture_thread = None
        self.packet_callback = None
        self.error_callback = None
    
    def start(self, packet_callback, error_callback=None, filter_protocol=None):
        if self.running:
            return
        
        self.packet_callback = packet_callback
        self.error_callback = error_callback
        self.running = True
        self.filter_protocol = filter_protocol
        
        # Start capture in a separate thread
        self.capture_thread = threading.Thread(target=self._capture_loop)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
    def stop(self):
        self.running = False
        if self.socket:
            try:
                # Force socket close to break out of blocking recv
                if os.name == 'nt':
                    self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                self.socket.close()
            except:
                pass
            self.socket = None

    def _capture_loop(self):
        try:
            if os.name == 'nt':
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                local_ip = get_interface_ip()
                self.socket.bind((local_ip, 0))
                self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
                
            while self.running:
                try:
                    if os.name == 'nt':
                        raw_data = self.socket.recvfrom(65565)[0]
                        version = (raw_data[0] >> 4)
                        
                        packet_info = None
                        if version == 4:
                            packet_info = self._process_ipv4_packet(raw_data)
                        elif version == 6:
                            packet_info = self._process_ipv6_packet(raw_data)
                            
                        if packet_info and self.running:
                            if self.filter_protocol:
                                if packet_info['protocol'] == self.filter_protocol or \
                                   packet_info['protocol'].upper() == self.filter_protocol.upper():
                                    self.packet_callback(packet_info)
                            else:
                                self.packet_callback(packet_info)
                                
                    else:
                        # Simple Linux support (similar to original)
                        raw_data, addr = self.socket.recvfrom(65565)
                        # ... (Implement Linux specific handling if needed, keeping it simple for now as user is on Windows)
                        pass
                        
                except OSError:
                    # Socket closed
                    break
                except Exception as e:
                    # Ignore minor errors during capture
                    pass
                    
        except Exception as e:
            if self.error_callback:
                self.error_callback(str(e))
            self.running = False

    def _process_ipv4_packet(self, data):
        try:
            version, header_length, ttl, proto, src_ip, target_ip, payload = parse_ipv4(data)
            protocol_name = PROTOCOLS.get(proto, f"Protocol {proto}")
            
            packet_info = {
                'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
                'version': 'IPv4',
                'source': src_ip,
                'destination': target_ip,
                'protocol': protocol_name,
                'length': len(data),
                'details': {
                    'version': version,
                    'header_length': header_length,
                    'ttl': ttl,
                    'protocol': proto,
                    'protocol_name': protocol_name,
                    'source': src_ip,
                    'destination': target_ip,
                    'payload': payload
                }
            }
            
            self._add_transport_layer_details(packet_info, proto, payload)
            return packet_info
        except:
            return None

    def _process_ipv6_packet(self, data):
        try:
            version, traffic_class, flow_label, payload_length, next_header, hop_limit, src_ip, target_ip, payload = parse_ipv6(data)
            protocol_name = PROTOCOLS.get(next_header, f"Protocol {next_header}")
            
            packet_info = {
                'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
                'version': 'IPv6',
                'source': src_ip,
                'destination': target_ip,
                'protocol': protocol_name,
                'length': len(data),
                'details': {
                    'version': version,
                    'traffic_class': traffic_class,
                    'flow_label': flow_label,
                    'payload_length': payload_length,
                    'next_header': next_header,
                    'hop_limit': hop_limit,
                    'protocol_name': protocol_name,
                    'source': src_ip,
                    'destination': target_ip,
                    'payload': payload
                }
            }
            
            self._add_transport_layer_details(packet_info, next_header, payload)
            return packet_info
        except:
            return None

    def _add_transport_layer_details(self, packet_info, proto, payload):
        if proto == 6:  # TCP
            try:
                src_port, dst_port, seq, ack, urg, ack_flag, psh, rst, syn, fin, data = tcp_packet(payload)
                packet_info['details'].update({
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'service': get_port_service(dst_port) if dst_port < 1024 or dst_port in PORTS else get_port_service(src_port),
                    'sequence': seq,
                    'acknowledgement': ack,
                    'flags': {
                        'URG': urg, 'ACK': ack_flag, 'PSH': psh,
                        'RST': rst, 'SYN': syn, 'FIN': fin
                    },
                    'payload_data': data
                })
            except:
                pass
        elif proto == 17:  # UDP
            try:
                src_port, dst_port, size, data = udp_packet(payload)
                packet_info['details'].update({
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'service': get_port_service(dst_port) if dst_port < 1024 or dst_port in PORTS else get_port_service(src_port),
                    'length': size,
                    'payload_data': data
                })
            except:
                pass
        elif proto == 1: # ICMP
             try:
                icmp_type, code, checksum, data = icmp_packet(payload)
                packet_info['details'].update({
                    'type': icmp_type,
                    'code': code,
                    'checksum': checksum,
                    'payload_data': data
                })
             except:
                pass
