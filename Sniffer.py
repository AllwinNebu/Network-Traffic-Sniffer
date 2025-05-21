import socket
import struct
import textwrap

#unpacking frame
def ethernet_frame(data):
    dest_mac , src_mac , proto = struct.unpack('! 6s 6s H',data[:14])
    return get_mac_addr (dest_mac), get_mac_addr(src_mac), socket.htonl(proto), data[:14]

#convert mac adddress we get into readable format
def get_mac_addr(bytes_addr):
    byte_str = map('{:02x}'.format , bytes_addr)
    return ':'.join(byte_str).upper()