import socket
import struct
import textwrap

#unpacking frame
def ethernet_frame(data):
    dest_mac , src_mac , proto = struct.unpack('! 6s 6s H',data[:14])
    return get_mac_addr (dest_mac), get_mac_addr(src_mac), socket.htonl(proto), data[:14]