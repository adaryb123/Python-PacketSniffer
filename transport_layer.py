import struct
import file_reader

def get_offset(bytes):
    return (bytes >> 12) * 4

def unpack_tcp_header(packet):
    source_port,dest_port,offset_reserved_flags = struct.unpack('! H H 8x H', packet[:14])
    offset = get_offset(offset_reserved_flags)
    return source_port,dest_port,packet[offset:]


def unpack_udp_header(packet):
    source_port,dest_port = struct.unpack('! H H ',packet[:4])
    return source_port,dest_port,packet[8:]


def determine_application_protocol_for_tcp(source_port,dest_port):
    if source_port <= dest_port:
        port = source_port
    else:
        port = dest_port

    return file_reader.read_data_file("TCP ports",port,"other application protocol")


def determine_application_protocol_for_udp(source_port,dest_port):
    if source_port <= dest_port:
        port = source_port
    else:
        port = dest_port

    return file_reader.read_data_file("UDP ports",port,"other application protocol")


def unpack_icmp_header(packet):
    type = struct.unpack('! B',packet[:1])
    return determine_icmp_message(type),packet[4:]

def determine_icmp_message(type):
    return file_reader.read_data_file("ICM types",type,"other ICM type")
