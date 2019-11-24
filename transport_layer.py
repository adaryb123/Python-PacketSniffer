import struct
import file_reader

def get_offset_and_flags(bytes):
   offset = (bytes >> 12) * 4
   flags = bytes & 63
   flag_u = (flags >> 5) & 1
   flag_a = (flags >> 4) & 1
   flag_p = (flags >> 3) & 1
   flag_r = (flags >> 2) & 1
   flag_s = (flags >> 1) & 1
   flag_f = flags & 1
   return offset,flag_u,flag_a,flag_p,flag_r,flag_s,flag_f

def unpack_tcp_header(bytes):
    source_port,dest_port,offset_reserved_flags = struct.unpack('! H H 8x H', bytes[:14])
    offset,flag_u,flag_a,flag_p,flag_r,flag_s,flag_f = get_offset_and_flags(offset_reserved_flags)
    return source_port,dest_port,flag_u,flag_a,flag_p,flag_r,flag_s,flag_f,bytes[offset:]


def unpack_udp_header(bytes):
    source_port,dest_port = struct.unpack('! H H ',bytes[:4])
    return source_port,dest_port,bytes[8:]


def determine_application_protocol_for_tcp(source_port,dest_port):
    if source_port <= dest_port:
        port = source_port
    else:
        port = dest_port

    return file_reader.read_data_file("TCP ports",port,"unknown application protocol")


def determine_application_protocol_for_udp(source_port,dest_port):                      #toto by slo zlucit do jednej s predoslou
    if source_port <= dest_port:
        port = source_port
    else:
        port = dest_port

    return file_reader.read_data_file("UDP ports",port,"unknown application protocol")


def unpack_icmp_header(bytes):
    type = struct.unpack('! B',bytes[:1])
    return determine_icmp_message(type),bytes[4:]

def determine_icmp_message(type):
    return file_reader.read_data_file("ICM types",type,"unknown ICM type")
