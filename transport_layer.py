import struct

def get_offset(bytes):
    return (bytes >> 12) * 4

def unpack_tcp_header(packet):
    source_port,dest_port,offset_reserved_flags = struct.unpack('! H H 8x H', packet[:14])
    offset = get_offset(offset_reserved_flags)
    return source_port,dest_port,packet[offset:]


def unpack_udp_header(packet):
    source_port,dest_port = struct.unpack('! H H ',packet[:4])
    return source_port,dest_port,packet[8:]


def determine_application_protocol(source_port,dest_port):
    if source_port > 1080 and dest_port <= 1080:
        print("Hladame podla dest_portu "+ str(dest_port))      #dalej nacitat zo subora
    elif dest_port > 1080 and source_port <= 1080:
        print("Hladame podla source_portu "+ str(source_port))
    else:
        print("obidve cisla vyhovuju - WTF?")
        print(str(source_port))
        print(str(dest_port))