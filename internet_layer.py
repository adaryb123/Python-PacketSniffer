import struct

def transform_to_ip_address(bytes):                   
   address = ""
   for i in range(len(bytes)):
       address += str(bytes[i]) + "."
   return address[:-1]

def determine_transport_protocol(protocol):          
    if protocol == 1:
        return "ICMP"
    elif protocol == 6:
        return "TCP"
    elif protocol == 17:
        return "UDP"
    else:
        return "other transport protocol"

def get_header_length(bytes):
   return (bytes & 15) * 4

def unpack_ipv4_header(packet):
    version_and_header_length,protocol,source_ip,dest_ip = struct.unpack('! B 8x B 2x 4s 4s',packet[:20])
    header_length = get_header_length(version_and_header_length)
    return determine_transport_protocol(protocol),transform_to_ip_address(source_ip),transform_to_ip_address(dest_ip), packet[header_length:]

