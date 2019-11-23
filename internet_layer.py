import struct
import file_reader
import ethernet_layer

def transform_to_ip_address(bytes):                   
   address = ""
   for i in range(len(bytes)):
       address += str(bytes[i]) + "."
   return address[:-1]

def determine_transport_protocol(protocol):       
     return file_reader.read_data_file("IP protocols",protocol,"other transport protocol")

def get_header_length(bytes):
   return (bytes & 15) * 4

def unpack_ipv4_header(bytes):
    version_and_header_length,protocol,source_ip,dest_ip = struct.unpack('! B 8x B 2x 4s 4s',bytes[:20])
    header_length = get_header_length(version_and_header_length)
    return determine_transport_protocol(protocol),transform_to_ip_address(source_ip),transform_to_ip_address(dest_ip), bytes[header_length:]


def unpack_arp_header(bytes):
    type,source_mac,source_ip,dest_mac,dest_ip = struct.unpack('! 6x H 6s 4s 6s 4s',bytes[:28])
    if type==1:
        type = "REQUEST"
        dest_mac = "?"

    elif type==2:
        type = "REPLY"
        dest_mac =  ethernet_layer.transform_to_mac_address(dest_mac)

    source_mac = ethernet_layer.transform_to_mac_address(source_mac)
    source_ip = transform_to_ip_address(source_ip)
    dest_ip = transform_to_ip_address(dest_ip)

    return type,source_mac,source_ip,dest_mac,dest_ip,bytes[28:]
    