import struct
import file_reader

def transform_to_mac_address(bytes):
    address = ""
    for i in range(len(bytes)):
        byte = hex(bytes[i])[2:].upper()
        if len(byte)==1:
            byte = "0" + byte
        address += byte + " "
    return address

def determine_ethernet_name(ethernet_type_or_length):      
    if int(ethernet_type_or_length) >= 1536:
        return "Ethernet II"
    else:
        return "IEEE 802.3"


def unpack_ethernet_header(bytes):             
    dest_mac_bytes , src_mac_bytes ,ethernet_type_or_length = struct.unpack('! 6s 6s H',bytes[:14])
    return transform_to_mac_address(dest_mac_bytes), transform_to_mac_address(src_mac_bytes),ethernet_type_or_length,bytes[14:]

def determine_internet_protocol_by_ethertype(ethertype):      
    return file_reader.read_data_file("EtherTypes",ethertype,"unknown internet protocol")
   
def determine_internet_protocol_by_lsap(bytes):
    lsap = bytes[0]
    return file_reader.read_data_file("SAPs",lsap,"unknown internet protocol"),lsap,bytes[3:]


def name_ieee_by_lsap(ether_name,lsap):
    if lsap == 255:
        return ether_name + "- RAW"
    elif lsap == 170:
        return ether_name + "-SNAP"
    return ether_name + "-LLC"

def fully_analyze_ethernet(bytes):
     dest_mac , src_mac ,ethernet_type_or_length ,remaining_bytes = unpack_ethernet_header(bytes)
     ethernet_name = determine_ethernet_name(ethernet_type_or_length)

     if ethernet_name == "Ethernet II":
            internet_protocol = determine_internet_protocol_by_ethertype(ethernet_type_or_length)
     else:
            internet_protocol,lsap,remaining_bytes = determine_internet_protocol_by_lsap(remaining_bytes)    
            ethernet_name = name_ieee_by_lsap(ethernet_name,lsap)
            if ethernet_name == "IEEE 802.3-SNAP":
                ethernet_type = struct.unpack('! 3x H',remaining_bytes[:5])           
                remaining_bytes = remaining_bytes[5:]
                internet_protocol = determine_internet_protocol_by_ethertype(int(ethernet_type[0]))

     return dest_mac,src_mac,ethernet_name,internet_protocol,remaining_bytes