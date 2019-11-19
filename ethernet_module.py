import struct

def transform_to_mac_address(bytes):
    address = ""
    for i in range(len(bytes)):
        byte = hex(bytes[i])[2:].upper()
        if len(byte)==1:
            byte = "0" + byte
        address += byte + " "
    return address

def determine_ethernet_name(ethernet_type_or_length,packet):              #treba zo suboru  
    if int(ethernet_type_or_length) >= 1536:
        return "Ethernet II"
    else:
        return "IEEE 802.3"


def unpack_ethernet_header(packet):             
    dest_mac_bytes , src_mac_bytes ,ethernet_type_or_length = struct.unpack('! 6s 6s H',packet[:14])
    return transform_to_mac_address(dest_mac_bytes), transform_to_mac_address(src_mac_bytes),ethernet_type_or_length,packet[14:]



def determine_internet_protocol_by_ethertype(ethertype):                  #treba zo suboru
    if ethertype == 2048:
        return "IPv4"
    elif ethertype == 2054:
        return "ARP"
    elif ethertype == 34525:
        return "IPv6"
    else:
        return "other internet protocol"


def determine_lsap(packet):
    lsap = packet[0]
    name = ""
    if lsap == 255:
        name = "IEEE 802.3 RAW"
    elif lsap == 170:
        name = "IEEE 802.3 SNAP"
    else:
        name = "IEEE 802.3 LLC"
    return name,lsap,packet[3:]

def determine_internet_protocol_by_lsap(packet): # nacitavanie zo suboru
    return "DOPLNIM"