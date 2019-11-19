import struct

def transform_to_mac_address(bytes):
    address = ""
    for i in range(len(bytes)):
        byte = hex(bytes[i])[2:].upper()
        if len(byte)==1:
            byte = "0" + byte
        address += byte + " "
    return address

def determine_ethernet_name(ethernet_type_or_length,packet):      
    if int(ethernet_type_or_length) >= 1536:
        return "Ethernet II"
    else:
        return "IEEE 802.3"


def unpack_ethernet_header(packet):             
    dest_mac_bytes , src_mac_bytes ,ethernet_type_or_length = struct.unpack('! 6s 6s H',packet[:14])
    return transform_to_mac_address(dest_mac_bytes), transform_to_mac_address(src_mac_bytes),ethernet_type_or_length,packet[14:]

def determine_internet_protocol_by_ethertype(ethertype):              
    with open('data_files/EtherTypes.txt') as data_file:
        line = data_file.readline()
        data_length = len(str(ethertype))
        while line != "":
          if line[:data_length] == str(ethertype):
              return line[data_length+1:-1]
          line = data_file.readline()

    return "other internet protocol"

def determine_internet_protocol_by_lsap(packet):
    lsap = packet[0]
    with open('data_files/SAPs.txt') as data_file:
        line = data_file.readline()
        data_length = len(str(lsap))
        while line != "":
          if line[:data_length] == str(lsap):
              return line[data_length+1:-1],lsap,packet[3:]
          line = data_file.readline()
    return "other internet protocol",lsap,packet[3:]


def name_ieee_by_lsap(ether_name,lsap):
    if lsap == 255:
        return ether_name + "- RAW"
    elif lsap == 170:
        return ether_name + "-SNAP"
    return ether_name + "-LLC"