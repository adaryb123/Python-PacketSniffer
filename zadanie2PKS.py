from scapy.all import *
import struct

def transform_address_to_string(add_in_bytes):
    add_in_hex = bytes_hex(add_in_bytes).decode()
    result = ""
    for i in range(0,len(add_in_hex),2):
        result = ':'.join([result,add_in_hex[i:i+2]])
    return result

def determine_protocol(prot_code):
    if prot_code == 2048:
        return "IPv4"
    else:
        return "no IPv4"

def unpack_ethernet_header(packet):
    dest_mac_bytes , src_mac_bytes ,protocol_code = struct.unpack('! 6s 6s H',packet[:14])
    print(dest_mac_bytes)
    return transform_address_to_string(dest_mac_bytes), transform_address_to_string(src_mac_bytes),determine_protocol(protocol_code),packet[14:]

vzorka = rdpcap("/Users/drnck/Desktop/workspace/zadanie2PKS/vzorky/eth-1.pcap")   #nacitavanie z pcap subora
prvy_packet = raw(vzorka[0])
dest_mac , src_mac ,protocol ,data = unpack_ethernet_header(prvy_packet)
print(prvy_packet)
print(protocol)

#for i in range(len(vzorka)):
  #  print("packet cislo " + str(i))
  #  print(raw(vzorka[i]))