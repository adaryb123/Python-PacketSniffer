from scapy.all import *
import struct

def transform_address_to_string(add_in_bytes):
    add_in_hex = bytes_hex(add_in_bytes).decode()
    result = ""
    for i in range(0,len(add_in_hex),2):
        result = ' '.join([result,add_in_hex[i:i+2]])
    return result

def determine_ethernet_type(ethernet_type,packet):              #tu bude mozno treba pridat dalsie
    if ethernet_type >= 1536:
        return "Ethernet II"
    else:
        byte1,byte2,byte3 = struct.unpack('! c c c',packet[:3])
        #byte1 = bytes_hex(byte1).decode()
       # byte2 = bytes_hex(byte2).decode()
        #byte3 = bytes_hex(byte3).decode()
        if byte1 == b'\xff' and byte2 == b'\xff':
             return "Novell raw IEEE 802.3"
        elif byte1 == b'\xaa' and byte2 == b'\xaa':
             return "IEEE 802.3 LLC + SNAP"
        else:
            return "IEEE 802.3 LLC"

def unpack_ethernet_header(packet):             #este je treba zistit typ ethernetu
    dest_mac_bytes , src_mac_bytes ,ethernet_type = struct.unpack('! 6s 6s H',packet[:14])
    return transform_address_to_string(dest_mac_bytes), transform_address_to_string(src_mac_bytes),ethernet_type,packet[14:]


def main():
    #filename = input("Enter trace name: ")
    filename = "trace-20"
    trace = rdpcap("/Users/drnck/Desktop/workspace/zadanie2PKS/vzorky/" + filename + ".pcap")
    for i in range(len(trace)):
        packet = raw(trace[i])
        packet_length = len(packet)
        dest_mac , src_mac ,ethernet_type ,packet = unpack_ethernet_header(packet)
        ethernet_type = determine_ethernet_type(ethernet_type,packet)
        
        print("rámec "+str(i+1))
        print("dĺžka rámca poskytnutá pcap API – "+str(packet_length)+" B")
        print("dĺžka rámca prenášaného po médiu – "+str(packet_length)+" B")            # toto neviem ako
        print(ethernet_type)
        print("Zdrojová MAC adresa: "+src_mac)
        print("Cieľová MAC adresa: "+dest_mac)
       # if ethernet_type == "Ethernet II":

     #   elif ethernet_type == "Novell raw IEEE 802.3":
            
      #  elif ethernet_type == "IEEE 802.2 SNAP":

      #  elif ethernet_type == "IEEE 802.2 LLC":

   # print(first_packet)
     # print(protocol)

main()
#for i in range(len(vzorka)):
  #  print("packet cislo " + str(i))
  #  print(raw(vzorka[i]))