from scapy.all import *
import struct

def transform_to_mac_address(bytes):
    hex = bytes_hex(bytes).decode()
    address = ""
    for i in range(0,len(hex),2):
        address = ' '.join([address,hex[i:i+2]])
    return address

def determine_ethernet_name(ethernet_type,packet):              #treba zo suboru  
    if ethernet_type >= 1536:
        return "Ethernet II"
    else:
        byte1,byte2,byte3 = struct.unpack('! c c c',packet[:3])
        if byte1 == b'\xff' and byte2 == b'\xff':
             return "Novell raw IEEE 802.3"
        elif byte1 == b'\xaa' and byte2 == b'\xaa':
             return "IEEE 802.3 LLC + SNAP"
        else:
            return "IEEE 802.3 LLC"

def unpack_ethernet_header(packet):             
    dest_mac_bytes , src_mac_bytes ,ethernet_type = struct.unpack('! 6s 6s H',packet[:14])
    return transform_to_mac_address(dest_mac_bytes), transform_to_mac_address(src_mac_bytes),ethernet_type,packet[14:]

def transform_to_ip_address(bytes):                   
   address = ""
   for i in range(0,4):
       address = ".".join([address,str(bytes[i])])
   return address[1:]

def determine_transport_protocol(protocol):           #treba zo suboru
    if protocol == 1:
        return "ICMP"
    elif protocol == 6:
        return "TCP"
    elif protocol == 17:
        return "UDP"
    else:
        return "other transport protocol"

def get_header_length(version_and_header_length):
    length = int.from_bytes(version_and_header_length, "little")  
    length = (length & 15) * 4
    return length

def unpack_ipv4_header(packet):
    version_and_header_length,protocol,source_ip,dest_ip = struct.unpack('! c 8x B 2x 4s 4s',packet[:20])
    header_length = get_header_length(version_and_header_length)
    return determine_transport_protocol(protocol),transform_to_ip_address(source_ip),transform_to_ip_address(dest_ip), packet[:header_length]
  

def determine_internet_protocol(protocol):                  #treba zo suboru
    if protocol == 2048:
        return "IPv4"
    elif protocol == 2054:
        return "ARP"
    elif protocol == 34525:
        return "IPv6"
    else:
        return "other internet protocol"

def main():
    #filename = input("Enter trace name: ")
    filename = "trace-20"
    trace = rdpcap("/Users/drnck/Desktop/workspace/zadanie2PKS/vzorky/" + filename + ".pcap")
    for i in range(len(trace)):
        packet = raw(trace[i])
        packet_length = len(packet)
        dest_mac , src_mac ,ethernet_type ,packet = unpack_ethernet_header(packet)
        ethernet_name = determine_ethernet_name(ethernet_type,packet)
        
        print("rámec "+str(i+1))
        print("dĺžka rámca poskytnutá pcap API – "+str(packet_length)+" B")
        print("dĺžka rámca prenášaného po médiu – "+str(packet_length)+" B")            # toto neviem ako
        print(ethernet_name)
        print("Zdrojová MAC adresa: "+src_mac)
        print("Cieľová MAC adresa: "+dest_mac)
        #print(aky protokol je? ipv4, ipv6, arp ... )
        if ethernet_name == "Ethernet II":
            internet_protocol = determine_internet_protocol(ethernet_type)
            print(internet_protocol)
     #   elif ethernet_type == "Novell raw IEEE 802.3":
            
      #  elif ethernet_type == "IEEE 802.2 SNAP":

      #  elif ethernet_type == "IEEE 802.2 LLC":

        if internet_protocol == "IPv4":
            transport_protocol,source_ip,dest_ip,packet = unpack_ipv4_header(packet)
            print("zdrojová IP adresa: "+ source_ip)
            print("cieľová IP adresa: " + dest_ip)
            print(transport_protocol)
        
        print("______________________________________________")
   # print(first_packet)
     # print(protocol)

main()
#for i in range(len(vzorka)):
  #  print("packet cislo " + str(i))
  #  print(raw(vzorka[i]))