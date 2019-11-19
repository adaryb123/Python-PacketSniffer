from scapy.all import *
import struct
import ethernet_module
import internet_module

def make_hex_output(bytes):
    output = ""
    for i in range(len(bytes)):
        byte = hex(bytes[i])[2:].upper()
        if len(byte)==1:
            byte = "0" + byte
        output += byte + " "

        if (i+1) % 12 == 0:
            output += " "

        if (i+1) % 24 == 0:
            output += "\n"
    return output

def main():
    #filename = input("Enter trace name: ")
    filename = "trace-20"
    trace = rdpcap("/Users/drnck/Desktop/workspace/zadanie2PKS/vzorky/" + filename + ".pcap")
    for i in range(len(trace)):
        packet = raw(trace[i])
        hex_output = make_hex_output(packet)
        packet_length = len(packet)
        dest_mac , src_mac ,ethernet_type_or_length ,packet = ethernet_module.unpack_ethernet_header(packet)
        ethernet_name = ethernet_module.determine_ethernet_name(ethernet_type_or_length,packet)
        
        print("rámec "+str(i+1))
        print("dĺžka rámca poskytnutá pcap API – "+str(packet_length)+" B")
        print("dĺžka rámca prenášaného po médiu – "+str(packet_length)+" B")            # toto neviem ako
        #print(aky protokol je? ipv4, ipv6, arp ... )
        if ethernet_name == "Ethernet II":
            internet_protocol = ethernet_module.determine_internet_protocol_by_ethertype(ethernet_type_or_length)
        else:
            ethernet_name,lsap,packet = ethernet_module.determine_lsap(packet)    
            if ethernet_name == "IEEE 802.3 SNAP":
                ethernet_type = struct.unpack('! 3x H',packet[:5])              #toto treba otestovat
                packet = packet[5:]
                internet_protocol = ethernet_module.determine_internet_protocol_by_ethertype(ethernet_type)
            else:
                internet_protocol = ethernet_module.determine_internet_protocol_by_lsap(lsap)   #toto treba doplnit

        print(ethernet_name)
        print("Zdrojová MAC adresa: "+src_mac)
        print("Cieľová MAC adresa: "+dest_mac)
        print(internet_protocol)

        if internet_protocol == "IPv4":
            transport_protocol,source_ip,dest_ip,packet = internet_module.unpack_ipv4_header(packet)
            print("zdrojová IP adresa: "+ source_ip)
            print("cieľová IP adresa: " + dest_ip)
            print(transport_protocol)

        print(hex_output)
        print("______________________________________________")

main()
#for i in range(len(vzorka)):
  #  print("packet cislo " + str(i))
  #  print(raw(vzorka[i]))