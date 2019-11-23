from scapy.all import *
import struct
import ethernet_layer
import internet_layer
import transport_layer

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

def print_ips_and_max(ip_list):
    max = 0
    max_ip = ""
    print("Zoznam IP adries vysielajucich uzlov: ")
    for i in ip_list.keys():
        print(i)
        if ip_list[i] > max:
            max = ip_list[i]
            max_ip = i

    print("Najviac packetov odislo z adresy " + max_ip + " a bolo ich "+ str(max))


def print_all_packets(trace):
    ipv4_address_list = {}
    for i in range(len(trace)):
        packet = raw(trace[i])
        hex_output = make_hex_output(packet)
        packet_length = len(packet)
        remaining_bytes = packet

        dest_mac , src_mac ,ethernet_type_or_length ,remaining_bytes = ethernet_layer.unpack_ethernet_header(remaining_bytes)
        ethernet_name = ethernet_layer.determine_ethernet_name(ethernet_type_or_length)
        
        print("rámec "+str(i+1))
     #   print("dĺžka rámca poskytnutá pcap API – "+str(packet_length)+" B")
     #   print("dĺžka rámca prenášaného po médiu – "+str(packet_length)+" B")            # toto neviem ako
        if ethernet_name == "Ethernet II":
            internet_protocol = ethernet_layer.determine_internet_protocol_by_ethertype(ethernet_type_or_length)
        else:
            internet_protocol,lsap,remaining_bytes = ethernet_layer.determine_internet_protocol_by_lsap(remaining_bytes)    
            ethernet_name = ethernet_layer.name_ieee_by_lsap(ethernet_name,lsap)
            if ethernet_name == "IEEE 802.3 SNAP":
                ethernet_type = struct.unpack('! 3x H',remaining_bytes[:5])              #toto treba otestovat
                remaining_bytes = remaining_bytes[5:]
                internet_protocol = ethernet_layer.determine_internet_protocol_by_ethertype(ethernet_type)

        print(ethernet_name)
        print("Zdrojová MAC adresa: "+src_mac)
        print("Cieľová MAC adresa: "+dest_mac)
        print(internet_protocol)

        if internet_protocol == "IPv4":
            transport_protocol,source_ip,dest_ip,remaining_bytes = internet_layer.unpack_ipv4_header(remaining_bytes)
            print("zdrojová IP adresa: "+ source_ip)
            print("cieľová IP adresa: " + dest_ip)
            print(transport_protocol)

            if source_ip in ipv4_address_list.keys():
                ipv4_address_list[source_ip] += 1
            else:
                ipv4_address_list.update({source_ip : 1})

            if transport_protocol == "TCP":
                source_port,dest_port,flag_u,flag_a,flag_p,flag_r,flag_s,flag_f,remaining_bytes = transport_layer.unpack_tcp_header(remaining_bytes)
                application_protocol = transport_layer.determine_application_protocol_for_tcp(source_port,dest_port)
                print("zdrojový port: "+str(source_port))
                print("cieľový port: " +str(dest_port))
                print(application_protocol)
            elif transport_protocol == "UDP":
                source_port,dest_port,remaining_bytes = transport_layer.unpack_udp_header(remaining_bytes)
                application_protocol = transport_layer.determine_application_protocol_for_udp(source_port,dest_port)
                print("zdrojový port: "+str(source_port))
                print("cieľový port: " +str(dest_port))
                print(application_protocol)
        #    elif transport_protocol == "ICMP":
       #         icmp_message,remaining_bytes = transport_layer.unpack_icmp_header(remaining_bytes)
         #       print(icmp_message)

       # elif internet_protocol == "ARP":
        #    type,source_mac,source_ip,dest_mac,dest_ip,remaining_bytes = internet_layer.unpack_arp_header(remaining_bytes)
           # print(type)
         #   print("zdrojová IP adresa: "+ source_ip)
          #  print("cieľová IP adresa: " + dest_ip)
         #   print("Zdrojová MAC adresa: "+src_mac)
          #  print("Cieľová MAC adresa: "+dest_mac)

       # print(hex_output)
        print("______________________________________________")
    print_ips_and_max(ipv4_address_list)

#________________________________________________________________________________________________________________________________________________________________
def shorten_communication(communication):
    if (len(communication)) >= 20:
        print("Komunikacia sa vypise skratena")
        communication = communication[:10] + communication[-10:]
    return communication

def print_communication(communication):
    is_complete = 0
    for i in communication:
        remaining_bytes = i[0]
        dest_mac , src_mac ,ethernet_type_or_length ,remaining_bytes = ethernet_layer.unpack_ethernet_header(remaining_bytes)
        ethernet_name = ethernet_layer.determine_ethernet_name(ethernet_type_or_length)
        if ethernet_name == "Ethernet II":
            internet_protocol = ethernet_layer.determine_internet_protocol_by_ethertype(ethernet_type_or_length)
        else:
            internet_protocol,lsap,remaining_bytes = ethernet_layer.determine_internet_protocol_by_lsap(remaining_bytes)    
            ethernet_name = ethernet_layer.name_ieee_by_lsap(ethernet_name,lsap)
            if ethernet_name == "IEEE 802.3 SNAP":
                ethernet_type = struct.unpack('! 3x H',remaining_bytes[:5])              #toto treba otestovat
                remaining_bytes = remaining_bytes[5:]
                internet_protocol = ethernet_layer.determine_internet_protocol_by_ethertype(ethernet_type)
        
        transport_protocol,source_ip,dest_ip,remaining_bytes = internet_layer.unpack_ipv4_header(remaining_bytes)
        source_port,dest_port,flag_u,flag_a,flag_p,flag_r,flag_s,flag_f,remaining_bytes = transport_layer.unpack_tcp_header(remaining_bytes)
        application_protocol = transport_layer.determine_application_protocol_for_tcp(source_port,dest_port)

        if flag_f == 1 or flag_r == 1:
            is_complete +=1

        print("rámec "+str(i[1]))
        #print("dĺžka rámca poskytnutá pcap API – "+str(packet_length)+" B")
        # print("dĺžka rámca prenášaného po médiu – "+str(packet_length)+" B")            # toto neviem ako
        print(ethernet_name)
        print("Zdrojová MAC adresa: "+src_mac)
        print("Cieľová MAC adresa: "+dest_mac)
        print(internet_protocol)
        print("zdrojová IP adresa: "+ source_ip)
        print("cieľová IP adresa: " + dest_ip)
        print(transport_protocol)
        print("zdrojový port: "+str(source_port))
        print("cieľový port: " +str(dest_port))
        print(application_protocol)
        # print(hex_output)
        print("______________________________________________")


    if is_complete <2 :
        print("Tato komunikacia bola nekompletna \n")
        return 0,1
    else:
        print("Tato komunikacia bola kompletna \n")
        return 1,0

def print_first_complete_and_incomplete(all_valid_packets):
    complete_exists = 0
    incomplete_exists = 0

    first_source_mac = ""
    first_dest_mac = ""
    first_packet_number = 0
    recent_packet_number = 0
    first_communication = []
    for i in all_valid_packets:
        remaining_bytes = i[0]
        dest_mac , src_mac ,ethernet_type_or_length ,remaining_bytes = ethernet_layer.unpack_ethernet_header(remaining_bytes)
        ethernet_name = ethernet_layer.determine_ethernet_name(ethernet_type_or_length)
        if ethernet_name == "Ethernet II":
            internet_protocol = ethernet_layer.determine_internet_protocol_by_ethertype(ethernet_type_or_length)
        else:
            internet_protocol,lsap,remaining_bytes = ethernet_layer.determine_internet_protocol_by_lsap(remaining_bytes)    
            ethernet_name = ethernet_layer.name_ieee_by_lsap(ethernet_name,lsap)
            if ethernet_name == "IEEE 802.3 SNAP":
                ethernet_type = struct.unpack('! 3x H',remaining_bytes[:5])              #toto treba otestovat
                remaining_bytes = remaining_bytes[5:]
                internet_protocol = ethernet_layer.determine_internet_protocol_by_ethertype(ethernet_type)
        
        transport_protocol,source_ip,dest_ip,remaining_bytes = internet_layer.unpack_ipv4_header(remaining_bytes)
        source_port,dest_port,flag_u,flag_a,flag_p,flag_r,flag_s,flag_f,remaining_bytes = transport_layer.unpack_tcp_header(remaining_bytes)
        application_protocol = transport_layer.determine_application_protocol_for_tcp(source_port,dest_port)

        if first_source_mac == "":
            first_source_mac = src_mac
            first_dest_mac = dest_mac
            first_packet_number = i[1]

        if ((src_mac == first_source_mac and dest_mac == first_dest_mac) or (src_mac == first_dest_mac and dest_mac == first_source_mac)) and ((i[1] == first_packet_number) or (i[1] == recent_packet_number + 1)):
            first_communication.append(i)
            recent_packet_number = i[1]
        else:       #tu niekde treba nadviazat, zistit este druhu komunikaciu
            break
    
    first_communication = shorten_communication(first_communication)
    complete_exists,incomplete_exists = print_communication(first_communication)
    


def filter_packets(trace,requested_protocol):
     all_valid_packets = []
     for i in range(len(trace)):
        packet = raw(trace[i])
        hex_output = make_hex_output(packet)
        packet_length = len(packet)
        remaining_bytes = packet

        dest_mac , src_mac ,ethernet_type_or_length ,remaining_bytes = ethernet_layer.unpack_ethernet_header(remaining_bytes)
        ethernet_name = ethernet_layer.determine_ethernet_name(ethernet_type_or_length)

        if ethernet_name == "Ethernet II":
            internet_protocol = ethernet_layer.determine_internet_protocol_by_ethertype(ethernet_type_or_length)
        else:
            internet_protocol,lsap,remaining_bytes = ethernet_layer.determine_internet_protocol_by_lsap(remaining_bytes)    
            ethernet_name = ethernet_layer.name_ieee_by_lsap(ethernet_name,lsap)
            if ethernet_name == "IEEE 802.3 SNAP":
                ethernet_type = struct.unpack('! 3x H',remaining_bytes[:5])              #toto treba otestovat
                remaining_bytes = remaining_bytes[5:]
                internet_protocol = ethernet_layer.determine_internet_protocol_by_ethertype(ethernet_type)

        if requested_protocol == internet_protocol: #ARP
                all_valid_packets.append(packet)
        else:
              transport_protocol,source_ip,dest_ip,remaining_bytes = internet_layer.unpack_ipv4_header(remaining_bytes)
              if requested_protocol == transport_protocol: #ICMP
                  all_valid_packets.append(packet)
              else:
                    application_protocol = ""
                    if transport_protocol == "UDP":
                        source_port,dest_port,remaining_bytes = transport_layer.unpack_udp_header(remaining_bytes)
                        application_protocol = transport_layer.determine_application_protocol_for_udp(source_port,dest_port)
                    elif transport_protocol == "TCP":
                        source_port,dest_port,flag_u,flag_a,flag_p,flag_r,flag_s,flag_f,remaining_bytes = transport_layer.unpack_tcp_header(remaining_bytes)
                        application_protocol = transport_layer.determine_application_protocol_for_tcp(source_port,dest_port)
                    
                    if application_protocol == requested_protocol:
                        if requested_protocol == "TFTP": #asi mi bude len prvy brat, treba osetrit
                            all_valid_packets.append(packet)
                        else:                                       #treba spravit nech sa posle len 20 a iba prva uzavreta a prva otvorena
                            all_valid_packets.append([packet,i+1])
                            continue

     print_first_complete_and_incomplete(all_valid_packets)

                     #       print("rámec "+str(i+1))
                         #   print("dĺžka rámca poskytnutá pcap API – "+str(packet_length)+" B")
                         #   print("dĺžka rámca prenášaného po médiu – "+str(packet_length)+" B")            # toto neviem ako
                     #       print(ethernet_name)
                      #      print("Zdrojová MAC adresa: "+src_mac)
                     #       print("Cieľová MAC adresa: "+dest_mac)
                     #       print(internet_protocol)
                     #       print("zdrojová IP adresa: "+ source_ip)
                    #        print("cieľová IP adresa: " + dest_ip)
                    #        print(transport_protocol)
                    #        print("zdrojový port: "+str(source_port))
                    #        print("cieľový port: " +str(dest_port))
                    #        print(application_protocol)
                    #        print(flag_u)
                   #         print(flag_a)
                    #        print(flag_p)
                    #        print(flag_r)
                    #        print(flag_s)
                    #        print(flag_f)
                            # print(hex_output)
                    #        print("______________________________________________")

    #     print_first_complete_and_incomplete(all_valid_packets)

def main():
   # filename = input("Zadajte nazov .pcap suboru ulozeneho v /traces : ")
   # filename = "trace-2"   #tato je kratka a dobra
    filename = "trace-20"  
    trace = rdpcap("/Users/drnck/Desktop/workspace/zadanie2PKS/traces/" + filename + ".pcap")
    print("Ak chcete vypisat vsetky ramce, zadajte 1")
    print("Ak chcete vypisat iba ramce pre specificky protokol, zadajte 2")
    option = input("Vyberte moznost : ")
    if (option == "1"):
        print("______________________________________________")
        print_all_packets(trace)
    elif (option == "2"):
        protocol_name = input("Zadajte nazov protokolu : ")
        print("______________________________________________")
        filter_packets(trace,protocol_name)
    else:
        print("Zadali ste nezmysel")
main()

