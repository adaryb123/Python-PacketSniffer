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

        dest_mac , src_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(remaining_bytes)
        print("rámec "+str(i+1))
        print("dĺžka rámca poskytnutá pcap API – "+str(packet_length)+" B")
        print("dĺžka rámca prenášaného po médiu – "+str(packet_length +4)+" B")            # toto neviem ako
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

        print(hex_output)
        print("______________________________________________")
    print_ips_and_max(ipv4_address_list)

#________________________________________________________________________________________________________________________________________________________________
def shorten_communication(communication):
    if (len(communication)) >= 20:
        communication = communication[:10] + communication[-10:]
    return communication

def test_communication(complete_exists,incomplete_exists,whole_communication):
    is_complete = 0
    for i in whole_communication:
        remaining_bytes = i[0]
        dest_mac , src_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(remaining_bytes)
        transport_protocol,source_ip,dest_ip,remaining_bytes = internet_layer.unpack_ipv4_header(remaining_bytes)
        source_port,dest_port,flag_u,flag_a,flag_p,flag_r,flag_s,flag_f,remaining_bytes = transport_layer.unpack_tcp_header(remaining_bytes)
        application_protocol = transport_layer.determine_application_protocol_for_tcp(source_port,dest_port)

        if flag_f == 1 or flag_r == 1:
            is_complete +=1

    if is_complete < 2:
        return complete_exists,1
    elif is_complete >= 2:
        return 1,incomplete_exists

def print_communication(complete_exists,incomplete_exists,whole_communication):
    is_complete = 0
    for i in whole_communication:
        packet = i[0]
        hex_output = make_hex_output(packet)
        packet_length = len(packet)
        remaining_bytes = i[0]
        dest_mac , src_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(remaining_bytes)
        transport_protocol,source_ip,dest_ip,remaining_bytes = internet_layer.unpack_ipv4_header(remaining_bytes)
        source_port,dest_port,flag_u,flag_a,flag_p,flag_r,flag_s,flag_f,remaining_bytes = transport_layer.unpack_tcp_header(remaining_bytes)
        application_protocol = transport_layer.determine_application_protocol_for_tcp(source_port,dest_port)

        if flag_f == 1 or flag_r == 1:
            is_complete +=1

        print("rámec "+str(i[1]))
        print("dĺžka rámca poskytnutá pcap API – "+str(packet_length)+" B")
        print("dĺžka rámca prenášaného po médiu – "+str(packet_length+4)+" B")            # toto neviem ako
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
        print(hex_output)
        print("______________________________________________")


    if is_complete <2 :
        print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  - Tato komunikacia bola neukoncena \n")
        return complete_exists,1
    else:
        print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ - Tato komunikacia bola ukoncena \n")
        return 1,incomplete_exists

def print_first_complete_and_incomplete(all_valid_packets):
    complete_exists = 0
    incomplete_exists = 0

    first_communiation_ended = 0
    current_source_mac = ""
    current_dest_mac = ""
    first_packet_number = 0
    recent_packet_number = 0
    whole_communication = []
    for i in all_valid_packets:
        remaining_bytes = i[0]
        dest_mac , src_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(remaining_bytes)
        transport_protocol,source_ip,dest_ip,remaining_bytes = internet_layer.unpack_ipv4_header(remaining_bytes)
        source_port,dest_port,flag_u,flag_a,flag_p,flag_r,flag_s,flag_f,remaining_bytes = transport_layer.unpack_tcp_header(remaining_bytes)
        application_protocol = transport_layer.determine_application_protocol_for_tcp(source_port,dest_port)

        if current_source_mac == "":
            current_source_mac = src_mac
            current_dest_mac = dest_mac
            first_packet_number = i[1]      

        if ((src_mac == current_source_mac and dest_mac == current_dest_mac) or (src_mac == current_dest_mac and dest_mac == current_source_mac)) and ((i[1] == first_packet_number) or (i[1] == recent_packet_number + 1)):
            whole_communication.append(i)
            recent_packet_number = i[1]
        else:       #ak nastane else znamena to ze jedna komunikacia skoncila a nasleduje ina
            first_communiation_ended = 1
            if complete_exists == 0 and incomplete_exists == 0:     #ak skoncila prva, vypiseme ju
                whole_communication = shorten_communication(whole_communication)
                complete_exists,incomplete_exists = print_communication(complete_exists,incomplete_exists,whole_communication)

                current_source_mac = src_mac
                current_dest_mac = dest_mac
                whole_communication.clear
                whole_communication.append(i)
                recent_packet_number = i[1]
            else:     #ak bola prva kompletna, vypiseme iba dalsiu nekompletnu , a naopak
                whole_communication = shorten_communication(whole_communication)
                complete_exists,incomplete_exists = test_communication(complete_exists,incomplete_exists,whole_communication)
                if complete_exists == 1 and incomplete_exists == 1:
                    complete_exists,incomplete_exists = print_communication(complete_exists,incomplete_exists,whole_communication)
                    break
    
    if first_communiation_ended == 0:    #toto nastane ak bol cely subor iba jedna komunikacia, alebo ziadna
        if len(whole_communication ) > 0:
             whole_communication = shorten_communication(whole_communication)
             complete_exists,incomplete_exists = print_communication(complete_exists,incomplete_exists,whole_communication)

    if complete_exists == 0 :
        print("\nUkoncena komunikacia neexistuje")
    if incomplete_exists == 0 :
        print("\nNeukoncena komunikacia neexistuje")

def print_matching_arps(requests,replies):
    matches_num = 0
    while (len(requests) > 0) and (len(replies) > 0):
        for i in requests:
            packet = i[0]
            hex_output1 = make_hex_output(packet)
            packet_length1 = len(packet)
            dest_mac , src_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(packet)
            type,request_source_mac,request_source_ip,request_dest_mac,request_dest_ip,remaining_bytes = internet_layer.unpack_arp_header(remaining_bytes)
            for j in replies:
                packet = j[0]
                hex_output2 = make_hex_output(packet)
                packet_length2 = len(packet)
                dest_mac , src_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(packet)
                type,reply_source_mac,reply_source_ip,reply_dest_mac,reply_dest_ip,remaining_bytes = internet_layer.unpack_arp_header(remaining_bytes)

                if (request_source_mac == reply_dest_mac and request_source_ip == reply_dest_ip and request_dest_ip == reply_source_ip):
                    matches_num += 1;
                    print("Komunikácia "+str(matches_num))
                    print("ARP-REQUEST")
                    print("rámec "+str(i[1]))
                    print("dĺžka rámca poskytnutá pcap API – "+str(packet_length1)+" B")
                    print("dĺžka rámca prenášaného po médiu – "+str(packet_length1+4)+" B")            # toto neviem ako
                    print(ethernet_name)
                    print(internet_protocol)
                    print("Zdrojová MAC adresa: "+request_source_mac)
                    print("zdrojová IP adresa: "+ request_source_ip)
                    print("cieľová IP adresa: " + request_dest_ip)
                    print("Cieľová MAC adresa: "+ request_dest_mac)
                    print(hex_output1)
                    print("")
                    print("ARP-REPLY")
                    print("rámec "+str(j[1]))
                    print("dĺžka rámca poskytnutá pcap API – "+str(packet_length2)+" B")
                    print("dĺžka rámca prenášaného po médiu – "+str(packet_length2+4)+" B")            # toto neviem ako
                    print(ethernet_name)
                    print(internet_protocol)
                    print("Zdrojová MAC adresa: "+reply_source_mac)
                    print("zdrojová IP adresa: "+ reply_source_ip)
                    print("cieľová IP adresa: " + reply_dest_ip)
                    print("Cieľová MAC adresa: "+ reply_dest_mac)
                    print(hex_output2)
                    print("__________________________________________________")

                    requests.remove(i)
                    replies.remove(j)
                    break
    
    if len(requests) > 0 :
            print("\n\nREQUESTS WIHOUT REPLY:")
            for i in requests:
                packet = i[0]
                hex_output = make_hex_output(packet)
                packet_length = len(packet)
                dest_mac , src_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(packet)
                type,request_source_mac,request_source_ip,request_dest_mac,request_dest_ip,remaining_bytes = internet_layer.unpack_arp_header(remaining_bytes)
                print("ARP-REQUEST")
                print("rámec "+str(i[1]))
                print("dĺžka rámca poskytnutá pcap API – "+str(packet_length)+" B")
                print("dĺžka rámca prenášaného po médiu – "+str(packet_length+4)+" B")            # toto neviem ako
                print(ethernet_name)
                print(internet_protocol)
                print("Zdrojová MAC adresa: "+request_source_mac)
                print("zdrojová IP adresa: "+ request_source_ip)
                print("cieľová IP adresa: " + request_dest_ip)
                print("Cieľová MAC adresa: "+ request_dest_mac)
                print(hex_output)
                print("__________________________________________________")

    if len(replies) > 0 :
            print("\n\nREPLIES WITHOUT REQUEST:")
            for i in replies:
                packet = i[0]
                hex_output = make_hex_output(packet)
                packet_length = len(packet)
                dest_mac , src_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(packet)
                type,reply_source_mac,reply_source_ip,reply_dest_mac,reply_dest_ip,remaining_bytes = internet_layer.unpack_arp_header(remaining_bytes)
                print("ARP-REPLY")
                print("rámec "+str(i[1]))
                print("dĺžka rámca poskytnutá pcap API – "+str(packet_length)+" B")
                print("dĺžka rámca prenášaného po médiu – "+str(packet_length+4)+" B")            # toto neviem ako
                print(ethernet_name)
                print(internet_protocol)
                print("Zdrojová MAC adresa: "+reply_source_mac)
                print("zdrojová IP adresa: "+ reply_source_ip)
                print("cieľová IP adresa: " + reply_dest_ip)
                print("Cieľová MAC adresa: "+ reply_dest_mac)
                print(hex_output)
                print("__________________________________________________")

def print_all_tftp(all_valid_packets):
    for i in all_valid_packets:
        packet = i[0]
        hex_output = make_hex_output(packet)
        packet_length = len(packet)
        remaining_bytes = i[0]
        dest_mac , src_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(remaining_bytes)
        transport_protocol,source_ip,dest_ip,remaining_bytes = internet_layer.unpack_ipv4_header(remaining_bytes)
        source_port,dest_port,remaining_bytes = transport_layer.unpack_udp_header(remaining_bytes)
        application_protocol = transport_layer.determine_application_protocol_for_udp(source_port,dest_port)
        if application_protocol == "other application protocol":
            application_protocol = "TFTP-pokracovanie"
        print("rámec "+str(i[1]))
        print("dĺžka rámca poskytnutá pcap API – "+str(packet_length)+" B")
        print("dĺžka rámca prenášaného po médiu – "+str(packet_length+4)+" B")            # toto neviem ako
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
        print(hex_output)
        print("______________________________________________")

def print_all_icmp(all_valid_packets):
    for i in all_valid_packets:
        packet = i[0]
        hex_output = make_hex_output(packet)
        packet_length = len(packet)
        remaining_bytes = i[0]

        dest_mac , src_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(remaining_bytes)
        transport_protocol,source_ip,dest_ip,remaining_bytes = internet_layer.unpack_ipv4_header(remaining_bytes)
        icmp_message,remaining_bytes = transport_layer.unpack_icmp_header(remaining_bytes)

        print("rámec "+str(i+1))
        print("dĺžka rámca poskytnutá pcap API – "+str(packet_length)+" B")
        print("dĺžka rámca prenášaného po médiu – "+str(packet_length+4)+" B")            # toto neviem ako
        print(ethernet_name)
        print("Zdrojová MAC adresa: "+src_mac)
        print("Cieľová MAC adresa: "+dest_mac)
        print(internet_protocol)
        print("zdrojová IP adresa: "+ source_ip)
        print("cieľová IP adresa: " + dest_ip)
        print(transport_protocol)
        print("správa: " + icmp_message)
        print(hex_output)
        print("______________________________________________")


def filter_packets(trace,requested_protocol):
     matches_number = 0
     all_valid_packets = []
     arp_requests = []
     arp_replies = []
     tftp_source_port = 0
     tftp_dest_port = 0
     tftp = 0
     for i in range(len(trace)):
        packet = raw(trace[i])
        remaining_bytes = packet

        dest_mac , src_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(remaining_bytes)
        if requested_protocol == internet_protocol: #ARP
                matches_number +=1
                type,source_mac,source_ip,dest_mac,dest_ip,remaining_bytes = internet_layer.unpack_arp_header(remaining_bytes)
                if type=="REQUEST":
                    arp_requests.append([packet,i+1])
                elif type == "REPLY":
                    arp_replies.append([packet,i+1])
        else:
              transport_protocol,source_ip,dest_ip,remaining_bytes = internet_layer.unpack_ipv4_header(remaining_bytes)
              if requested_protocol == transport_protocol: #ICMP
                    matches_number +=1
                    all_valid_packets.append([packet,i+1])
              else:
                    application_protocol = ""
                    if transport_protocol == "UDP":
                        source_port,dest_port,remaining_bytes = transport_layer.unpack_udp_header(remaining_bytes)
                        application_protocol = transport_layer.determine_application_protocol_for_udp(source_port,dest_port)
                        if application_protocol == "other application protocol":  #TFTP  pokracovanie
                            if (tftp == 1) and (source_port == tftp_source_port or source_port == tftp_dest_port or dest_port == tftp_source_port or dest_port == tftp_dest_port):
                                all_valid_packets.append([packet,i+1])
                                continue
                    elif transport_protocol == "TCP":
                        source_port,dest_port,flag_u,flag_a,flag_p,flag_r,flag_s,flag_f,remaining_bytes = transport_layer.unpack_tcp_header(remaining_bytes)
                        application_protocol = transport_layer.determine_application_protocol_for_tcp(source_port,dest_port)
                    
                    if application_protocol == requested_protocol:       
                        matches_number +=1
                        if requested_protocol == "TFTP":                    
                           tftp_source_port = source_port
                           tftp_dest_port = dest_port
                           tftp = 1
                           all_valid_packets.append([packet,i+1])
                        else:    
                            tftp = 0
                            all_valid_packets.append([packet,i+1])
                            continue
    
     if requested_protocol == "ARP":
         print_matching_arps(arp_requests,arp_replies)
     elif requested_protocol == "ICMP":
         print_all_icmp(all_valid_packets)
     elif requested_protocol == "TFTP":
         print_all_tftp(all_valid_packets)
     else:
        print_first_complete_and_incomplete(all_valid_packets)

     if matches_number == 0:
         print("Nenasli sa ziadne ramce obsahujuce protokol "+requested_protocol)


def main():
    filename = input("Zadajte nazov .pcap suboru ulozeneho v /traces : ")
    while True:
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

        again = input("Chcete pokracovat? A/N:  ")
        if again == "A":
            filename = input("Zadajte nazov .pcap suboru ulozeneho v /traces : ")
        else:
            break
main()

