from scapy.all import *
import struct
import ethernet_layer
import internet_layer
import transport_layer

def print_general_data(packet,packet_number,ethernet_name,source_mac,dest_mac,internet_protocol, source_ip = None, dest_ip = None , transport_protocol = None, source_port = None, dest_port = None, application_protocol = None):
        packet_length = len(packet)    
        hex_output = make_hex_output(packet)
        print("Rámec "+str(packet_number))
        print("Dĺžka rámca poskytnutá pcap API – "+str(packet_length)+" B")
        print("Dĺžka rámca prenášaného po médiu – "+str(max(packet_length +4,64))+" B")             
        print(ethernet_name)
        print("Zdrojová MAC adresa: "+source_mac)
        print("Cieľová MAC adresa: "+dest_mac)
        print(internet_protocol)
        if source_ip != None:
            print("Zdrojová IP adresa: "+ source_ip)
            print("Cieľová IP adresa: " + dest_ip)
            if transport_protocol != None:
                print(transport_protocol)
                if transport_protocol == "TCP" or transport_protocol == "UDP":
                    print("Zdrojový port: "+str(source_port))
                    print("Cieľový port: " +str(dest_port))
                    print(application_protocol)
        print(hex_output)

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

def check_if_protocol_name_is_valid(protocol_name):
    if protocol_name == "HTTP":
        return 1
    elif protocol_name == "HTTPS":
        return 1
    elif protocol_name == "SSH":
        return 1
    elif protocol_name == "TELNET":
        return 1
    elif protocol_name == "FTP-DATA":
        return 1
    elif protocol_name == "FTP-CONTROL":
        return 1
    elif protocol_name == "TFTP":
        return 1
    elif protocol_name == "ICMP":
        return 1
    elif protocol_name == "ARP":
        return 1
    else:
        return 0

def print_all_packets(trace):
    ipv4_address_list = {}
    for i in range(len(trace)):
        packet = raw(trace[i])
        dest_mac , source_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(packet)

        if internet_protocol == "IPv4":
            transport_protocol,source_ip,dest_ip,remaining_bytes = internet_layer.unpack_ipv4_header(remaining_bytes)

            if source_ip in ipv4_address_list.keys():
                ipv4_address_list[source_ip] += 1
            else:
                ipv4_address_list.update({source_ip : 1})

            if transport_protocol == "TCP":
                source_port,dest_port,flag_u,flag_a,flag_p,flag_r,flag_s,flag_f,remaining_bytes = transport_layer.unpack_tcp_header(remaining_bytes)
                application_protocol = transport_layer.determine_application_protocol_for_tcp(source_port,dest_port)
                print_general_data(packet,i+1,ethernet_name,source_mac,dest_mac,internet_protocol, source_ip , dest_ip , transport_protocol , source_port , dest_port , application_protocol)
            elif transport_protocol == "UDP":
                source_port,dest_port,remaining_bytes = transport_layer.unpack_udp_header(remaining_bytes)
                application_protocol = transport_layer.determine_application_protocol_for_udp(source_port,dest_port)
                print_general_data(packet,i+1,ethernet_name,source_mac,dest_mac,internet_protocol, source_ip , dest_ip , transport_protocol , source_port , dest_port , application_protocol)
            else:
                print_general_data(packet,i+1,ethernet_name,source_mac,dest_mac,internet_protocol, source_ip , dest_ip , transport_protocol)
        else:
            print_general_data(packet,i+1,ethernet_name,source_mac,dest_mac,internet_protocol)
        print("______________________________________________")

    print_ips_and_max(ipv4_address_list)

#________________________________________________________________________________________________________________________________________________________________
#________________________________________________________________________________________________________________________________________________________________
#________________________________________________________________________________________________________________________________________________________________
def shorten_communication(communication):
    if (len(communication)) >= 20:
        communication = communication[:10] + communication[-10:]
    return communication

def test_communication(complete_exists,incomplete_exists,whole_communication):
    is_complete = 0
    for i in whole_communication:
        packet = i[0]
        dest_mac , src_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(packet)
        transport_protocol,source_ip,dest_ip,remaining_bytes = internet_layer.unpack_ipv4_header(remaining_bytes)
        source_port,dest_port,flag_u,flag_a,flag_p,flag_r,flag_s,flag_f,remaining_bytes = transport_layer.unpack_tcp_header(remaining_bytes)
        application_protocol = transport_layer.determine_application_protocol_for_tcp(source_port,dest_port)

        if flag_f == 1 or flag_r == 1:
            is_complete +=1

    if is_complete == 0:
        return complete_exists,1
    elif is_complete > 0:
        return 1,incomplete_exists

def print_communication(is_complete,whole_communication):
    for i in whole_communication:
        packet = i[0]
        dest_mac , source_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(packet)
        transport_protocol,source_ip,dest_ip,remaining_bytes = internet_layer.unpack_ipv4_header(remaining_bytes)
        source_port,dest_port,flag_u,flag_a,flag_p,flag_r,flag_s,flag_f,remaining_bytes = transport_layer.unpack_tcp_header(remaining_bytes)
        application_protocol = transport_layer.determine_application_protocol_for_tcp(source_port,dest_port)

        print_general_data(packet,i[1],ethernet_name,source_mac,dest_mac,internet_protocol, source_ip , dest_ip , transport_protocol , source_port , dest_port , application_protocol)
        print("______________________________________________")

    if is_complete == 0 :
        print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^  - Tato komunikacia bola neukoncena \n")
    else:
        print("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ - Tato komunikacia bola ukoncena \n")

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
        packet = i[0]
        dest_mac , src_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(packet)
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
                complete_exists,incomplete_exists = test_communication(complete_exists,incomplete_exists,whole_communication)
                print_communication(complete_exists,whole_communication)
                current_source_mac = src_mac
                current_dest_mac = dest_mac
                whole_communication.clear
                whole_communication.append(i)
                recent_packet_number = i[1]
            else:     #ak bola prva kompletna, vypiseme iba dalsiu nekompletnu , a naopak
                whole_communication = shorten_communication(whole_communication)
                complete_exists,incomplete_exists = test_communication(complete_exists,incomplete_exists,whole_communication)
                if complete_exists == 1 and incomplete_exists == 1:
                    print_communication(complete_exists,whole_communication)
                    break
    
    if first_communiation_ended == 0:    #toto nastane ak bol cely subor iba jedna komunikacia, alebo ziadna
        if len(whole_communication ) > 0:
             whole_communication = shorten_communication(whole_communication)
             complete_exists,incomplete_exists = test_communication(complete_exists,incomplete_exists,whole_communication)
             print_communication(complete_exists,whole_communication)

    if complete_exists == 0 :
        print("\nUkoncena komunikacia neexistuje")
    if incomplete_exists == 0 :
        print("\nNeukoncena komunikacia neexistuje")

#________________________________________________________________________________________________________________________________________________________________

def print_matching_arps(requests,replies):
    matches_num = 0
    while (len(requests) > 0) and (len(replies) > 0):
        for i in requests:
            packet1 = i[0]
            dest_mac , source_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(packet1)
            type,request_source_mac,request_source_ip,request_dest_mac,request_dest_ip,remaining_bytes = internet_layer.unpack_arp_header(remaining_bytes)
            for j in replies:
                packet2 = j[0]
                dest_mac , source_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(packet2)
                type,reply_source_mac,reply_source_ip,reply_dest_mac,reply_dest_ip,remaining_bytes = internet_layer.unpack_arp_header(remaining_bytes)

                if (request_source_mac == reply_dest_mac and request_source_ip == reply_dest_ip and request_dest_ip == reply_source_ip):
                    matches_num += 1;
                    print("Komunikácia "+str(matches_num))
                    print("ARP-REQUEST")
                    print_general_data(packet1,i[1],ethernet_name,request_source_mac,request_dest_mac,internet_protocol, request_source_ip , request_dest_ip)
                    print("")
                    print("ARP-REPLY")
                    print_general_data(packet2,i[1],ethernet_name,reply_source_mac,reply_dest_mac,internet_protocol, reply_source_ip , reply_dest_ip)
                    print("__________________________________________________")

                    requests.remove(i)
                    replies.remove(j)
                    break
    
    if len(requests) > 0 :
            print("\nREQUESTS WIHOUT REPLY:\n")
            for i in requests:
                packet = i[0]
                dest_mac , source_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(packet)
                type,request_source_mac,request_source_ip,request_dest_mac,request_dest_ip,remaining_bytes = internet_layer.unpack_arp_header(remaining_bytes)
                print("ARP-REQUEST")
                print_general_data(packet,i[1],ethernet_name,request_source_mac,request_dest_mac,internet_protocol, request_source_ip , request_dest_ip)
                print("__________________________________________________")

    if len(replies) > 0 :
            print("\nREPLIES WITHOUT REQUEST:\n")
            for i in replies:
                packet = i[0]
                dest_mac , source_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(packet)
                type,reply_source_mac,reply_source_ip,reply_dest_mac,reply_dest_ip,remaining_bytes = internet_layer.unpack_arp_header(remaining_bytes)
                print("ARP-REPLY")
                print_general_data(packet1,i[1],ethernet_name,request_source_mac,request_dest_mac,internet_protocol, request_source_ip , request_dest_ip)
                print("__________________________________________________")

#________________________________________________________________________________________________________________________________________________________________

def print_all_tftp(all_valid_packets):                 
    current_source_ip = ""
    current_dest_ip = ""
    for i in all_valid_packets:
        packet = i[0]
        dest_mac , source_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(packet)
        transport_protocol,source_ip,dest_ip,remaining_bytes = internet_layer.unpack_ipv4_header(remaining_bytes)
        source_port,dest_port,remaining_bytes = transport_layer.unpack_udp_header(remaining_bytes)
        application_protocol = transport_layer.determine_application_protocol_for_udp(source_port,dest_port)

        if application_protocol == "unknown application protocol":
            application_protocol = "TFTP-pokracovanie"

        if current_source_ip == "" and current_dest_ip == "":
            current_source_ip = source_ip
            current_dest_ip = dest_ip
            print("JEDNA KOMUNIKACIA\n")
        elif ((source_ip == current_source_ip and dest_ip == current_dest_ip ) or (dest_ip == current_source_ip and source_ip == current_dest_ip )) == False:
            print("KONIEC KOMUNIKACIE\n")
            print("DALSIA KOMUNIKACIA\n")
            current_source_ip = source_ip
            current_dest_ip = dest_ip

        print_general_data(packet,i[1],ethernet_name,source_mac,dest_mac,internet_protocol, source_ip , dest_ip , transport_protocol , source_port , dest_port , application_protocol)
        print("______________________________________________")
#________________________________________________________________________________________________________________________________________________________________

def print_all_icmp(all_valid_packets):     
    current_source_ip = ""
    current_dest_ip = ""
    for i in all_valid_packets:
        packet = i[0]
        dest_mac , source_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(packet)
        transport_protocol,source_ip,dest_ip,remaining_bytes = internet_layer.unpack_ipv4_header(remaining_bytes)
        icmp_message,remaining_bytes = transport_layer.unpack_icmp_header(remaining_bytes)

        if current_source_ip == "" and current_dest_ip == "":
            current_source_ip = source_ip
            current_dest_ip = dest_ip
            print("JEDNA KOMUNIKACIA\n")
        elif ((source_ip == current_source_ip and dest_ip == current_dest_ip ) or (dest_ip == current_source_ip and source_ip == current_dest_ip )) == False:
            print("KONIEC KOMUNIKACIE\n")
            print("DALSIA KOMUNIKACIA\n")
            current_source_ip = source_ip
            current_dest_ip = dest_ip

        print_general_data(packet,i[1],ethernet_name,source_mac,dest_mac,internet_protocol, source_ip , dest_ip , transport_protocol)
        print("správa: " + icmp_message)
        print("______________________________________________")
#________________________________________________________________________________________________________________________________________________________________


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
        dest_mac , source_mac,ethernet_name,internet_protocol,remaining_bytes = ethernet_layer.fully_analyze_ethernet(packet)
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
                        if application_protocol == "unknown application protocol":  #TFTP  pokracovanie
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
    while True:
        try:
            filename = input("Zadajte nazov .pcap suboru ulozeneho v /traces : ")
            trace = rdpcap("/Users/drnck/Desktop/workspace/zadanie2PKS/traces/" + filename.lower() + ".pcap")
            print("Ak chcete vypisat vsetky ramce, zadajte 1")
            print("Ak chcete vypisat iba ramce pre specificky protokol, zadajte 2")
            option = input("Vyberte moznost : ")
            if (option == "1"):
                print("______________________________________________")
                print_all_packets(trace)
            elif (option == "2"):
                protocol_name = input("Zadajte nazov protokolu : ")
                if check_if_protocol_name_is_valid(protocol_name)==0:
                    print("Nepovoleny protokol")
                else:
                    print("______________________________________________")
                    filter_packets(trace,protocol_name)
            else:
                print("Zadali ste nezmysel")

            again = input("Chcete pokracovat? A/N:  ")
            if again == "N":
                break
        except:
            print("\nSubor s takymto menom neexistuje. Skontrolujte, ci sa nachadza v  priecinku /traces, a napiste ho bez pripony\n")
main()