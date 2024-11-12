import sys
from scapy.all import rdpcap
import ruamel.yaml
from  ruamel.yaml import YAML
from packet import Packet
from connection import Connection
import copy

def extract_hexadecimal_data(protocols):
    pcap_index = sys.argv.index('-f')
    pcap_file = sys.argv[pcap_index+1]
    # pcap_file = 'vzorky_pcap_na_analyzu/trace-12.pcap'
    packets = rdpcap(pcap_file)
    packets_list = []

    for index, packet in enumerate(packets):
        packet = Packet(packet, index, protocols)
        packets_list.append(packet)

    return packets_list, pcap_file


def load_protocols(protocols_file):
    with open(protocols_file, 'r') as file:
        data = ruamel.yaml.safe_load(file)

    return data

def print_packet(packet):
    dict = {
            'frame_number': packet.frame_number,
            'len_frame_pcap': packet.frame_length,
            'len_frame_medium': packet.wire_length,
            'frame_type': packet.frame_type,
            'src_mac': packet.src_mac,
            'dst_mac': packet.dst_mac
        }
    if hasattr(packet, 'ether_type'): dict['ether_type'] = packet.ether_type
    
    if hasattr(packet, 'src_ip'): dict['src_ip'] = packet.src_ip
    
    if hasattr(packet, 'dst_ip'): dict['dst_ip'] = packet.dst_ip
    
    if hasattr(packet, 'protocol'): dict['protocol'] = packet.protocol
    
    if hasattr(packet, 'arp_opcode'): dict['arp_opcode'] = packet.arp_opcode

    if hasattr(packet, 'src_port'): dict['src_port'] = packet.src_port
    
    if hasattr(packet, 'dst_port'): dict['dst_port'] = packet.dst_port
    
    if hasattr(packet, 'app_protocol'): dict['app_protocol'] = packet.app_protocol

    if hasattr(packet, 'sap'): dict['sap'] = packet.sap
    
    if hasattr(packet, 'pid'): dict['pid'] = packet.pid
        
    dict['hexa_frame'] = packet.hexa_frame
    
    return dict

def case_print_packets(packets_list, pcap_file):
    
    print_packets = []
    ipv4_senders = {}
    
    for packet in packets_list:
        dict = print_packet(packet)
        print_packets.append(dict)

        # ip senders count
        if packet.frame_type == 'ETHERNET II' and packet.ether_type == 'IPv4':
            if packet.src_ip in ipv4_senders:
                ipv4_senders[packet.src_ip] += 1
            else:
                ipv4_senders[packet.src_ip] = 1

    print_senders = []
    for sender, sent_packets in ipv4_senders.items():
        tmp_dict = {
            'node': sender,
            'number_of_sent_packets': sent_packets
        }
        print_senders.append(tmp_dict)

    max_value = max(ipv4_senders.values())
    keys_with_max_value = [key for key, value in ipv4_senders.items() if value == max_value]

    output_data = {
        'name': 'PKS2023/24',
        'pcap_name': f'{pcap_file}',
        'packets': print_packets,
        'ipv4_senders': print_senders,
        'max_send_packets_by': keys_with_max_value
    }
    
    yaml = YAML()
    output_file = 'output.yaml'
    with open(output_file, 'w') as file:
        yaml.dump(output_data, file)


def case_arp(packets_list, pcap_file):
    arp_requests = {}
    incomplete_req = []
    incomplete_rep = []
    arp_pairs = []

    for packet in packets_list:
        if hasattr(packet, 'arp_opcode'):
            if packet.arp_opcode == 'REQUEST':
                # ARP request
                if packet.src_ip in arp_requests:
                    arp_requests[packet.src_ip].insert(0, packet)
                else:
                    arp_requests[packet.src_ip] = [packet]
            elif packet.arp_opcode == 'REPLY':
                # ARP reply
                # check for pairs3
                for request in arp_requests[packet.dst_ip]:
                    if packet.dst_ip == request.src_ip and packet.src_ip == request.dst_ip and packet.dst_mac == request.src_mac:
                        arp_pairs.append(request)
                        arp_pairs.append(packet)
                        arp_requests[packet.dst_ip].remove(request)
                        
                    else:
                        incomplete_rep.append(packet)
                # remove all request from arp_requests
                for ip, packet_list in arp_requests.items():
                    incomplete_req.extend(copy.copy(packet_list))
                arp_requests.clear()

    for ip, packet_list in arp_requests.items():
        incomplete_req.extend(copy.copy(packet_list))


    complete = []
    counter = 1
    for packet in (arp_pairs):
        if counter%2 == 1:
            tmp_dict = {}
            tmp_dict['number_comm'] = counter//2 + 1
            tmp_dict['packets'] = [print_packet(packet)]
        else:
            tmp_dict['packets'].append(print_packet(packet))
            complete.append(tmp_dict)

        counter += 1


    partial_comms = []
    incomplete_req_list = []
    num_comm = 1

    for packet in incomplete_req:
        incomplete_req_list.append(print_packet(packet))
    if incomplete_req_list:
        tmp_dict = {
            'number_comm': copy.copy(num_comm),
            'packets': incomplete_req_list
        }
        partial_comms.append(tmp_dict)
        num_comm += 1

    incomplete_rep_list = []
    for packet in incomplete_rep:
        incomplete_rep_list.append(print_packet(packet))
    if incomplete_rep_list:
        tmp_dict = {
            'number_comm': num_comm,
            'packets': incomplete_rep_list
        }
        partial_comms.append(tmp_dict)

    output_data = {
        'name': 'PKS2023/24',
        'pcap_name': f'{pcap_file}',
        'filter_name': 'ARP',
        'complete_comms': complete
    }
    if partial_comms:
        output_data['partial_comms'] = partial_comms
    yaml = YAML()
    output_file = 'output.yaml'
    with open(output_file, 'w') as file:
        yaml.dump(output_data, file)
    
def case_tcp(packets_list, pcap_file, filter_protocol):
    connections = {}  # dictionary to store connections

    for packet in packets_list:
        if hasattr(packet, 'protocol') and hasattr(packet, 'app_protocol') and packet.protocol == 'TCP' and packet.app_protocol == filter_protocol:
            key = tuple(sorted((packet.src_ip, str(packet.src_port), packet.dst_ip, str(packet.dst_port))))
            if key not in connections:
                connections[key] = Connection()

            connection = connections[key]
            connection.packets.append(packet)

            if 'syn' in packet.flags:
                if connection.state == "CLOSED":
                    connection.state = "SYN_SENT"
                    connection.src_ip = packet.src_ip
                    connection.dst_ip = packet.dst_ip
                    connection.src_port = packet.src_port
                    connection.dst_port = packet.dst_port
                elif connection.state == "SYN_SENT":
                    connection.state = "SYN_RECEIVED"
            
            
            if connection.state == "SYN_RECEIVED" and 'ack' in packet.flags:
                connection.state = "ESTABLISHED"

            if 'fin' in packet.flags:
                if connection.state == "ESTABLISHED":
                    connection.state = "FIN_WAIT_1"
                elif connection.state == "FIN_WAIT_1":
                    connection.state = "CLOSE_WAIT"
            if 'ack' in packet.flags and connection.state == "CLOSE_WAIT":
                connection.state = "LAST_ACK"

            if 'reset' in packet.flags:
                connection.state = "RESET"

    # comlete/incomplete communications
    complete_communications = []
    incomplete_communications = []

    for key, connection in connections.items():
        if connection.state == "LAST_ACK" or connection.state == "RESET":
            complete_communications.append(connection)
        else:
            incomplete_communications.append(connection)

    # format to yaml
    print_complete = []
    for number, comm in enumerate(complete_communications):
        packets = []
        for packet in comm.packets:
            packets.append(print_packet(packet))
        tmp_dict = {
            'number_comm': number + 1,
            'src_comm': connection.src_ip,
            'dst_comm': connection.dst_ip,
            'packets': packets
        }
        print_complete.append(tmp_dict)
    
    if incomplete_communications:
        print_incomplete = []
        comm = incomplete_communications[0]
        packets = []
        for packet in comm.packets:
            packets.append(print_packet(packet))
        tmp_dict = {
            'number_comm': 1,
            'packets': packets
        }
        print_incomplete.append(tmp_dict)

    output_data = {
        'name': 'PKS2023/24',
        'pcap_name': f'{pcap_file}',
        'filter_name': filter_protocol,
        'complete_comms': print_complete
    }
    if incomplete_communications:
        output_data['partial_comms'] = print_incomplete

    yaml = YAML()
    output_file = 'output.yaml'
    with open(output_file, 'w') as file:
        yaml.dump(output_data, file)

if __name__ == '__main__':

    helpMenu = """******************** pouzite programu ********************\n
Prepinace (mozu byt pouzite v lubovolnom poradi): 
-f cestak k pcap suboru (musi byt zadany na vstupe, inak sa program nespusti)
-p filter na protokol (nemusi byt)
-help vypis tohto menu (ak je zadany, tak bez ohladu na ine prepinace vypise help menu a program konci)

Spustenie programu: 
python assignment1.py -f <cesta k pcap suboru> -p <nazov protokolu>
"""

    knownProtocols = ['ARP', 'HTTP', 'HTTPS', 'TELNET', 'SSH', 'FTP-CONTROL', 'FTP-DATA']

    if '-help' in sys.argv:
        print(helpMenu)
        sys.exit()
    
    if not '-f' in sys.argv:
        helpMenu += """

Nezadal si pcap subor.
"""
        print(helpMenu)
        sys.exit()


    protocols_file = 'protocols.yaml'
    protocols = load_protocols(protocols_file)
    packets_list,  pcap_file = extract_hexadecimal_data(protocols)

    if not '-p' in sys.argv:
        case_print_packets(packets_list, pcap_file)
        sys.exit()

    protocol_index = sys.argv.index('-p')
    filter_protocol = (sys.argv[protocol_index + 1]).upper()

    if filter_protocol == 'ARP':
        case_arp(packets_list, pcap_file)
    elif filter_protocol in ['HTTP', 'HTTPS', 'TELNET', 'SSH', 'FTP-CONTROL', 'FTP-DATA']:
        case_tcp(packets_list, pcap_file, filter_protocol)
    else:
        print('Neznamy protokol')
        sys.exit()