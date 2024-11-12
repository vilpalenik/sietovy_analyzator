import binascii
import socket
import ruamel.yaml

class Packet:
    def __init__(self, hex_frame, frame_number, protocols):

        self.frame = bytes(hex_frame)
        self.frame_number = frame_number+1
        
        hex_string = binascii.hexlify(self.frame).decode('utf-8')
        byte_groups = [hex_string[i:i+2].upper() for i in range(0, len(hex_string), 2)]
        separated_bytes = ' '.join(byte_groups)
        lines = [separated_bytes[i:i+48] for i in range(0, len(separated_bytes), 48)]
        lines = [line.rstrip() for line in lines]
        done = '\n'.join(lines)
        done = done + '\n'
        self.hexa_frame = ruamel.yaml.scalarstring.LiteralScalarString(done)
        
        dst_str = binascii.hexlify(self.frame[0:6]).decode('utf-8')
        dst_bytes = [dst_str[i:i+2].upper() for i in range(0, len(dst_str), 2)]
        self.dst_mac = ':'.join(dst_bytes)
        src_str = binascii.hexlify(self.frame[6:12]).decode('utf-8')
        src_bytes = [src_str[i:i+2].upper() for i in range(0, len(dst_str), 2)]
        self.src_mac = ':'.join(src_bytes)
        self.frame_length = len(self.frame)
        
        # length
        if len(hex_frame) + 4 < 64: 
            self.wire_length = 64
        else:
            self.wire_length = len(self.frame) + 4
            
        # ethernet II
        if int.from_bytes(self.frame[12:14], byteorder='big') >= 1536:
            self.ethernet_II(protocols)
        # IEEE 802.3
        else:
            self.IEEE_802_3(protocols)

    
    def ethernet_II(self, protocols):
        self.frame_type = 'ETHERNET II'
        ether_type = int.from_bytes(self.frame[12:14], byteorder='big')
        if ether_type in protocols['ether_type']:
            self.ether_type = protocols['ether_type'][ether_type]

        # ipv4
        network_start = 14
        if hasattr(self, 'ether_type') and self.ether_type == 'IPv4':
            src_ip = self.frame[network_start+12 : network_start+16]
            src_address = socket.inet_ntoa(src_ip)
            self.src_ip = str(src_address)
            dst_ip = self.frame[network_start+16 : network_start+20]
            dst_address = socket.inet_ntoa(dst_ip)
            self.dst_ip = str(dst_address)

            # protocol
            ipv4_protocol = int(self.frame[network_start+9])
            if ipv4_protocol in protocols['ipv4_protocol']:
                self.protocol = protocols['ipv4_protocol'][ipv4_protocol]

            ihl = self.frame[network_start] & 0x0f
            transport_start = network_start + ihl*4
            
            # src/dst ip address
            if self.protocol == 'TCP' or self.protocol == 'UDP':
                src_port = int.from_bytes(self.frame[transport_start : transport_start+2], byteorder='big')
                self.src_port = src_port
                dst_port = int.from_bytes(self.frame[transport_start+2 : transport_start+4], byteorder='big')
                self.dst_port = dst_port

                # app protocol
                if self.protocol == 'TCP':
                    prot = 'tcp_protocol'
                    # self.sequence_number = int.from_bytes(self.frame[transport_start+4:transport_start+8], byteorder='big')
                    # self.acknowledgment_number = int.from_bytes(self.frame[transport_start+8:transport_start+12], byteorder='big')
                    self.flags = []
                    flags = int.from_bytes(self.frame[transport_start+12:transport_start+14], byteorder='big')
                    if flags & 1:
                        self.flags.append('fin')
                    flags = flags >> 1
                    if flags & 1:
                        self.flags.append('syn')
                    flags = flags >> 1
                    if flags & 1:
                        self.flags.append('reset')
                    flags = flags >> 1
                    if flags & 1:
                        self.flags.append('push')
                    flags = flags >> 1
                    if flags & 1:
                        self.flags.append('ack')
                else:
                    prot = 'udp_protocol'
                app_protocol = self.src_port
                if app_protocol in protocols[prot]:
                    self.app_protocol = protocols[prot][app_protocol]
                
                app_protocol = self.dst_port
                if app_protocol in protocols[prot]:
                    self.app_protocol = protocols[prot][app_protocol]
            
                
        # arp
        network_start = 14
        if hasattr(self, 'ether_type') and self.ether_type == 'ARP':
            src_ip = self.frame[network_start+14 : network_start+18]
            src_address = socket.inet_ntoa(src_ip)
            self.src_ip = str(src_address)
            dst_ip = self.frame[network_start+24 : network_start+28]
            dst_address = socket.inet_ntoa(dst_ip)
            self.dst_ip = str(dst_address)
            opcode = int.from_bytes(self.frame[network_start+6 : network_start+8], byteorder='big')
            if opcode == 1:
                self.arp_opcode = 'REQUEST'
            else:
                self.arp_opcode = 'REPLY'


    def IEEE_802_3(self, protocols):
        # AA
        if int(self.frame[14]) == 170:
            self.frame_type = 'IEEE 802.3 LLC & SNAP'
            pid = int.from_bytes(self.frame[20:22], byteorder='big')
            if pid in protocols['pid']:
                self.pid = protocols['pid'][pid]
        # FF
        elif int(self.frame[14]) == 255:
            self.frame_type = 'IEEE 802.3 RAW'
        # it must be LLC now
        else:
            self.frame_type = 'IEEE 802.3 LLC'
            sap = int(self.frame[14])
            if sap in protocols['sap']:
                self.sap = protocols['sap'][sap]