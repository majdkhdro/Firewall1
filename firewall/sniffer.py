import socket
import struct



#main()
def get_packet():
     s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
     while True:
        raw_data, add = s.recvfrom(65535)
        des_mac, src_mac, et_protocol, data = ethernet(raw_data)
        print("Ethernet Frame:")
        print('\tDestination_MAC: {}, Source MAC: {}, Ethernet Protocol: {}'.format(des_mac, src_mac, et_protocol))
        # if ethernet_protocol = 8 ==> Ip version 4
        if et_protocol == 8 :
            IP_version, IP_header_length, ttl, protocol, src_ip, target_ip, data_ip = ipv4_packet(data)
            print("\t\t-IP Frame:")
            print('\t\t\tIP_Version: {}, IP_Header_Length: {}, Time_TO_Live:{}'.format(IP_version, IP_header_length, ttl))
            print('\t\t\tProtocol:{}, Source IP: {}, Target IP: {}'.format(protocol, src_ip, target_ip))

            # if protocol = 1 ==> ICMP Protocol
            if protocol == 1:
                icmp_type, code, checksum = icmp_packet(data_ip)
                print('\t\t-ICMP Packet:')
                print('\t\t\tICMP Type: {}, ICMP Code: {}, checksum: {}'.format(icmp_type, code, checksum))

            #if protocol = 6 ==> TCP protocol
            elif protocol == 6:
                src_port, dest_port, seq_num, ack, data_tcp= tcp_packet(data_ip)
                print('\t\t-TCP Segment:')
                print("\t\t\tSource Port: {}, Destination Port: {}".format(src_port, dest_port,))
                print("\t\t\tSequnce Number: {}, Acknolegment: {}".format(seq_num, ack,))



            elif protocol == 17 :
                src_port, dest_port, udp_length = udp_packet(data_ip)
                print('\t\t-UDP Segment:')
                print("\t\t\tSource Port: {}, Destination Port: {}, UDP Length: {}".format(src_port, dest_port,udp_length ))

        print('\n')
        print('\n')

# Ethernet Header
def ethernet(data):
    des_mac, src_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    nde_mac = get_mac(des_mac)
    nsr_mac = get_mac(src_mac)
    proto = socket.htons(protocol)
    rdata = data[14:]
    return nde_mac, nsr_mac , proto, rdata

# get mac address like : AA:BB:CC:DD:EE:FF
def get_mac(bytes_add):
    bytes_str = map("{:02x}".format, bytes_add)
    return ":".join(bytes_str)

# IP v4 Header
def ipv4_packet(data):
    version_header_length = data[0]
    IP_version = version_header_length >> 4
    IP_header_length = (version_header_length & 15 ) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return IP_version, IP_header_length, ttl, proto, ipv4(src), ipv4(target), data[IP_header_length:]

# get IP address like: 192.168.1.1
def ipv4(bytes_add):
    return '.'.join(map(str, bytes_add))

# ICMP Header
def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H',data[:4])
    return icmp_type, code, checksum

# TCP Header
def tcp_packet(data):
    src_port, dest_port, seq_num, ack, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 14) * 4
    return src_port, dest_port, seq_num, ack, data[offset:]

# UDP Header
def udp_packet(data):
    src_port, dest_port, udp_length = struct.unpack('! H H H ',data[:6])
    return src_port, dest_port, udp_length

get_packet()