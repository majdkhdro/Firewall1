import ipaddress
import socket
import struct
import sys
import tkinter
from tkinter import *
from tkinter import ttk
from ipaddress import ip_interface
import csv
import  os


class GUI:
    def __init__(self, root ):
        self.root = root

        width_screen = self.root.winfo_screenwidth()-70
        height_screen = self.root.winfo_screenheight()-65
        print(width_screen)
        self.root.geometry("%dx%d" % (width_screen, height_screen))
        self.root.title("Firewall")
        self.root.resizable(False, False)

        #------ frame header___________
        lable_frame = Frame(self.root , bg='#06283D')
        lable_frame.place(x=0,y=0,width=width_screen,height=100)
        label = Label(lable_frame , text="Information About Captured Packets" , font=('Times',20, 'bold') , bg='#06283D',fg='#ffffff')
        label.place(relx=0.5, rely=0.5, anchor=CENTER)        #--------- frame treeview ---------
        data_frame = Frame(self.root)
        data_frame.place(x=0, y=100 , width=width_screen , height=height_screen-150)
        #--------style tree--------
        style=ttk.Style()
        style.theme_use('alt')
        style.configure("Treeview" , bg='#DFF6FF',  rowheight=40 , fieldbackground='#DFF6FF',foreground='#000000',background='#DFF6FF')
        style.configure("Treeview.Heading" , background='#06283D',fonisize=20,foreground='#ffffff')
        #-----treeview--------
        self.tree = ttk.Treeview(data_frame ,columns=("Source_MAC","Destination_MAC", "Protocol", "Source_IP", "Target_IP","src_port", "dest_port","Action") , style="Treeview",padding=(0,0,13,0))
        self.tree.place(x=13, y=0 , width=width_screen , height=height_screen-150)
        #------scroll-------
        scroll_y = Scrollbar(data_frame, orient=VERTICAL)
        scroll_y.pack(side=LEFT, fill=Y)
        scroll_y.config(command=self.tree.yview,activebackground='#06283D')
        self.tree.config(yscrollcommand=scroll_y.set)
        self.tree['show']='headings'
        self.tree.heading('Source_MAC',text='Source MAC')
        self.tree.heading('Destination_MAC',text='Destination MAC')
        self.tree.heading('Protocol',text='Protocol')
        self.tree.heading('Source_IP',text='Source IP')
        self.tree.heading('Target_IP',text='Target IP')
        self.tree.heading('src_port',text='Source Port')
        self.tree.heading('dest_port',text='Destination Port')
        self.tree.heading('Action',text='Action')

        self.tree.column('Source_MAC',width=int(width_screen/8), anchor=CENTER)
        self.tree.column('Destination_MAC', width=int(width_screen/8), anchor=CENTER)
        self.tree.column('Protocol',width=int(width_screen/8), anchor=CENTER)
        self.tree.column('Source_IP', width=int(width_screen/8), anchor=CENTER)
        self.tree.column('Target_IP', width=int(width_screen/8), anchor=CENTER)
        self.tree.column('src_port', width=int(width_screen/8), anchor=CENTER)
        self.tree.column('dest_port', width=int(width_screen/8), anchor=CENTER)
        self.tree.column('Action', width=int(width_screen/9), anchor=CENTER)



        #-------------bottom frame-----------
        bottom_frame = Frame(self.root , bg='#06283D')
        bottom_frame.place(x=0,y=height_screen-50,width=width_screen,height=50)


    def print_gui(self,Source_MAC,Destination_MAC,Protocol,Source_IP,Target_IP,src_port,dest_port,Action):
        self.Source_MAC = Source_MAC
        self.Destination_MAC = Destination_MAC
        self.Protocol = Protocol
        self.Source_IP = Source_IP
        self.Target_IP = Target_IP
        self.src_port = src_port
        self.dest_port = dest_port
        self.Action = Action
        if self.Protocol ==1:
            self.tree.insert('' , END, values=( self.Source_MAC,self.Destination_MAC, 'ICMP', self.Source_IP, self.Target_IP,self.src_port,self.dest_port,self.Action))
        elif self.Protocol == 6:
            self.tree.insert('' , END, values=( self.Source_MAC,self.Destination_MAC, 'TCP', self.Source_IP, self.Target_IP,self.src_port,self.dest_port,self.Action))
        elif self.Protocol ==17:
            self.tree.insert('' , END, values=( self.Source_MAC,self.Destination_MAC, 'UDP', self.Source_IP, self.Target_IP,self.src_port,self.dest_port,self.Action))

root = Tk()
ob = GUI(root)
send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
#main()
def get_packet():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        root.update()
        s.settimeout(.2)
        try:
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
                     src_port, dest_port, seq_num, ack, data_tcp = tcp_packet(data_ip)
                     print('\t\t-TCP Segment:')
                     print("\t\t\tSource Port: {}, Destination Port: {}".format(src_port, dest_port, ))
                     print("\t\t\tSequnce Number: {}, Acknolegment: {}".format(seq_num, ack, ))

                 #if protocol == 17 ==> udp protocol
                 elif protocol == 17 :
                     src_port, dest_port, udp_length = udp_packet(data_ip)
                     print('\t\t-UDP Segment:')
                     print("\t\t\tSource Port: {}, Destination Port: {}, UDP Length: {}".format(src_port, dest_port,udp_length ))
                 '''
                 #----------Rule Of Firewall-----------
                 ip1 = ipaddress.IPv4Address(src_ip)
                 ip2 = ipaddress.IPv4Network('127.0.0.0/24')
                 if ip1 in ip2 and protocol == 1:
                    Action = "Deny"
                 else:
                    Action = "Permit"
                 '''
                 if validate_with_route_table(src_ip,protocol):
                     Action = "D"
                     sendpacket(send_sock, data, "127.0.0.2")

                 else:
                     Action = "P"

                 #-------insert the values in GUI--------------------
                 if protocol == 1:
                     ob.print_gui(src_mac,des_mac, protocol, src_ip, target_ip, '-' ,'-',Action)
                     root.update()
                 else:
                     ob.print_gui(src_mac,des_mac, protocol, src_ip, target_ip, src_port, dest_port,Action)
                     root.update()
                 print('\n')
                 print('\n')
        except:
             root.update()
             continue


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


def compare_rules(primary_rule: str, secondary_rules: str):
    result = []
    if str(primary_rule).strip() == str(secondary_rules).strip():
        result.append(True)
    else:
        result.append(False)
    return any(result)

list_ip=[]
def cont(sip):
  length = len(list_ip)
  if length == 30:
      list_ip.clear()
  count = 0
  for i in list_ip:
      if sip == i:
          count = count + 1

  list_ip.append(sip)
  print("frequncy",sip ,"in list=",count)
  print(list_ip)
  return count



def validate_with_route_table(src_ip , src_port):
    if cont(src_ip) > 20:
        file = open('iplist.csv', 'r+', newline='')
        x = True
        for line in file:
            rule = line.strip().split(",")
            if str(rule[0]) == str(src_ip):
                x = False
        if x:
            wr = csv.writer(file)
            wr.writerow([src_ip, src_port])
        file.close()
    with open("/home/majd/PycharmProjects/github/Firewall1/firewall/iplist.csv" ) as rules_stream:
        for line in rules_stream:
            rule = line.strip().split(",")
            print(rule)
            if compare_rules(rule[0],src_ip) and compare_rules(rule[1],src_port):
                return True
            else:
                continue
        return False

def sendpacket(conn: socket.socket, payload, dst_ip):
    try:
        conn.sendto(payload, (dst_ip, 0))
    except PermissionError as broadcastError:
        print(broadcastError)
        pass
    except OSError as Error:
        print(Error)
        pass

get_packet()












