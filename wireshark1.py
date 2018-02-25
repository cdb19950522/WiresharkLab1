#!/usr/bin/python
# 
# This is the skeleton of the CS 352 Wireshark Assignment 1
#
# (c) 2018, R. P. Martin, GPL version 2

# Given a pcap file as input, you should report:
#
#1) number of the packets (use number_of_packets), 
#2) list distinct source IP addresses and number of packets for each IP address, in descending order 
#3) list distinct destination TCP ports and number of packers for each port(use list_of_tcp_ports, in descending order)
#4) The number of distinct source IP, destination TCP port pairs, in descending order 

import dpkt
import socket
import argparse 
import operator
from collections import OrderedDict

# this helper method will turn an IP address into a string
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# main code 
def main():
    number_of_packets = 0             # you can use these structures if you wish 
    list_of_ips = dict()
    list_of_tcp_ports = dict()
    list_of_ip_tcp_ports = dict()
    ipcountlist = list()
    dportlist=list()
    iptcplist=list()
    ##list_of_ip_tcp_ports.setdefault("",0)

    # parse all the arguments to the client 
    parser = argparse.ArgumentParser(description='CS 352 Wireshark Assignment 1')
    parser.add_argument('-f','--filename', help='pcap file to input', required=True)

    # get the filename into a local variable
    args = vars(parser.parse_args())
    filename = args['filename']

    # open the pcap file for processing 
    input_data=dpkt.pcap.Reader(open(filename,'r'))

    # this main loop reads the packets one at a time from the pcap file
    for timestamp, packet in input_data:
        eth = dpkt.ethernet.Ethernet(packet)
        ip= eth.data
        tcp = ip.data
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            number_of_packets = number_of_packets+1
            src = socket.inet_ntoa(ip.src)
            ipcountlist.append(src)
            if ip.p not in (dpkt.ip.IP_PROTO_TCP, 0):
                continue
            dport = tcp.dport
            dportlist.append(dport)
            
            combine = src +":"+ str(dport)
            ##print combine
            iptcplist.append(combine)
            

            
        else:
            number_of_packets = number_of_packets+1
    ##Get the sorted list for part 2##   
    bufferlist1 = []
    for x in ipcountlist:
        if x not in bufferlist1:
            bufferlist1.append(x)
    for x in bufferlist1:
        list_of_ips.update({x:ipcountlist.count(x)})
    sortedlist1 = sorted(list_of_ips.items(), key =operator.itemgetter(1),reverse=True)
    #########################################################
    ## For part3##
    bufferlist2 = []
    for x in dportlist:
        if x not in bufferlist2:
            bufferlist2.append(x)
    for x in bufferlist2:
        list_of_tcp_ports.update({x:dportlist.count(x)})
    sortedlist2 = sorted(list_of_tcp_ports.items(),key=operator.itemgetter(1),reverse=True)
    #######################################################
    ## For part4##
    bufferlist3 = []
    for x in iptcplist:
        if x not in bufferlist3:
            bufferlist3.append(x)
    for x in bufferlist3:
        list_of_ip_tcp_ports.update({x:iptcplist.count(x)})
    sortedlist3 = sorted(list_of_ip_tcp_ports.items(),key=operator.itemgetter(1),reverse=True)
    

    print "CS 352 Wireshark, part 1"
    print 'Total number of packets', number_of_packets
    print 'Source IP addresses, count'
    for x in sortedlist1:
        print("%s,%d"%(x[0],x[1]))
    print 'Destination TCP ports,count'
    for x in sortedlist2:
        print("%s,%d"%(x[0],x[1]))
    print 'Source IPs/Destination TCP ports,count'
    for x in sortedlist3:
        print("%s,%d"%(x[0],x[1]))

    


# execute a main function in Python
if __name__ == "__main__":
    main()    