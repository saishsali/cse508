#!/usr/bin/env python
import argparse
from scapy.all import *
from collections import deque

packet_queue = deque(maxlen = 10)

def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(UDP) and packet.haslayer(DNS) and packet.haslayer(DNSRR):
        if len(packet_queue) > 0:
            for old_packet in packet_queue:
                if old_packet[IP].dst == packet[IP].dst and\
                old_packet[IP].sport == packet[IP].sport and\
                old_packet[IP].dport == packet[IP].dport and\
                old_packet[DNSRR].rdata != packet[DNSRR].rdata and\
                old_packet[DNS].id == packet[DNS].id and\
                old_packet[DNS].qd.qname == packet[DNS].qd.qname and\
                old_packet[IP].payload != packet[IP].payload:
                    print "\n" + datetime.fromtimestamp(old_packet.time).strftime('%Y-%m-%d %H:%M:%S.%f') +\
                    " DNS poisoning attempt detected"
                    print "TXID %s Request URL %s" % (old_packet[DNS].id, old_packet[DNS].qd.qname.rstrip('.'))
                    print "Answer1 [%s]" % old_packet[DNSRR].rdata
                    print "Answer2 [%s]" % packet[DNSRR].rdata
        packet_queue.append(packet)

def main():
    parser = argparse.ArgumentParser(description='DNS poisoning attack detector', add_help = False)

    parser.add_argument("-i", help = "Listen on network device <interface> (e.g., eth0). If not specified,\
                        the program selects a default interface to listen on.",
                        type = str, required = False, default = None)

    parser.add_argument("-r", help = "Read packets from <tracefile> (tcpdump format). Useful for detecting\
                        DNS poisoning attacks in existing network traces.",
                        type = str, required = False, default = None)

    parser.add_argument("expression", help = "A BPF filter that specifies a subset of the traffic to be\
                        monitored.", nargs='?', type = str, default = None)

    args = parser.parse_args()

    print "Starting DNS poisoning attack detector"

    if args.i is not None and args.r is not None:
        print "Either use interface or tracefile"
        sys.exit()
    elif args.i is None and args.r is None:
        print "Sniffing on all interfaces"
        sniff(filter = args.expression, prn = process_packet)
    elif args.i is not None and args.r is None:
        print "Sniffing on interface " + args.i
        sniff(filter = args.expression, iface = args.i, prn = process_packet)
    else:
        print "Sniffing on tracefile " + args.r
        sniff(filter = args.expression, offline = args.r, prn = process_packet)

if __name__ == "__main__":
    main()
