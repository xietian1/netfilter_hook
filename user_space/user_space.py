from netfilterqueue import NetfilterQueue
#import pyshark
import os
import sys
import scapy.all as scapy
from scapy.layers.tls import TLS

#filename = "test.pcap"
f = open("test.pcap", "w")
f.close()

def print_and_accept(pkt):
    print(pkt)
    pkt_scapy = scapy.IP(pkt.get_payload())
    print(pkt_scapy[TLS])
    #pkt_scapy.extend(sniff(offline=file))
    #wrpcap('test.pcap', pkt_scapy)
    #f = open("test.pcap", "a")
    #f.write(pkt.get_payload())
    #f.close()

    pkt.accept()
    
print("start!")


nfqueue = NetfilterQueue()
nfqueue.bind(0, print_and_accept)


try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()