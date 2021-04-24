from netfilterqueue import NetfilterQueue
#import pyshark
import os
import sys
import scapy.all as scapy
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapWriter, PcapWriter



#create a new file
filename = "test.pcap"

f = open(filename, "w")
f.close()

writer = PcapWriter(filename, append=True)


def print_and_accept(pkt):
    print(pkt)
    writer.write(scapy.IP(pkt.get_payload()))
    pkt.accept()
    
print("start!")
nfqueue = NetfilterQueue()
nfqueue.bind(0, print_and_accept)


try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()