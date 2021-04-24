import os
import sys
#import scapy.all as scapy
from scapy.all import *
from scapy.layers import *
from scapy.utils import RawPcapWriter, PcapWriter, PcapReader
import socket
import pyshark
from cryptography import x509
import codecs
import re
import OpenSSL.crypto 

# Read public key from file
fd = open('CA-cert.pem', 'r') #
cert_data = fd.read()
fd.close()
trustedcert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_data)
x509store = OpenSSL.crypto.X509Store()
x509store.add_cert(trustedcert)

# load saved traces
data = pyshark.FileCapture("test.pcap")

for pkt in data:
    if "SSL" in pkt:
        # Look for attribute of x509
        if hasattr(pkt['SSL'], 'x509sat_utf8string'):
            #cert = x509.load_pem_x509_certificate(pkt['SSL'].handshake_certificate)
            
            #print(dir(pkt['SSL']))

            #get hex string of the certificate
            cert = pkt["SSL"].handshake_certificate

            #remove : in the string
            cert = re.sub('[:]', '', cert)
            #decode as base64
            b64 = codecs.encode(codecs.decode(cert, 'hex'), 'base64').decode()
            b64 = "-----BEGIN CERTIFICATE-----\n" + b64 + "-----END CERTIFICATE-----\n"
            try:
                tobeverifiedcert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, b64)
            except:
                print("Verify Fail!\n")
                break
            

            #print(cert.get_notBefore())
            #print(cert.get_notAfter())
            store_ctx = OpenSSL.crypto.X509StoreContext(x509store, tobeverifiedcert)
            print("Expired?" + str(tobeverifiedcert.has_expired()) + "\n")
            try:
                store_ctx.verify_certificate()
            except:
                print("Verify Fail!\n")
            else:
                print("Verify Pass!\n")

            


#print(dir(pkt['SSL']))
