# A simple demo on Linux for stream certificate validation.

Due to the time limitation, I haven't tested it on a pc configured as the Wi-Fi router. But the kernel space hook function should work once the hook point/IP address is configured properly (In the demo, I set the hook point on NF_INET_PRE_ROUTING. On the router, the hook point should be set on INET_FORWARD). 


## Setting (tested): 
1. A vitual machine with Ubuntu 20.04 as the primary device. (IP: 192.168.1.10)
2. A vitual machine with Ubuntu 16.04 as the apache2 server that has the https service enabled. (IP: 192.168.1.30) The certificates & keys are stored in the folder `cert`.  


The user space part is implemented by python3, which can be quickly deployed on the pc.  

This demo contains 3 parts.

# Part 1: Kernel Hook Module

The main folder contains the kernel hook module. 
The kernel module can be compiled by
```
make
```
After it succesfully compiles, the kernel module can be installed by
```
sudo insmod mydrv.ko
```
The module can be removed by
```
sudo rmmod mydrv
```
To check the debug message, we can use the command
```
dmesg
```

# Part 2: User Space Module 
This part is stored in the folder `user_space`. 

This module will accept the TLS packets by NF_QUEUE from the kernel module. 

To run this module, dependencies `netfilterqueue` and `scapy` need to be installed. 

Run
```
sudo python3 user_space.py
```

It should save the TLS packets forwarded from the kernel space to the file `test.pcap`. 

# Part 3: Phrase Module
This part is stored in the folder `pharse`.

This module will extract the certificate from the trace `test.pcap` from *User Space Module* and validate the certificate (i.e., check expiration, validate if the certificate is trusted). 

To validate the ceritifcate, it will read a CA-certificate, which is `CA-cert.pem` provided in the folder. 

To run this module, dependencies `pyshark`, `cryptography` and `OpenSSL` need to be installed. 

Run
```
python3 pharse.py
```

It should print out the validation results
```
test@ubuntu:~/netfilter_hook/phrase$ python3 phrase.py 

Expired?False

Verify Pass!
```

# Todo:
1. Currently, user space module and pharse module are in two files due to the rush implementation. They can be merged with a thread manager or directly phrase the scapy packet on the user space module I guess. 

2. Once the validation fails, we can configure the iptables to block the following tracces to protect the connected devices. 