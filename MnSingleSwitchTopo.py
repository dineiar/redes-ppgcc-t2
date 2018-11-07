from mininet.net import Mininet
from mininet.topo import SingleSwitchTopo

topology = SingleSwitchTopo(k=4)
net = Mininet(topo=topology)
net.start()

h1, h4  = net.hosts[0], net.hosts[3]

print h1.cmd('ping -c4 %s' % h4.IP())

net.stop()

