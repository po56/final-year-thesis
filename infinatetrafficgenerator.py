
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel

class SingleSwitchTopo(Topo):
	def build(self, n=2):
		switch = self.addSwitch('s1')
		for h in range(n):
			host = self.addHost('h%s' % (h+1))
			self.addLink(host, switch)
def generatesometraffic():
	topo = SingleSwitchTopo(n=2)
	net = Mininet(topo)
	net.start()
	dumpNodeConnections(net.hosts)
	h1, h2 = net.get('h1', 'h2')
	var = 1
	while var == 1:
		net.pingAll()
		net.iperf((h1,h2), l4Type = 'UDP')
		net.iperf((h1,h2))

if __name__ == '__main__':
       # Tell mininet to print useful information
        setLogLevel('info')
        generatesometraffic()


