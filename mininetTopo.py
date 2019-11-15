'''
Please add your name:
Please add your matric number: 
'''

import os
import sys
import atexit
from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.link import Link
from mininet.link import TCLink

from mininet.node import RemoteController

net = None

class TreeTopo(Topo):
			
    def __init__(self):
		# Initialize topology
	Topo.__init__(self)        
	
	# You can write other functions as you need.

	# Add hosts
    	# > self.addHost('h%d' % [HOST NUMBER])
    	h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')
        h7 = self.addHost('h7')

	# Add switches
        sconfig1 = {'dpid': "%016x" % 1}
    	s1 = self.addSwitch('s1', **sconfig1)
        sconfig2 = {'dpid': "%016x" % 2}
        s2 = self.addSwitch('s2', **sconfig2)
        sconfig3 = {'dpid': "%016x" % 3}
        s3 = self.addSwitch('s3', **sconfig3)
        sconfig4 = {'dpid': "%016x" % 4}
        s4 = self.addSwitch('s4', **sconfig4)
    	# > sconfig = {'dpid': "%016x" % [SWITCH NUMBER]}
    	# > self.addSwitch('s%d' % [SWITCH NUMBER], **sconfig)

    
	# Add links
	# > self.addLink([HOST1], [HOST2])
   	self.addLink(h1, s1, bw=10)
    self.addLink(h2, s1, bw=10)
    self.addLink(h3, s2, bw=10)
    self.addLink(h4, s2, bw=10)
    self.addLink(h5, s3, bw=10)
    self.addLink(h6, s3, bw=10)
    self.addLink(h7, s3, bw=10)
    self.addLink(s1, s2, bw=100)
    self.addLink(s2, s3, bw=100)
    self.addLink(s3, s4, bw=100)
    self.addLink(s1, s4, bw=100)


def startNetwork():
    info('** Creating the tree network\n')
    topo = TreeTopo()

    global net
    net = Mininet(topo=topo, link = TCLink,
                  controller=lambda name: RemoteController(name, ip=192.168.1.143.
                  listenPort=6633, autoSetMacs=True)

    info('** Starting the network\n')
    net.start()
    #net.pingAll()
    # Create QoS Queues
    # > os.system('sudo ovs-vsctl -- set Port [INTERFACE] qos=@newqos \
    #            -- --id=@newqos create QoS type=linux-htb other-config:max-rate=[LINK SPEED] queues=0=@q0,1=@q1,2=@q2 \
    #            -- --id=@q0 create queue other-config:max-rate=[LINK SPEED] other-config:min-rate=[LINK SPEED] \
    #            -- --id=@q1 create queue other-config:min-rate=[X] \
    #            -- --id=@q2 create queue other-config:max-rate=[Y]')

    info('** Running CLI\n')
    CLI(net)

def stopNetwork():
    if net is not None:
        net.stop()
        # Remove QoS and Queues
        os.system('sudo ovs-vsctl --all destroy Qos')
        os.system('sudo ovs-vsctl --all destroy Queue')


if __name__ == '__main__':
    # Force cleanup on exit by registering a cleanup function
    atexit.register(stopNetwork)

    # Tell mininet to print useful information
    setLogLevel('info')
    startNetwork()
    
