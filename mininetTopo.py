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
TOPO_FILE_NAME = 'topology.in'

class TreeTopo(Topo):
			
    def __init__(self):
        Topo.__init__(self) 
		# Initialize topology
        self.link_to_bw = dict()
        self.setup_topo(TOPO_FILE_NAME)
        


    def create_one_queue(self, port, bw):
        command = 'sudo ovs-vsctl -- set Port %s qos=@newqos \
                -- --id=@newqos create QoS type=linux-htb other-config:max-rate=%i queues=0=@q0,1=@q1 \
                -- --id=@q0 create queue other-config:min-rate=%i  \
                other-config:max-rate=%i \
                -- --id=@q1 create queue \
                other-config:min-rate=%i \
                other-config:max-rate=%i' % (port, bw, 0.8*bw, bw, 0, 0.5*bw)

        os.system(command)
    
    def create_queues(self):
        for link in self.links(True, False, True):
            left = link[0]
            right = link[1]
            bw = self.link_to_bw['%s-%s' % (left, right)]
            if 's' in left:
                interface = left + '-eth' + str(link[2]['port1'])
                self.create_one_queue(interface, bw)
                print("create queues for {}".format(left))
            if 's' in right:
                interface = right + '-eth' + str(link[2]['port2'])
                self.create_one_queue(interface, bw)
                print("create queues for {}".format(right))
            
	
	# You can write other functions as you need.
    def setup_topo(self, topo_file_name):
        link_to_bw = dict()
        topo_file = open(topo_file_name)     
        topo = topo_file.readlines()
        metadata = topo[0].split()
        num_of_host = int(metadata[0])
        num_of_switch = int(metadata[1])
        num_of_link = int(metadata[2])
        for i in range(num_of_host):
            self.addHost('h%d' % (i + 1))
        for i in range(num_of_switch):
            sconfig = {'dpid' : "%016x" % (i + 1)}
            self.addSwitch('s%d' % (i + 1), **sconfig)
        cursor = 1
        for i in range(num_of_link):
            link = topo[cursor].split(',')
            print(link)
            link_to_bw['%s-%s' % (link[0], link[1])] = int(link[2]) * 1000000
            link_to_bw['%s-%s' % (link[1], link[0])] = int(link[2]) * 1000000
            self.addLink(link[0], link[1])
            print("adding in one more link")
            cursor += 1

        self.link_to_bw = link_to_bw
        print(self.link_to_bw)
        


def startNetwork():
    info('** Creating the tree network\n')
    topo = TreeTopo()
    
    global net
    net = Mininet(topo=topo, link = TCLink,
                  controller=lambda name: RemoteController(name, ip='192.168.1.143'),
                  listenPort=6633, autoSetMacs=True)

    info('** Starting the network\n')
    net.start()
    topo.create_queues()
    #net.pingAll()
    # Create QoS Queues

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
    
