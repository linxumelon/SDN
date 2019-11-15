'''
Please add your name:
Please add your matric number: 
'''

import sys
import os
from sets import Set

from pox.core import core

import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery
import pox.openflow.spanning_tree

from pox.lib.revent import *
from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr, EthAddr

log = core.getLogger()

class LearningSwitch(object):
    def __init__ (self, connection):
        self.connection = connection
        self.macToPort = {}
        connection.addListeners(self)
        print("hey getting initialized")
        log.debug("Initializing LearningSwitch")

    def _handle_PacketIn (self, event):
        packet = event.parsed
        print("event received!")
        def flood (message = None):
            msg = of.ofp_packet_out()
            if message is not None: 
                log.debug(message)
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            msg.data = event.ofp
            msg.in_port = event.port
            self.connection.send(msg)
            
        def forward(message = None):
            if packet.dst.is_multicast:
                flood()
                return
            else:
                if packet.dst not in self.macToPort:
                    print("unknown port tho")
                    flood("Port for %s unknown -- flooding" % (packet.dst))
                else:
                    if event.port == self.macToPort[packet.dst] and packet.src == packet.dst:
                        log.warning("Same port for packet from %s -> %s on %s.%s.  Drop." % (packet.src, packet.dst, dpid_to_str(event.dpid), self.macToPort[packet.dst]))
                        return

                    self.macToPort[packet.src] = event.port
                    log.debug("installing flow for %s.%i -> %s.%i" %
                        (packet.src, event.port, packet.dst, self.macToPort[packet.dst]))
                    msg = of.ofp_flow_mod()
                    msg.match = of.ofp_match.from_packet(packet, event.port)
                    msg.hard_timeout = 30
                    msg.actions.append(of.ofp_action_output(port = self.macToPort[packet.dst])) 
                    msg.data = event.ofp
                    self.connection.send(msg)   
        forward()
                    
            

class Controller(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        core.openflow_discovery.addListeners(self)
        
    # You can write other functions as you need.
        
    # def _handle_PacketIn (self, event):    
    # 	# install entries to the route table
    #     def install_enqueue(event, packet, outport, q_id):
        

    # 	# Check the packet and decide how to route the packet
    #     def forward(message = None):


    #     # When it knows nothing about the destination, flood but don't install the rule
    #     def flood (message = None):
        
        
    #     forward()

    def _handle_ConnectionUp(self, event):
        dpid = dpid_to_str(event.dpid)
        log.debug("Switch %s has come up.", dpid)
        LearningSwitch(event.connection)
        # Send the firewall policies to the switch
        #def sendFirewallPolicy(connection, policy):
            

        # for i in [FIREWALL POLICIES]:
        #     sendFirewallPolicy(event.connection, i)
            

def launch():
    # Run discovery and spanning tree modules
    pox.openflow.discovery.launch()
    pox.openflow.spanning_tree.launch()

    # Starting the controller module
    core.registerNew(Controller)

