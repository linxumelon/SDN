'''
Please add your name:
Please add your matric number: 
'''

import sys
import os
import time
from sets import Set

from pox.core import core

import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery
import pox.openflow.spanning_tree

from pox.lib.revent import *
from pox.lib.util import dpid_to_str
from pox.lib.addresses import IPAddr, EthAddr
import pox.lib.packet as pkt

BANNED_PORT = 4001
POLICY_FILE_NAME = './pox/misc/policy.in'
TTL = 30
log = core.getLogger()

class LearningSwitch(object):
    def __init__ (self, connection, policies, host_to_vLAN_map, vLANs):
        self.connection = connection
        self.mac_to_port = {}
        self.policies = policies
        self.host_to_vLAN_map = host_to_vLAN_map
        self.vLANs = vLANs
        connection.addListeners(self)
        print("hey getting initialized")
        log.debug("Initializing LearningSwitch")
        print(self.policies)
        print(self.host_to_vLAN_map)

        def install_protocol_flow (self, proto, dl_type):
            msg = of.ofp_flow_mod()
            match = of.ofp_match()
            match.nw_src = None
            match.nw_dst = None
            match.tp_src = None
            match.tp_dst = None
            match.nw_proto = proto # 1 for ICMP or ARP opcode
            match.dl_type = dl_type # == 0x0800 for IP, 0x0806 for ARP
            msg.match = match
            msg.hard_timeout = 0
            msg.idle_timeout = 0
            msg.priority = 32768
            msg.actions.append(of.ofp_action_output(port = of.OFPP_NORMAL))
            self.connection.send(msg)
            # establish base rules for ICMP, ARP, and dropping unknown packets

        print "Inserting icmp packet flow"
        # add rule to allow ALL ICMP packets
        install_protocol_flow(self, pkt.ipv4.ICMP_PROTOCOL, pkt.ethernet.IP_TYPE)

        print "Inserting arp packet flows"
        # add rule to allow ALL ARP packetsf
        install_protocol_flow(self, pkt.arp.REQUEST, pkt.ethernet.ARP_TYPE)
        install_protocol_flow(self, pkt.arp.REPLY, pkt.ethernet.ARP_TYPE)
        install_protocol_flow(self, pkt.arp.REV_REQUEST, pkt.ethernet.ARP_TYPE)
        install_protocol_flow(self, pkt.arp.REV_REPLY, pkt.ethernet.ARP_TYPE)

    
    def check_if_allowed(self, srcip, dstip, dstport):
        if dstport == BANNED_PORT:
            src_vLAN = self.host_to_vLAN_map[srcip]
            dst_vLAN = self.host_to_vLAN_map[dstip]
            print("src:{}, dst:{}".format(src_vLAN, dst_vLAN))
            if src_vLAN != dst_vLAN:
                print("after checking these two really not allowed")
                return False
        return True
            

    def install_flow_entry(self, event, srcip, srcport, dstip, dstport, is_allowed):
        packet = event.parsed
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        match.nw_src = srcip
        match.nw_dst = dstip
        match.tp_src = int(srcport)
        match.tp_dst = int(dstport)
        match.nw_proto = pkt.ipv4.TCP_PROTOCOL # == 6
        # specify all packets as IP
        match.dl_type = pkt.ethernet.IP_TYPE # == 0x0800
        msg.match = match
        msg.priority = 65530    
        msg.hard_timeout = 0
        msg.idle_timeout = 0
        if is_allowed:
            #msg.data = event.ofp
            action = of.ofp_action_output(port = of.OFPP_NORMAL)
            print("yes this is allowed, srcip = {}, srcport = {} and dstip = {}, dstport = {}".format(srcip, srcport, dstip, dstport))
        else:
            print("oops firewall pls drop")
        self.connection.send(msg) 
        # if is_allowed:
        self.resend_packet(packet)


    def install_bidirec_flow(self, event, srcip, srcport, dstip, dstport, is_allowed_src_to_dst, is_allowed_dst_to_src):
        self.install_flow_entry(event, srcip, srcport, dstip, dstport, is_allowed_src_to_dst)
        self.install_flow_entry(event, dstip, dstport, srcip, srcport, is_allowed_dst_to_src)

    def resend_packet(self, packet):
        msg = of.ofp_packet_out()
        msg.data = packet
        msg.actions.append(of.ofp_action_output(port = of.OFPP_NORMAL))
        self.connection.send(msg)
        print "packet has been resent!!"


    def remove_expired_mac_to_port(self):
        for entry in self.mac_to_port:
            print entry
            if entry['time'] + TTL <= time.time():
                del entry

    def _handle_PacketIn (self, event):
        packet = event.parsed
        ip_packet = packet.payload
        tcp_packet = ip_packet.payload
        srcip = ip_packet.srcip
        srcport = tcp_packet.srcport
        dstip = ip_packet.dstip
        dstport = tcp_packet.dstport
        is_allowed_src_to_dst = self.check_if_allowed(str(srcip), str(dstip), int(dstport))
        is_allowed_dst_to_src = self.check_if_allowed(str(dstip), str(srcip), int(srcport))
        print("event received!")
        def flood (message = None):
            msg = of.ofp_packet_out()
            if message is not None: 
                log.debug(message)
            vLAN = self.host_to_vLAN_map[str(srcip)]
            for host in self.vLANs[vLAN]:
                if host != packet.src:
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_NORMAL))
            msg.data = event.ofp
            msg.in_port = event.port
            self.connection.send(msg)
            
        def forward(message = None):
            if packet.dst.is_multicast:
                flood()
                return
            else:
                # if packet.dst not in self.mac_to_port:
                #     print("unknown port tho")
                #     flood("Port for %s unknown -- flooding" % (packet.dst))
                # else:
                if packet.dst in self.mac_to_port and event.port == self.mac_to_port[packet.dst]['port']:
                    log.warning("Same port for packet from %s -> %s on %s.%s.  Drop." % (packet.src, packet.dst, dpid_to_str(event.dpid), self.mac_to_port[packet.dst]['port']))
                    return
                self.mac_to_port[packet.src] = {'port' : event.port, 'time': time.time()}
                self.install_bidirec_flow(event, srcip, srcport, dstip, dstport, is_allowed_src_to_dst, is_allowed_dst_to_src)
                self.resend_packet(packet)
        forward()

        #self.remove_expired_mac_to_port()
                    
            

class Controller(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        self.host_to_vLAN_map = dict()
        self.vLANs = []
        self.policies = list()
        self.read_config(POLICY_FILE_NAME)
        print(self.policies)
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
    def read_config(self, policy_file_name):
        print("Test!")
        policy_file = open(policy_file_name)
        policy_lines = policy_file.readlines()
        premium_info = policy_lines[0].split()
        LAN_info = policy_lines[1].split()
        premium_LAN_num = premium_info[0]
        premium_host_num = premium_info[1]
        cursor = 2
        num_of_vLAN = len(LAN_info)
        vLANs = []
        policies = list()
        host_to_vLAN_map = dict()
        for i in range(num_of_vLAN):
            print("i = {}".format(i))
            vLANs.append(list())
            j = 0
            while j < int(LAN_info[i]):
                ip_addr = policy_lines[cursor].rstrip('\r\n')
                vLANs[i].append(ip_addr)
                print(vLANs[i])
                host_to_vLAN_map[ip_addr] = i
                print(host_to_vLAN_map[ip_addr])
                cursor += 1
                j += 1
        print("hi!")
        print(vLANs)
        for i in range(num_of_vLAN):
            vLAN1 = vLANs[i]
            for j in range(i + 1, num_of_vLAN):
                vLAN2 = vLANs[j]
                for host_vLAN1 in vLAN1:
                    for host_vLAN2 in vLAN2:
                        policies.append([host_vLAN1, host_vLAN2, BANNED_PORT])
                        policies.append([host_vLAN2, host_vLAN1, BANNED_PORT])
        print(policies)
        self.host_to_vLAN_map = host_to_vLAN_map
        self.vLANs = vLANs
        print("host to vLAN:::::::")
        print(self.host_to_vLAN_map)
        self.policies = policies
        
        
    def _handle_ConnectionUp(self, event):
        dpid = dpid_to_str(event.dpid)
        log.debug("Switch %s has come up.", dpid)
        LearningSwitch(event.connection, self.policies, self.host_to_vLAN_map, self.vLANs)


        # Send the firewall policies to the switch
        #def send_firewall_policy(connection, policy):
            

        # for i in [FIREWALL POLICIES]:
        #     send_firewall_policy(event.connection, i)
        

def launch():
    # Run discovery and spanning tree modules
    pox.openflow.discovery.launch()
    pox.openflow.spanning_tree.launch()

    # Starting the controller module
    core.registerNew(Controller)

    