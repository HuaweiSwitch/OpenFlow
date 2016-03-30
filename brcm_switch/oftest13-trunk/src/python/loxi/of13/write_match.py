# Copyright (c) 2014 InCNTRE

from oftest import config
from oftest.testutils import *
from time import sleep
from oftest.mpls import *
import actions as action
import logging
import ofp
import oftest.base_tests as base_tests
import oftest.controller as controller
import oftest.dataplane as dataplane
import oftest.illegal_message as illegal_message
import oftest.parse as parse
import sys

def verify_write_modify(test, actions, pkt, exp_pkt,ingress,egress,table_id,
                        instructions_type,table_miss):
        
    
    
    actions = actions + [ofp.action.output(egress)]
    match = ofp.match([ofp.oxm.in_port(ingress)])
    instructions = [ofp.instruction.apply_actions(actions)]
    if instructions_type == "write":
        instructions = [ofp.instruction.write_actions(actions)]
    logging.info("Running actions test for %s", actions)
    
    delete_all_flows(test.controller)
    do_barrier(test.controller)
    priority = 0 if table_miss else 1
    logging.info("Inserting flow")
    request = ofp.message.flow_add(table_id=table_id,
                                   match=match,
                                   instructions=instructions,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   priority=priority)
    test.controller.message_send(request)
    reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
    test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow ")
    logging.info("Successfully installed the flow")
    do_barrier(test.controller)
    
    logging.info("Sending packet, expecting output to port %d", egress)
    test.dataplane.send(ingress, str(pkt))
    verify_packet(test, str(exp_pkt), egress)

def eth_type(test,table_id,ingress,egress,instructions_type,table_miss=False):
    
    pkt = str(simple_tcp_packet())
    exp_pkt = str(simple_tcpv6_packet())
    actions = [ofp.action.set_field(ofp.oxm.eth_type(0x86dd))]
    verify_write_modify(test,actions=actions,
                        pkt=pkt,exp_pkt=exp_pkt,
                        ingress=ingress,egress=egress,
                        table_id=table_id,instructions_type=instructions_type,table_miss=table_miss)


def ip_proto(test,table_id,ingress,egress,instructions_type,table_miss=False):

    pkt = str(simple_tcp_packet())
    exp_pkt = str(simple_udp_packet())
    actions = [ofp.action.set_field(ofp.oxm.ip_proto(17))]
    verify_write_modify(test,actions=actions,
                        pkt=pkt,exp_pkt=exp_pkt,
                        ingress=ingress,egress=egress,
                        table_id=table_id,instructions_type=instructions_type,table_miss=table_miss)


def eth_dst(test,table_id,ingress,egress,instructions_type,table_miss=False):
    
    pkt = str(simple_tcp_packet(eth_dst='65:12:A4:87:C7:E3'))
    exp_pkt = str(simple_tcp_packet(eth_dst='00:A1:CD:83:36:55'))
    actions = [ofp.action.set_field(ofp.oxm.eth_dst([0x00,0xA1,0xCD,0x83,0x36,0x55]))]
    verify_write_modify(test,actions=actions,
                        pkt=pkt,exp_pkt=exp_pkt,
                        ingress=ingress,egress=egress,
                        table_id=table_id,instructions_type=instructions_type,table_miss=table_miss)


def eth_src(test,table_id,ingress,egress,instructions_type,table_miss=False):

    pkt = str(simple_tcp_packet(eth_src='65:12:a4:87:c7:e3'))
    exp_pkt = str(simple_tcp_packet(eth_src='00:a1:cd:83:36:55'))
    actions = [ofp.action.set_field(ofp.oxm.eth_src([0x00,0xA1,0xCD,0x83,0x36,0x55]))]

    verify_write_modify(test,actions=actions,
                        pkt=pkt,exp_pkt=exp_pkt,
                        ingress=ingress,egress=egress,
                        table_id=table_id,instructions_type=instructions_type,table_miss=table_miss)
                                                                            
def vlan_vid(test,table_id,ingress,egress,instructions_type,table_miss=False):

    actions = [ofp.action.set_field(ofp.oxm.vlan_vid(2))]
    pkt = simple_tcp_packet(dl_vlan_enable=True, vlan_vid=1,vlan_pcp=3)
    exp_pkt = simple_tcp_packet(dl_vlan_enable=True, vlan_vid=2,vlan_pcp=3)
    verify_write_modify(test,actions=actions,
                        pkt=pkt,exp_pkt=exp_pkt,
                        ingress=ingress,egress=egress,
                        table_id=table_id,instructions_type=instructions_type,table_miss=table_miss)


def vlan_pcp(test,table_id,ingress,egress,instructions_type,table_miss=False):

    actions = [ofp.action.set_field(ofp.oxm.vlan_pcp(2))]
    pkt = simple_tcp_packet(dl_vlan_enable=True, vlan_pcp=1,vlan_vid=3)
    exp_pkt = simple_tcp_packet(dl_vlan_enable=True, vlan_pcp=2,vlan_vid=3)
    verify_write_modify(test,actions=actions,
                        pkt=pkt,exp_pkt=exp_pkt,
                        ingress=ingress,egress=egress,
                        table_id=table_id,instructions_type=instructions_type,table_miss=table_miss)


def ip_dscp(test,table_id,ingress,egress,instructions_type,table_miss=False):

    actions = [ofp.action.set_field(ofp.oxm.ip_dscp(0x01))]
    pkt = simple_tcp_packet()
    exp_pkt = simple_tcp_packet(ip_tos=0x04)
    verify_write_modify(test,actions=actions,
                        pkt=pkt,exp_pkt=exp_pkt,
                        ingress=ingress,egress=egress,
                        table_id=table_id,instructions_type=instructions_type,table_miss=table_miss)


    actions = [ofp.action.set_field(ofp.oxm.ip_dscp(0x01))]
    pkt = simple_tcpv6_packet()
    exp_pkt = simple_tcpv6_packet(ipv6_tc=0x04)
    verify_write_modify(test,actions=actions,
                        pkt=pkt,exp_pkt=exp_pkt,
                        ingress=ingress,egress=egress,
                        table_id=table_id,instructions_type=instructions_type,table_miss=table_miss)

def ipv4_src(test,table_id,ingress,egress,instructions_type,table_miss=False):

    actions = [ofp.action.set_field(ofp.oxm.ipv4_src(167772161))]
    pkt = simple_tcp_packet()
    exp_pkt = simple_tcp_packet(ip_src="10.0.0.1")
    verify_write_modify(test,actions=actions,
                        pkt=pkt,exp_pkt=exp_pkt,
                        ingress=ingress,egress=egress,
                        table_id=table_id,instructions_type=instructions_type,table_miss=table_miss)


def ipv4_dst(test,table_id,ingress,egress,instructions_type,table_miss=False):

    actions = [ofp.action.set_field(ofp.oxm.ipv4_dst(167772161))]
    pkt = simple_tcp_packet()
    exp_pkt = simple_tcp_packet(ip_dst="10.0.0.1")
    verify_write_modify(test,actions=actions,
                        pkt=pkt,exp_pkt=exp_pkt,
                        ingress=ingress,egress=egress,
                        table_id=table_id,instructions_type=instructions_type,table_miss=table_miss)

def tcp_src(test,table_id,ingress,egress,instructions_type,table_miss=False):


    actions = [ofp.action.set_field(ofp.oxm.tcp_src(800))]
    pkt = simple_tcp_packet()
    exp_pkt = simple_tcp_packet(tcp_sport=800)
    verify_write_modify(test,actions=actions,
                        pkt=pkt,exp_pkt=exp_pkt,
                        ingress=ingress,egress=egress,
                        table_id=table_id,instructions_type=instructions_type,table_miss=table_miss)


def tcp_dst(test,table_id,ingress,egress,instructions_type,table_miss=False):


    actions = [ofp.action.set_field(ofp.oxm.tcp_dst(800))]
    pkt = simple_tcp_packet()
    exp_pkt = simple_tcp_packet(tcp_dport=800)
    verify_write_modify(test,actions=actions,
                        pkt=pkt,exp_pkt=exp_pkt,
                        ingress=ingress,egress=egress,
                        table_id=table_id,instructions_type=instructions_type,table_miss=table_miss)

def udp_src(test,table_id,ingress,egress,instructions_type,table_miss=False):

    actions = [ofp.action.set_field(ofp.oxm.udp_src(800))]
    pkt = simple_udp_packet()
    exp_pkt = simple_udp_packet(udp_sport=800)
    verify_write_modify(test,actions=actions,
                        pkt=pkt,exp_pkt=exp_pkt,
                        ingress=ingress,egress=egress,
                        table_id=table_id,instructions_type=instructions_type,table_miss=table_miss)

def udp_dst(test,table_id,ingress,egress,instructions_type,table_miss=False):

    actions = [ofp.action.set_field(ofp.oxm.udp_dst(800))]
    pkt = simple_udp_packet()
    exp_pkt = simple_udp_packet(udp_dport=800)
    verify_write_modify(test,actions=actions,
                        pkt=pkt,exp_pkt=exp_pkt,
                        ingress=ingress,egress=egress,
                        table_id=table_id,instructions_type=instructions_type,table_miss=table_miss)


def ipv6_src(test,table_id,ingress,egress,instructions_type,table_miss=False):

    actions = [ofp.action.set_field(ofp.oxm.ipv6_src("\x20\x01\xab\xb1\x34\x56\xbc\xcb\x00\x00\x00\x00\x03\x70\x73\x36"))]
    pkt = simple_tcpv6_packet()
    exp_pkt = simple_tcpv6_packet(ipv6_src="2001:abb1:3456:bccb:0000:0000:0370:7336")
    verify_write_modify(test,actions=actions,
                        pkt=pkt,exp_pkt=exp_pkt,
                        ingress=ingress,egress=egress,
                        table_id=table_id,instructions_type=instructions_type,table_miss=table_miss)

def ipv6_dst(test,table_id,ingress,egress,instructions_type,table_miss=False):
    
    actions = [ofp.action.set_field(ofp.oxm.ipv6_dst("\x20\x01\xab\xb1\x34\x56\xbc\xcb\x00\x00\x00\x00\x03\x70\x73\x36"))]
    pkt = simple_tcpv6_packet()
    exp_pkt = simple_tcpv6_packet(ipv6_dst="2001:abb1:3456:bccb:0000:0000:0370:7336")
    verify_write_modify(test,actions=actions,
                        pkt=pkt,exp_pkt=exp_pkt,
                        ingress=ingress,egress=egress,
                        table_id=table_id,instructions_type=instructions_type,table_miss=table_miss)


def ipv6_flabel(test,table_id,ingress,egress,instructions_type,table_miss=False):

    actions = [ofp.action.set_field(ofp.oxm.ipv6_flabel(10))]
    pkt = simple_tcpv6_packet()
    exp_pkt = simple_tcpv6_packet(ipv6_fl=10)
    verify_write_modify(test,actions=actions,
                        pkt=pkt,exp_pkt=exp_pkt,
                        ingress=ingress,egress=egress,
                        table_id=table_id,instructions_type=instructions_type,table_miss=table_miss)

def mpls_label(test,table_id,ingress,egress,instructions_type,table_miss=False):

    actions = [ofp.action.set_field(ofp.oxm.mpls_label(30))]
    labels = [MPLS(label=3,ttl=25,s=1),MPLS(label=20,ttl=30,s=0)]
    pkt=simple_mpls_packet(mpls_labels=labels)
    exp_labels = [MPLS(label=3,ttl=25,s=1),MPLS(label=30,ttl=30,s=0)]
    exp_pkt=simple_mpls_packet(mpls_labels=labels)
    verify_write_modify(test,actions=actions,
                        pkt=pkt,exp_pkt=exp_pkt,
                        ingress=ingress,egress=egress,
                        table_id=table_id,instructions_type=instructions_type,table_miss=table_miss)


def mpls_tc(test,table_id,ingress,egress,instructions_type,table_miss=False):
    pass

def tunnel_id(test,table_id,ingress,egress,instructions_type,table_miss=False):
    pass


def ip_ecn(test,table_id,ingress,egress,instructions_type,table_miss=False):
    actions = [ofp.action.set_field(ofp.oxm.ip_ecn(0x01))]
    pkt = simple_tcp_packet()
    exp_pkt = simple_tcp_packet(ip_tos=0x01)
    verify_write_modify(test,actions=actions,
                        pkt=pkt,exp_pkt=exp_pkt,
                        ingress=ingress,egress=egress,
                          table_id=table_id,instructions_type=instructions_type,table_miss=table_miss)

    actions = [ofp.action.set_field(ofp.oxm.ip_ecn(0x01))]
    pkt = simple_tcpv6_packet()
    exp_pkt = simple_tcpv6_packet(ipv6_tc=0x01)
    verify_write_modify(test,actions=actions,
                        pkt=pkt,exp_pkt=exp_pkt,
                        ingress=ingress,egress=egress,
                          table_id=table_id,instructions_type=instructions_type,table_miss=table_miss)
