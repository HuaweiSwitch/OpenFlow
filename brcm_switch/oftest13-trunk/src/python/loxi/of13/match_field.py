# Copyright (c) 2014 InCNTRE

from oftest import config
from oftest.testutils import *
from time import sleep

import actions as action
import logging
import ofp
import oftest.base_tests as base_tests
import oftest.controller as controller
import oftest.dataplane as dataplane
import oftest.illegal_message as illegal_message
import oftest.parse as parse
import sys


def in_port(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([ofp.oxm.in_port(ingress)])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on port {0} " 
                             "and action forward to port {1}"
                             .format(ingress, egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow.")
                logging.info("Installed the flow.")
        pkt = str(simple_tcp_packet())
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)


def metadata_masked(test,ingress,egress,table_id=0,match=False,table_miss=False):
        return

def eth_dst(test,ingress,egress,table_id=0,match=False,table_miss=False):
         if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_dst([0,1,2,8,4,7])
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on eth_dst "
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR.Could not insert the flow.")
                logging.info("Installed the flow.")
         pkt = str(simple_tcp_packet(eth_dst='00:01:02:08:04:07'))
         test.dataplane.send(ingress,pkt)
         verify_packet(test,pkt,egress)

def eth_dst_masked(test,ingress,egress,table_id=0,match=False,table_miss=False):
         if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_dst_masked([0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
                                                       [0x00, 0xff, 0xff, 0x0f, 0xff, 0xff])
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on  eth_dst_masked "
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow.")
         pkt = str(simple_tcp_packet(eth_dst='ff:01:02:f3:04:05'))
         test.dataplane.send(ingress,pkt)
         verify_packet(test,pkt,egress)

def eth_src(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_src([0,1,2,8,4,7])
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on  eth_src"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow.")
        pkt = str(simple_tcp_packet(eth_src='00:01:02:08:04:07'))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)

def eth_src_masked(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_src_masked([0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
                                                       [0x00, 0xff, 0xff, 0x0f, 0xff, 0xff])
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on  eth_src_masked "
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow.")
        pkt = str(simple_tcp_packet(eth_src='ff:01:02:f3:04:05'))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)
        
def eth_type(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0800)
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on  eth_type 0x800"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow.")
                pkt = str(simple_tcp_packet())
                test.dataplane.send(ingress,pkt)
                verify_packet(test,pkt,egress)
                #Test for eth_type 0x86dd
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x86dd)
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on  eth_type 0x86dd"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow.")
                pkt = str(simple_udpv6_packet())
                test.dataplane.send(ingress,pkt)
                verify_packet(test,pkt,egress)
        pkt = str(simple_tcp_packet())
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)

def vlan_vid(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.vlan_vid(ofp.OFPVID_PRESENT|2),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on vlan_id "
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow.")
        pkt =str(simple_tcp_packet(dl_vlan_enable=True, vlan_vid=2, vlan_pcp=3))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)

def vlan_pcp(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.vlan_vid(ofp.OFPVID_PRESENT|2),
                                ofp.oxm.vlan_pcp(3),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on vlan_pcp "
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow.")
                logging.info("Installed the flow.")
        pkt = str(simple_tcp_packet(dl_vlan_enable=True, vlan_vid=2, vlan_pcp=3))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)

def ip_dscp(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0800),
                                ofp.oxm.ip_dscp(4),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on ip_dscp"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow.")
                logging.info("Installed the flow.")
        pkt = str(simple_tcp_packet(ip_tos=0x13))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)

def ip_proto(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0800),
                                ofp.oxm.ip_proto(6),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on ip_proto tcp"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow.")
                pkt = str(simple_tcp_packet())
                test.dataplane.send(ingress,pkt)
                verify_packet(test,pkt,egress)
                #Test for ip_proto udp
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0800),
                                ofp.oxm.ip_proto(17),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on ip_proto udp"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow.")
                pkt = str(simple_udp_packet())
                test.dataplane.send(ingress,pkt)
                verify_packet(test,pkt,egress)

        pkt = str(simple_tcp_packet())
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)

def ipv4_src(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0800),
                                ofp.oxm.ipv4_src(0xc0a80001), # 192.168.0.1
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on ipv4_src"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow.")
        pkt =  str(simple_tcp_packet(ip_src='192.168.0.1'))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)


def ipv4_src_masked(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0800),
                                # 192.168.0.1 255.254.255.255
                                ofp.oxm.ipv4_src_masked(0xc0a80001, 0xfffeffff),
                                ])

                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on ipv4_src_masked"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow.")
                logging.info("Installed the flow.")
        pkt =  str(simple_tcp_packet(ip_src='192.169.0.1'))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)


def ipv4_dst(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0800),
                                ofp.oxm.ipv4_dst(0xc0a80001), # 192.168.0.1
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on ipv4_dst_masked"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow.")
                logging.info("Installed the flow.")
                pkt =  str(simple_tcp_packet(ip_dst='192.168.0.1'))
                test.dataplane.send(ingress,pkt)
                verify_packet(test,pkt,egress)

def ipv4_dst_masked(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0800),
                                # 192.168.0.1 255.254.255.255
                                ofp.oxm.ipv4_dst_masked(0xc0a80001, 0xfffeffff),
                                ])

                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on ipv4_dst_masked"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow.")
        pkt =  str(simple_tcp_packet(ip_dst='192.169.0.1'))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)

def tcp_src(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0800),
                                ofp.oxm.ip_proto(6),
                                ofp.oxm.tcp_src(53),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on ipv4 tcp src"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow.")
                logging.info("Installed the flow.")
                pkt = str(simple_tcp_packet(tcp_sport=53))
                test.dataplane.send(ingress,pkt)
                verify_packet(test,pkt,egress)
                #Match on IPv6 tcp src
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x086dd),
                                ofp.oxm.ip_proto(6),
                                ofp.oxm.tcp_src(53),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on ipv6 tcp src"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow.")
                pkt = str(simple_tcpv6_packet(tcp_sport=53))
                test.dataplane.send(ingress,pkt)
                verify_packet(test,pkt,egress)
        pkt = str(simple_tcp_packet(tcp_sport=53))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)

def tcp_src_masked(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0800),
                                ofp.oxm.ip_proto(6),
                                ofp.oxm.tcp_src_masked(52, 0xFE),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on tcp_src_masked"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR.Could not insert the flow.")
                logging.info("Installed the flow.")
        pkt = str(simple_tcp_packet(tcp_sport=53))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)


def tcp_dst_masked(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0800),
                                ofp.oxm.ip_proto(6),
                                ofp.oxm.tcp_dst_masked(52, 0xFE),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on ipv4 tcp dst masked"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow.")
        pkt = str(simple_tcp_packet(tcp_dport=53))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)

def tcp_dst(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0800),
                                ofp.oxm.ip_proto(6),
                                ofp.oxm.tcp_dst(53),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on ipv4 tcp destination port"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow.")
                logging.info("Installed the flow.")
                pkt = str(simple_tcp_packet(tcp_dport=53))
                test.dataplane.send(ingress,pkt)
                verify_packet(test,pkt,egress)
                #Match on ipv6 tcp destination port
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x86dd),
                                ofp.oxm.ip_proto(6),
                                ofp.oxm.tcp_dst(53),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on ipv6 tcp destination port"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow.")
                logging.info("Installed the flow.")
                pkt = str(simple_tcp_packet(tcp_dport=53))
                test.dataplane.send(ingress,pkt)
                verify_packet(test,pkt,egress)
        pkt = str(simple_tcp_packet(tcp_dport=53))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)



def udp_src_masked(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0800),
                                ofp.oxm.ip_proto(17),
                                ofp.oxm.udp_src_masked(52, 0xFE),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on udp_src_masked"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow.")
        pkt = str(simple_udp_packet(udp_sport=53))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)

def udp_src(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0800),
                                ofp.oxm.ip_proto(17),
                                ofp.oxm.udp_src(53),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on ipv4 udp source port"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow")
                pkt = str(simple_udp_packet(udp_sport=53))
                test.dataplane.send(ingress,pkt)
                verify_packet(test,pkt,egress)
                #Match of ipv6 udp src port.
                match = ofp.match([
                                ofp.oxm.eth_type(0x86dd),
                                ofp.oxm.ip_proto(17),
                                ofp.oxm.udp_src(53),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on ipv6 udp source port"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow.")
                pkt = str(simple_udpv6_packet(udp_sport=53))
                test.dataplane.send(ingress,pkt)
                verify_packet(test,pkt,egress)
        pkt = str(simple_udp_packet(udp_sport=53))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)



def udp_dst(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0800),
                                ofp.oxm.ip_proto(17),
                                ofp.oxm.udp_dst(53),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on ipv4 udp destination port"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow.")
                pkt = str(simple_udp_packet(udp_dport=53))
                test.dataplane.send(ingress,pkt)
                verify_packet(test,pkt,egress)
                #Match on ipv6 udp destination port.
                match = ofp.match([
                                ofp.oxm.eth_type(0x0800),
                                ofp.oxm.ip_proto(17),
                                ofp.oxm.udp_dst(53),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on ipv6 udp destination port"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow.")
                pkt = str(simple_udp_packet(udp_dport=53))
                test.dataplane.send(ingress,pkt)
                verify_packet(test,pkt,egress)
        pkt = str(simple_udp_packet(udp_dport=53))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)

def udp_dst_masked(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0800),
                                ofp.oxm.ip_proto(17),
                                ofp.oxm.udp_dst_masked(52, 0xFE),
                                ])

                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on udp_dst_masked"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch generated OFPT_ERROR. Could not insert the flow.")
                logging.info("Installed the flow.")
        pkt = str(simple_udp_packet(udp_dport=53))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)

def sctp_src_masked(test,ingress,egress,match=False,table_miss=False):
        return

def sctp_dst_masked(test,ingress,egress,match=False,table_miss=False):
        return

def icmpv4_type(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0800),
                                ofp.oxm.ip_proto(1),
                                ofp.oxm.icmpv4_type(3),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on icmpv4_type"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow.")
        pkt = str(simple_icmp_packet(icmp_type=3, icmp_code=1))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)

def icmpv4_code(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0800),
                                ofp.oxm.ip_proto(1),
                                ofp.oxm.icmpv4_code(2),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on icmpv4_code"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow")
        pkt = str(simple_icmp_packet(icmp_type=5, icmp_code=2))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)


def arp_op(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0806),
                                ofp.oxm.arp_op(3),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on arp_op"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow.")
                logging.info("Installed the flow.")
        pkt =  str(simple_arp_packet(arp_op=3))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)

def arp_spa_masked(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0806),
                                # 192.168.0.1 255.254.255.255
                                ofp.oxm.arp_spa_masked(0xc0a80001, 0xfffeffff),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on arp_spa_masked "
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR.Could not insert the flow.")
                logging.info("Installed the flow.")
        pkt = str(simple_arp_packet(ip_snd='192.169.0.1'))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)

def arp_tpa_masked(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0806),
                                # 192.168.0.1 255.254.255.255
                                ofp.oxm.arp_tpa_masked(0xc0a80001, 0xfffeffff),
                                ])

                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on arp_tpa_masked"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch generated OFPT_ERROR.Could not insert the flow.")
                logging.info("Installed the flow.")
        pkt = str(simple_arp_packet(ip_tgt='192.169.0.1'))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)

def arp_sha_masked(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0806),
                                ofp.oxm.arp_sha_masked([0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
                                                       [0x00, 0xff, 0xff, 0x0f, 0xff, 0xff])
                                ])

                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on arp_sha_masked "
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow.")
                logging.info("Installed the flow.")
        pkt = str(simple_arp_packet(hw_snd='ff:01:02:f3:04:05'))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)

def arp_tha_masked(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x0806),
                                ofp.oxm.arp_sha_masked([0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
                                                       [0x00, 0xff, 0xff, 0x0f, 0xff, 0xff])
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on arp_tha_masked"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR.Could not insert the flow.")
                logging.info("Installed the flow.")
        pkt = str(simple_arp_packet(hw_tgt='ff:01:02:f3:04:05'))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)

def icmpv6_type(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x86dd),
                                ofp.oxm.ip_proto(58),
                                ofp.oxm.icmpv6_type(3),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on icmpv6_type"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch generated OFPT_ERROR. Could not insert the flow.")
                logging.info("Installed the flow.")
        pkt = str(simple_icmpv6_packet(icmp_type=3, icmp_code=2))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)

def icmpv6_code(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                match = ofp.match([
                                ofp.oxm.eth_type(0x86dd),
                                ofp.oxm.ip_proto(58),
                                ofp.oxm.icmpv6_code(2),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on icmpv6_code"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow.")
                logging.info("Installed the flow.")
        pkt = str(simple_icmpv6_packet(icmp_type=3, icmp_code=2))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)


def ipv6_src(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                src = "2001:db8:85a3::8a2e:370:7334"
                match = ofp.match([
                                ofp.oxm.eth_type(0x86dd),
                                ofp.oxm.ipv6_src(parse_ipv6(src)),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on ipv6_src"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow.")
        pkt =  str(simple_tcpv6_packet(ipv6_src="2001:db8:85a3::8a2e:370:7334"))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)

def ipv6_src_masked(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                src ="2001:0db8:85a3::0001"
                mask ="ffff:ffff:ffff::000f"
                match = ofp.match([
                                ofp.oxm.eth_type(0x86dd),
                                ofp.oxm.ipv6_src_masked(parse_ipv6(src), parse_ipv6(mask)),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on ipv6_src_masked"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow.")
        pkt =  str(simple_tcpv6_packet(ipv6_src='2001:0db8:85a3::ffff:ffff:fff1'))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)

def ipv6_dst(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                dst = "2001:db8:85a3::8a2e:370:7334"
                match = ofp.match([
                                ofp.oxm.eth_type(0x86dd),
                                ofp.oxm.ipv6_dst(parse_ipv6(dst)),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on ipv6_dst"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow.")
        pkt =  str(simple_tcpv6_packet(ipv6_dst="2001:db8:85a3::8a2e:370:7334"))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)


def ipv6_dst_masked(test,ingress,egress,table_id=0,match=False,table_miss=False):
        if match:
                delete_all_flows(test.controller)
                dst ="2001:0db8:85a3::0001"
                mask ="ffff:ffff:ffff::000f"
                match = ofp.match([
                                ofp.oxm.eth_type(0x86dd),
                                ofp.oxm.ipv6_dst_masked(parse_ipv6(dst), parse_ipv6(mask)),
                                ])
                actions=[ofp.action.output(port=egress)]
                instructions=[ofp.instruction.apply_actions(actions=actions)]
                priority = 0 if table_miss else 1
                logging.info("Installing  a flow to match on ipv6_dst_masked"
                             "and action forward to port {0}"
                             .format(egress))
                req = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority)
                test.controller.message_send(req)
                reply, _ = test.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                test.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow")
                logging.info("Installed the flow.")
        pkt =  str(simple_tcpv6_packet(ipv6_dst='2001:0db8:85a3::ffff:ffff:fff1'))
        test.dataplane.send(ingress,pkt)
        verify_packet(test,pkt,egress)
