# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Pan Zhang
"""
Test suite 90 verifies the behavior of various combinations of OXM types used in a single flow entry.
Notes
All supported matches in an individual table (as reported by a device) must be available in parallel as long as they are not mutually exclusive. This test suite is responsible for testing each of these match combinations with as many OXM types as possible.
Basic conformance
To satisfy the basic requirements an OpenFlow enabled device must pass test case 90.60.



"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
import oftest.packet as scapy

from oftest.testutils import *
from oftest.parse import parse_ipv6
from oftest.oflog import *

class Testcase_90_60_All_supported(base_tests.SimpleDataPlane):
    """

    TODO: Verify subtestcases with another DUT which supports Flow2. Then verify the correctness of subtestcases involved with ipv6.

    Purpose
    This needs several subtests, as not all mandatory header match fields can exist in one flow -- Match on: OXM_OF_IN_PORT; OXM_OF_ETH_DST; OXM_OF_ETH_SRC; OXM_OF_ETH_TYPE==IPv4; OXM_OF_IP_PROTO; OXM_OF_IPV4_SRC; OXM_OF_IPV4_DST; OXM_OF_TCP_SRC; OXM_OF_TCP_DST


    Methodology
    Configure and connect DUT to controller. After control channel establishment, install four separate flows. Flow1 matches on OXM_OF_IN_PORT, OXM_OF_ETH_DST, OXM_OF_ETH_SRC, OXM_OF_ETH_TYPE, OXM_OF_IP_PROTO, OXM_OF_IPV4_SRC, OXM_OF_IPV4_DST, OXM_OF_TCP_SRC, and OXM_OF_TCP_DST with an output action to a data plane port. Flow2 matches on OXM_OF_IN_PORT, OXM_OF_ETH_DST, OXM_OF_ETH_SRC, OXM_OF_ETH_TYPE, OXM_OF_IP_PROTO, OXM_OF_IPV4_SRC, OXM_OF_IPV4_DST, OXM_OF_UDP_SRC, OXM_OF_UDP_DST, with an output action to a data plane port. Flow3 matches on OXM_OF_IN_PORT, OXM_OF_ETH_DST, OXM_OF_ETH_SRC, OXM_OF_ETH_TYPE, OXM_OF_IP_PROTO, OXM_OF_IPV6_SRC, OXM_OF_IPV6_DST, OXM_OF_TCP_SRC, OXM_OF_TCP_DST, with an output action to a data plane port. Flow4 matches on OXM_OF_IN_PORT, OXM_OF_ETH_DST, OXM_OF_ETH_SRC, OXM_OF_ETH_TYPE, OXM_OF_IP_PROTO, OXM_OF_IPV6_SRC, OXM_OF_IPV6_DST, OXM_UDP_SRC, OXM_UDP_DST with an output action to a data plane port. Generate matching packets for each flow, and verify packets are forwarded to the correct data plane ports.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 90.60 all supported")

        delete_all_flows(self.controller)
        in_port, out_port,bad_port = openflow_ports(3)
        table_id = test_param_get("table", 0)
        priority=1
        actions=[ofp.action.output(port=out_port,max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        
        #Flow 1
        match = ofp.match([
                    ofp.oxm.eth_src_masked([0x00, 0x06, 0x07, 0x08, 0x09, 0x0a],
                                           [0x00, 0xff, 0xff, 0x0f, 0xff, 0xff]),
                    ofp.oxm.eth_dst_masked([0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
                                           [0x00, 0xff, 0xff, 0x0f, 0xff, 0xff]),
                    ofp.oxm.in_port(in_port),
                    ofp.oxm.eth_type(0x0800),
                    ofp.oxm.ip_proto(6),
                    ofp.oxm.ipv4_src_masked(0xc0a80001, 0xfffeffff),
                    ofp.oxm.ipv4_dst_masked(0xc0a80002, 0xfffeffff),
                    ofp.oxm.tcp_src(53),
                    ofp.oxm.tcp_dst(54), # change dst port to a port different from src port
                    ])
        req = ofp.message.flow_add(table_id=table_id,
                                   match= match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority)
        self.controller.message_send(req)
        reply, _= self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply,"The switch generated an OFPT_ERROR")
        matching_pkt = str(simple_tcp_packet(eth_dst ='00:01:02:f3:04:05',
                                             eth_src ='00:06:07:f8:09:0a',
                                             ip_src ='192.169.0.1',
                                             ip_dst='192.168.0.2',
                                             tcp_sport=53,
                                             tcp_dport=54))
        self.dataplane.send(in_port,matching_pkt)
        verify_packet(self,matching_pkt,out_port)
        logging.info("Packet in received for a matching packet")
        nonmatching_pkt = str(simple_tcp_packet(eth_dst ='00:01:02:f3:04:05',
                                             eth_src ='00:06:07:f8:09:0a',
                                             ip_src ='192.167.0.1',
                                             ip_dst='192.168.0.2',
                                             tcp_sport=53,
                                             tcp_dport=52))
        self.dataplane.send(in_port,nonmatching_pkt)
        verify_no_packet(self,nonmatching_pkt,out_port)
        logging.info("Packet in not received for a non matching packet")
        logging.info("Installing a different combination of match fields")

        #Flow 2
        match = ofp.match([
                ofp.oxm.eth_dst_masked([0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
                                       [0x00, 0xff, 0xff, 0x0f, 0xff, 0xff]),
                ofp.oxm.eth_src_masked([0x00, 0x06, 0x07, 0x08, 0x09, 0x0a],
                                       [0x00, 0xff, 0xff, 0x0f, 0xff, 0xff]),
                ofp.oxm.in_port(in_port),
                ofp.oxm.eth_type(0x0800),
                ofp.oxm.ip_proto(17),
                ofp.oxm.ipv4_src_masked(0xc0a80000, 0xfffff000),
                ofp.oxm.ipv4_dst_masked(0xc0a80000, 0xfffff000), # change ip dst to a address different from ip src
                ofp.oxm.udp_src(53),
                ofp.oxm.udp_dst(54), # change dst port to a port different from src port
                ])
        req = ofp.message.flow_add(table_id=table_id,
                                   match= match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply,"The switch generated an OFPT_ERROR")
        matching_pkt = str(simple_udp_packet(eth_dst ='00:01:02:f3:04:05',
                                             eth_src ='00:06:07:f8:09:0a',
                                             ip_src ='192.168.4.2',
                                             ip_dst='192.168.4.3',
                                             udp_sport=53,
                                             udp_dport=54))
        self.dataplane.send(in_port,matching_pkt)
        verify_packet(self,matching_pkt,out_port)
        logging.info("Packet in received for a matching packet")
        nonmatching_pkt = str(simple_udp_packet(eth_dst ='00:01:02:f3:04:05',
                                             eth_src ='00:06:07:f8:09:0a',
                                             ip_src ='192.168.4.2',
                                             ip_dst='192.167.255.255',
                                             udp_sport=53,
                                             udp_dport=55))
        self.dataplane.send(in_port,nonmatching_pkt)
        verify_no_packet(self,nonmatching_pkt,out_port)
        logging.info("Packet in not received for a non matching packet")

        #Flow3
        flow =       "2001:0db8:85a3::0001"
        mask =       "ffff:ffff:ffff::000f"
        match = ofp.match([
                ofp.oxm.eth_dst_masked([0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
                                       [0x00, 0xff, 0xff, 0x0f, 0xff, 0xff]),
                ofp.oxm.eth_src_masked([0x00, 0x06, 0x07, 0x08, 0x09, 0x0a],
                                       [0x00, 0xff, 0xff, 0x0f, 0xff, 0xff]),
                ofp.oxm.in_port(in_port),
                ofp.oxm.eth_type(0x86dd),
                ofp.oxm.ip_proto(6),
                ofp.oxm.ipv6_src_masked(parse_ipv6(flow), parse_ipv6(mask)),
                ofp.oxm.ipv6_dst_masked(parse_ipv6(flow), parse_ipv6(mask)),
                ofp.oxm.tcp_src(53),
                ofp.oxm.tcp_dst(54), # change dst port to a port different from src port
                ])
        req = ofp.message.flow_add(table_id=table_id,
                                   match= match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply,"The switch generated an OFPT_ERROR")
        matching_pkt = str(simple_tcpv6_packet(eth_dst ='00:01:02:f3:04:05',
                                             eth_src ='00:06:07:f8:09:0a',
                                             ipv6_src ='2001:0db8:85a3::8a2e:0370:7331',
                                             ipv6_dst='2001:0db8:85a3::8a2e:0370:7331',
                                             tcp_sport=53,
                                             tcp_dport=54))
        self.dataplane.send(in_port,matching_pkt)
        verify_packet(self,matching_pkt,out_port)
        logging.info("Packet in received for a matching packet")
        nonmatching_pkt = str(simple_tcpv6_packet(eth_dst ='00:01:02:f3:04:05',
                                             eth_src ='00:06:07:f8:09:0a',
                                             ipv6_src ='2001:0db8:85a2::0001',
                                             ipv6_dst='2001:0db8:85a2::0001',
                                             tcp_sport=53,
                                             tcp_dport=55))
        self.dataplane.send(in_port,nonmatching_pkt)
        verify_no_packet(self,nonmatching_pkt,out_port)
        logging.info("Packet in not received for a non matching packet")

        #Flow4
        match = ofp.match([
                ofp.oxm.eth_dst_masked([0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
                                       [0x00, 0xff, 0xff, 0x0f, 0xff, 0xff]),
                ofp.oxm.eth_src_masked([0x00, 0x06, 0x07, 0x08, 0x09, 0x0a],
                                       [0x00, 0xff, 0xff, 0x0f, 0xff, 0xff]),
                ofp.oxm.in_port(in_port),
                ofp.oxm.eth_type(0x86dd),
                ofp.oxm.ip_proto(17),
                ofp.oxm.ipv6_src_masked(parse_ipv6(flow), parse_ipv6(mask)),
                ofp.oxm.ipv6_dst_masked(parse_ipv6(flow), parse_ipv6(mask)),
                ofp.oxm.udp_src(53),
                ofp.oxm.udp_dst(54), # change dst port to a port different from src port
                ])
        req = ofp.message.flow_add(table_id=table_id,
                                   match= match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply,"The switch generated an OFPT_ERROR")
        matching_pkt = str(simple_udpv6_packet(eth_dst ='00:01:02:f3:04:05',
                                             eth_src ='00:06:07:f8:09:0a',
                                             ipv6_src ='2001:0db8:85a3::8a2e:0370:7331',
                                             ipv6_dst='2001:0db8:85a3::8a2e:0370:7331',
                                             udp_sport=53,
                                             udp_dport=54))
        self.dataplane.send(in_port,matching_pkt)
        verify_packet(self,matching_pkt,out_port)
        logging.info("Packet in received for a matching packet")
        nonmatching_pkt = str(simple_udpv6_packet(eth_dst ='ff:01:02:f3:04:05',
                                             eth_src ='ff:06:07:f8:09:0a',
                                             ipv6_src ='2001:0db8:85a2::0001',
                                             ipv6_dst='2001:0db8:85a2::0001',
                                             udp_sport=53,
                                             udp_dport=55))
        self.dataplane.send(in_port,nonmatching_pkt)
        verify_no_packet(self,nonmatching_pkt,out_port)
        logging.info("Packet in not received for a non matching packet")
        