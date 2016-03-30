# Distributed under the OpenFlow Software License (see LICENSE)
# Copyright (c) 2010 The Board of Trustees of The Leland Stanford Junior University
# Copyright (c) 2012, 2013 Big Switch Networks, Inc.
# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Pan Zhang
"""
Test suite 60 verifies the device under test is able to match on the thirteen OXM types marked as required in table 11 of the OpenFlow v1.3 Specification.
Remarks
Masked OXM types
Because masked OXM types are not explicitly marked as required, test suite 60 does not verify matching on masked OXM types.
Basic conformance
To satisfy the basic requirements an OpenFlow enabled device must pass test cases 60.10 - 60.140.

"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
import oftest.packet as scapy

from oftest.testutils import *
from oftest.parse import parse_ipv6
from oftest.oflog import *
from loxi.of13.oxm import *

class Testcase_60_10_list_matches_per_table(base_tests.SimpleDataPlane):
    """
    Purpose
    Different tables may support different match fields. Here, we check that the 13 required match fields are each supported in at least one table. We also gather the information what match groups are supported per table.

    Methodology
    Configure and connect DUT to controller. If device is not properly configured upon connection, use table configuration messages to setup the device for the correct test profile. Verify device reports support for all required match fields defined in table 11 of the v1.3.4 OpenFlow Specification as required by the correct test profile.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 60.10 Request the list of supported tables and matches per table")
        delete_all_flows(self.controller)

        required_match_fields = ["in_port", "eth_dst", "eth_dst_masked", "eth_src", "eth_src_masked", "eth_type", "ipv4_src", "ipv4_src_masked",
                          "ipv4_dst", "ipv4_dst_masked", "ipv6_src", "ipv6_src_masked", "ipv6_dst", "ipv6_dst_masked","ip_proto", 
                          "ip_proto_masked","tcp_src", "tcp_src_masked", "tcp_dst", "tcp_dst_masked", "udp_src", "udp_src_masked", "udp_dst",
                          "udp_dst_masked"]

        req = ofp.message.table_features_stats_request()
        res = get_stats(self,req)
        self.assertIsNotNone(res, "Didn't receive table stats information.")
        supported_matches_fields = [] 
        optional_matches_fields = [] 
        unknown_matches_fields = [] 
        unsupported_matches_fields = [] 
        for stats in res:
            for prop in stats.properties:
                if prop.type == ofp.const.OFPTFPT_MATCH:
                    for oxm_id in prop.oxm_ids:
                        if oxm_id.value not in oxm.subtypes.keys():
                            unknown_matches_fields.append(oxm_id.value)
                        elif oxm.subtypes[oxm_id.value].__name__ in required_match_fields:
                            if oxm.subtypes[oxm_id.value].__name__ not in supported_matches_fields:
                                supported_matches_fields.append(oxm.subtypes[oxm_id.value].__name__)
                        elif oxm.subtypes[oxm_id.value].__name__ not in required_match_fields:
                            if oxm.subtypes[oxm_id.value].__name__ not in optional_matches_fields:
                                optional_matches_fields.append(oxm.subtypes[oxm_id.value].__name__)
        
        
        for match in supported_matches_fields:
            if match or match.endswith("_masked") in required_match_fields:
                logging.info("Support by DUT : %s " %match)
            else:
                logging.info("Not Support by DUT : %s " %match)
                unsupported_matches_fields.append(match)
        
        if len(optional_matches_fields) != 0:
            for match in optional_matches_fields:
                logging.info("Optional Support by DUT : %s " %match)
        
        self.assertEqual(len(unsupported_matches_fields), 0, "Some required match fields are not supported by DUT.")
        logging.info("All the required match fields are supported by DUT.")
       

class Testcase_60_20_OXM_OF_IN_PORT(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify the switch is able to match on the previously named field as a single header field match (under the given Pre-requisites for the match).

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), action is forwarding to an output port. Send a matching packet on the data plane. Verify the packet is received only at the port specified in the flow action. Send a non-matching packet, verify the flow does not forward it but a table-miss is triggered.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 60.20 OXM_OF_IN_PORT: Ingress Port.")
        delete_all_flows(self.controller)
        in_port, out_port, bad_port = openflow_ports(3)
        table_id = test_param_get("table",0)
        
        logging.info("Inserting table-miss flows")
        request = ofp.message.flow_add(
            table_id=table_id,
            instructions=[
                ofp.instruction.apply_actions(
                    actions=[
                        ofp.action.output(
                            port=ofp.OFPP_CONTROLLER,
                            max_len=ofp.OFPCML_NO_BUFFER)])],
            buffer_id=ofp.OFP_NO_BUFFER,
            priority=0)
        self.controller.message_send(request)
        reply, _ = self.controller.poll(exp_msg = ofp.OFPT_ERROR, timeout = 3)
        self.assertIsNone(reply, "Received error message, could not install the flow")
        logging.info("Installed the flow successfully")
        
        logging.info("Inserting flow sending in_port matching packets to port %d", out_port)
        match = ofp.match([ofp.oxm.in_port(in_port)])
        pkt = simple_tcp_packet()
        req = ofp.message.flow_add(table_id = table_id,
                                    match = match,
                                    instructions=[ofp.instruction.apply_actions(
                                        actions = [ofp.action.output(
                                                                    port = out_port,
                                                                    max_len = ofp.OFPCML_NO_BUFFER)])],
                                    buffer_id = ofp.OFP_NO_BUFFER,
                                    priority = 1)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg = ofp.OFPT_ERROR, timeout = 3)
        self.assertIsNone(reply, "Received error message, could not install the flow")
        logging.info("Installed the flow successfully")

        logging.info("Sending a matching packet to match on %d", in_port)
        strpkt=str(pkt)
        self.dataplane.send(in_port, strpkt)
	verify_packets(self,strpkt,[out_port])
        logging.info("Received packet on outport %d", out_port)
        logging.info("Sending a non-matching packet to match on %d", bad_port)
        self.dataplane.send(bad_port, strpkt)
        verify_no_packet(self, strpkt, out_port)
        logging.info("Did not receive a packet on %d", out_port)
        verify_packet_in(self, strpkt, bad_port, None)
        logging.info("Received the expected packet-in message")


class MatchTest(base_tests.SimpleDataPlane):
    """
    Base class for match tests
    """

    def verify_match(self, match, matching, nonmatching):
        """
        Verify matching behavior

        Checks that all the packets in 'matching' match 'match', and that
        the packets in 'nonmatching' do not.

        'match' is a LOXI match object. 'matching' and 'nonmatching' are
        dicts mapping from string names (used in log messages) to string
        packet data.
        """
        in_port, out_port = openflow_ports(2)
        table_id = test_param_get("table", 0)

        logging.info("Running match test for %s", match.show())

        delete_all_flows(self.controller)

        logging.info("Inserting flow sending matching packets to port %d", out_port)
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=[
                    ofp.instruction.apply_actions(
                        actions=[
                            ofp.action.output(
                                port=out_port,
                                max_len=ofp.OFPCML_NO_BUFFER)])],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        reply, _ = self.controller.poll(exp_msg = ofp.OFPT_ERROR, timeout = 3)
        self.assertIsNone(reply, "Received error message, could not install the flow")
        logging.info("Installed the flow successfully")

        logging.info("Inserting match-all flow sending packets to controller")
        request = ofp.message.flow_add(
            table_id=table_id,
            instructions=[
                ofp.instruction.apply_actions(
                    actions=[
                        ofp.action.output(
                            port=ofp.OFPP_CONTROLLER,
                            max_len=ofp.OFPCML_NO_BUFFER)])],
            buffer_id=ofp.OFP_NO_BUFFER,
            priority=0)
        self.controller.message_send(request)
        reply, _ = self.controller.poll(exp_msg = ofp.OFPT_ERROR, timeout = 3)
        self.assertIsNone(reply, "Received error message, could not install the flow")
        logging.info("Installed the flow successfully")

        do_barrier(self.controller)

        for name, pkt in matching.items():
            logging.info("Sending matching packet %s, expecting output to port %d", repr(name), out_port)
            pktstr = str(pkt)
            self.dataplane.send(in_port, pktstr)
            verify_packets(self, pktstr, [out_port])

        for name, pkt in nonmatching.items():
            logging.info("Sending non-matching packet %s, expecting packet-in", repr(name))
            pktstr = str(pkt)
            self.dataplane.send(in_port, pktstr)
            #verify_packet_in(self, pktstr, in_port, ofp.OFPR_ACTION)
            verify_packet_in(self, pktstr, in_port, reason = None)




class Testcase_60_30_OXM_OF_ETH_DST(MatchTest):
    """
    Purpose
    Verify the switch is able to match on the previously named field as a single header field match (under the given Pre-requisites for the match).

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), action is forwarding to an output port. Send a matching packet on the data plane. Verify the packet is received only at the port specified in the flow action. Send a non-matching packet, verify the flow does not forward it but a table-miss is triggered.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 60.30 matching on ethernet destination")
        match = ofp.match([
            ofp.oxm.eth_dst([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])
        ])

        matching = {
            "00:01:02:03:04:05": simple_tcp_packet(eth_dst='00:01:02:03:04:05')
        }

        nonmatching = {
            "00:02:02:03:04:05": simple_tcp_packet(eth_dst='00:02:02:03:04:05')
        }

        self.verify_match(match, matching, nonmatching)



class Testcase_60_40_OXM_OF_ETH_SRC(MatchTest):
    """
    Purpose
    Verify the switch is able to match on the previously named field as a single header field match (under the given Pre-requisites for the match).

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), action is forwarding to an output port. Send a matching packet on the data plane. Verify the packet is received only at the port specified in the flow action. Send a non-matching packet, verify the flow does not forward it but a table-miss is triggered.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 60.40 matching on ethernet source")
        match = ofp.match([
            ofp.oxm.eth_src([0x00, 0x06, 0x07, 0x08, 0x09, 0x0a])
        ])

        matching = {
            "00:06:07:08:09:0a": simple_tcp_packet(eth_src='00:06:07:08:09:0a')
        }

        nonmatching = {
            "00:07:08:09:0a:0b": simple_tcp_packet(eth_src='00:07:08:09:0a:0b')
        }

        self.verify_match(match, matching, nonmatching)

class Testcase_60_50_ETH_TYPE(MatchTest):
    """
    Purpose
    Verify the switch is able to match on the previously named field as a single header field match (under the given Pre-requisites for the match).

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), action is forwarding to an output port. Send a matching packet on the data plane. Verify the packet is received only at the port specified in the flow action. Send a non-matching packet, verify the flow does not forward it, but a table-miss is triggered.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 60.50 for matching on Ethernet types")
        logging.info("---Running subtestcases")
        logging.info("Running for Ethernet type IPv4")
        match = ofp.match([
            ofp.oxm.eth_type(0x0800)
        ])

        snap_pkt = \
            scapy.Ether(dst='00:01:02:03:04:05', src='00:06:07:08:09:0a', type=48)/ \
            scapy.LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)/ \
            scapy.SNAP(OUI=0x000000, code=0x0800)/ \
            scapy.IP(src='192.168.0.1', dst='192.168.0.2', proto=6)/ \
            scapy.TCP(sport=1234, dport=80)

        llc_pkt = \
            scapy.Ether(dst='00:01:02:03:04:05', src='00:06:07:08:09:0a', type=17)/ \
            scapy.LLC(dsap=0xaa, ssap=0xab, ctrl=0x03)

        matching = {
            "ipv4/tcp": simple_tcp_packet(),
            "ipv4/udp": simple_udp_packet(),
            "ipv4/icmp": simple_icmp_packet(),
            #"vlan tagged": simple_tcp_packet(dl_vlan_enable=True, vlan_vid=2, vlan_pcp=3),
            #"qinq/tcp": qinq_tcp_packet(),
        }

        nonmatching = {
            "arp": simple_arp_packet(),
            "llc": llc_pkt,
            "ipv6/tcp": simple_tcpv6_packet(),
        }

        self.verify_match(match, matching, nonmatching)

        logging.info("---Running subtestcases")
        logging.info("Running for Ethernet Type IPv6")
        match = ofp.match([
            ofp.oxm.eth_type(0x86dd)
        ])

        matching = {
            "ipv6/tcp": simple_tcpv6_packet(),
            "ipv6/udp": simple_udpv6_packet(),
            "ipv6/icmp": simple_icmpv6_packet(),
            #"vlan tagged": simple_tcpv6_packet(dl_vlan_enable=True, vlan_vid=2, vlan_pcp=3),
        }

        nonmatching = {
            "ipv4/tcp": simple_tcp_packet(),
            "arp": simple_arp_packet(),
        }

        self.verify_match(match, matching, nonmatching)

        logging.info("---Running subtestcases")
        logging.info("Running for Ethernet Type ARP")
        match = ofp.match([
            ofp.oxm.eth_type(0x0806)
        ])

        matching = {
            "arp": simple_arp_packet(),
            #"vlan tagged": simple_arp_packet(vlan_vid=2, vlan_pcp=3),
        }

        nonmatching = {
            "ipv4/tcp": simple_tcp_packet(),
            "ipv6/tcp": simple_tcpv6_packet(),
        }

        self.verify_match(match, matching, nonmatching)



class Testcase_60_60_OXM_OF_IP_PROTO(MatchTest):
    """
    Purpose
    Verify the switch is able to match on the previously named field as a single header field match (under the given Pre-requisites for the match).

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), action is forwarding to an output port. Send a matching packet on the data plane. Verify the packet is received only at the port specified in the flow action. Send a non-matching packet, verify the flow does not forward it, but a table-miss is triggered.


    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 60.60 for matching on IPv6 and IPv4 Protocol number")
        logging.info("---Running subtestcases")
        logging.info("Running for IPv4Proto TCP")
        match = ofp.match([
            ofp.oxm.eth_type(0x0800),
            ofp.oxm.ip_proto(6),
        ])

        matching = {
            "tcp": simple_tcp_packet(),
        }

        nonmatching = {
            "udp": simple_udp_packet(),
            "icmp": simple_icmp_packet(),
        }

        self.verify_match(match, matching, nonmatching)


        logging.info("---Running subtestcases")
        logging.info("Running for IPv6Proto TCP")
        match = ofp.match([
            ofp.oxm.eth_type(0x86dd),
            ofp.oxm.ip_proto(6),
        ])

        matching = {
            "tcp": simple_tcpv6_packet(),
        }

        nonmatching = {
            "udp": simple_udpv6_packet(),
            "icmp": simple_icmpv6_packet(),
        }

        self.verify_match(match, matching, nonmatching)

        match = ofp.match([
            ofp.oxm.eth_type(0x0800),
            ofp.oxm.ip_proto(17),
        ])


        logging.info("---Running subtestcases")
        logging.info("Running for IPv4Proto UDP")
        matching = {
            "udp": simple_udp_packet(),
        }

        nonmatching = {
            "tcp": simple_tcp_packet(),
            "icmp": simple_icmp_packet(),
        }

        self.verify_match(match, matching, nonmatching)


        logging.info("---Running subtestcases")
        logging.info("Running for IPv6Proto UDP")
        match = ofp.match([
            ofp.oxm.eth_type(0x86dd),
            ofp.oxm.ip_proto(17),
        ])

        matching = {
            "udp": simple_udpv6_packet(),
        }

        nonmatching = {
            "tcp": simple_tcpv6_packet(),
            "icmp": simple_icmpv6_packet(),
        }

        self.verify_match(match, matching, nonmatching)



class Testcase_60_70_OXM_OF_IPv4_SRCSubnetMasked(MatchTest):
    """
    Purpose
    Verify the switch is able to match on the previously named field as a single header field match (under the given Pre-requisites for the match).

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), action is forwarding to an output port. Send a matching packet on the data plane. Verify the packet is received only at the port specified in the flow action. Send a non-matching packet, verify the flow does not forward it, but a table-miss is triggered.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 60.70 for matching on IPv4 src(subnet masked)")
        match = ofp.match([
            ofp.oxm.eth_type(0x0800),
            # 192.168.0.0/20 (255.255.240.0)
            ofp.oxm.ipv4_src(0xc0a80000),
        ])

        matching = {
            #"192.168.0.1": simple_tcp_packet(ip_src='192.168.0.1'),
            #"192.168.0.2": simple_tcp_packet(ip_src='192.168.0.2'),
            #"192.168.4.2": simple_tcp_packet(ip_src='192.168.4.2'),
            "192.168.0.0": simple_tcp_packet(ip_src='192.168.0.0'),
            #"192.168.15.255": simple_tcp_packet(ip_src='192.168.15.255'),
        }

        nonmatching = {
            "192.168.16.0": simple_tcp_packet(ip_src='192.168.16.0'),
            "192.167.255.255": simple_tcp_packet(ip_src='192.167.255.255'),
            "192.168.31.1": simple_tcp_packet(ip_src='192.168.31.1'),
        }

        self.verify_match(match, matching, nonmatching)



class Testcases_60_80_OXM_OF_IPV4_DSTSubnetMasked(MatchTest):
    """
    Purpose
    Verify the switch is able to match on the previously named field as a single header field match (under the given Pre-requisites for the match).

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), action is forwarding to an output port. Send a matching packet on the data plane. Verify the packet is received only at the port specified in the flow action. Send a non-matching packet, verify the flow does not forward it, but a table-miss is triggered.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 60.80 for matching on IPv4 dst(subnet masked)")
        match = ofp.match([
            ofp.oxm.eth_type(0x0800),
            # 192.168.0.0/20 (255.255.240.0)
            ofp.oxm.ipv4_dst(0xc0a80000),
        ])

        matching = {
            #"192.168.0.1": simple_tcp_packet(ip_dst='192.168.0.1'),
            #"192.168.0.2": simple_tcp_packet(ip_dst='192.168.0.2'),
            #"192.168.4.2": simple_tcp_packet(ip_dst='192.168.4.2'),
            "192.168.0.0": simple_tcp_packet(ip_dst='192.168.0.0'),
            #"192.168.15.255": simple_tcp_packet(ip_dst='192.168.15.255'),
        }

        nonmatching = {
            "192.168.16.0": simple_tcp_packet(ip_dst='192.168.16.0'),
            "192.167.255.255": simple_tcp_packet(ip_dst='192.167.255.255'),
            "192.168.31.1": simple_tcp_packet(ip_dst='192.168.31.1'),
        }

        self.verify_match(match, matching, nonmatching)



class Testcase_60_90_OXM_OF_IPV6_SRCSubnetMasked(MatchTest):
    """
    Purpose
    Verify the switch is able to match on the previously named field as a single header field match (under the given Pre-requisites for the match).

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), action is forwarding to an output port. Send a matching packet on the data plane. Verify the packet is received only at the port specified in the flow action. Send a non-matching packet, verify the flow does not forward it, but a table-miss is triggered.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 60.90 for matching on IPv6 src(subnet masked)")
        flow =       "2001:0db8:85a3::"
        mask =       "ffff:ffff:ffff::"
        correct1 =   "2001:0db8:85a3::8a2e:0370:7331"
        correct2 =   "2001:0db8:85a3::ffff:ffff:ffff"
        incorrect1 = "2001:0db8:85a2::"

        match = ofp.match([
            ofp.oxm.eth_type(0x86dd),
            ofp.oxm.ipv6_src(parse_ipv6(flow)),
        ])

        matching = {
            "flow": simple_tcpv6_packet(ipv6_src=flow),
            #"correct1": simple_tcpv6_packet(ipv6_src=correct1),
            #"correct2": simple_tcpv6_packet(ipv6_src=correct2),
        }

        nonmatching = {
            "incorrect1": simple_tcpv6_packet(ipv6_src=incorrect1),
        }

        self.verify_match(match, matching, nonmatching)



class Testcase_60_100_OXM_OF_IPv6_DSTSubnetMasked(MatchTest):
    """
    Purpose
    Verify the switch is able to match on the previously named field as a single header field match (under the given Pre-requisites for the match).

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), action is forwarding to an output port. Send a matching packet on the data plane. Verify the packet is received only at the port specified in the flow action. Send a non-matching packet, verify the flow does not forward it, but a table-miss is triggered.


    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 60.100 for matching on IPv6 dst(subnet masked)")
        flow =       "2001:0db8:85a3::"
        mask =       "ffff:ffff:ffff::"
        correct1 =   "2001:0db8:85a3::8a2e:0370:7331"
        correct2 =   "2001:0db8:85a3::ffff:ffff:ffff"
        incorrect1 = "2001:0db8:85a2::"

        match = ofp.match([
            ofp.oxm.eth_type(0x86dd),
            ofp.oxm.ipv6_dst(parse_ipv6(flow)),
        ])

        matching = {
            "flow": simple_tcpv6_packet(ipv6_dst=flow),
            #"correct1": simple_tcpv6_packet(ipv6_dst=correct1),
            #"correct2": simple_tcpv6_packet(ipv6_dst=correct2),
        }

        nonmatching = {
            "incorrect1": simple_tcpv6_packet(ipv6_dst=incorrect1),
        }

        self.verify_match(match, matching, nonmatching)



class Testcase_60_110_OXM_OF_TCP_SRC(MatchTest):
    """
    Match on ipv4 tcp source port
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 60.110 for matching on TCP Src port")
        match = ofp.match([
            ofp.oxm.eth_type(0x0800),
            ofp.oxm.ip_proto(6),
            ofp.oxm.tcp_src(53),
        ])

        matching = {
            "tcp sport=53": simple_tcp_packet(tcp_sport=53),
        }

        nonmatching = {
            "tcp sport=52": simple_tcp_packet(tcp_sport=52),
            "udp sport=53": simple_udp_packet(udp_sport=53),
        }

        self.verify_match(match, matching, nonmatching)



class Testcase_60_120_OXM_OF_TCP_DST(MatchTest):
    """
    Purpose
    Verify the switch is able to match on the previously named field as a single header field match (under the given Pre-requisites for the match).

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), action is forwarding to an output port. Send a matching packet on the data plane. Verify the packet is received only at the port specified in the flow action. Send a non-matching packet, verify the flow does not forward it, but a table-miss is triggered.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 60.120 for matching on TCP Dst port")
        match = ofp.match([
            ofp.oxm.eth_type(0x0800),
            ofp.oxm.ip_proto(6),
            ofp.oxm.tcp_dst(53),
        ])

        matching = {
            "tcp dport=53": simple_tcp_packet(tcp_dport=53),
        }

        nonmatching = {
            "tcp dport=52": simple_tcp_packet(tcp_dport=52),
            "udp dport=53": simple_udp_packet(udp_dport=53),
        }

        self.verify_match(match, matching, nonmatching)



class Testcase_60_130_OXM_OF_UDP_SRC(MatchTest):
    """
    Purpose
    Verify the switch is able to match on the previously named field as a single header field match (under the given Pre-requisites for the match).

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), action is forwarding to an output port. Send a matching packet on the data plane. Verify the packet is received only at the port specified in the flow action. Send a non-matching packet, verify the flow does not forward it, but a table-miss is triggered.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 60.120 for matching on UDP Src port")
        match = ofp.match([
            ofp.oxm.eth_type(0x0800),
            ofp.oxm.ip_proto(17),
            ofp.oxm.udp_src(53),
        ])

        matching = {
            "udp sport=53": simple_udp_packet(udp_sport=53),
        }

        nonmatching = {
            "udp sport=52": simple_udp_packet(udp_sport=52),
            "tcp sport=53": simple_tcp_packet(tcp_sport=53),
        }

        self.verify_match(match, matching, nonmatching)



class Testcase_60_140_OXM_OF_UDP_DST(MatchTest):
    """
    Purpose
    Verify the switch is able to match on the previously named field as a single header field match (under the given Pre-requisites for the match).

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), action is forwarding to an output port. Send a matching packet on the data plane. Verify the packet is received only at the port specified in the flow action. Send a non-matching packet, verify the flow does not forward it, but a table-miss is triggered.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 60.120 for matching on UDP Dst port")
        match = ofp.match([
            ofp.oxm.eth_type(0x0800),
            ofp.oxm.ip_proto(17),
            ofp.oxm.udp_dst(53),
        ])

        matching = {
            "udp dport=53": simple_udp_packet(udp_dport=53),
        }

        nonmatching = {
            "udp dport=52": simple_udp_packet(udp_dport=52),
            "tcp dport=53": simple_tcp_packet(tcp_dport=53),
        }

        self.verify_match(match, matching, nonmatching)
"""
class Testcase_IPv4_DST_CIDR_masking(MatchTest):
    """"""
    Purpose
    Verify the switch is able to match on the previously named field as a single header field match (under the given Pre-requisites for the match).

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), action is forwarding to an output port. Send a matching packet on the data plane. Verify the packet is received only at the port specified in the flow action. Send a non-matching packet, verify the flow does not forward it, but a table-miss is triggered.

    """"""
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase for matching on IPv4 CIDR masking")
        match = ofp.match([
            ofp.oxm.eth_type(0x0800),
            # 192.168.0.0/20 (255.255.240.0)
            ofp.oxm.ipv4_dst_masked(0xc0a80000, 0xfffff000),
        ])

        matching = {
            "192.168.0.1": simple_tcp_packet(ip_dst='192.168.0.1'),
            "192.168.0.2": simple_tcp_packet(ip_dst='192.168.0.2'),
            "192.168.4.2": simple_tcp_packet(ip_dst='192.168.4.2'),
            "192.168.0.0": simple_tcp_packet(ip_dst='192.168.0.0'),
            "192.168.15.255": simple_tcp_packet(ip_dst='192.168.15.255'),
        }

        nonmatching = {
            "192.168.16.0": simple_tcp_packet(ip_dst='192.168.16.0'),
            "192.167.255.255": simple_tcp_packet(ip_dst='192.167.255.255'),
            "192.168.31.1": simple_tcp_packet(ip_dst='192.168.31.1'),
        }

        self.verify_match(match, matching, nonmatching)
""""""
class Testcase_IPv6_DST_CIDR_Masking(MatchTest):
    """"""
    Purpose
    Verify the switch is able to match on the previously named field as a single header field match (under the given Pre-requisites for the match).

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), action is forwarding to an output port. Send a matching packet on the data plane. Verify the packet is received only at the port specified in the flow action. Send a non-matching packet, verify the flow does not forward it, but a table-miss is triggered.


    """"""
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase   for matching on IPv6 dst CIDR masking")
        flow =       "2001:0db8:85a3::"
        mask =       "ffff:ffff:fffe::"
        correct1 =   "2001:0db8:85a3::8a2e:0370:7331"
        correct2 =   "2001:0db8:85a2::ffff:ffff:ffff"
        incorrect1 = "2001:0db8:85a1::"

        match = ofp.match([
            ofp.oxm.eth_type(0x86dd),
            ofp.oxm.ipv6_dst_masked(parse_ipv6(flow), parse_ipv6(mask)),
        ])

        matching = {
            "flow": simple_tcpv6_packet(ipv6_dst=flow),
            "correct1": simple_tcpv6_packet(ipv6_dst=correct1),
            "correct2": simple_tcpv6_packet(ipv6_dst=correct2),
        }

        nonmatching = {
            "incorrect1": simple_tcpv6_packet(ipv6_dst=incorrect1),
        }

        self.verify_match(match, matching, nonmatching)
"""
