# Distributed under the OpenFlow Software License (see LICENSE)
# Copyright (c) 2010 The Board of Trustees of The Leland Stanford Junior University
# Copyright (c) 2012, 2013 Big Switch Networks, Inc.
# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Pan Zhang
"""
Test suite 140 verifies the behavior of flow modification messages with a focus on testing overlapping flows, flow flags, and flow commands.
Basic conformance
To satisfy basic conformance an OpenFlow enabled device must pass test cases 140.10 - 140.150, and 140.170 - 140.220.

"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
import oftest.packet as scapy
from loxi.pp import pp

from oftest.testutils import *
from oftest.parse import parse_ipv6
from oftest.oflog import *
from time import sleep

class Testcase_140_10_Overlap_Check(base_tests.SimpleDataPlane):
    """
   
    Purpose
    Verify how the "OFPFC_ADD" is processed while "OFPFF_CHECK_OVERLAP" flag is set and how error reporting is handled.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the given Pre-requisites for the match). Add a second flow with an overlapping match, OFPFF_CHECK_OVERLAP flag set, and a different priority.  Verify flow gets installed in the flow table. Install a third flow with the OFPFF_CHECK_OVERLAP flag set, with a match overlapping that of flow 1, and a priority set equal to flow 1. Verify corresponding error type and code (OFPET_FLOW_MOD_FAILED type OFPFMFC_OVERLAP code) message is triggered and the flow is not added to the flow table.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 140.10 Add with overlap check - overlapping")

        in_port, out_port = openflow_ports(2)
        flags = ofp.OFPFF_CHECK_OVERLAP

        actions = [ofp.action.output(out_port)]

        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000, flags = flags)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forwarded packet to port %d with priority 1000", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1001, flags = flags)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forwarded packet to port %d with priority 1001", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")

        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000, flags = flags)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forwarded packet to port %d with priority 1000 and OVERLAP flag set", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "Did not receive error message.")
        #self.assertIsNone(reply, "Switch generated an error when inserting flow") 
        self.assertEqual(reply.err_type, ofp.OFPET_FLOW_MOD_FAILED, "The response type is not flow_mod_failed")
        logging.info("The DUT responded with the correct error type %s", reply.type)
        self.assertEqual(reply.code, ofp.OFPFMFC_OVERLAP, " The response code is not OFPFMFC_OVERLAP")
        logging.info("The DUT responded with the correct code %s", reply.code)
        logging.info(" Received Error message with the correct type and code field set")

        #pktstr = str(pkt)

        #logging.info("Sending packet, expecting output to port %d", out_port)
        #self.dataplane.send(in_port, pktstr)
        #verify_packets(self, pktstr, [out_port]) 

class Testcase_140_20_No_Overlap_Check(base_tests.SimpleDataPlane):
    """
    TODO: Verify the correctness of this testcase by using another DUT
    Purpose
    Verify how the "OFPFC_ADD" is processed while "OFPFF_CHECK_OVERLAP" flag is NOT set.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the given Pre-requisites for the match). Add a second flow with a non-overlapping match, the OFPFF_CHECK_OVERLAP flag set, and the same priority as flow one. Verify flow gets installed in the flow table. Install a third flow with the OFPFF_CHECK_OVERLAP flag not set, with a match overlapping that of flow 1, and a priority set equal to flow 1. Verify all three flows are installed in the flow table.


    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 140.20 Add with no overlap")

        in_port, out_port, overlap_port = openflow_ports(3)
        flags = ofp.OFPFF_CHECK_OVERLAP

        match1 = ofp.match([ofp.oxm.in_port(in_port)])
        match2 = ofp.match([ofp.oxm.eth_type(0x0800)])
        match3 = ofp.match([ofp.oxm.in_port(overlap_port)])

        actions = [ofp.action.output(out_port)]

        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=match1,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d with priority 1000 and match field in port", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=match2,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000, flags = flags)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forwarded packet to port %d with priority 1000 and non-overlapping match field", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")

        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=match3,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forwarded packet to port %d with priority 1000 overlapped match field and OVERLAP flag set", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow") 

class Testcase_140_30_Add_Identical(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify how the "OFPFC_ADD" is processed while "OFPFF_CHECK_OVERLAP" flag is set for identical flow entries in the table

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the given Pre-requisites for the match). Wait a set period of time. Add a second flow with an identical match, the OFPFF_CHECK_OVERLAP flag not set, the same priority as flow one, but a different cookie value from flow one. Verify that flow one has been removed, that flow two is installed, the second flow's cookie field is set correctly, and the flow's duration counter has reset.


    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 140.30 Add Identical flows")

        in_port, out_port = openflow_ports(2)
        flags = ofp.OFPFF_CHECK_OVERLAP

        actions = [ofp.action.output(out_port)]
        match = ofp.match([ofp.oxm.eth_type(0x0800)])
        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000, cookie = 1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d with cookie 1000", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")
        sleep(5)
        do_barrier(self.controller)
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000, cookie = 1001)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d with cookie 1001, flag not set", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        stats = get_flow_stats(self, match = ofp.match(), table_id = test_param_get("table", 0))
        table_stats = get_stats(self, ofp.message.table_stats_request())
        self.assertIsNotNone(stats,"Did not receive flow stats reply messsage")
        self.assertEqual(table_stats[test_param_get("table", 0)].active_count, 1, "active flow count is not 1")
        self.assertEqual(stats[0].cookie, 1001, "Cookie did not change")


class Testcase_140_40_Add_Reset_Counters(base_tests.SimpleDataPlane):
    """
    
    Purpose
    Verify counters are cleared when "OFPFC_ADD" is processed and "OFPFF_CHECK_OVERLAP" and "OFPFF_RESET_COUNTS" flags are set.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the given Pre-requisites for the match). Wait a set period of time. Create some data plane traffic matching the flow so the counters are increased. Add a second flow with an identical match, the OFPFF_CHECK_OVERLAP flag not set, the OFPFF_RESET_COUNTS flag set, and the same priority as flow one, but a different cookie value from flow one. Verify that flow one has been removed, that flow two is installed, the second flow's cookie field is set correctly, and all counters have been reset.


    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 140.40 Add with reset counters flag set")

        in_port, out_port = openflow_ports(2)
        flags = ofp.OFPFF_RESET_COUNTS


        actions = [ofp.action.output(out_port)]
        match = ofp.match([ofp.oxm.eth_type(0x0800)])
        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000, cookie = 1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d with cookie 1000", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")
        sleep(5)
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))#send a packet
	sleep(5)
        stats = get_flow_stats(self, match = ofp.match(), table_id = test_param_get("table", 0))
        self.assertTrue(stats[0].packet_count > 0, "The packet count is not incrmented")
        self.assertTrue(stats[0].byte_count > 0, "The byte count is not incrmented")

        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,flags = flags,
                priority=1000, cookie = 1001)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d with cookie 1001, flag not set", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
	sleep(5)
        stats = get_flow_stats(self, match = ofp.match(), table_id = test_param_get("table", 0))
        table_stats = get_stats(self, ofp.message.table_stats_request())
        self.assertIsNotNone(stats,"Did not receive flow stats reply messsage")
        self.assertEqual(table_stats[test_param_get("table", 0)].active_count, 1, "active flow count is not 1")
        self.assertEqual(stats[0].cookie, 1001, "Cookie did not change")
        self.assertEqual(stats[0].packet_count, 0, "The packet count is not reset")
        self.assertEqual(stats[0].byte_count,0, "The byte count is not reset")
        
"""
class Testcase_140_50_Add_Reset_Counters_Flag_Not_Set(base_tests.SimpleDataPlane):
    
    Purpose
    Verify counters are replaced when "OFPFC_ADD" is processed and "OFPFF_CHECK_OVERLAP" flag is set and "OFPFF_RESET_COUNTS" flag is not set.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the given Pre-requisites for the match). Wait a set period of time. Add a second flow with an identical match, the OFPFF_CHECK_OVERLAP flag not set, the same priority as flow one, but a different cookie value from flow one. Verify that flow one has been removed, that flow two is installed, the second flow's cookie field is set correctly, and the flow's duration counter has reset.


    
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 140.50 Add with Reset Counters Flag not Set")

        in_port, out_port = openflow_ports(2)
        flags = ofp.OFPFF_CHECK_OVERLAP

        actions = [ofp.action.output(out_port)]

        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000, cookie = 1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d with cookie 1000", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")
        sleep(5)
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))#send a packet
        stats = get_flow_stats(self, match = ofp.match(), table_id = test_param_get("table", 0))
        self.assertTrue(stats[0].packet_count > 0, "The packet count is not incrmented")
        self.assertTrue(stats[0].byte_count > 0, "The byte count is not incrmented")
        replace_packet_count = stats[0].packet_count
        replace_byte_count = stats[0].byte_count

        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000, cookie = 1001)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d with cookie 1001, flag not set", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        stats = get_flow_stats(self, match = ofp.match(), table_id = test_param_get("table", 0))
        table_stats = get_stats(self, ofp.message.table_stats_request())
        self.assertIsNotNone(stats,"Did not receive flow stats reply messsage")
        self.assertEqual(table_stats[test_param_get("table", 0)].active_count, 1, "active flow count is not 1")
        self.assertEqual(stats[0].cookie, 1001, "Cookie did not change")
        self.assertEqual(stats[0].packet_count, replace_packet_count, "The packet count is not replaced")
        self.assertEqual(stats[0].byte_count,replace_byte_count, "The byte count is not replaced")
        
"""
class Testcase_140_60_Add_no_flow_removed(base_tests.SimpleDataPlane):
    """
    TODO: Verify the correctness of the testcase by using another DUT
    Purpose
    Verify flow-removed msg status when "OFPFC_ADD" is processed and "OFPFF_CHECK_OVERLAP" flag is set.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the given Pre-requisites for the match), with the flow-removed flag set. Add a second flow with an identical match, the OFPFF_CHECK_OVERLAP flag not set, , and the same priority as flow one, but a different cookie value from flow one. Verify that flow one has been removed, that flow two is installed, the second flow's cookie field is set correctly. Verify no flow removed message was generated


    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 140.60 Add generates no flow removed message")

        in_port, out_port = openflow_ports(2)
        flags = ofp.OFPFF_SEND_FLOW_REM

        match = ofp.match([ofp.oxm.eth_type(0x0800)])
        actions = [ofp.action.output(out_port)]

        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000, cookie = 1000, flags = flags)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d with cookie 1000", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")
        sleep(5)
        do_barrier(self.controller)
        #self.dataplane.send(in_port, str(pkt))#send a packet
        #stats = get_flow_stats(self, match = ofp.match(), table_id = 0)
        #self.assertTrue(stats[0].packet_count > 0, "The packet count is not incrmented")
        #self.assertTrue(stats[0].byte_count > 0, "The byte count is not incrmented")

        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000, cookie = 1001)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d with cookie 1001, flag not set", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_FLOW_REMOVED, timeout=3)
        self.assertIsNone(reply, "Received flow removed message")
        stats = get_flow_stats(self, match = ofp.match(), table_id = test_param_get("table", 0))
        table_stats = get_stats(self, ofp.message.table_stats_request())
        self.assertIsNotNone(stats,"Did not receive flow stats reply messsage")
        self.assertEqual(table_stats[test_param_get("table", 0)].active_count, 1, "active flow count is not 1")
        self.assertEqual(stats[0].cookie, 1001, "Cookie did not change")
        #self.assertEqual(stats[0].packet_count, 0, "The packet count is not reset")
        #self.assertEqual(stats[0].byte_count,0, "The byte count is not reset")


class Testcase_140_70_Modify_Preserved_fields(base_tests.SimpleDataPlane):
    """
    Purpose
    For ofp_flow_mod messages using a modify or modify_strict command, verify that the instruction field of all matching flows are updated. In addition verify that cookies, timeouts, flags, counters, and durations are not modified. 

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the given Pre-requisites for the match). Modify this flows instructions. verify its cookie, idle_timeout, hard_timeout, flags, counters and duration fields are left unchanged


    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 140.70 modify preserved fields")

        in_port, out_port = openflow_ports(2)
        flags = ofp.OFPFF_SEND_FLOW_REM


        actions = [ofp.action.output(out_port)]
        match = ofp.match([ofp.oxm.eth_type(0x0800)])
        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000, cookie = 1000, hard_timeout = 100, idle_timeout = 100, flags = flags)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d with cookie 1000", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")
        sleep(5)
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))#send a packet
	sleep(5)
        stats = get_flow_stats(self, match = ofp.match(), table_id = test_param_get("table", 0))
        packet_count1 = stats[0].packet_count
        byte_count1 = stats[0].byte_count
        #self.assertTrue(stats[0].packet_count > 0, "The packet count is not incrmented")
        #self.assertTrue(stats[0].byte_count > 0, "The byte count is not incrmented")

        request = ofp.message.flow_mod(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions([ofp.action.output(ofp.OFPP_CONTROLLER)])],
                buffer_id=ofp.OFP_NO_BUFFER,
                _command=ofp.OFPFC_MODIFY)
        self.controller.message_send(request)
        logging.info("Modifying the flow")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when modifying flow")
	sleep(5)
        stats = get_flow_stats(self, match = ofp.match(), table_id = test_param_get("table", 0))
        #table_stats = get_stats(self, ofp.message.table_stats_request())
        self.assertIsNotNone(stats,"Did not receive flow stats reply messsage")
        #self.assertEqual(table_stats[0].active_count, 1, "active flow count is not 1")
        self.assertEqual(stats[0].cookie, 1000, "Cookie is not unchanged")
        self.assertEqual(stats[0].packet_count, packet_count1, "The packet count is not unchanged")
        self.assertEqual(stats[0].byte_count,byte_count1, "The byte count is not unchanged")
        self.assertEqual(stats[0].hard_timeout,100, "The hard_timeout is not unchanged")
        self.assertEqual(stats[0].idle_timeout,100, "The idle_timeout is not unchanged")
        self.assertEqual(stats[0].flags,ofp.OFPFF_SEND_FLOW_REM, "The flags is not unchanged")


class Testcase_140_80_Modify_Reset_Countersflag(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify counters are cleared for "OFP_FLOW_MOD" with "OFPFF_RESET_COUNTS" flag set  

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the given Pre-requisites for the match). Send data plane traffic matching the installed flow. Modify this flow's instructions with the OFPFF_RESET_COUNTS flag set in the flow-mod command. verify its cookie, idle_timeout, hard_timeout, flags, and duration fields are left unchanged. Verify its counter fields are cleared.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 140.80 modify with reset counters flag set")

        in_port, out_port = openflow_ports(2)
        flags = ofp.OFPFF_RESET_COUNTS


        actions = [ofp.action.output(out_port)]
        match = ofp.match([ofp.oxm.eth_type(0x0800)])
        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000, cookie = 1000, hard_timeout = 100, idle_timeout = 100, flags = flags)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d with cookie 1000", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")
        sleep(5)
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))#send a packet
	sleep(5)
        stats = get_flow_stats(self, match = ofp.match(), table_id =test_param_get("table", 0))
        packet_count1 = stats[0].packet_count
        byte_count1 = stats[0].byte_count
        self.assertTrue(stats[0].packet_count > 0, "The packet count is not incrmented")
        self.assertTrue(stats[0].byte_count > 0, "The byte count is not incrmented")

        request = ofp.message.flow_mod(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions([ofp.action.output(ofp.OFPP_CONTROLLER)])],
                buffer_id=ofp.OFP_NO_BUFFER, flags = flags,
                _command=ofp.OFPFC_MODIFY)
        self.controller.message_send(request)
        logging.info("Modifying the flow")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when modifying flow")
	sleep(5)
        stats = get_flow_stats(self, match = ofp.match(), table_id = test_param_get("table", 0))
        #table_stats = get_stats(self, ofp.message.table_stats_request())
        self.assertIsNotNone(stats,"Did not receive flow stats reply messsage")
        #self.assertEqual(table_stats[0].active_count, 1, "active flow count is not 1")
        self.assertEqual(stats[0].cookie, 1000, "Cookie is not unchanged")
        self.assertEqual(stats[0].packet_count, 0, "The packet count is not cleared")
        self.assertEqual(stats[0].byte_count,0, "The byte count is not cleared")
        self.assertEqual(stats[0].hard_timeout,100, "The hard_timeout is not unchanged")
        self.assertEqual(stats[0].idle_timeout,100, "The idle_timeout is not unchanged")
        self.assertEqual(stats[0].flags,ofp.OFPFF_RESET_COUNTS, "The flags is not unchanged")

class Testcase_140_90_Modify_non_existent(base_tests.SimpleDataPlane):
    """
    Purpose
    Check error handling and table modification for "OFP_FLOW_MOD" with no table match.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, send OFPFC_MODIFY request for a flow not present in the table with matching field (under given Pre-requisites for match) and action as output port X. Verify no errors are received. Send a packet matching this flow, verify packet is dropped in switch. Packet is dropped since neither table-miss flow nor modify request was configured on switch.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 140.90 modify non-existent flow")

        in_port, out_port = openflow_ports(2)
        #flags = ofp.OFPFF_RESET_COUNTS

        actions = [ofp.action.output(out_port)]
        match = ofp.match([ofp.oxm.eth_type(0x0800)])
        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_modify(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,priority = 1000)
        self.controller.message_send(request)
        logging.info("Modifying a flow to forward packet to port %d", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when modifying flow")
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))
        verify_no_packet(self, str(pkt),out_port)

class Testcase_140_100_Default_delete(base_tests.SimpleDataPlane):
    """
    Purpose
    Check a flow is deleted for "OFPFC_DELETE" or "_STRICT"

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the Pre-requisites for the match) with action as output port X. Send a packet for matching field and verify packet is received on port X. Send a OFPFC_DELETE request for previous flow. Send the same packet as earlier and verify packet is not received by output port and dropped by the switch.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 140.100 Default delete")

        in_port, out_port = openflow_ports(2)
        #flags = ofp.OFPFF_RESET_COUNTS

        actions = [ofp.action.output(out_port)]
        match = ofp.match([ofp.oxm.eth_type(0x0800)])
        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_port)
        request = ofp.message.flow_delete(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                out_port = ofp.OFPP_ANY,
                out_group = ofp.OFPG_ANY,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 1000)
        self.controller.message_send(request)
        logging.info("deleting the previous flow")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when deleting flow")
        self.dataplane.send(in_port, str(pkt))
        verify_no_packet(self, str(pkt),out_port)

class Testcase_140_110_Delete_Flow_removed(base_tests.SimpleDataPlane):
    """
    Purpose
    Check a flow is deleted for "OFPFC_DELETE" or "_STRICT"

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the Pre-requisites for the match) with action as output port X. Send a packet for matching field and verify packet is received on port X. Send a OFPFC_DELETE request for previous flow. Send the same packet as earlier and verify packet is not received by output port and dropped by the switch.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 140.110 Delete with flow removed flag set")

        in_port, out_port = openflow_ports(2)
        flags = ofp.OFPFF_SEND_FLOW_REM

        actions = [ofp.action.output(out_port)]
        match = ofp.match([ofp.oxm.eth_type(0x0800)])
        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 1000, flags = flags)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_port)
        request = ofp.message.flow_delete(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                out_port = ofp.OFPP_ANY,
                out_group = ofp.OFPG_ANY,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 1000)
        self.controller.message_send(request)
        logging.info("deleting the previous flow")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_FLOW_REMOVED, timeout=3)
        self.assertIsNotNone(reply, "Switch did not generated flow removed message")
        self.dataplane.send(in_port, str(pkt))
        verify_no_packet(self, str(pkt),out_port)


class Testcase_140_120_Delete_nonexisting(base_tests.SimpleDataPlane):
    """
    Purpose
    Check error handling and table modification when "OFPFC_DELETE" sent for no matching flow 

    Methodology
    Configure and connect DUT to controller. After control channel establishment, send OFPMP_TABLE request. Calculate the active entries in  the table. Now send OFPFC_DELETE request for a flow not present in the table with matching field (under given Pre-requisites for match). Verify no errors are received. Send OFPMP_TABLE request. Verify the active entries are same as before the delete request.


    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 140.120 delete non existing entry")

        in_port, out_port = openflow_ports(2)
        #flags = ofp.OFPFF_SEND_FLOW_REM

        actions = [ofp.action.output(out_port)]

        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        table_stats = get_stats(self, ofp.message.table_stats_request())
        self.assertIsNotNone(table_stats,"Did not receive flow stats reply messsage")
        active_count = table_stats[test_param_get("table", 0)].active_count
        logging.info("Active flow entry: %d",active_count)

        request = ofp.message.flow_delete(
                table_id=test_param_get("table", 0),
                match=ofp.match([ofp.oxm.eth_type(0x08dd)]),
                out_port = ofp.OFPP_ANY,
                out_group = ofp.OFPG_ANY,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 1000)
        self.controller.message_send(request)
        logging.info("deleting a not existing flow")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error")
        #self.dataplane.send(in_port, str(pkt))
        #verify_no_packet(self, str(pkt),out_port)
        table_stats = get_stats(self, ofp.message.table_stats_request())
        self.assertIsNotNone(table_stats,"Did not receive flow stats reply messsage")
        self.assertEqual(table_stats[test_param_get("table", 0)].active_count, active_count, "The active counts are not equal")
        logging.info("The active counts are equal")

class Testcase_140_130_Priority_strict(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify how modify and delete strict vs non strict command is processed.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the Pre-requisites for the match) with action as output port X and priority p1. Add another flow with same match as previous flow with action as output port Y and priority p2. Verify flows are installed. Send a OFPFC_DELETE_STRICT request for flow 1 with appropriate match and priority p1. Verify only flow 1 is deleted and flow 2 remains in the switch table.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 140.130 Priority strict")

        in_port, out_port, out_portY = openflow_ports(3)
        #flags = ofp.OFPFF_SEND_FLOW_REM

        actions = [ofp.action.output(out_port)]
        match = ofp.match([ofp.oxm.eth_type(0x0800)])
        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_port)



        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions([ofp.action.output(out_portY)])],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 1001)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_portY)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_portY)



        request = ofp.message.flow_delete_strict(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                out_port = ofp.OFPP_ANY,
                out_group = ofp.OFPG_ANY,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 1000)
        self.controller.message_send(request)
        logging.info("deleting the previous flow")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error message")
        self.dataplane.send(in_port, str(pkt))
        verify_no_packet(self, str(pkt),out_port)
        verify_packet(self, str(pkt),out_portY)

class Testcase_140_140_Strict_delete(base_tests.SimpleDataPlane):
    """
    Purpose
    For ofp_flow_mod messages using a delete or delete_strict command, verify that the DUT removes all matching flows according to the behaviors defined for strict and nonstrict. 

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add first flow flow1 matching on a named field (under the Pre-requisites for the match) with action as output port X with priority 100. Add  second flow flow2 matching on a named field same as flow1 with action as output port Y with priority 200.  Add  third flow flow3 matching on a named field same as flow1 with action as output port Z with priority 300. Send a packet matching to above flow and verify it is received out of port Z. Send a OFPFC_DELETE_STRICT flow_mod request with the same match fields as before and priority 300. Send a packet matching above flow1 and verify it is now received on port Y instead of Z. Send OFPFC_DELETE flow_mod request with no match fields. Send a packet matching above flow1 and verify packet is dropped (table-miss) at switch.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 140.140 strict delete checks")
        ports = openflow_ports(4)
        in_port, out_port, out_portY, out_portZ = openflow_ports(4)
        #flags = ofp.OFPFF_SEND_FLOW_REM

        actions = [ofp.action.output(out_port)]
        match = ofp.match([ofp.oxm.eth_type(0x0800),
                           ofp.oxm.in_port(in_port)])
        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 100)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        sleep(1)
        do_barrier(self.controller)
        sleep(1)
        self.dataplane.send(in_port, str(pkt))
        sleep(1)
        verify_packet(self, str(pkt),out_port)
        sleep(1)



        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions([ofp.action.output(out_portY)])],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 200)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_portY)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        sleep(1)
        do_barrier(self.controller)
        sleep(1)
        self.dataplane.send(in_port, str(pkt))
        sleep(1)
        verify_packet(self, str(pkt),out_portY)
        sleep(1)



        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions([ofp.action.output(out_portZ)])],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 300)
        self.controller.message_send(request)
        sleep(1)
        logging.info("Inserting a flow to forward packet to port %d", out_portZ)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
        sleep(1)
        self.dataplane.send(in_port, str(pkt))
        sleep(1)
        verify_packet(self, str(pkt),out_portZ)
        sleep(1)


        request = ofp.message.flow_delete_strict(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                out_port = ofp.OFPP_ANY,
                out_group = ofp.OFPG_ANY,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 300)
        self.controller.message_send(request)
        logging.info("deleting the previous flow")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error message")
        self.dataplane.send(in_port, str(pkt))
        sleep(1)
        #verify_no_packet(self, str(pkt),out_port)
        verify_packet(self, str(pkt),out_portY)
        sleep(1)



        request = ofp.message.flow_delete(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                out_port = ofp.OFPP_ANY,
                out_group = ofp.OFPG_ANY,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 300)
        self.controller.message_send(request)
        logging.info("deleting the previous flow")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error message")
        self.dataplane.send(in_port, str(pkt))
        #verify_no_packet(self, str(pkt),out_port)
        verify_no_other_packets(self)


class Testcase_140_150_Nonstrict_delete(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify behavior of "non-strict" version for exact or more specific match 

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add first flow flow1 matching a named field A (under the Pre-requisites for the match) with specific value, dst_port = 80 and with action as output port X with priority 100. Add second flow with same matching field as above but with ANY (wildcard) value, dst_port=80 and with action as output port Y with priority 200. Send a packet that matches above flow and verify packet is received on port Y. Add a third flow with matching src_port=80, and with action as output port Z. Now, send  OFPFC_DELETE flow_mod request with match fields as ANY for field A and 80 for dst_port. Verify first two flows are removed from flow table. Send a packet matching first flow and verify it is dropped on switch. Verify third flow is still installed.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 140.150 Nonstrict delete multiple matches")
        ports = openflow_ports(4)
        in_port, out_port, out_portY, out_portZ = openflow_ports(4)
        #flags = ofp.OFPFF_SEND_FLOW_REM
        match1 = ofp.match([ofp.oxm.eth_type(0x0800), ofp.oxm.ip_proto(6), ofp.oxm.tcp_dst(80), ofp.oxm.tcp_src(50)])
        match2 = ofp.match([ofp.oxm.eth_type(0x0800), ofp.oxm.ip_proto(6), ofp.oxm.tcp_dst(80)])
        match3 = ofp.match([ofp.oxm.eth_type(0x0800), ofp.oxm.ip_proto(6), ofp.oxm.tcp_src(80)])

        #match1 = ofp.match([ofp.oxm.eth_type(ANY),ofp.oxm.tcp_dst(80)])
        actions = [ofp.action.output(out_port)]

        pkt = simple_tcp_packet(tcp_dport = 80, tcp_sport = 50)
        pkt1 = simple_tcp_packet(tcp_sport = 80)


        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=match1,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 100)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_port)



        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=match2,
                instructions=[
                    ofp.instruction.apply_actions([ofp.action.output(out_portY)])],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 200)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_portY)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_portY)



        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=match3,
                instructions=[
                    ofp.instruction.apply_actions([ofp.action.output(out_portZ)])],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 300)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_portZ)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt1))
        verify_packet(self, str(pkt1),out_portZ)


        request = ofp.message.flow_delete(
                table_id=test_param_get("table", 0),
                match=match2,
                out_port = ofp.OFPP_ANY,
                out_group = ofp.OFPG_ANY,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 300)
        self.controller.message_send(request)
        logging.info("deleting the previous flow")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error message")
        self.dataplane.send(in_port, str(pkt))
        #verify_no_packet(self, str(pkt),out_port)
        verify_no_other_packets(self)

        self.dataplane.send(in_port,str(pkt1))
        verify_packet(self, str(pkt1), out_portZ)



class Testcase_140_170_Delete_match_syntax(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify behavior for modified tables for AGGREGATE FLOWS

    Methodology
    Configure and connect DUT to controller. After control channel establishment, install three flows. Flow1 matching on hw_src=a with a priority of 100. Flow2 matching on hw_src=a,hw_dst=b with a priority of 200. Flow3 matching on ANY with a priority of 300. Send an ofp_multipart_request with type OFPMP_AGGREGATE that matches on hw_src=a. Verify aggregate statistics are received for Flows 1 and 2. Send ofp_multipart_request with type OFPMP_AGGREGATE that matches on priority=300. Verify aggregate statistics are received for Flow3

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 140.170 Delete-match syntax")
        ports = openflow_ports(4)
        in_port, out_port, out_portY, out_portZ = openflow_ports(4)
        #flags = ofp.OFPFF_SEND_FLOW_REM
        match2 = ofp.match([ofp.oxm.eth_src([0,6,7,8,9,10]), ofp.oxm.eth_dst([0,1,2,3,4,5])])
        match1 = ofp.match([ofp.oxm.eth_src([0,6,7,8,9,10])])
        match3 = ofp.match()

        #match1 = ofp.match([ofp.oxm.eth_type(ANY),ofp.oxm.tcp_dst(80)])
        actions = [ofp.action.output(out_port)]

        pkt = simple_tcp_packet()
        


        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=match1,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 100)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_port)



        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=match2,
                instructions=[
                    ofp.instruction.apply_actions([ofp.action.output(out_portY)])],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 200)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_portY)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_portY)



        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=match3,
                instructions=[
                    ofp.instruction.apply_actions([ofp.action.output(out_portZ)])],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 300)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_portZ)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_portZ)

        request = ofp.message.aggregate_stats_request(table_id = test_param_get("table", 0), match = match1, out_port = ofp.OFPP_ANY, out_group = ofp.OFPG_ANY)
        stats, _= self.controller.transact(request)
        self.assertEqual(stats.flow_count, 2, "Did not contains all the necessary flows")


class Testcase_140_180_Delete_filters(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify OFPFC_DELETE command functionality when filtered by destination group or OUT_PORT

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add first flow flow1 matching a named field (under the Pre-requisites for the match) with priority 100 and actions as output port X. Add second flow flow2 with same matching fields but with priority 200 and actions as output port Y. Send a packet matching above flows and verify packet is received from port Y. Send a OFPFC_DELETE flow_mod request with above match fields and out_port field as Y. Verify the flow2 is removed from the flow table. Send a packet again and now verify the packet is received from port X.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 140.180 Delete filters")
        ports = openflow_ports(4)
        in_port, out_port, out_portY, out_portZ = openflow_ports(4)
        #flags = ofp.OFPFF_SEND_FLOW_REM

        actions = [ofp.action.output(out_port)]
        match = ofp.match([ofp.oxm.eth_type(0x0800)])
        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 100)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_port)



        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions([ofp.action.output(out_portY)])],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 200)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_portY)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_portY)


        request = ofp.message.flow_delete(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                out_port = out_portY,
                out_group = ofp.OFPG_ANY,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 200)
        self.controller.message_send(request)
        logging.info("deleting the previous flow")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error message")
        self.dataplane.send(in_port, str(pkt))
        #verify_no_packet(self, str(pkt),out_port)
        verify_packet(self, str(pkt),out_port)

class Testcase_140_200_Add_modify_ignore(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify the OUT_PORT of OFPT_FLOW_MOD should be ignored by OFPFC_ADD, OFPFC_MODIFY and OFPFC_MODIFY_STRICT.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the given Pre-requisites for the match) with actions as output port X. Using a flow mod with a modify command, modify this flow's instructions with ofp_flow_mod.out_port=Y and instructions as output set to Z. Verify flow is modified by sending a packet matching the flow and packet received from port Z. 

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 140.200 Add and modify ignore filters")
        ports = openflow_ports(4)
        in_port, out_port, out_portY, out_portZ = openflow_ports(4)
        #flags = ofp.OFPFF_SEND_FLOW_REM
        match = ofp.match([ofp.oxm.eth_type(0x0800)])
        actions = [ofp.action.output(out_port)]

        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 100)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
        #self.dataplane.send(in_port, str(pkt))
        #verify_packet(self, str(pkt),out_port)

        request = ofp.message.flow_modify(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                out_port = out_portY,
                instructions=[
                    ofp.instruction.apply_actions([ofp.action.output(out_portZ)])],
                buffer_id=ofp.OFP_NO_BUFFER,)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when modifying flow")
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_portZ)


class Testcase_140_210_Delete_cookie(base_tests.SimpleDataPlane):
    """
    TODO: Verify the correctness of this testcase by using another DUT
    Purpose
    Verify the OUT_PORT of OFPT_FLOW_MOD should be ignored by OFPFC_ADD, OFPFC_MODIFY and OFPFC_MODIFY_STRICT.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the given Pre-requisites for the match) with actions as output port X. Using a flow mod with a modify command, modify this flow's instructions with ofp_flow_mod.out_port=Y and instructions as output set to Z. Verify flow is modified by sending a packet matching the flow and packet received from port Z. 

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 140.210 delete cookie")
        ports = openflow_ports(4)
        in_port, out_port, out_portY, out_portZ = openflow_ports(4)
        #flags = ofp.OFPFF_SEND_FLOW_REM

        actions = [ofp.action.output(out_port)]
        match = ofp.match([ofp.oxm.eth_type(0x0800)])
        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 100, cookie= 0x1)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
        #self.dataplane.send(in_port, str(pkt))
        #verify_packet(self, str(pkt),out_port)
        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions([ofp.action.output(out_portY)])],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 200, cookie= 0x5)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_portY)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)


        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
               # match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions([ofp.action.output(out_portZ)])],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 300, cookie= 0x6)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_portZ)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)

        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_portZ)



        request = ofp.message.flow_delete(
                table_id=test_param_get("table", 0),

                cookie = 0x4,
                cookie_mask = 0x4,
                buffer_id=ofp.OFP_NO_BUFFER,out_port = ofp.OFPP_ANY,out_group = ofp.OFPG_ANY)
        self.controller.message_send(request)
        logging.info("Deleting a flow cookie 0x4, cookie_mask 0x4")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when deleting flow")
        #stats = get_flow_stats(self, match = ofp.match(), table_id = 0)
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_port)

class Testcase_140_220_Delete_all_tables(base_tests.SimpleDataPlane):
    """
    TODO: Verify the correctness of this testcase by using another DUT
    Purpose
    OFPFC_DELETE command for "OFPTT_ALL" addresses all tables

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow into every table existing, matching a named field (under the Pre-requisites for the match) with priority 100 and actions as output port X. Send a OFPFC_DELETE flow_mod request matching all the flows and OFPTT_ALL as table_id. Verify the flow is removed from all flow tables.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 140.220 delete in all tables")
        ports = openflow_ports(4)
        in_port, out_port, out_portY, out_portZ = openflow_ports(4)
        #flags = ofp.OFPFF_SEND_FLOW_REM
        
        actions = [ofp.action.output(out_port)]
        match = ofp.match([ofp.oxm.eth_type(0x0800)])
        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)
        
        """request = ofp.message.table_features_stats_request()
        stats = get_stats(self, request)
        self.assertIsNotNone(stats, "Did not receive table features stats reply.")
        logging.info("Received table stats reply as expected")

        self.assertEqual(len(stats), tables_no, "Reported table number in table stats is not correct")
        logging.info("Reported table number in table stats is correct")

        report_tables = []
        for item in stats:
            self.assertNotIn(item.table_id, report_tables, "Reported table id is not unique")
            report_tables.append(item.table_id)"""
            
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        #tables_no = reply.n_tables 

        logging.info("Inserting flow")
        pkt = simple_tcp_packet()
        
        #for table_id in range(tables_no):
        req = ofp.message.flow_add(table_id=test_param_get("table", 0),
                                   #match=packet_to_flow_match(self, pkt),
                                   match = match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=[ofp.instruction.apply_actions(actions)],
                                   priority = 100)
        logging.info("Inserting a flow to table %d ", test_param_get("table", 0))
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow to table %d "%test_param_get("table", 0))
        do_barrier(self.controller)
            
      
        delete_all_flows(self.controller)
        logging.info("Deleting the flow from all the tables")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when deleting flow")
        stats = get_flow_stats(self,match=ofp.match(),table_id=ofp.OFPTT_ALL)
        self.assertEqual(len(stats), 0, "Incorrect flow stats.")
