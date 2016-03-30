# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Maple Yip

"""
Test suite 260 verifies the ofp_flow_mod structures various fields. Of specific interest 
are overlapping flow entries, flow removed messages, strict / non strict flow modifications 
and flow deletions, and additional constraints on modifications and flow deletions (output, 
and cookie).
    
To satisfy the basic requirements an OpenFlow enabled device must pass 260.30 - 260.320, and 
260.340 - 260.420.
"""

import logging
import time
import sys

import unittest
import random
from oftest import config
import oftest.controller as controller
import ofp
import oftest.dataplane as dataplane
import oftest.parse as parse
import oftest.base_tests as base_tests
import oftest.illegal_message as illegal_message
import BII_testgroup60
import BII_testgroup140
import BII_testgroup150
import BII_testgroup230

from oftest.oflog import *
from oftest.testutils import *
from time import sleep
"""
class Testcase_260_30_FlowmodMsg(BII_testgroup60.Testcase_60_20_OXM_OF_IN_PORT):
    
    Tested in 60.20
    260.30 - OFPT_FLOW_MOD message modifies flow table
    Verify OFPT_FLOW_MOD message modifies flow table.
    
"""


class Testcase_260_40_FlowmodCookies(base_tests.SimpleDataPlane):
    """
    260.40 - uint64_t cookie; /* Opaque controller-issued identifier. */
    Verify OFPT_FLOW_MOD message modifies flow table.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 260.40 - uint64_t cookie test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port1, in_port2, in_port3, out_port, = openflow_ports(4)
        table_id=0
        cookie = 11
        priority=1
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match1 = ofp.match([ofp.oxm.in_port(in_port1)])
        req = ofp.message.flow_add(table_id=table_id,
                               cookie=cookie,
                               match= match1,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending flowmod 1")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 1")
        sleep(3)

        pkt = str(simple_tcp_packet())
        logging.info("Sending a packet to match on port %s.", in_port1)
        self.dataplane.send(in_port1, pkt)
        verify_packet(self, pkt, out_port)

        match2 = ofp.match([ofp.oxm.in_port(in_port2)])
        req = ofp.message.flow_add(table_id=table_id,
                               cookie=cookie,
                               match= match2,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending flowmod 2")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 2")

        
        sleep(3)

        logging.info("Sending a packet to match on port %s.", in_port2)
        self.dataplane.send(in_port2, pkt)
        verify_packet(self, pkt, out_port)

        cookie2 = 12
        match3 = ofp.match([ofp.oxm.in_port(in_port3)])
        req = ofp.message.flow_add(table_id=table_id,
                               cookie=cookie2,
                               match= match3,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending flowmod 3")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 3")

        sleep(3)

        logging.info("Sending a packet to match on port %s.", in_port3)
        self.dataplane.send(in_port3, pkt)
        verify_packet(self, pkt, out_port)

        cookie_mask = 15
        req = ofp.message.flow_delete(buffer_id=ofp.OFP_NO_BUFFER,
                                      cookie=cookie,
                                      cookie_mask=cookie_mask,
                                      out_port=ofp.const.OFPP_ANY,
                                      out_group=ofp.const.OFPG_ANY,
                                      table_id=table_id)
        logging.info("Deleting flow1 and flow2")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to delete flows")

	sleep(5)
        logging.info("Sending a packet to match on port %s.", in_port1)
        self.dataplane.send(in_port1, pkt)
        verify_no_packet(self, pkt, out_port)
        logging.info("Sending a packet to match on port %s.", in_port2)
        self.dataplane.send(in_port2, pkt)
        verify_no_packet(self, pkt, out_port)
        logging.info("Sending a packet to match on port %s.", in_port3)
        self.dataplane.send(in_port3, pkt)
        verify_packet(self, pkt, out_port)



class Testcase_260_50_FlowmodCookieMask(base_tests.SimpleDataPlane):
    """
    260.50 - uint64_t cookie_mask
    Verify matching on a cookie field using an OFPT_FLOW_MOD with a cookie_mask value not equal to -1.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 260.50 - uint64_t cookie_mask test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port1, in_port2, in_port3, out_port, = openflow_ports(4)
        table_id=0
        priority=1
        cookie1 = 0x00000011
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match1 = ofp.match([ofp.oxm.in_port(in_port1)])
        req = ofp.message.flow_add(table_id=table_id,
                               cookie=cookie1,
                               match= match1,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending flowmod 1")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 1")
        
        cookie2 = 0x00000022
        match2 = ofp.match([ofp.oxm.in_port(in_port2)])
        req = ofp.message.flow_add(table_id=table_id,
                               cookie=cookie2,
                               match= match2,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending flowmod 2")
        rv = self.controller.message_send(req)

        cookie3 = 0x00330000
        match3 = ofp.match([ofp.oxm.in_port(in_port3)])
        req = ofp.message.flow_add(table_id=table_id,
                               cookie=cookie3,
                               match= match3,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending flowmod 3")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 3")

        cookie_mask = 0x00330000
        req = ofp.message.flow_delete(buffer_id=ofp.OFP_NO_BUFFER,
                                      cookie=cookie1,
                                      cookie_mask=cookie_mask,
                                      out_port=ofp.const.OFPP_ANY,
                                      out_group=ofp.const.OFPG_ANY,
                                      table_id=table_id)
        logging.info("Deleting flow1 and flow2")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to delete flows")

        pkt = str(simple_tcp_packet())
        logging.info("Sending a packet to match on port %s.", in_port1)
        self.dataplane.send(in_port1, pkt)
        verify_no_packet(self, pkt, out_port)
        logging.info("Sending a packet to match on port %s.", in_port2)
        self.dataplane.send(in_port2, pkt)
        verify_no_packet(self, pkt, out_port)



class Testcase_260_60_FlowmodCookieMaskStats(base_tests.SimpleDataPlane):
    """
    260.60 - Flow mod cookie mask statistics
    Verify flow statistics can be filtered by cookie and cookie mask values.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 260.60 - Flow mod cookie mask statistics test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port1, in_port2, in_port3, out_port, = openflow_ports(4)
        table_id=0
        priority=1
        cookie1 = 0x00000011
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match1 = ofp.match([ofp.oxm.in_port(in_port1)])
        req = ofp.message.flow_add(table_id=table_id,
                               cookie=cookie1,
                               match= match1,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending flowmod 1")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 1")
        
        cookie2 = 0x00000022
        match2 = ofp.match([ofp.oxm.in_port(in_port2)])
        req = ofp.message.flow_add(table_id=table_id,
                               cookie=cookie2,
                               match= match2,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending flowmod 2")
        rv = self.controller.message_send(req)

        cookie3 = 0x00330000
        match3 = ofp.match([ofp.oxm.in_port(in_port3)])
        req = ofp.message.flow_add(table_id=table_id,
                               cookie=cookie3,
                               match= match3,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending flowmod 3")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 3")

        cookie_mask=0x00330000
        stats = get_flow_stats(self, table_id=table_id,match=ofp.match(), cookie=cookie1,
                               cookie_mask=cookie_mask)
        self.assertEqual(len(stats), 2, "Cookie mask stats is incorrct.")



class Testcase_260_70_FlowmodCookieQuary(base_tests.SimpleDataPlane):
    """
    260.70 - Flow mod cookie query
    Verify cookie values are set and reported correctly in ofp_flow_stats messages.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 260.70 - Flow mod cookie query test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port1, in_port2, in_port3, out_port, = openflow_ports(4)
        table_id=0
        priority=1
        cookie = 0x00000011
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match1 = ofp.match([ofp.oxm.in_port(in_port1)])
        req = ofp.message.flow_add(table_id=table_id,
                               cookie=cookie,
                               match= match1,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending flowmod 1")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 1")
        
        stats = get_flow_stats(self, table_id=table_id,match=ofp.match())
        self.assertEqual(len(stats), 1, "Statistic is incorrct.")
        self.assertEqual(stats[0].cookie, cookie, "Invalid cookie value.")



class Testcase_260_80_FlowmodCookieMod(base_tests.SimpleDataPlane):
    """
    260.80 - Flow mod cookie modification
    Verify cookie values are not changed when flow entries are modified.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 260.80 - Flow mod cookie modification test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port1, out_port2, = openflow_ports(3)
        table_id=0
        priority=1
        cookie = 0x00000011
        actions=[ofp.action.output(port=out_port1, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match1 = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               cookie=cookie,
                               match= match1,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending flowmod 1")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 1")
        
	
        cookie_mod = 0x00000022
        actions=[ofp.action.output(port=out_port2, max_len=128)]
        req = ofp.message.flow_modify(table_id=table_id,
                               cookie=cookie_mod,
                               match= match1,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Modifying flow 1")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to modify flow 1")

        stats = get_flow_stats(self, table_id=table_id,match=ofp.match())
        self.assertEqual(len(stats), 1, "Statistic is incorrct.")
        self.assertEqual(stats[0].cookie, cookie, "Invalid cookie value.")



class Testcase_260_90_FlowmodCookieRestriction(base_tests.SimpleDataPlane):
    """
    260.90 - Flow mod cookie restriction
    Ensure that using a non-zero cookie value can be used to restrict flow matching.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 260.90 - Flow mod cookie restriction test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port, = openflow_ports(2)
        table_id=0
        priority=1
        cookie1 = 0x00000011
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               cookie=cookie1,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending flowmod 1")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 1")
        
	priority=2
        cookie2 = 0x00000022
        req = ofp.message.flow_add(table_id=table_id,
                               cookie=cookie2,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending flowmod 2")
        rv = self.controller.message_send(req)

	cookie_mask = 255
        req = ofp.message.flow_delete(buffer_id=ofp.OFP_NO_BUFFER,
                                      cookie=cookie2,
					cookie_mask=cookie_mask,
                                      match= match,
                                      priority=priority,
                                      out_port=ofp.const.OFPP_ANY,
                                      out_group=ofp.const.OFPG_ANY,
                                      table_id=table_id)
        logging.info("Deleting flow2")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to delete flows")

        stats = get_flow_stats(self, table_id=table_id,match=ofp.match())
        self.assertEqual(len(stats), 1, "Received unexpected stats length.")
        self.assertEqual(stats[0].cookie, cookie1, "Invalid cookie value.")




class Testcase_260_100_FlowmodIgnoreCookieMask(base_tests.SimpleDataPlane):
    """
    260.100 - Flow mod add ignore cookie mask
    Check that a non-zero cookie mask field is ignored in ofp_flow_mod messages with an add command.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 260.100 - Flow mod add ignore cookie mask test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port, = openflow_ports(2)
        table_id=0
        priority=1
        cookie = 0x00000011
        cookie_mask = 0x00000001
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match1 = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               cookie=cookie,
                               cookie_mask=cookie_mask,
                               match= match1,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending flowmod")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")
        
        stats = get_flow_stats(self, table_id=table_id,match=ofp.match())
        self.assertEqual(len(stats), 1, "Statistic is incorrect.")
        self.assertEqual(stats[0].cookie, cookie, "Invalid cookie value.")



class Testcase_260_110_FlowmodDeleteTable(base_tests.SimpleDataPlane):
    """ 
    260.110 - Flow mod delete table
    For ofp_flow_mod messages with a delete or modify command, ensure that table_id can be used to select flows.
    """ 

    @wireshark_capture
    def runTest(self):
        logging.info("Running 260.110 - Flow mod delete table test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port,out_port2, = openflow_ports(3)
        table_id=0
        priority=1
        cookie1 = 0x00000011
        actions=[ofp.action.output(port=out_port, max_len=128)]
        actions2=[ofp.action.output(port=out_port2, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        instructions_mod=[ofp.instruction.apply_actions(actions=actions2)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               cookie=cookie1,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending flowmod")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")
        
        req = ofp.message.flow_modify(table_id=table_id,
                               cookie=cookie1,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions_mod,
                               priority=priority)
        logging.info("Sending flowmod")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")
        
        req = ofp.message.flow_delete(buffer_id=ofp.OFP_NO_BUFFER,
                                      match= match,
                                      priority=priority,
                                      out_port=ofp.const.OFPP_ANY,
                                      out_group=ofp.const.OFPG_ANY,
                                      table_id=table_id)
        logging.info("Deleting flows from Table")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to delete flows")

        stats = get_flow_stats(self, table_id=table_id,match=ofp.match())
        self.assertEqual(len(stats), 0, "Received unexpected stats length.")



class Testcase_260_120_FlowmodDelete_OFPTT_ALL(base_tests.SimpleDataPlane):
    """ 
    260.120 - Flow mod OFPTT_ALL
    Ensure DUT exhibits correct behavior when table OFPTT_ALL is specified in ofp_flow_mod messages.
    """ 

    @wireshark_capture
    def runTest(self):
        logging.info("Running 260.120 - Flow mod OFPTT_ALL test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port, = openflow_ports(2)
        table_id=ofp.const.OFPTT_ALL
        priority=1
        cookie1 = 0x00000011
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               cookie=cookie1,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending flowmod")
        self.controller.message_send(req)
        err, _ = self.controller.poll(exp_msg=ofp.const.OFPT_ERROR)
        self.assertIsNotNone(err, "Did not receive err msg")
        self.assertEqual(err.err_type, ofp.const.OFPET_FLOW_MOD_FAILED,"Erroe type is not OFPET_FLOW_MOD_FAILED")
        self.assertEqual(err.code, ofp.const.OFPFMFC_BAD_TABLE_ID,"Error code is not OFPFMFC_BAD_TABLE_ID")
        logging.info("Received expected error message")

        req = ofp.message.flow_add(table_id=0,
                               cookie=cookie1,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending flowmod")
        self.controller.message_send(req)
        err, _ = self.controller.poll(exp_msg=ofp.const.OFPT_ERROR)
        self.assertIsNone(err, "Received err msg when inserting the flow")

        req = ofp.message.flow_delete(buffer_id=ofp.OFP_NO_BUFFER,
                                      match= match,
                                      priority=priority,
                                      out_port=ofp.const.OFPP_ANY,
                                      out_group=ofp.const.OFPG_ANY,
                                      table_id=ofp.const.OFPTT_ALL)
        logging.info("Deleting flows from Table")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to delete flows")

        stats = get_flow_stats(self, table_id=table_id,match=ofp.match())
        self.assertEqual(len(stats), 0, "Received unexpected stats length.")

        
"""

class Testcase_260_130_FlowmodCommand(BII_testgroup60.Testcase_60_20_OXM_OF_IN_PORT):
    """"""
    Tested in 60.20
    260.130 - OFP_FLOW_MOD_COMMAND
    Verify the switch is able to match on the previously named field as a single header field match (under the given Pre-requisites for the match).
    """"""



class Testcase_260_140_FlowmodNewFlow(BII_testgroup140.Testcase_140_70_Modify_Preserved_fields):
    """"""
    Tested in 140.70
    260.140 - New flow.
    Test a new flow can be added OFPFCC_ADD
    """"""



class Testcase_260_150_FlowmodModifyAllMatchingFlows(BII_testgroup140.Testcase_140_70_Modify_Preserved_fields):
    """ """
    Tested in 140.70
    260.150 - Modify all matching flows
    For ofp_flow_mod messages using a modify or modify_strict command, verify that the instruction field of all matching flows are updated. 
    In addition verify that cookies, timeouts, flags, counters, and durations are not modified. 
    """ """



class Testcase_260_160_FlowmodModifyStrict(BII_testgroup140.Testcase_140_70_Modify_Preserved_fields):
    """ """
    Tested in 140.70
    260.160 - Modify entry strictly matching wildcards and priority.
    For ofp_flow_mod messages using a modify or modify_strict command, verify that the instruction field of all matching flows are updated. 
    In addition verify that cookies, timeouts, flags, counters, and durations are not modified.  
    """ """



class Testcase_260_170_FlowmodDeleteAllMatchingFlows(BII_testgroup140.Testcase_140_140_Strict_delete):
    """ """
    Tested in 140.140
    260.170 - Delete all matching flows.
    For ofp_flow_mod messages using a delete or delete_strict command, verify that the DUT removes all matching flows according to the 
    behaviors defined for strict and nonstrict. 
    """ """



class Testcase_260_180_FlowmodDeleteStrict(BII_testgroup140.Testcase_140_140_Strict_delete):
    
    Tested in 140.140
    260.180 - Delete entry strictly matching wildcards and priority.
    For ofp_flow_mod messages using a delete or delete_strict command, verify that the DUT removes all matching flows according to the 
    behaviors defined for strict and nonstrict. 
    
"""


class Testcase_260_190_FlowmodIdleTimeout(base_tests.SimpleDataPlane):
    """
    260.190 - Idle time before discarding (seconds).
    Verify IDLE_TIIMEOUT fields control length of time flow remains in the table.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 260.190 - Idle timeout test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port, = openflow_ports(2)
        table_id=0
        priority=1
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority,
                               hard_timeout=0,
                               idle_timeout=5)
        logging.info("Sending flowmod")
        self.controller.message_send(req)
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")

        pkt = str(simple_tcp_packet())
        logging.info("Sending dataplane packet")
        self.dataplane.send(in_port, pkt)
        verify_packet(self, pkt, out_port)

        time.sleep(6)
        stats = get_flow_stats(self,match=ofp.match())
        self.assertEqual(len(stats), 0, "Flow did not timeout")
        logging.info("Flow timeout as expected")



class Testcase_260_200_FlowmodHardTimeout(base_tests.SimpleDataPlane):
    """
    260.200 - Max time before discarding (seconds).
    Verify IDLE_TIIMEOUT fields control length of time flow remains in the table.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 260.200 - Hard timeout test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port, = openflow_ports(2)
        table_id=0
        priority=1
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority,
                               hard_timeout=5,
                               idle_timeout=0)
        logging.info("Sending flowmod")
        self.controller.message_send(req)
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")

        pkt = str(simple_tcp_packet())
        logging.info("Sending dataplane packet")
        self.dataplane.send(in_port, pkt)
        verify_packet(self, pkt, out_port)

        time.sleep(1)
        self.dataplane.send(in_port, pkt)
        verify_packet(self, pkt, out_port)

        time.sleep(3)
        self.dataplane.send(in_port, pkt)
        verify_packet(self, pkt, out_port)

        time.sleep(2)
        stats = get_flow_stats(self,match=ofp.match())
        self.assertEqual(len(stats), 0, "Flow did not timeout")
        logging.info("Flow timeout as expected")


"""
class Testcase_260_210_FlowmodIdleTimeoutwithHardTimeout0(Testcase_260_190_FlowmodIdleTimeout):
    
    Tested in 260.190
    260.210 - Flow modification with IDLE_TIMEOUT with HARD_TIMEOUT = 0
    Treating flow with IDLE_TIMEOUT set and HARD_TIMEOUT = 0.
    """

"""

class Testcase_260_220_FlowmodHardTimeoutwithIdleTimeout0(Testcase_260_200_FlowmodHardTimeout):
    
    Tested in 260.200
    260.220 - Flow modification with IDLE_TIMEOUT = 0  with HARD_TIMEOUT set.
    Treating flow with IDLE_TIMOUTE = 0 and HARD_TIMEOUT SET.
    """



class Testcase_260_230_FlowmodHard_IdleTimeout(base_tests.SimpleDataPlane):
    """
    260.230 - Flow modification with IDLE_TIMEOUT with HARD_TIMEOUT both set.
    Treating flow with IDLE_TIMOUTE and HARD_TIMEOUT both SET
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 260.230 - IDLE_TIMEOUT with HARD_TIMEOUT both set test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port, = openflow_ports(2)
        table_id=0
        priority=1
        cookie1 = 0x00000011
        actions=[ofp.action.output(port = ofp.OFPP_CONTROLLER, max_len = 128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               cookie=cookie1,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority,
                               hard_timeout=5,
                               idle_timeout=3)
        logging.info("Sending flowmod")
        self.controller.message_send(req)
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")
        
        sleep(2)
        pkt = str(simple_tcp_packet())
        logging.info("Sending dataplane packet within idle_timeout")
        self.dataplane.send(in_port, pkt)
        logging.info("Sending Multipart msgs")
        stats = get_flow_stats(self, match = ofp.match(), table_id = test_param_get("table", 0))
        verify_packet_in(self,pkt,in_port,ofp.OFPR_ACTION,self.controller)
        logging.info("Wait until hard_timeout")
        sleep(4)
        logging.info("Sending dataplane packet after hard_timeout")
        self.dataplane.send(in_port, pkt)
        verify_no_packet_in(self,pkt,in_port,self.controller)

        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority,
                               hard_timeout=5,
                               idle_timeout=3)
        logging.info("Sending flowmod")
        self.controller.message_send(req)
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")

        for i in range(5):
            pkt = str(simple_tcp_packet())
            logging.info("Sending dataplane packets")
            sleep(1.2)
            self.dataplane.send(in_port, pkt)
            stats = get_flow_stats(self, match = ofp.match(), table_id = test_param_get("table", 0))
            
            if i == 4:
                verify_no_packet_in(self,pkt,in_port,self.controller)
            else:
                verify_packet_in(self,pkt,in_port,ofp.OFPR_ACTION,self.controller)

        logging.info("Flow timeout as expected")



class Testcase_260_240_FlowmodTimeoutBoth0(base_tests.SimpleDataPlane):
    """
    260.240 - Flow modification with IDLE_TIMEOUT and HARD_TIMEOUT both = 0.
    Verify that flows with idle and hard timeouts of zero are installed indefinitely.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 260.240 - IDLE_TIMEOUT with HARD_TIMEOUT both 0 test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port, = openflow_ports(2)
        table_id=0
        priority=1
        actions=[ofp.action.output(port = ofp.OFPP_CONTROLLER, max_len = 128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority,
                               hard_timeout=0,
                               idle_timeout=0)
        logging.info("Sending flowmod")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")

        for i in range(6):
            pkt = str(simple_tcp_packet())
            logging.info("Sending dataplane packets")
            self.dataplane.send(in_port, pkt)
            verify_packet_in(self,pkt,in_port,ofp.OFPR_ACTION,self.controller)
            sleep(2)

        logging.info("IDLE_TIMEOUT with HARD_TIMEOUT both 0. Flow did not timeout")



class Testcase_260_250_FlowmodPriority(base_tests.SimpleDataPlane):
    """
    260.250 - Priority level of flow entry
    Verify that traffic matches against higher priority rules
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 260.250 - Priority level of flow entry test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port1, out_port2= openflow_ports(3)
        table_id=0
        priority=1000
        actions=[ofp.action.output(port=out_port1, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([
            ofp.oxm.eth_dst([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])
        ])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending flowmod")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")

        priority=2000
        actions=[ofp.action.output(port=out_port2, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([
            ofp.oxm.eth_type(0x0800)
        ])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending flowmod")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")

        pkt = str(simple_tcp_packet())
        logging.info("Sending dataplane packets")
        self.dataplane.send(in_port, pkt)
        verify_packet(self, pkt, out_port2)
        logging.info("Packet forwarded as expected")



class Testcase_260_260_FlowmodModifyDeleteBuffer(base_tests.SimpleDataPlane):
    """ 
    Tested in 230.60
    260.260 - Buffered packet to apply to, or OFP_NO_BUFFER. Not meaningful for OFPFC_DELETE*
    Verify packets "send to controller" action with MAX_LEN of OFPCML_NO_BUFFER set to 0xffff are sent in their entirety
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running 230.60 - OFPCML_NO_BUFFER = 0xffff packets are sent entirely test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        in_port, = openflow_ports(1)
        table_id=0
        priority=1
        actions=[ofp.action.output(port=ofp.OFPP_CONTROLLER, max_len=ofp.const.OFPCML_NO_BUFFER)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.eth_type(0x0800)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                                priority=priority)
        logging.info("Sending flowmod")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")

        pkt = simple_tcp_packet()
        self.dataplane.send(in_port, str(pkt))
        logging.info("Sending a dataplane packet")
        rv, _ = self.controller.poll(exp_msg=ofp.const.OFPT_PACKET_IN)
        self.assertIsNotNone(rv, "Did not receive packet in message")
        self.assertEqual(len(rv.data), len(pkt), "length of data in packet in is not correct")
        logging.info("Got packet in as expected")

class Testcase_260_270_FlowmodBufferID(base_tests.SimpleDataPlane):
    """
    260.270 - Valid BUFFER_ID in FLOW_MOD
    Verify that an entry with all wildcards, priority 0 and action send to the controller can be created in all tables.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 260.270 - Valid BUFFER_ID in FLOW_MOD test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        ports = openflow_ports(3)
        port1 = ports[0]
        out_ports = ports[1:3]
        priority=1
        table_id=0
        actions=[ofp.action.output(port=ofp.OFPP_CONTROLLER, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([])
        req = ofp.message.flow_add(table_id=table_id,
                                  match= match,
                                  buffer_id=ofp.OFP_NO_BUFFER,
                                  instructions=instructions,
                                  priority=priority)
        logging.info("Sending flowmod")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")

        timeout = 5
        pkt = str(simple_tcp_packet(pktlen=512))
        self.dataplane.send(port1, pkt)
        logging.info("Sending a dataplane packet")
        rv, raw=self.controller.poll(exp_msg=ofp.const.OFPT_PACKET_IN, timeout=timeout)
        self.assertTrue(rv is not None, 'Packet in message not received')
        self.assertNotEqual(rv.buffer_id, ofp.const.OFP_NO_BUFFER, "Packet not buffered.")
        logging.info("Packet In received as expected")

        buffer_id=rv.buffer_id
	priority=2
        actions = [ofp.action.output(port=ports[1], max_len=128)]
        instructions = [ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.eth_type(0x0800)])
        req = ofp.message.flow_add(buffer_id=buffer_id,
                                   instructions=instructions,
                                   match=match,
                                   priority=priority,
                                   table_id=table_id)
        logging.info("Sending flowmod")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")

        verify_packet(self, pkt, ports[1])
        logging.info("Received packet out as expected")
        verify_no_packet(self,pkt,ports[2])
        logging.info("Negative check for pkt on other ports")




class Testcase_260_280_FlowmodBufferIDIgnored(base_tests.SimpleDataPlane):
    """
    260.280 - BUFFER_ID for DELETE messages
    BUFFER_ID in OFP_PACKET_IN is ignored by DELETE messages.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 260.280 - BUFFER_ID for DELETE messages test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        port1, out_port, = openflow_ports(2)
        priority=1
        table_id=0
        actions=[ofp.action.output(port=ofp.OFPP_CONTROLLER, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([])
        req = ofp.message.flow_add(table_id=table_id,
                                  match= match,
                                  buffer_id=ofp.OFP_NO_BUFFER,
                                  instructions=instructions,
                                  priority=priority)
        logging.info("Sending flowmod")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")

        timeout = 5
        pkt = str(simple_tcp_packet(pktlen=512))
        self.dataplane.send(port1, pkt)
        logging.info("Sending a dataplane packet")
        rv, raw=self.controller.poll(exp_msg=ofp.const.OFPT_PACKET_IN, timeout=timeout)
        self.assertTrue(rv is not None, 'Packet in message not received')
        self.assertNotEqual(rv.buffer_id, ofp.const.OFP_NO_BUFFER, "Packet not buffered.")
        logging.info("Packet In received as expected")

        buffer_id=rv.buffer_id
        req = ofp.message.flow_delete(buffer_id=buffer_id,
                                   table_id=0xff,
                                   out_port=ofp.const.OFPP_ANY,
                                   out_group=ofp.const.OFPG_ANY)
        logging.info("Deleting flow")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to delete flow")

        self.dataplane.send(port1, pkt)
        verify_no_packet(self, pkt, out_port)
        logging.info("Packet dropped as expected")


"""
class Testcase_260_290_FlowmodModifyDeleteOutport(BII_testgroup140.Testcase_140_180_Delete_filters):
    
    Tested in 140.180
    260.290 - For OFPFC_DELETE* commands, require matching entries to include this as an output port. A value of OFPP_ANY indicates no restriction.
    OFPFC_DELETE command for OUT_PORT as a filter.
    """



class Testcase_260_310_FlowmodDeleteFilter(base_tests.SimpleDataPlane):
    """
    260.310 - OFPFC_DELETE* commands, A value of OFPC_ANY and OFPG_ANY disables filtering.
    OFPFC_DELETE for OUT_PORT and OUT_GROUP set to OFPP_ANY and OFPG_ANY respectively.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 260.310 - OFPFC_DELETE* commands test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        in_port, out_port1, out_port2= openflow_ports(3)
        priority=100
        table_id=0
        actions=[ofp.action.output(port=out_port1, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.eth_dst([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])])
        req = ofp.message.flow_add(table_id=table_id,
                                  match= match,
                                  buffer_id=ofp.OFP_NO_BUFFER,
                                  instructions=instructions,
                                  priority=priority)
        logging.info("Insert flow 1")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 1")

        priority=200
        table_id=0
        actions=[ofp.action.output(port=out_port2, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.eth_dst([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])])
        req = ofp.message.flow_add(table_id=table_id,
                                  match= match,
                                  buffer_id=ofp.OFP_NO_BUFFER,
                                  instructions=instructions,
                                  priority=priority)
        logging.info("Insert flow 2")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 2")

        req = ofp.message.flow_delete(buffer_id=ofp.OFP_NO_BUFFER,
                                   table_id=0xff,
                                   out_port=ofp.const.OFPP_ANY,
                                   out_group=ofp.const.OFPG_ANY)
        logging.info("Deleting flow")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to delete flow")

        time.sleep(2)
        stats = get_flow_stats(self,match=ofp.match())
        self.assertEqual(len(stats), 0, "Flow statistic is incorrect")
        logging.info("Flows deleted as expected")



class Testcase_260_320_FlowmodModifyStrict(base_tests.SimpleDataPlane):
    """
    260.320 - OFPFC_ADD, OFPFC_MODIFY or OFPFC_MODIFY_STRICT ignore OUT_PORT and OUT_GROUP
    Verify OFPFC_ADD, OFPFC_MODIFY or OFPFC_MODIFY_STRICT ignore OUT_PORT and OUT_GROUP.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 260.320 - OFPFC_ADD, OFPFC_MODIFY or OFPFC_MODIFY_STRICT ignore OUT_PORT and OUT_GROUP test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        in_port, out_port1, out_port2, out_port3= openflow_ports(4)
        priority=100
        table_id=0
        actions=[ofp.action.output(port=out_port1, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.eth_dst([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])])
        req = ofp.message.flow_add(table_id=table_id,
                                  match= match,
                                  buffer_id=ofp.OFP_NO_BUFFER,
                                  instructions=instructions,
                                  priority=priority,
                                  out_port=ofp.const.OFPP_ANY,
                                  out_group=ofp.const.OFPG_ANY)
        logging.info("Insert flow 1")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 1")

        pkt = str(simple_tcp_packet())
        self.dataplane.send(in_port, pkt)
        logging.info("Sending a dataplane packet")
        verify_packet(self, pkt, out_port1)
        logging.info("Packet forwarded as expected")

        priority=200
        table_id=0
        actions=[ofp.action.output(port=out_port2, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.eth_dst([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])])
        req = ofp.message.flow_add(table_id=table_id,
                                  match= match,
                                  buffer_id=ofp.OFP_NO_BUFFER,
                                  instructions=instructions,
                                  priority=priority,
                                  out_port=ofp.const.OFPP_ANY,
                                  out_group=ofp.const.OFPG_ANY)
        logging.info("Insert flow 2")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 2")

        self.dataplane.send(in_port, pkt)
        logging.info("Sending a dataplane packet")
        verify_packet(self, pkt, out_port2)
        logging.info("Packet forwarded as expected")

        priority=100
        table_id=0
        actions=[ofp.action.output(port=out_port1, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port), ofp.oxm.eth_dst([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])])
        req = ofp.message.flow_modify_strict(table_id=table_id,
                                         match= match,
                                         buffer_id=ofp.OFP_NO_BUFFER,
                                         instructions=instructions,
                                         priority=priority,
                                         out_port=out_port3,
                                         out_group=ofp.const.OFPG_ANY)
        logging.info("Modifying flow")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to Modify flow")

        self.dataplane.send(in_port, pkt)
        logging.info("Sending a dataplane packet")
        verify_packet(self, pkt, out_port2)
        logging.info("Packet forwarded as expected")


"""
class Testcase_260_340_FlowmodRemoveFlow(BII_testgroup140.Testcase_140_110_Delete_Flow_removed):
    """ """
    Tested in 140.110
    260.340 - Send flow removed message when flow expires or is deleted.
    Verify correct switch behavior with OFPFF_SEND_FLOW_REM flag
    """"""



class Testcase_260_350_FlowmodOverlapping(BII_testgroup140.Testcase_140_10_Overlap_Check):
    """ """
    Tested in 140.10
    260.350 - Check for overlapping entries first
    Switch behavior with OFPFF_CHECK_OVERLAP flag
    """"""



class Testcase_260_360_FlowmodOverlappingError(BII_testgroup140.Testcase_140_10_Overlap_Check):
    """ """
    Tested in 140.10
    260.360 - Check for error generation for OVERLAPPING entries
    Switch behavior with OFPFF_CHECK_OVERLAP flag and flow entry with same priority
    """ """



class Testcase_260_370_FlowmodResetCounter(BII_testgroup140.Testcase_140_40_Add_Reset_Counters):
    
    Tested in 140.40
    260.370 - Reset flow packet and byte counts
    Verify flow entry counters are cleared.
    """ 



class Testcase_260_380_FlowmodPacketCount(base_tests.SimpleDataPlane):
    """ 
    260.380 - Don't keep track of packet count
    Check how OFPFF_NO_PKT_COUNTS is handled.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 260.380 - Don't keep track of packet count set test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port = openflow_ports(2)
        flags = ofp.OFPFF_NO_PKT_COUNTS

        priority=100
        table_id=0
        actions=[ofp.action.output(port = ofp.OFPP_CONTROLLER, max_len = 128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.eth_dst([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])])
        req = ofp.message.flow_add(table_id=table_id,
                                  match= match,
                                  buffer_id=ofp.OFP_NO_BUFFER,
                                  instructions=instructions,
                                  priority=priority,
                                  flags = flags)
        logging.info("Insert flow")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")

        for i in range(10):
            pkt = str(simple_tcp_packet(pktlen=200))
            self.dataplane.send(in_port, pkt)

        time.sleep(2)
        stats = get_flow_stats(self,match=ofp.match())
        self.assertTrue((stats[0].packet_count==10) or (stats[0].packet_count==0xffffffffffffffff), "The packet count is incorrect")
        logging.info("The packet count is correct")



class Testcase_260_390_FlowmodByteCount(base_tests.SimpleDataPlane):
    """ 
    260.390 - Don't keep track of byte count
    Check how OFPFF_NO_BYT_COUNTS is handled.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 260.390 - Don't keep track of byte count set test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port = openflow_ports(2)
        flags = ofp.OFPFF_NO_BYT_COUNTS

        priority=100
        table_id=0
        actions=[ofp.action.output(port = ofp.OFPP_CONTROLLER, max_len = 128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.eth_dst([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])])
        req = ofp.message.flow_add(table_id=table_id,
                                  match= match,
                                  buffer_id=ofp.OFP_NO_BUFFER,
                                  instructions=instructions,
                                  priority=priority,
                                  flags = flags)
        logging.info("Insert flow")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")

        for i in range(10):
            pkt = str(simple_tcp_packet(pktlen=200))
            self.dataplane.send(in_port, pkt)

        time.sleep(2)
        stats = get_flow_stats(self,match=ofp.match())
        self.assertTrue((stats[0].byte_count==2000) or (stats[0].byte_count==0xffffffffffffffff), "The byte count is incorrect")
        logging.info("The byte count is correct")


class Testcase_260_400_FlowmodNoCounts(Testcase_260_380_FlowmodPacketCount):
    """ 
    Tested in 260.380
    260.400 - OFPFF_NO_PKT_COUNTS and OFPFF_NO_BYT_COUNTS flags in flow statistics.
    Verify how switch handles OFPFF_NO_PKT_COUNTS and OFPFF_NO_BYT_COUNTS
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 260.400 - OFPFF_NO_PKT_COUNTS and OFPFF_NO_BYT_COUNTS flags in flow statistics")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port = openflow_ports(2)
        flags = ofp.OFPFF_NO_PKT_COUNTS|ofp.OFPFF_NO_BYT_COUNTS

        priority=100
        table_id=0
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.eth_dst([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])])
        req = ofp.message.flow_add(table_id=table_id,
                                  match= match,
                                  buffer_id=ofp.OFP_NO_BUFFER,
                                  instructions=instructions,
                                  priority=priority,
                                  flags = flags)
        logging.info("Insert flow")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")

        for i in range(10):
            pkt = str(simple_tcp_packet(pktlen=200))
            self.dataplane.send(in_port, pkt)

        time.sleep(2)
        stats = get_flow_stats(self,match=ofp.match())
        self.assertTrue((stats[0].packet_count==10) or (stats[0].packet_count==0xffffffffffffffff), "The packet count is incorrect")
        self.assertTrue((stats[0].byte_count==2000) or (stats[0].byte_count==0xffffffffffffffff), "The byte count is incorrect")
        logging.info("The packet count and byte count are correct")



class Testcase_260_410_FlowmodFlagsIgnored(base_tests.SimpleDataPlane):
    """ 
    260.410 - OFPFF_NO_PKT_COUNTS and OFPFF_NO_BYT_COUNTS flags are ignored
    Check how OFPFF_NO_BYT_COUNTS is handled.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 260.410 - OFPFF_NO_PKT_COUNTS and OFPFF_NO_BYT_COUNTS flags are ignored test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port = openflow_ports(2)
        flags = ofp.OFPFF_NO_BYT_COUNTS

        priority=100
        table_id=0
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.eth_dst([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])])
        req = ofp.message.flow_add(table_id=table_id,
                                  match= match,
                                  buffer_id=ofp.OFP_NO_BUFFER,
                                  instructions=instructions,
                                  priority=priority,
                                  flags = flags)
        logging.info("Insert flow")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")

        time.sleep(2)
        stats = get_flow_stats(self,match=ofp.match())
        self.assertEqual(len(stats), 1, "Flow statistics is incorrect.")

        req = ofp.message.flow_modify(table_id=table_id,
                                match= match,
                                buffer_id=ofp.OFP_NO_BUFFER,
                                instructions=instructions,
                                priority=priority)
        logging.info("Modify flow")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to modify flow")

        stats = get_flow_stats(self,match=ofp.match())
        self.assertEqual(len(stats), 1, "Flow statistics is incorrect.")
        self.assertEqual(stats[0].flags, ofp.OFPFF_NO_BYT_COUNTS, "The flags are incorrect")
        logging.info("The flags are correct")

"""

class Testcase_260_420_FlowmodInvalidInstructions(BII_testgroup150.Testcase_150_50_unsupported_instruction):
    
    Tested in 150.50
    260.420 - Check how an invalid or unsupported instructions are handled.
    Check error generation for invalid or unsupported instruction.
    """



