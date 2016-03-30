# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Maple Yip

"""
Test suite 50 verifies the basic behavior of packets which fail to match against any 
standard flow table entry (non table miss entry).

To satisfy the basic requirements an OpenFlow enabled device must pass test cases 50.10 
- 50.40, and 50.60.
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

from oftest.oflog import *
from oftest.testutils import *
from time import sleep
from oftest import *

class Testcase_50_10_TableMissDefaultBehavior(base_tests.SimpleDataPlane):
    """
    50.10 - Default behavior
    Verify the switch drops unmatched packets if no table miss flow entry exists.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 50.10 - Default behavior test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        timeout = 5
        port1, = openflow_ports(1)
        pkt = simple_tcp_packet()
        self.dataplane.send(port1, str(pkt))
        logging.info("Sending a dataplane packet")
        verify_packets(self, pkt, [])
        rv, raw=self.controller.poll(exp_msg=ofp.const.OFPT_PACKET_IN, timeout=timeout)
        self.assertIsNone(rv, "Switch did not drop dataplane packet")
        logging.info("Switch dropped dataplane packets as expected")




class Testcase_50_20_TableMissPacketIn(base_tests.SimpleDataPlane):
    """
    50.20 - Packet in
    Verify that an entry with all wildcards, priority 0 and action send to the controller can be created in all tables.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 50.20 - Packet in test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        tables_no = reply.n_tables

        table_id = test_param_get("table",0)
        priority=0
        actions=[ofp.action.output(port=ofp.OFPP_CONTROLLER, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending Table Miss flowmod")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert Table Miss flow")
        do_barrier(self.controller)

	    timeout = 20
        port1, = openflow_ports(1)
        pkt = str(simple_tcp_packet())
        self.dataplane.send(port1, pkt)
        logging.info("Sending a dataplane packet")
        verify_packets(self, pkt, [])
        rv, raw=self.controller.poll(exp_msg=ofp.const.OFPT_PACKET_IN, timeout=timeout)
	self.assertTrue(rv is not None, 'Packet in message not received')
        self.assertEqual(str(rv.data), pkt, ("Received pkt did not match sending pkt."))
        logging.info("Packet In received as expected")




class Testcase_50_30_TableMissPacketInReason(base_tests.SimpleDataPlane):
    """
    50.30 - Packet in reason
    Verify that action output:CONTROLLER sets the reason field to table-miss
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 50.30 - Packet in reason test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        tables_no = reply.n_tables

        table_id = test_param_get("table",0)
        priority=0
        actions=[ofp.action.output(port=ofp.OFPP_CONTROLLER, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending Table Miss flowmod")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert Table Miss flow")
        do_barrier(self.controller)

        timeout = 20
        port1, = openflow_ports(1)
        pkt = str(simple_tcp_packet())
        self.dataplane.send(port1, pkt)
        logging.info("Sending a dataplane packet")
        verify_packets(self, pkt, [])
        rv, raw=self.controller.poll(exp_msg=ofp.const.OFPT_PACKET_IN, timeout=timeout)
        self.assertTrue(rv is not None, 'Packet in message not received')
        self.assertEqual(str(rv.data), pkt, ("Received pkt did not match sending pkt."))
        logging.info("Packet In received as expected")
        self.assertEqual(rv.reason, ofp.const.OFPR_NO_MATCH,"Packet In reason not correct")



class Testcase_50_40_TableMissClearActions(base_tests.SimpleDataPlane):
    """
    50.40 - Drop by clear actions
    Verify that using the Clear-Actions instruction drops the packet
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 50.40 - Drop by clear actions test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        tables_no = reply.n_tables

        table_id = test_param_get("table",0)
        priority=0
        actions=[ofp.action.output(port=ofp.OFPP_CONTROLLER, max_len=128)]
        instructions=[ofp.instruction.clear_actions()]
        match = ofp.match([])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Sending Table Miss flowmod")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert Table Miss flow")
        do_barrier(self.controller)

        timeout = 5
        port1, = openflow_ports(1)
        pkt = str(simple_tcp_packet())
        self.dataplane.send(port1, pkt)
        logging.info("Sending a dataplane packet")
        verify_packets(self, pkt, [])
        rv, raw=self.controller.poll(exp_msg=ofp.const.OFPT_PACKET_IN, timeout=timeout)
        self.assertIsNone(rv, "Switch did not drop dataplane packet")
        logging.info("Switch dropped dataplane packets as expected")




class Testcase_50_60_TableMissExpire(base_tests.SimpleDataPlane):
    """
    50.60 - Entry timeout
    Verify that table-miss entries timeout accordingly to their hard and idle timeouts.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 50.60 - Entry timeout test")

        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        port1, = openflow_ports(1)
        pkt = str(simple_tcp_packet())
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        tables_no = reply.n_tables

        table_id = test_param_get("table",0)
        priority=0
        actions=[ofp.action.output(port=ofp.OFPP_CONTROLLER, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority,
                               hard_timeout=15,
                               idle_timeout=5)
        logging.info("Sending Table Miss flowmod")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert Table Miss flow")
        pkt = str(simple_tcp_packet())
	
        #do_barrier(self.controller)
        for i in range (0,19):
            self.dataplane.send(port1, pkt)
            if i < 15:
                verify_packet_in(self, pkt, port1, reason = None)
		time.sleep(1)
            else:
		time.sleep(1)
                verify_no_packet_in(self,pkt,port1)
            

        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority,
                               hard_timeout=15,
                               idle_timeout=5)
        logging.info("Sending Table Miss flowmod")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert Table Miss flow")
        self.dataplane.send(port1, pkt)
        verify_packet_in(self, pkt, port1, reason = None)
        time.sleep(6)
        self.dataplane.send(port1, pkt)
        verify_no_packet_in(self,pkt,port1)
        #stats = get_flow_stats(self,match=ofp.match())
        #self.assertEqual(len(stats), 0, "Table Miss flow did not timeout")
        logging.info("Table Miss expired as expected")



