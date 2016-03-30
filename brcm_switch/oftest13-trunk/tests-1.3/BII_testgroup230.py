# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Maple Yip

"""
Test suite 230 verifies the ofp_action_header structures various fields.

To satisfy the basic requirements an OpenFlow enabled device must pass 230.10 - 230.60
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


"""
class Testcase_230_10_ActionHeaderOutput(base_tests.SimpleDataPlane):
    
    230.10 - OFPAT_OUTPUT out to PORT
    Test OFPAT_OUTPUT action sends to out port 
    

    @wireshark_capture
    def runTest(self):
        logging.info("Running 230.10 - OFPAT_OUTPUT out to PORT test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        in_port,out_port,no_port = openflow_ports(3)
        table_id=0
        priority=1
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port)])
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
        verify_packet(self,str(pkt),out_port)
        logging.info("Received packet as expected")
        self.dataplane.send(no_port,str(pkt))
        verify_no_packet(self,str(pkt),out_port)
        logging.info("Did not receive packet as expected")



class Testcase_230_20_ActionHeaderOutput2Port(base_tests.SimpleDataPlane):
    
    230.20 - Flow with action output to port
    Verify packet is sent to a port with OUTPUT action.
    

    @wireshark_capture
    def runTest(self):
        logging.info("Running 230.20 - Flow with action output to port")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        in_port,out_port,no_port = openflow_ports(3)
        table_id=0
        priority=1
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port)])
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
        verify_packet(self,str(pkt),out_port)
        logging.info("Received packet as expected")
        self.dataplane.send(no_port,str(pkt))
        verify_no_packet(self,str(pkt),out_port)
        logging.info("Did not receive packet as expected")




class Testcase_230_30_ActionHeaderMaxLen(base_tests.SimpleDataPlane):
    
    230.30 - MAX_LEN size packets
    Verify packet "send to controller" action sends MAX_LEN bytes
    

    @wireshark_capture
    def runTest(self):
        logging.info("Running 230.30 - MAX_LEN size packets test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        in_port, = openflow_ports(1)
        table_id=0
        priority=1
        actions=[ofp.action.output(port=ofp.OFPP_CONTROLLER, max_len=100)]
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
        self.assertTrue(len(rv.data)<=100, "length of data in packet in is not correct")
        logging.info("Got packet in as expected")
"""


class Testcase_230_40_ActionHeaderMaxLenZero(base_tests.SimpleDataPlane):
    """
    230.40 - MAX_LEN of 0 is empty packet
    Verify packet "send to controller" action with MAX_LEN set to 0 sends 0 bytes of the packet
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 230.40 - MAX_LEN of 0 is empty packet test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        in_port, = openflow_ports(1)
        table_id=0
        priority=1
        actions=[ofp.action.output(port=ofp.OFPP_CONTROLLER, max_len=0)]
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
        
        if (len(rv.data)) > 0:
            self.assertEqual(rv.data,str(pkt),"Packet does not include in the pakcet in msg")
            logging.info("DUT does not has buffer")
        else:
            self.assertEqual(len(rv.data), 0, "length of data in packet in is not correct")
            logging.info("Got packet in as expected")
        """
        self.assertEqual(len(rv.data), 0, "length of data in packet in is not correct")
        logging.info("Got packet in as expected")
        """

class Testcase_230_50_ActionHeaderMaxLenMax(base_tests.SimpleDataPlane):
    """
    230.50 - OFPCML_MAX = 0xffe5 smaller packets sent entirely
    Verify packets "send to controller" action that are smaller than OFPCML_MAX = 0xffe5 are sent in their entirety.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 230.50 - OFPCML_MAX = 0xffe5 smaller packets sent entirely test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        in_port, = openflow_ports(1)
        
        table_id=0
        priority=1
        max_len_list=[0xffe5,1000,100,10]
        for max_len in max_len_list:
            rv = delete_all_flows(self.controller)
            self.assertEqual(rv, 0, "Failed to delete all flows")
            actions=[ofp.action.output(port=ofp.OFPP_CONTROLLER, max_len=max_len)]
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
            self.assertTrue(len(rv.data)<=max_len, "length of data in packet in is not correct")
            logging.info("Got packet in as expected")



class Testcase_230_60_ActionHeaderMaxLenNoBuffer(base_tests.SimpleDataPlane):
    """
    230.60 - OFPCML_NO_BUFFER = 0xffff packets are sent entirely
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