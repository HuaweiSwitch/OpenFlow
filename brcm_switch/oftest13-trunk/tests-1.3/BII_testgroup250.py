# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Maple Yip

"""
Test suite 250 verifies the ofp_switch_config structures various fields.

To satisfy the basic requirements an OpenFlow enabled device must pass 250.10 - 250.20, 250.70, and 250.140 - 250.150.
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
class Testcase_250_10_SwitchConfigConfigrationRequest(base_tests.SimpleProtocol):
    """"""
    250.10 - Configuration request
    Verify that the controller can correctly get the switch information.
    """"""

    @wireshark_capture
    def runTest(self):
        logging.info("Running 250.10 - Configuration request test")
        timeout = 5
        request = ofp.message.get_config_request()
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, " Failed to send get config request.")
        (reply, pkt) = self.controller.poll(exp_msg=ofp.OFPT_GET_CONFIG_REPLY,timeout=timeout)
        self.assertIsNotNone(reply,'Did not receive get config reply')
        logging.info("Get config reply received")



class Testcase_250_20_SwitchConfigFlagsBitmap(base_tests.SimpleProtocol):
    """"""
    250.20 - Bitmap of OFPC_* flags
    Verify OFP_SWITCH_CONFIG supports flags
    """"""

    @wireshark_capture
    def runTest(self):
        logging.info("Running 250.20 - Bitmap of OFPC_* flags test")
        timeout = 5
        request = ofp.message.get_config_request()
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, " Failed to send get config request.")
        (reply, pkt) = self.controller.poll(exp_msg=ofp.OFPT_GET_CONFIG_REPLY,timeout=timeout)
        self.assertIsNotNone(reply,'Did not receive get config reply')
        logging.info("Frag is set to %s", reply.flags)

"""

class Testcase_250_70_SwitchConfigMaxBytes(base_tests.SimpleDataPlane):
    """
    250.70 - Max bytes of packet that data path should send to the controller. See ofp_controller_max_len for valid values.
    Verify OFP_CONTROLLER_MAX_LEN value is the max bytes sent to controller.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 250.70 - Max bytes of packet test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        timeout = 5        
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        tables_no = reply.n_tables

        priority=0
        actions=[ofp.action.output(port=ofp.OFPP_CONTROLLER, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([])
        req = ofp.message.flow_add(table_id=test_param_get("table", 0),
                                   match= match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority)
        logging.info("Sending Table Miss flowmod")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert Table Miss flow")
        do_barrier(self.controller)

        request =ofp.message.get_config_request()
        self.controller.message_send(request)
        verify_no_errors(self.controller)
        (reply, pkt) = self.controller.poll(exp_msg=ofp.OFPT_GET_CONFIG_REPLY,timeout=timeout)
        self.assertIsNotNone(reply,'Did not receive get config reply')
        logging.info("Received get config reply ")
        self.assertEqual(reply.miss_send_len, 128 , "Default miss_send_len is incorrect.")

        port1, = openflow_ports(1)
        pkt = str(simple_tcp_packet(pktlen=200))
        self.dataplane.send(port1, pkt)
        logging.info("Sending a dataplane packet")
        verify_packets(self, pkt, [])
        rv, raw=self.controller.poll(exp_msg=ofp.const.OFPT_PACKET_IN, timeout=timeout)
        self.assertTrue(rv is not None, 'Packet in message not received')
        self.assertEqual(len(rv.data),128, "length of data in packet in is not 128.")
        logging.info("Packet In received as expected")




class Testcase_250_140_SwitchConfigMissSendLen(base_tests.SimpleDataPlane):
    """
    250.140 - MISS_SEND_LEN specifies size of OFP_PACKET_IN
    Verify size of data in OFP_PACKET_IN message specified by MISS_SEND_LEN when action output is not OFFP_CONTROLLER.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 250.140 - MISS_SEND_LEN specifies size of OFP_PACKET_IN test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        timeout = 5
        #request = ofp.message.features_request()
        #(reply, pkt)= self.controller.transact(request)
        #self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        #tables_no = reply.n_tables
        table_id = test_param_get("table", 0)
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

        port1, = openflow_ports(1)
        pkt = str(simple_tcp_packet(pktlen=1500))
        
        miss_send_len_list=[0,0xffe5,0xffff]
        for miss_send_len in miss_send_len_list:
            request = ofp.message.set_config(miss_send_len=miss_send_len)
            self.controller.message_send(request)
            self.dataplane.send(port1, pkt)
            logging.info("Sending a dataplane packet")
            verify_packets(self, pkt, [])
            rv, raw=self.controller.poll(exp_msg=ofp.const.OFPT_PACKET_IN, timeout=timeout)
            self.assertTrue(rv is not None, 'Packet in message not received')
            self.assertTrue(len(rv.data)<=miss_send_len, "length of data in packet in is not correct.")
            logging.info("Packet In received as expected")
            
        request = ofp.message.set_config(miss_send_len=128)
        self.controller.message_send(request)
           


"""

class Testcase_250_150_SwitchConfigMissSendLenNoBuffer(base_tests.SimpleDataPlane):
    """"""
    250.150 - MISS_SEND_LEN value set to OFPCML_NO_BUFFER
    Check the complete message is sent if OFPCML_NO_BUFFER set.
    """"""

    @wireshark_capture
    def runTest(self):
        logging.info("Running 250.150 - MISS_SEND_LEN value set to OFPCML_NO_BUFFER test")
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
"""