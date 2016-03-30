# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Maple Yip

"""
Test suite 380 verifies the correct implementation of the fields contained in each of the following message structs; 
ofp_queue_stats, ofp_get_queue_config_request, and ofp_packet_queue.

To satisfy the basic requirements an OpenFlow enabled device must pass test cases 380.40 - 380.130.
"""

from oftest import config
from oftest.parse import parse_ip, parse_ipv6, parse_mac
from oftest.testutils import *
from time import sleep

import json
import logging
import ofp
import oftest.base_tests as base_tests
import oftest.controller as controller
import oftest.dataplane as dataplane
import oftest.illegal_message as illegal_message
import oftest.parse as parse
import os
import sys
from oftest.oflog import *

import BII_testgroup380

class Testcase_380_40_MultipartQueueStats(base_tests.SimpleDataPlane):

    """
    Test the basic implementation of Multipart Queue Stats Request
    Check that a queue stats request with a port field set to OFPP_ANY results in a queue stats 
    reply which includes each test ports' configured queues.
    """
    @wireshark_capture
    def runTest(self):  
        logging.info("Running test case Multipart Queue Stats Request")      
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")

        port1, = openflow_ports(1)
        request = ofp.message.queue_stats_request()
        request.port_no = port1
        self.controller.message_send(request)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_STATS_REPLY, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an Multipart Reply Message.")
        self.assertTrue(reply.stats_type == 5, "Reply is not multipart queue stata reply")
        logging.info("Multipart Reply Message Received")




class Testcase_380_50_MultipartQueueStatsContent(base_tests.SimpleDataPlane):

    """
    380.50 - Queue stats request standard
    Check that a queue stats request for a configured test port results in a queue stats reply 
    which includes the test port's configured queues.
    """
    @wireshark_capture
    def runTest(self):  
        logging.info("Running test case Multipart Queue Stats Request Content")      
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")

        port1, = openflow_ports(1)
        request = ofp.message.queue_stats_request(queue_id=ofp.const.OFPQ_ALL)
        request.port_no = port1
        stats = get_stats(self, request)
        self.assertIsNotNone(stats, "The switch failed to generate an Multipart Reply Message.")
        port=[]
        for item in stats:
            if item.port_no in openflow_ports(1):
                port.append(item.port_no)
        self.assertEqual(port[0], port1, "Port is not matched")
        logging.info("Correct Reply Message Received")


"""
class Testcase_380_60_MultipartQueueStatsReply(BII_testgroup380.Testcase_380_40_MultipartQueueStats):

    """"""
    Tested in 380.40
    380.60 - Queue stats reply reserved
    Check that a queue stats request with a port field set to OFPP_ANY results in a queue stats reply 
    which includes each test ports' configured queues.
    """"""




class Testcase_380_70_MultipartQueueStatsReplyContent(BII_testgroup380.Testcase_380_50_MultipartQueueStatsContent):

    """"""
    Tested in 380.50
    380.70 - Queue stats reply standard
    Check that a queue stats request for a configured test port results in a queue stats reply 
    which includes the test port's configured queues.
    """




class Testcase_380_80_MultipartQueueStatsQueueID(base_tests.SimpleDataPlane):

    """
    380.80 - Queue stats
    Verify the correct number of queues are reported for each configured test port.
    """

    @wireshark_capture
    def runTest(self):  
        logging.info("Running test case Multipart Queue Stats Request Queue ID")      
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")

        port1, = openflow_ports(1)
        request = ofp.message.queue_stats_request()
        request.port_no = port1
	(reply, pkt)= self.controller.transact(request)
	if reply.type==ofp.OFPT_ERROR:
	    logging.warn("DUT does not support Queue stats")
	else:
	    stats = get_stats(self, request)
            self.assertIsNotNone(stats, "The switch failed to generate an Multipart Reply Message.")
            queue=[]
            for item in stats:
                queue.append(item.queue_id)
	    logging.info("Received reply including queue: %r",queue)




class Testcase_380_90_QueueGetConfigEmpty(base_tests.SimpleDataPlane):

    """
    380.90 - Queue config request reserved
    Check that an ofp_queue_get_config_request with a port field set to OFPP_ANY results in an ofp_queue_get_config_reply 
    which includes each test ports' configured queues.
    """
    @wireshark_capture
    def runTest(self):  
        logging.info("Running test case Multipart Queue Get Config Empty")      
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")
        request = ofp.message.queue_get_config_request()
        request.port = ofp.const.OFPP_ANY
        #self.controller.message_send(request)
        #reply, _ = self.controller.poll(exp_msg=ofp.OFPT_QUEUE_GET_CONFIG_REPLY, timeout=3)
        #self.assertIsNotNone(reply, "The switch failed to generate an Reply.")
	(reply, pkt)= self.controller.transact(request)
	if reply.type==ofp.OFPT_QUEUE_GET_CONFIG_REPLY:
	    self.assertIsNotNone(reply, "The switch failed to generate an Reply.")
	elif reply.type==ofp.OFPT_ERROR:
	    self.assertEqual(reply.err_type, ofp.OFPET_BAD_REQUEST,
                         ("Error type %d was received, but we expected OFPET_BAD_REQUEST.") % reply.err_type)
            self.assertEqual(reply.code, ofp.OFPBRC_BAD_TYPE,
                         ("Flow mod failed code %d was received, but we expected OFPBRC_BAD_TYPE.") % reply.code)
	else:
	    self.assertEqual(0,1, "The switch failed to generate an Reply.")


	    




class Testcase_380_100_QueueGetConfigPort(base_tests.SimpleDataPlane):

    """
    380.100 - Queue config request standard
    Check that an ofp_queue_get_config_request for a configured test port results in an ofp_queue_get_config_reply 
    which includes the test port's configured queues.
    """
    @wireshark_capture
    def runTest(self):  
        logging.info("Running test case Multipart Queue Get Config Port")      
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")
        port1, = openflow_ports(1)
        request = ofp.message.queue_get_config_request()
        request.port = port1
	(reply, pkt)= self.controller.transact(request)
	if reply.type==ofp.OFPT_QUEUE_GET_CONFIG_REPLY:
	    self.assertIsNotNone(reply, "The switch failed to generate an Reply.")
	elif reply.type==ofp.OFPT_ERROR:
	    self.assertEqual(reply.err_type, ofp.OFPET_BAD_REQUEST,
                         ("Error type %d was received, but we expected OFPET_BAD_REQUEST.") % reply.err_type)
            self.assertEqual(reply.code, ofp.OFPBRC_BAD_TYPE,
                         ("Flow mod failed code %d was received, but we expected OFPBRC_BAD_TYPE.") % reply.code)
	else:
	    self.assertEqual(0,1, "The switch failed to generate an Reply.")


"""
class Testcase_380_110_QueueGetConfigReplyEmpty(BII_testgroup380.Testcase_380_90_QueueGetConfigEmpty):

    """"""
    Tested in 380.90
    380.110 - Queue config reply reserved
    Check that an ofp_queue_get_config_request with a port field set to OFPP_ANY results in an ofp_queue_get_config_reply 
    which includes each test ports' configured queues.
    """"""




class Testcase_380_120_QueueGetConfigReplyPort(BII_testgroup380.Testcase_380_100_QueueGetConfigPort):

    """"""
    Tested in 380.100
    380.120 - Queue config reply standard
    Check that an ofp_queue_get_config_request for a configured test port results in an ofp_queue_get_config_reply 
    which includes the test port's configured queues.
    """




class Testcase_380_130_QueueGetConfigQueueID(base_tests.SimpleDataPlane):

    """
    380.130 - Queue configuration
    Verify the correct number of queues are reported for each configured test port.
    """
    @wireshark_capture
    def runTest(self):  
        logging.info("Running test case Queue Get Config Queue ID")      
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")

        port1, = openflow_ports(1)
        request = ofp.message.queue_get_config_request()
        request.port = port1
        self.controller.message_send(request)
	(reply, pkt)= self.controller.transact(request)
	if reply.type==ofp.OFPT_QUEUE_GET_CONFIG_REPLY:
	    self.assertIsNotNone(reply, "The switch failed to generate an Reply.")
	elif reply.type==ofp.OFPT_ERROR:
	    self.assertEqual(reply.err_type, ofp.OFPET_BAD_REQUEST,
                         ("Error type %d was received, but we expected OFPET_BAD_REQUEST.") % reply.err_type)
            self.assertEqual(reply.code, ofp.OFPBRC_BAD_TYPE,
                         ("Flow mod failed code %d was received, but we expected OFPBRC_BAD_TYPE.") % reply.code)
	else:
	    self.assertEqual(0,1, "The switch failed to generate an Reply.")
