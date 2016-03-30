# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Maple Yip

"""
Test suite 300 verifies the ofp_multipart_request structures various fields. In particular we define 
tests for multipart flags, features, statistics, and port descriptions.

To satisfy the basic requirements an OpenFlow enabled device must pass 300.40, 300.80 - 300.110, and 
300.130 - 300.300.
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
import BII_testgroup300
import BII_testgroup40
import BII_testgroup380

from oftest.oflog import *
from oftest.testutils import *
from time import sleep

class Testcase_300_40_MultipartRequestMoreFlag(base_tests.SimpleDataPlane):
    """
    300.40 - Multipart request more flag
    Verify a multipart request composed of multiple ofp_multipart_request messages is correctly replied to.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 300.40 - Multipart request more flag test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        flags = ofp.const.OFPSF_REQ_MORE
        request = ofp.message.port_desc_stats_request(flags=flags)
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, "Failed to send multipart")

        request = ofp.message.port_desc_stats_request(flags=flags)
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, "Failed to send multipart")


        request = ofp.message.port_desc_stats_request()
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, "Failed to send multipart")
      
        for x in range(3):
            reply,_=self.controller.poll(exp_msg=ofp.const.OFPT_STATS_REPLY)
            self.assertIsNotNone(reply, "Did not receive multipart reply")
            while reply.flags != 0:
                reply,_=self.controller.poll(exp_msg=ofp.const.OFPT_STATS_REPLY)
                self.assertIsNotNone(reply, "Did not receive more multipart reply")

	logging.info("Switch behavior is as expected")



class Testcase_300_80_MultipartReplyMoreFlag(base_tests.SimpleDataPlane):
    """
    300.80 - Multipart reply more flag
    Verify that replies composed of multiple ofp_multipart_reply messages have the OFPMPF_REPLY_MORE flag set on all but the last message.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 300.80 - Multipart reply more flag test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        request = ofp.message.port_stats_request(port_no=ofp.const.OFPP_ANY)
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, "Failed to send multipart")
      
        reply,_=self.controller.poll(exp_msg=ofp.const.OFPT_STATS_REPLY)
        self.assertIsNotNone(reply, "Did not receive multipart reply")
        while reply.flags != 0:
            reply,_=self.controller.poll(exp_msg=ofp.const.OFPT_STATS_REPLY)
            self.assertIsNotNone(reply, "Did not receive more multipart reply")

        logging.info("Switch behavior is as expected")

"""
class Testcase_300_90_MultipartReplyMoreFlagSet(BII_testgroup300.Testcase_300_80_MultipartReplyMoreFlag):
    
    Tested in 300.80
    300.90 - Multipart reply more flag set
    Verify that replies composed of multiple ofp_multipart_reply messages have the OFPMPF_REPLY_MORE flag set on all but the last message.
    """



class Testcase_300_100_MultipartXid(base_tests.SimpleDataPlane):
    """
    300.100 - Multipart message xid
    Verify that replies composed of multiple ofp_multipart_reply messages have the same xid as the request.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 300.100 - Multipart message xid test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        request = ofp.message.port_desc_stats_request()
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, "Failed to send multipart")

        reply,_=self.controller.poll(exp_msg=ofp.const.OFPT_STATS_REPLY)
        self.assertIsNotNone(reply, "Did not receive multipart reply")
        self.assertEqual(reply.xid, request.xid , "xid is not the same as multipart request")
        while reply.flags != 0:
            reply,_=self.controller.poll(exp_msg=ofp.const.OFPT_STATS_REPLY)
            self.assertIsNotNone(reply, "Did not receive more multipart reply")
            self.assertEqual(reply.xid, request.xid , "xid is not the same as multipart request")

        logging.info("Switch behavior is as expected")


"""
class Testcase_300_110_MultipartXidType(BII_testgroup300.Testcase_300_100_MultipartXid):
    """"""
    Tested in 300.100
    300.110 - Multipart message xid type
    Verify that replies composed of multiple ofp_multipart_reply messages have the same xid as the request.
    """"""



class Testcase_300_130_MultipartXidTypeDesc(BII_testgroup40.Testcase_40_170_ManufacturerDescription):
    """"""
    Tested in 40.170
    300.130 - Multipart type description
    Verify the switch reports the Manufacturer description
    """"""

        


class Testcase_300_140_MultipartTypeFlowStats(base_tests.SimpleDataPlane):
    """"""
    300.140 - Multipart type flow statistics
    Verify the switch can reply to the OFPMP_FLOW multipart request
    """"""

    @wireshark_capture
    def runTest(self):
        logging.info("Running 300.140 - Multipart type flow statistics test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port1, in_port2, in_port3, out_port, = openflow_ports(4)
        table_id=0
        priority=100
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port1)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow 1")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 1")
        
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port2)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow 2")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 2")

        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port3)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority) 
        logging.info("Insert flow 3")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 3") 

        stats = get_flow_stats(self,match=ofp.match())
        self.assertEqual(len(stats), 3, "Incorrect flow stats.")
        logging.info("Received multipart reply as expected")



class Testcase_300_150_MultipartTypeAggFlowStats(base_tests.SimpleDataPlane):
    """"""
    300.150 - Multipart type aggregate flow statistics
    verify the switch can reply to the OFPMP_AGGREGATE multipart request.
    """"""

    @wireshark_capture
    def runTest(self):
        logging.info("Running 300.150 - Multipart type aggregate flow statistics test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.aggregate_stats_request()
        reply, _=self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive stats reply")
        self.assertEqual(reply.type, ofp.const.OFPT_STATS_REPLY, "Type of stats reply is not correct")
        logging.info("Received stats reply as expected")



class Testcase_300_160_MultipartTypeFlowTableStats(base_tests.SimpleDataPlane):
    """"""
    300.160 - Multipart type flow table statistics
    Verify that the n_tables ofp_table_stats messages are returned in response to a multipart table request.
    """"""

    @wireshark_capture
    def runTest(self):
        logging.info("Running 300.160 - Multipart type flow table statistics test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.features_request()
        self.controller.message_send(request)
        reply, _ = self.controller.poll(exp_msg=ofp.const.OFPT_FEATURES_REPLY)
        self.assertIsNotNone(reply, "Did not receive features reply")

        request = ofp.message.table_stats_request()
        table_stats = get_stats(self, request)
        self.assertEqual(reply.n_tables, len(table_stats), "Flow Table Stats are not correct")



class Testcase_300_170_MultipartTypePortStats(base_tests.SimpleDataPlane):
    """"""
    300.170 - Multipart type port statistics
    The port_no field optionally filters the stats request to the given port. To request all port statistics, 
    port_no must be set to OFPP_ANY. The response is reported in ofp_port_stats structs.
    """"""

    @wireshark_capture
    def runTest(self):
        logging.info("Running 300.170 - Multipart type port statistics test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.port_stats_request(port_no=ofp.const.OFPP_ANY)
        stats = get_stats(self, request)
        ports = []
        for port_stats in stats:
            if port_stats.port_no in openflow_ports(4):
                  ports.append(port_stats.port_no)
        ports.sort()
        self.assertEqual(ports, openflow_ports(4), "Ports reoprted incorrectly")
        logging.info("All the ports are reported")

        port1, = openflow_ports(1)
        request = ofp.message.port_stats_request(port_no=port1)
        stats = get_stats(self, request)
        self.assertEqual(len(stats),1, "Port stats is not correct")
        self.assertEqual(stats[0].port_no,port1, "Returned port number is not correct")
        logging.info("Received port stats reply as expected")



class Testcase_300_180_MultipartTypeQueueStats(BII_testgroup380.Testcase_380_40_MultipartQueueStats):
    """"""
    300.180 - Multipart type queue statistics
    Verify that the n_tables ofp_table_stats messages are returned in response to a multipart table request.Check that a queue stats 
    request with a port field set to OFPP_ANY results in a queue stats reply which includes each test ports' configured queues.
    """



class Testcase_300_190_MultipartTypeGroupStats(base_tests.SimpleDataPlane):
    """
    300.190 - Multipart type group counter statistics
    Verify a valid response is received when requesting group counter statistics.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 300.190 - Multipart type group counter statistics test")
        rv = delete_all_flows(self.controller)
	delete_all_groups(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port,port_a, = openflow_ports(2)

        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_ALL,
            group_id=1,
            buckets=[
                ofp.bucket(actions=[ofp.action.output(port_a)])])
        #self.controller.message_send(msg)
        rv = self.controller.message_send(msg)
        self.assertTrue(rv != -1, "Failed to add group")

        table_id = 0
        priority = 100
        actions=[ofp.action.group(group_id = 1)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        request = ofp.message.flow_add(table_id=table_id,
                                   match=match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority)
        logging.info("Insert flow")
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, "Failed to insert flow") 

        request = ofp.message.group_stats_request(group_id = ofp.OFPG_ALL)
        reply, _= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive group stats reply")
        if reply.type == ofp.const.OFPT_ERROR:
            self.assertEqual(reply.err_type, ofp.const.OFPET_BAD_REQUEST, "Error type is not OFPET_BAD_REQUEST")
            self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_STAT, "Error code is not OFPBRC_BAD_STAT")
            logging.info("DUT does not support group stats and returned error msg as expected")
        else:
            self.assertEqual(reply.stats_type,ofp.const.OFPST_GROUP,"Received group stats reply as expected")



class Testcase_300_200_MultipartTypeGroupDescs(base_tests.SimpleDataPlane):
    """
    300.200 - Multipart type group description
    Verify a valid response is received when requesting group descriptions.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 300.200 - Multipart type group description test")
        rv = delete_all_flows(self.controller)
	delete_all_groups(self.controller)
	self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port,port_a, = openflow_ports(2)

        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_ALL,
            group_id=1,
            buckets=[
                ofp.bucket(actions=[ofp.action.output(port_a)])])
        rv = self.controller.message_send(msg)
        self.assertTrue(rv != -1, "Failed to Modify flow")

        table_id = 0
        priority = 100
        actions=[ofp.action.group(group_id = 1)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        request = ofp.message.flow_add(table_id=table_id,
                                   match=match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority)
        logging.info("Insert flow")
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, "Failed to add group") 

        request = ofp.message.group_desc_stats_request()
        reply, _= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive group desc stats reply")
        if reply.type == ofp.const.OFPT_ERROR:
            self.assertEqual(reply.err_type, ofp.const.OFPET_BAD_REQUEST, "Error type is not OFPET_BAD_REQUEST")
            self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_STAT, "Error code is not OFPBRC_BAD_STAT")
            logging.info("DUT does not support group desc stats and returned error msg as expected")
        else:
            self.assertEqual(reply.stats_type,ofp.const.OFPST_GROUP_DESC,"Received group desc stats reply as expected")



class Testcase_300_210_MultipartTypeGroupFeatures(base_tests.SimpleDataPlane):
    """
    300.210 - Multipart type group features
    Verify a valid response is received when requesting group features.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 300.210 - Multipart type group features test")
        rv = delete_all_flows(self.controller)
	delete_all_groups(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port,port_a, = openflow_ports(2)

        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_ALL,
            group_id=1,
            buckets=[
                ofp.bucket(actions=[ofp.action.output(port_a)])])
        rv = self.controller.message_send(msg)
        self.assertTrue(rv != -1, "Failed to add group") 

        table_id = 0
        priority = 100
        actions=[ofp.action.group(group_id = 1)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        request = ofp.message.flow_add(table_id=table_id,
                                   match=match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority)
        logging.info("Insert flow")
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, "Failed to insert flow") 

        request = ofp.message.group_features_stats_request()
        reply, _= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive group features reply")
        if reply.type == ofp.const.OFPT_ERROR:
            self.assertEqual(reply.err_type, ofp.const.OFPET_BAD_REQUEST, "Error type is not OFPET_BAD_REQUEST")
            self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_STAT, "Error code is not OFPBRC_BAD_STAT")
            logging.info("DUT does not support group features and returned error msg as expected")
        else:
            self.assertEqual(reply.stats_type,ofp.const.OFPST_GROUP_FEATURES,"Received msg is not group features")



class Testcase_300_220_MultipartTypeMeterStats(base_tests.SimpleDataPlane):
    """
    300.220 - Multipart type meter statistics
    Verify a valid response is received when requesting meter statistics.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 300.220 - Multipart type meter statistics test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port,port_a, = openflow_ports(2)

        """msg = ofp.message.meter_mod()
        msg.command = ofp.OFPMC_ADD
        msg.meter_id = 1
        msg.flags = ofp.OFPMF_KBPS
        band1 = ofp.meter_band.drop()
        band1.rate = 1024
        band1.burst_size = 12
        msg.meters = [band1]
        rv = self.controller.message_send(msg)
        self.assertTrue(rv != -1, "Failed to insert meter")

        table_id = 0
        priority = 100
        instructions=[ofp.instruction.meter(meter_id=1)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        request = ofp.message.flow_add(table_id=table_id,
                                   match=match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority)
        logging.info("Insert flow")
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, "Failed to insert flow") """

        request = ofp.message.meter_stats_request(meter_id=ofp.OFPM_ALL)
        reply, _= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive meter stats reply")
        if reply.type == ofp.const.OFPT_ERROR:
            self.assertEqual(reply.err_type, ofp.const.OFPET_BAD_REQUEST, "Error type is not OFPET_BAD_REQUEST")
            self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_STAT, "Error code is not OFPBRC_BAD_STAT")
            logging.info("DUT does not support meter stats and returned error msg as expected")
        else:
            self.assertEqual(reply.stats_type,ofp.const.OFPST_METER,"Received meter stats reply as expected")



class Testcase_300_230_MultipartTypeMeterConfig(base_tests.SimpleDataPlane):
    """
    300.230 - Multipart type meter configuration
    Verify a valid response is received when requesting meter configurations.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 300.230 - Multipart type meter configuration test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port,port_a, = openflow_ports(2)

        """msg = ofp.message.meter_mod()
        msg.command = ofp.OFPMC_ADD
        msg.meter_id = 1
        msg.flags = ofp.OFPMF_KBPS
        band1 = ofp.meter_band.drop()
        band1.rate = 1024
        band1.burst_size = 12
        msg.meters = [band1]
        rv = self.controller.message_send(msg)
        self.assertTrue(rv != -1, "Failed to insert meter")

        table_id = 0
        priority = 100
        instructions=[ofp.instruction.meter(meter_id=1)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        request = ofp.message.flow_add(table_id=table_id,
                                   match=match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority)
        logging.info("Insert flow")
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, "Failed to insert flow") """

        request = ofp.message.meter_config_stats_request(meter_id=ofp.OFPM_ALL)
        reply, _= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive meter config reply")
        if reply.type == ofp.const.OFPT_ERROR:
            self.assertEqual(reply.err_type, ofp.const.OFPET_BAD_REQUEST, "Error type is not OFPET_BAD_REQUEST")
            self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_STAT, "Error code is not OFPBRC_BAD_STAT")
            logging.info("DUT does not support meter config and returned error msg as expected")
        else:
            #self.assertEqual(reply.stats_type,ofp.const.OFPST_METER_CONFIG,"Received meter config reply as expected"
            strmsg = 'Please manually verify the reply in the packet trace'
            print strmsg




class Testcase_300_240_MultipartTypeMeterFeatures(base_tests.SimpleDataPlane):
    """
    300.240 - Multipart type meter features
    Verify a valid response is received when requesting meter features.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 300.240 - Multipart type meter features test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port,port_a, = openflow_ports(2)

        """msg = ofp.message.meter_mod()
        msg.command = ofp.OFPMC_ADD
        msg.meter_id = 1
        msg.flags = ofp.OFPMF_KBPS
        band1 = ofp.meter_band.drop()
        band1.rate = 1024
        band1.burst_size = 12
        msg.meters = [band1]
        rv = self.controller.message_send(msg)
        self.assertTrue(rv != -1, "Failed to insert meter")

        table_id = 0
        priority = 100
        instructions=[ofp.instruction.meter(meter_id=1)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        request = ofp.message.flow_add(table_id=table_id,
                                   match=match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority)
        logging.info("Insert flow")
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, "Failed to insert flow") """

        request = ofp.message.meter_features_stats_request()
        reply, _= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive meter features reply")
        if reply.type == ofp.const.OFPT_ERROR:
            self.assertEqual(reply.err_type, ofp.const.OFPET_BAD_REQUEST, "Error type is not OFPET_BAD_REQUEST")
            self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_STAT, "Error code is not OFPBRC_BAD_STAT")
            logging.info("DUT does not support meter features and returned error msg as expected")
        else:
            self.assertEqual(reply.stats_type,ofp.const.OFPST_METER_FEATURES,"Received msg is not meter features")


"""
class Testcase_300_250_MultipartTypeTableFeatures(base_tests.SimpleDataPlane):
    
    300.250 - Multipart type table features
    Verify that the oft_multipart_reply contains correct information without error.
    

    @wireshark_capture
    def runTest(self):
        logging.info("Running 300.250 - Multipart type table features test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.table_features_stats_request()
        reply = get_stats(self, request)
        self.assertIsNotNone(reply, "Did not receive table stats reply.")
        logging.info("Received table stats reply as expected")
"""


class Testcase_300_260_MultipartTypePortDesc(base_tests.SimpleDataPlane):
    """
    300.260 - Multipart type port description
    Verify a response composed of multiple ofp_port structs is received when requesting port descriptions.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 300.260 - Multipart type port description test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.port_desc_stats_request()
        response,pkt = self.controller.transact(request)
        self.assertTrue(response is not None,"Did not received port stats request")
        logging.info("Received Port stats reply as expected")



class Testcase_300_270_MultipartTypeExperimenter(base_tests.SimpleDataPlane):
    """
    300.270 - Multipart type experimenter extension
    Verify a valid response is received when requesting an experimenter extension.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 300.270 - Multipart type experimenter extension test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.experimenter_stats_request(experimenter=0x10111011)
        reply, _= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not get a reply to experimenter stats request")
        if reply.type == ofp.const.OFPT_ERROR:
            self.assertEqual(reply.err_type, ofp.const.OFPET_BAD_REQUEST, "Error type is not OFPET_BAD_REQUEST")
            self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_EXPERIMENTER, "Error code is not OFPBRC_BAD_EXPERIMENTER")
            logging.info("DUT does not support experimenter extension and returned error msg as expected")
        else:
            self.assertEqual(reply.stats_type,ofp.const.OFPST_EXPERIMENTER,"Received experimenter reply as expected")



class Testcase_300_280_MultipartBufferOverflow(base_tests.SimpleDataPlane):
    """
    300.280 - Multipart request buffer overflow
    Verify a valid response is received when requesting an experimenter extension.If a multipart request contains 
    more data than a device can buffer, verify a bad request error with a multipart buffer overflow code is generated.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 300.280 - Multipart request buffer overflow test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.port_stats_request(port_no=ofp.const.OFPP_ANY)
        stats = get_stats(self, request)
        self.assertIsNotNone(stats, "Did not receive port_stats_reply")

        try:
            # print stats.entries
            entry = []
            for i in range(200):
                entry.append(stats[0])

            req = ofp.message.port_stats_request(entries=entry) 
            self.controller.message_send(req)
            reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)

            self.assertIsNotNone(reply, "The switch failed to generate an error.")
            self.assertEqual(reply.err_type, ofp.const.OFPET_BAD_REQUEST, "Error type is not OFPET_BAD_REQUEST")
            self.assertEqual(reply.code, ofp.const.OFPBRC_MULTIPART_BUFFER_OVERFLOW, "Error code is not OFPBRC_MULTIPART_BUFFER_OVERFLOW")
            logging.info("Received correct error message")
        except   AttributeError:
            print   'No entry included in port stats reply'
            self.assertEqual(0,1, "No entry included in port stats reply")





class Testcase_300_290_MultipartUnsupportedType(base_tests.SimpleDataPlane):
    """
    300.290 - Multipart message unsupported type
    If a multipart request contains a type that is not supported, the switch must respond with an error message 
    of type OFPET_BAD_REQUEST and code OFPBRC_BAD_MULTIPART.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 300.290 - Multipart message unsupported type test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.stats_request()
        request.stats_type = 15
        reply,_ =self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive error msg")
        self.assertEqual(reply.type, ofp.OFPT_ERROR, "Did not receive error msg")
        self.assertEqual(reply.err_type, ofp.const.OFPET_BAD_REQUEST, "Error type is not OFPET_BAD_REQUEST")
        self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_STAT, "Error code is not OFPBRC_BAD_STAT")
        logging.info("Received error msg as expected")


