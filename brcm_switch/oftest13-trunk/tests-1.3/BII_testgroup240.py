# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Maple Yip

"""
Test suite 240 verifies the ofp_switch_features structures various fields.

To satisfy the basic requirements an OpenFlow enabled device must pass 240.10 - 240.130.
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
class Testcase_240_10_SwitchFeatures(base_tests.SimpleProtocol):
    """"""
    240.10 - Features
    Verify for OFPT_FEATURES_REQUEST we get an OFPT_FEATURES_REQUEST back.
    """"""

    @wireshark_capture
    def runTest(self):
        logging.info("Running 240.10 - Features test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        self.assertEqual(reply.xid, request.xid, "xid is not correct")
        logging.info("Features reply received as expected.")



class Testcase_240_20_SwitchFeaturesDPID(base_tests.SimpleProtocol):
    """"""
    240.20 - Features DPID
    Verify lower 48 bits in DATAPAH_ID are for MAC and top 16 are for implementer use.
    """"""

    @wireshark_capture
    def runTest(self):
        logging.info("Running 240.20 - Features DPID test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        self.assertTrue(reply.datapath_id is not None, "Invalid DatapathID!")
        logging.info("Received datapath id: " + str(reply.datapath_id))



class Testcase_240_30_SwitchFeaturesMaxBuffers(base_tests.SimpleProtocol):
    """"""
    240.30 - Features reply - max buffers
    Verify number of packets switch can buffer is N_BUFFER when sending PACKET-IN.
    """"""

    @wireshark_capture
    def runTest(self):
        logging.info("Running 240.30 - Features max buffers test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        self.assertTrue(reply.n_buffers  is not None, "Invalid max buffers!")
        logging.info("Supported number of buffers: " + str(reply.n_buffers)) 



class Testcase_240_40_SwitchFeaturesTables(base_tests.SimpleProtocol):
    """"""
    240.40 - Number of tables supported by datapath
    Verify number of tables switch supports is what was contained in Features Reply N_TABLES.
    """"""

    @wireshark_capture
    def runTest(self):
        logging.info("Running 240.40 - Number of tables supported by datapath test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        self.assertTrue(reply.n_tables >= 1, "Invalid number of tables!")
        logging.info("Supported number of buffers: " + str(reply.n_tables))



class Testcase_240_50_SwitchFeaturesAuxiliaryID(base_tests.SimpleProtocol):
    """"""
    240.50 - Features auxiliary ID
    Verify type of connection by AUXILIARY_ID. 0 for main and other for auxiliary.
    """"""

    @wireshark_capture
    def runTest(self):
        logging.info("Running 240.50 - Features auxiliary ID test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        self.assertTrue(reply.auxiliary_id == 0, "Connection aux_id should be 0")
        logging.info("Connection aux_id: " + str(reply.auxiliary_id))



class Testcase_240_60_SwitchFeaturesCapabilities(base_tests.SimpleProtocol):
    """"""
    240.60 - Features capabilities
    Verify "ofp_capabilities".
    """"""

    @wireshark_capture
    def runTest(self):
        logging.info("Running 240.60 - Features capabilities test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        logging.info("Switch Capabilities: " + str(reply.capabilities))



class Testcase_240_70_SwitchFeaturesFlowStats(base_tests.SimpleProtocol):
    """"""
    240.70 - Features flow capabilities
    Verify "ofp_capabilities" supports OFPC_FLOW_STATS 
    """"""

    @wireshark_capture
    def runTest(self):
        logging.info("Running 240.70 - Features flow capabilities test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        mask = 1
        cap = mask & int(reply.capabilities)
        self.assertTrue(cap != 0, "Flow stats not supported by switch")
        logging.info("Flow stats supported by switch")



class Testcase_240_80_SwitchFeaturesTableStats(base_tests.SimpleProtocol):
    """"""
    240.80 - Features table capabilities
    Verify "ofp_capabilities" supports OFPC_TABLE_STATS
    """"""

    @wireshark_capture
    def runTest(self):
        logging.info("Running 240.80 - Features table capabilities test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        mask = 2
        cap = mask & int(reply.capabilities)
        self.assertTrue(cap != 0, "Table stats not supported by switch")
        logging.info("Table stats supported by switch")



class Testcase_240_90_SwitchFeaturesPortStats(base_tests.SimpleProtocol):
    """"""
    240.90 - Features port capabilities
    Verify "ofp_capabilities" supportsOFPC_PORT_STATS
    """"""

    @wireshark_capture
    def runTest(self):
        logging.info("Running 240.90 - Features port capabilities test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        mask = 4
        cap = mask & int(reply.capabilities)
        self.assertTrue(cap != 0, "Port stats not supported by switch")
        logging.info("Port stats supported by switch")



class Testcase_240_100_SwitchFeaturesGroupStats(base_tests.SimpleProtocol):
    """"""
    240.100 - Features reply - Group statistics
    Verify "ofp_capabilities" OFPC_GROUP_STATS
    """"""

    @wireshark_capture
    def runTest(self):
        logging.info("Running 240.100 - Features group capabilities test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        mask = 8
        cap = mask & int(reply.capabilities)
        self.assertTrue(cap != 0, "Group stats not supported by switch")
        logging.info("Group stats supported by switch")



class Testcase_240_110_SwitchFeaturesIPFragment(base_tests.SimpleProtocol):
    """"""
    240.110 - Supports IP fragments
    Verify "ofp_capabilities" supports OFPC_IP_REASM
    """"""

    @wireshark_capture
    def runTest(self):
        logging.info("Running 240.110 - Supports IP fragments test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        mask = 32
        cap = mask & int(reply.capabilities)
        self.assertTrue(cap != 0, "Reassemble IP fragments not supported by switch")
        logging.info("Reassemble IP fragments supported by switch")



class Testcase_240_120_SwitchFeaturesQueueStats(base_tests.SimpleProtocol):
    """"""
    240.120 - Features queue capabilities
    Verify "ofp_capabilities" supports OFPC_QUEUE_STATS
    """"""

    @wireshark_capture
    def runTest(self):
        logging.info("Running 240.120 - Features queue capabilities test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        mask = 64
        cap = mask & int(reply.capabilities)
        self.assertTrue(cap != 0, "Queue statistics not supported by switch")
        logging.info("Queue statistics supported by switch")



class Testcase_240_130_SwitchFeaturesBlockLooping(base_tests.SimpleProtocol):
    """"""
    240.130 - Supports block looping ports
    Verify "ofp_capabilities" supports OFPC_PORT_BLOCKED
    """"""

    @wireshark_capture
    def runTest(self):
        logging.info("Running 240.130 - Supports block looping ports test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        mask = 256
        cap = mask & int(reply.capabilities)
        self.assertTrue(cap != 0, "Block looping ports not supported by switch")
        logging.info("Block looping ports supported by switch")
"""