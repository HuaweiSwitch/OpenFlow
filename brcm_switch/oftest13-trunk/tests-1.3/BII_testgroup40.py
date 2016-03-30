# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Maple Yip

"""
Test suite 40 verifies that all basic information is correctly reported by a device.

To satisfy the basic requirements an OpenFlow enabled device must pass test cases 40.10 - 40.210.
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


class Testcase_40_10_FeaturesReplyDatapathID(base_tests.SimpleProtocol):
    """
    40.10 - Features reply - Datapath ID
    Verify that an OFPT_FEATURES_REQUEST message from generates an OFPT_FEATURES_REPLY from the switch containing a valid datapath ID.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 40.10 - Features reply - Datapath ID test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        self.assertTrue(reply.datapath_id is not None, "Invalid DatapathID!")
        logging.info("Received datapath id: " + str(reply.datapath_id))
        strmsg = 'Please manually verify the datapath id recorded in the log file'
        print strmsg



class Testcase_40_20_FeaturesReplyMaxBuffers(base_tests.SimpleProtocol):
    """
    40.20 - Features reply - max buffers
    Verify OFPT_FEATURES_REQUEST message generates OFPT_FEATURES_REPLY from the switch containing correct number of buffers.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 40.20 - Features reply - max buffers test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        self.assertTrue(reply.n_buffers  is not None, "Invalid max buffers!")
        logging.info("Supported number of buffers: " + str(reply.n_buffers)) 



class Testcase_40_30_FeaturesReplyTables(base_tests.SimpleProtocol):
    """
    40.30 - Features reply - Number of tables supported
    Verify OFPT_FEATURES_REQUEST message generates OFPT_FEATURES_REPLY from the switch containing correct number of tables supported.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 40.30 - Features reply - Number of tables supported test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        self.assertTrue(reply.n_tables >= 1, "Invalid number of tables!")
        logging.info("Supported number of tables: " + str(reply.n_tables))
        strmsg = 'Please manually verify the number of tables recorded in the log file'
        print strmsg



class Testcase_40_40_FeaturesReplyAuxiliaryID(base_tests.SimpleProtocol):
    """
    40.40 - Features reply - Auxiliary ID
    Verify that an OFPT_FEATURES_REQUEST message generates OFPT_FEATURES_REPLY from the switch containing a valid Auxiliary ID.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 40.40 - Features reply - Auxiliary ID test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        self.assertTrue(reply.auxiliary_id == 0, "Connection aux_id should be 0")
        logging.info("Connection aux_id: " + str(reply.auxiliary_id))



class Testcase_40_50_FeaturesReplyFlowStats(base_tests.SimpleProtocol):
    """
    40.50 - Features reply - Flow statistics
    Check whether the switch supports flow statistics
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 40.50 - Features reply - Flow statistics test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        mask = 1
        cap = mask & int(reply.capabilities)
        if cap !=0:
            logging.info("Flow stats supported by switch")
        else:
            logging.info("Flow stats not supported by switch")



class Testcase_40_60_FeaturesReplyTableStats(base_tests.SimpleProtocol):
    """
    40.60 - Features reply - Table statistics
    Check whether the switch supports table statistics
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 40.60 - Features reply - Table statistics test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        mask = 2
        cap = mask & int(reply.capabilities)
        if cap !=0:
            logging.info("Table stats supported by switch")
        else:
            logging.info("Table stats not supported by switch")




class Testcase_40_70_FeaturesReplyPortStats(base_tests.SimpleProtocol):
    """
    40.70 - Features reply - Port statistics
   Check whether the switch supports port statistics
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 40.70 - Features reply - Port statistics test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        mask = 4
        cap = mask & int(reply.capabilities)
        self.assertTrue(cap != 0, "Port stats not supported by switch")
        logging.info("Port stats supported by switch")



class Testcase_40_80_FeaturesReplyGroupStats(base_tests.SimpleProtocol):
    """
    40.80 - Features reply - Group statistics
    Check whether the switch supports group statistics
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 40.80 - Features reply - Group statistics test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        mask = 8
        cap = mask & int(reply.capabilities)
        if cap !=0:
            logging.info("Group stats supported by switch")
        else:
            logging.info("Group stats not supported by switch")
        



class Testcase_40_90_FeaturesReplyReassemble(base_tests.SimpleProtocol):
    """
    40.90 - Features reply - reassemble IP fragments
    Check whether the switch supports reassembling IP fragments
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 40.90 - Features reply - reassemble IP fragments test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        mask = 32
        cap = mask & int(reply.capabilities)
        if cap !=0:
            logging.info("Reassemble IP fragments supported by switch")
        else:
            logging.info("Reassemble IP fragments not supported by switch")




class Testcase_40_100_FeaturesReplyQueueStats(base_tests.SimpleProtocol):
    """
    40.100 - Features reply - Queue statistics
    Check whether the switch supports queue statistics
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 40.100 - Features reply - Queue statistics test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        mask = 64
        cap = mask & int(reply.capabilities)
        if cap !=0:
            logging.info("Queue statistics supported by switch")
        else:
            logging.info("Queue statistics not supported by switch")




class Testcase_40_110_FeaturesReplyBlockLooping(base_tests.SimpleProtocol):
    """
    40.110 - Features reply - Block looping ports
    Check whether the switch supports blocking of looping ports
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 40.110 - Features reply - Block looping ports test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        mask = 256
        cap = mask & int(reply.capabilities)
        if cap !=0:
            logging.info("Block looping ports supported by switch")
        else:
            logging.info("Block looping ports not supported by switch")




class Testcase_40_120_GetConfigMissSendLen(base_tests.SimpleProtocol):
    """
    40.120 - Get switch config - Miss send len
    Check the miss_send_len value returned by the switch.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 40.120 - Get switch config - Miss send len test")
        timeout = 5
        request = ofp.message.get_config_request()
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, " Failed to send get config request.")
        (reply, pkt) = self.controller.poll(exp_msg=ofp.OFPT_GET_CONFIG_REPLY,timeout=timeout)
        self.assertIsNotNone(reply,'Did not receive get config reply')
        logging.info("miss_send_len is %s", reply.miss_send_len)




class Testcase_40_130_GetConfigFragNormal(base_tests.SimpleProtocol):
    """
    40.130 - Get switch config - Frag normal
    Check whether the switch is configured for "No special handling for fragments".
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 40.130 - Get switch config - Frag normal test")
        timeout = 5
        request = ofp.message.set_config(flags=0,miss_send_len=128)
        self.controller.message_send(request)
        (response, pkt) = self.controller.poll(exp_msg=ofp.OFPT_ERROR,         
                                               timeout=5)
        self.assertTrue(response is None, 
                               'Switch replied with error message') 
        request = ofp.message.get_config_request()
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, " Failed to send get config request.")
        (reply, pkt) = self.controller.poll(exp_msg=ofp.OFPT_GET_CONFIG_REPLY,timeout=timeout)
        self.assertIsNotNone(reply,'Did not receive get config reply')
        self.assertTrue(reply.flags == 0, "Frag normal is not set")
        logging.info("Frag normal is set")




class Testcase_40_140_GetConfigFragDrop(base_tests.SimpleProtocol):
    """
    40.140 - Get switch config - Frag drop
    Check whether the switch is configured for drop fragments.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 40.140 - Get switch config - Frag drop test")
        timeout = 5
        request = ofp.message.set_config(flags=1,miss_send_len=128)
        self.controller.message_send(request)
        (response, pkt) = self.controller.poll(exp_msg=ofp.OFPT_ERROR,         
                                               timeout=5)
        self.assertTrue(response is None, 
                               'Switch replied with error message') 
        request = ofp.message.get_config_request()
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, " Failed to send get config request.")
        (reply, pkt) = self.controller.poll(exp_msg=ofp.OFPT_GET_CONFIG_REPLY,timeout=timeout)
        self.assertIsNotNone(reply,'Did not receive get config reply')
        self.assertTrue(reply.flags == 1, "Frag drop is not set")
        logging.info("Frag drop is set")
        request = ofp.message.set_config(flags=0,miss_send_len=128)
        self.controller.message_send(request)
        (response, pkt) = self.controller.poll(exp_msg=ofp.OFPT_ERROR,         
                                               timeout=5)
        self.assertTrue(response is None, 
                               'Switch replied with error message') 




class Testcase_40_150_GetConfigFragReasm(base_tests.SimpleProtocol):
    """
    40.150 - Get switch config - Frag reasm
    Check whether the switch is configured for reassembling fragments.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 40.150 - Get switch config - Frag reasm test")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        self.assertEqual(reply.type, ofp.OFPT_FEATURES_REPLY, "Received message is not features reply")
        mask = 16
        cap = mask & int(reply.capabilities)
        timeout = 5
        request = ofp.message.set_config(flags=2,miss_send_len=128)
        self.controller.message_send(request)
        (response, pkt) = self.controller.poll(exp_msg=ofp.OFPT_ERROR,         
                                               timeout=5)
        if cap == 0:
            self.assertTrue(response is not None, 
                               'Switch did not reply with error message')
            logging.info("Switch does not support Frag reasm")
        else:
            request = ofp.message.get_config_request()
            rv = self.controller.message_send(request)
            self.assertTrue(rv != -1, " Failed to send get config request.")
            (reply, pkt) = self.controller.poll(exp_msg=ofp.OFPT_GET_CONFIG_REPLY,timeout=timeout)
            self.assertIsNotNone(reply,'Did not receive get config reply')
            self.assertTrue(reply.flags == 2, "Frag reasm is not set")
            logging.info("Frag reasm is set")
            
        request = ofp.message.set_config(flags=0,miss_send_len=128)
        self.controller.message_send(request)
        (response, pkt) = self.controller.poll(exp_msg=ofp.OFPT_ERROR,         
                                               timeout=5)
        self.assertTrue(response is None, 
                               'Switch replied with error message') 




class Testcase_40_160_GetConfigFragMask(base_tests.SimpleProtocol):
    """
    40.160 - Get switch config - Frag mask
    Check whether the switch is configured for Frag Mask
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 40.160 - Get switch config - Frag mask test")
        timeout = 5
        request = ofp.message.set_config(flags=3,miss_send_len=128)
        self.controller.message_send(request)
        (response, pkt) = self.controller.poll(exp_msg=ofp.OFPT_ERROR,         
                                               timeout=5)
        self.assertTrue(response is None, 
                               'Switch replied with error message') 
        request = ofp.message.get_config_request()
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, " Failed to send get config request.")
        (reply, pkt) = self.controller.poll(exp_msg=ofp.OFPT_GET_CONFIG_REPLY,timeout=timeout)
        self.assertIsNotNone(reply,'Did not receive get config reply')
        self.assertTrue(reply.flags != 3, "Flags field cannot be OFPC_FRAG_MASK")
        logging.info("Frag mask is set")
        request = ofp.message.set_config(flags=0,miss_send_len=128)
        self.controller.message_send(request)
        (response, pkt) = self.controller.poll(exp_msg=ofp.OFPT_ERROR,         
                                               timeout=5)
        self.assertTrue(response is None, 
                               'Switch replied with error message') 




class Testcase_40_170_ManufacturerDescription(base_tests.SimpleProtocol):
    """
    40.170 - Manufacturer description
    Verify the switch reports the Manufacturer description
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 40.170 - Manufacturer description test")
        timeout = 5
        request = ofp.message.desc_stats_request()
        (reply, pkt)= self.controller.transact(request, timeout=timeout)
        self.assertTrue(reply is not None, "Did not receive reply")
        self.assertTrue(reply.type == ofp.const.OFPT_STATS_REPLY, "Received message is not desc stats reply")
        self.assertTrue(reply.mfr_desc is not None, "Invalid MFR description")
        logging.info("MFR description is " + reply.mfr_desc)




class Testcase_40_180_HWDescription(base_tests.SimpleProtocol):
    """
    40.180 - Hardware description
    Verify the switch reports the Hardware description
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 40.180 - Hardware description test")
        timeout = 5
        request = ofp.message.desc_stats_request()
        (reply, pkt)= self.controller.transact(request, timeout=timeout)
        self.assertTrue(reply is not None, "Did not receive reply")
        self.assertTrue(reply.type == ofp.const.OFPT_STATS_REPLY, "Received message is not desc stats reply")
        self.assertTrue(reply.hw_desc is not None, "Invalid Hardware description")
        logging.info("Hardware description is " + reply.hw_desc)




class Testcase_40_190_SoftwareDescription(base_tests.SimpleProtocol):
    """
    40.190 - Software description
    Verify the switch reports the Software description
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 40.190 - Software description test")
        timeout = 5
        request = ofp.message.desc_stats_request()
        (reply, pkt)= self.controller.transact(request, timeout=timeout)
        self.assertTrue(reply is not None, "Did not receive reply")
        self.assertTrue(reply.type == ofp.const.OFPT_STATS_REPLY, "Received message is not desc stats reply")
        self.assertTrue(reply.sw_desc is not None, "Invalid Software description")
        logging.info("Software description is " + reply.sw_desc)




class Testcase_40_200_SNDescription(base_tests.SimpleProtocol):
    """
    40.200 - Serial Number
    Verify the switch reports the Serial Number
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 40.200 - Serial Number test")
        timeout = 5
        request = ofp.message.desc_stats_request()
        (reply, pkt)= self.controller.transact(request, timeout=timeout)
        self.assertTrue(reply is not None, "Did not receive reply")
        self.assertTrue(reply.type == ofp.const.OFPT_STATS_REPLY, "Received message is not desc stats reply")
        self.assertTrue(reply.serial_num is not None, "Invalid Serial Number")
        logging.info("Serial Number is " + reply.serial_num)




class Testcase_40_210_DPDescription(base_tests.SimpleProtocol):
    """
    40.210 - Human readable datapath description of datapath
    Verify the switch reports the Human readable datapath description of datapath
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 40.210 - Human readable datapath description of datapath test")
        timeout = 5
        request = ofp.message.desc_stats_request()
        (reply, pkt)= self.controller.transact(request, timeout=timeout)
        self.assertTrue(reply is not None, "Did not receive reply")
        self.assertTrue(reply.type == ofp.const.OFPT_STATS_REPLY, "Received message is not desc stats reply")
        self.assertTrue(reply.dp_desc is not None, "Invalid Datapath Description")
        logging.info("Datapath Description is " + reply.dp_desc)
