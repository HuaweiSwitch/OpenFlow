# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Maple Yip

"""
Test suite 450 verifies the device correctly implements various symmetric message types including ofp_hello, 
ofp_echo_request / ofp_echo_reply, and OUIs included in experimenter message types.

To satisfy the basic requirements an OpenFlow enabled device must pass 450.10 - 450.90.
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

import BII_testgroup10
import BII_testgroup200
import BII_testgroup430
import BII_testgroup450

class Testcase_450_10_HelloMessage(base_tests.SimpleDataPlane):

    """
    450.10 - Unknown hello elements
    Verify device can deal with unknown hello elements and their data.
    """

    def setUp(self):


        base_tests.BaseTest.setUp(self)
        self.controller = controller.Controller(
            switch=config["switch_ip"],
            host=config["controller_host"],
            port=config["controller_port"])
        self.controller.initial_hello = False
        #self.controller.start()

        #try:                                                                                                                    
            #self.controller.connect(timeout=20)                                                                                           
            #self.controller.keep_alive = True
            #if not self.controller.active:
                #raise Exception("Controller startup failed")
            #if self.controller.switch_addr is None:
                #raise Exception("Controller startup failed (no switch addr)")
            #logging.info("Connected " + str(self.controller.switch_addr))
        #except:
            #self.controller.kill()
            #del self.controller
            #raise 
    @wireshark_capture
    def runTest(self):  
        logging.info("Running test case Hello Message")  
        self.controller.start()
        self.controller.keep_alive = True
        ofp_field_version = 4
        res, pkt = self.controller.poll(exp_msg=ofp.OFPT_HELLO, timeout=3)

        req = ofp.message.hello()
        req.version = ofp_field_version
        bitmap = ofp.common.uint32(0x10) 
        hello_elem = ofp.common.hello_elem_versionbitmap(bitmaps=[bitmap])
        hello_elem2 = ofp.common.hello_elem_versionbitmap(bitmaps=[bitmap],type=5)
        #hello_elem2.type = 5
        req.elements.append(hello_elem)
        req.elements.append(hello_elem2)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "The switch generated an OFPT_ERROR")

    def tearDown(self):
        self.controller.shutdown()
        self.controller.join()
        del self.controller
        base_tests.BaseTest.tearDown(self)


# class Testcase_450_20_HelloElements(BII_testgroup10.Testcase_10_90_VersionNegotiationBitmap):

    # """
    # Tested in 10.90
    # 450.20 - Version negotiation based on bitmap
    # Verify that version negotiation based on bitmap is successful.
    # """




class Testcase_450_30_HelloMessage2Bitmap(base_tests.SimpleDataPlane):

    """
    450.30 - Multiple version bitmaps
    Verify that version negotiation based on multiple bitmaps is successful.
    """

    def setUp(self):

        base_tests.BaseTest.setUp(self)

        self.controller = controller.Controller(
            switch=config["switch_ip"],
            host=config["controller_host"],
            port=config["controller_port"])
        self.controller.initial_hello = False
        #self.controller.start()

        """try:                                                                                                                    
            self.controller.connect(timeout=20)                                                                                            
            self.controller.keep_alive = True
            if not self.controller.active:
                raise Exception("Controller startup failed")
            if self.controller.switch_addr is None:
                raise Exception("Controller startup failed (no switch addr)")
            logging.info("Connected " + str(self.controller.switch_addr))
        except:
            self.controller.kill()
            del self.controller
            raise"""

    @wireshark_capture
    def runTest(self):  
        logging.info("Running test case Hello Message")    
        self.controller.start()
        self.controller.keep_alive = True     
            
        res, pkt = self.controller.poll(exp_msg=ofp.OFPT_HELLO, timeout=3)
        
        hello_element_support = test_param_get("hello_element_support",0)
        if hello_element_support == 0:
            ofp_field_version = 4 # OpenFlow v1.3
        else:
            ofp_field_version = 0

        req = ofp.message.hello()
        req.version = ofp_field_version
        bitmap = ofp.common.uint32(0x10) 
        bitmap2 = ofp.common.uint32(0x02)
        hello_elem = ofp.common.hello_elem_versionbitmap(bitmaps=[bitmap])
        hello_elem2 = ofp.common.hello_elem_versionbitmap(bitmaps=[bitmap2])
        req.elements.append(hello_elem)
        req.elements.append(hello_elem2)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "The switch generated an OFPT_ERROR")
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")
        self.assertEqual(reply.version, ofp_field_version, "Response is not version 1.3")

    def tearDown(self):
        self.controller.shutdown()
        self.controller.join()
        del self.controller
        base_tests.BaseTest.tearDown(self)

"""
class Testcase_450_40_EchoData(base_tests.SimpleDataPlane):

    """"""
    450.40 - Basic OFPT_ECHO_REQUEST / OFPT_ECHO_REPLY
    Verify response to ECHO request
    """"""
    @wireshark_capture
    def runTest(self): 
        logging = get_logger()
        logging.info("Running test case 450.40 - Basic OFPT_ECHO_REQUEST")      
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request(data='abcdabcd')
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")
        self.assertEqual(reply.data, request.data, "Data is not the same as sended Echo Request Message")
        logging.info("Received a Echo Request")

"""

class Testcase_450_50_EchoEmpty(base_tests.SimpleDataPlane):

    """
    Tested in 200.30
    450.50 - Echo request reply with no data
    Verify response to ECHO request
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 200.30 basic ECHO REQUEST")
        delete_all_flows(self.controller)
        request = ofp.message.echo_request()
        self.controller.message_send(request)
        reply,_= self.controller.poll(exp_msg = ofp.OFPT_ECHO_REPLY, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive echo_reply messge")



# class Testcase_450_60_EchoReplyData(BII_testgroup450.Testcase_450_40_EchoData):

    # """
    # Tested in 450.40
    # 450.60 - Basic OFPT_ECHO_REQUEST / OFPT_ECHO_REPLY
    # Verify response to ECHO request
    # """



# class Testcase_450_90_Experimenter(BII_testgroup430.Testcase_430_120_BadRequestBadExperimenter):

    # """
    # Tested in 430.120
    # 450.90 - Bad request bad experimenter
    # If an unsupported experimenter request is sent to a device, check that 
    # the device generates a bad request error with a bad experimenter error.
    # """
