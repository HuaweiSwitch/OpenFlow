# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Maple Yip

"""
Test suite 430 verifies the device correctly implements various required error messages. Some devices may be unable 
to trigger specific error messages. The results of these test cases may be marked as not applicable or pass.

To satisfy the basic requirements an OpenFlow enabled device must pass 430.10 - 430.30, 430.50 - 430.70, 430.90 - 
430.180, 430.200 - 430.230, 430.250 - 430.330, 430.480, 430.500 - 430.510, 430.530 - 430.650, and 430.670 - 430.750.
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

import BII_testgroup80
import BII_testgroup150
import BII_testgroup300

"""
class Testcase_430_10_ErrorMessage(BII_testgroup150.Testcase_150_10_Invalid_table):

    
    Tested in 150.10
    430.10 - Error message notification
    Ensure that when a problem occurs on a device an error message is sent to the controller.
    """



class Testcase_430_20_ErrorMessage64BytesData(base_tests.SimpleDataPlane):

  """
  430.20 - Error message data
  Verify that if a request triggers an error message a portion of the request is included 
  in the data field of the resulting ofp_error_message.
  """
  @wireshark_capture
  def runTest(self):
    logging.info("Running test case ErrorMessage64BytesData")
    delete_all_flows(self.controller)
    in_port,out_port = openflow_ports(2)
    table_id=test_param_get("table", 254)
    priority = 1
    actions=[ofp.action.output(port=out_port,max_len=128)]
    instructions=[ofp.instruction.apply_actions(actions=actions)]
    match = ofp.match([ofp.oxm.in_port(in_port)])
    del_req = ofp.message.flow_delete(table_id=table_id,
                              match= match,
                              buffer_id=ofp.OFP_NO_BUFFER,
                              instructions=instructions,
                              priority=priority)
    logging.info("Deleting a flow with invalid table id, expect an error message")
    self.controller.message_send(del_req)
    logging.info("Polling for expected error message.")
    err, raw = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
    self.assertIsNotNone(err, "The switch failed to generate an error.")
#    self.assertEqual(err.err_type, ofp.const.OFPET_FLOW_MOD_FAILED,
#                        ("Error type %d was received, but we expected "
#                        "OFPET_FLOW_MOD_FAILED.") % err.err_type)
#    self.assertEqual(err.code, ofp.const.OFPFMFC_BAD_TABLE_ID,
#                        ("Flow mod failed code %d was received, but we "
#                        "expected OFPFMFC_BAD_TABLE_ID.") % err.code)
    self.assertTrue(len(err.data) >= 64, "Data field of error message should include at least 64 bytes")
    logging.info("The DUT generated error with appropriate type and code")



class Testcase_430_30_ErrorMessageXid(base_tests.SimpleDataPlane):

  """
  430.30 - Error message xid
  If a request triggers an error message, check that the error's xid is 
  equal to the original request.
  """
  @wireshark_capture
  def runTest(self):
    logging.info("Running test case ErrorMessageXid")
    delete_all_flows(self.controller)
    in_port,out_port = openflow_ports(2)
    table_id=test_param_get("table", 254)
    priority = 1
    actions=[ofp.action.output(port=out_port,max_len=128)]
    instructions=[ofp.instruction.apply_actions(actions=actions)]
    match = ofp.match([ofp.oxm.in_port(in_port)])
    del_req = ofp.message.flow_delete(table_id=table_id,
                              match= match,
                              buffer_id=ofp.OFP_NO_BUFFER,
                              instructions=instructions,
                              priority=priority)
    logging.info("Deleting a flow with invalid table id, expect an error message")
    self.controller.message_send(del_req)
    logging.info("Polling for expected error message.")
    err, raw = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
    self.assertIsNotNone(err, "The switch failed to generate an error.")
    self.assertTrue(err.xid == del_req.xid, "Error message have a different XID than the flow")
    logging.info("The DUT generated error with appropriate type and code")


"""
class Testcase_430_50_HelloFailedIncompatible(base_tests.SimpleDataPlane):

    """"""
    Tested in 10.80
    430.50 - Hello failed Incompatible
    Verify correct behavior in case of version negotiation failure.
    """"""
    @wireshark_capture
    def runTest(self):
        logging.info("Running 10.80 - Version negotiation failure test")
        timeout = 5
        nego_version = 0
        logging.info("Received Hello msg with correct version")
        request = ofp.message.hello()
        request.version=nego_version
        self.controller.message_send(request)
        logging.info("Sending Hello msg with version 0")
        (rv, pkt) = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=timeout)
        self.assertIsNotNone(rv, 'Did not receive Error msg')
        self.assertEqual(rv.err_type,ofp.const.OFPET_HELLO_FAILED, " Error type is not correct. Expect error type: OFPET_HELLO_FAILED")
        logging.info("Received OFPET_HELLO_FAILED")
        self.assertEqual(rv.code, ofp.const.OFPHFC_INCOMPATIBLE, "Error Code is not correct. Expect error code: OFPHFC_INCOMPATIBLE")
        logging.info("Received Error code is OFPHFC_INCOMPATIBLE")
"""


class Testcase_430_70_HelloFailData(base_tests.SimpleProtocol):
    """
    430.70 - Hello failed data
    Record a hello failure's data string.
    """

    def setUp(self):
        """
        This is similar to basic Setup except that initial hello is set to False
        """
        base_tests.BaseTest.setUp(self)

        self.controller = controller.Controller(
            switch=config["switch_ip"],
            host=config["controller_host"],
            port=config["controller_port"])
        self.controller.initial_hello = False
        #self.controller.start()

        """try:
            #self.controller.connect(timeout=20)
            #self.controller.keep_alive = True
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
        logging.info("Running Grp430No70 Hello Failed Data")                                    
        logging.info("Sending Hello message(controller -> switch) with version < 4")
        self.controller.start()
        self.controller.keep_alive = True
        
        request = ofp.message.hello()
        request.version=2
        logging.info("Veryfying the switch sends an error")
        (reply,pkt)=self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive error message")
        self.assertEqual(reply.type,ofp.OFPT_ERROR, "Did not receive OFPT_ERROR")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.OFPET_HELLO_FAILED, " Error type is not HELLO_FAILED")
        logging.info("Received HELLO_FAILED")
        self.assertEqual(reply.code, ofp.OFPHFC_INCOMPATIBLE, "Error Code is not OFPHFC_INCOMPATIBLE")
        logging.info("Received Error code is OFPHFC_INCOMPATIBLE")
        self.assertTrue(len(reply.data) > 0, "Data field is empty")
        logging.info("Data of err msg:" + str(reply.data))


        
class Testcase_430_90_ErrorMessageBadRequest(base_tests.SimpleDataPlane):

    """
    430.90 - Bad request bad version
    Verify that if a request with a bad version number is transmitted, a bad_request 
    error message with a bad version code is generated.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Bad Request")
        request = ofp.message.echo_request()
        request.version=2
        self.controller.message_send(request)
        reply, _  = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_REQUEST, " Error type is not OFPET_BAD_REQUEST")
        logging.info("Received OFPET_BAD_REQUEST")
        self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_VERSION, "Error Code is not OFPBRC_BAD_VERSION")
        logging.info("Received Error code is OFPBRC_BAD_VERSION")


        
class Testcase_430_100_ErrorMessageBadType(base_tests.SimpleDataPlane):

    """
    430.100 - Bad request bad type
    If that when a request uses an undefined type, the device generates a bad request 
    error with a bad type code.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Bad Type")
        request = ofp.message.barrier_request()
        request.type=30
        self.controller.message_send(request)
        reply, _  = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_REQUEST, " Error type is not OFPET_BAD_REQUEST")
        logging.info("Received OFPET_BAD_REQUEST")
        self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_TYPE, "Error Code is not OFPBRC_BAD_TYPE")
        logging.info("Received Error code is OFPBRC_BAD_TYPE")


"""
class Testcase_430_110_BadRequestBadMultipart(BII_testgroup300.Testcase_300_290_MultipartUnsupportedType):

    """"""
    Tested in 300.290
    430.110 - Bad request bad multipart
    If a request uses an undefined multipart type, the device generates a bad request error 
    with a bad multipart code.
    """



class Testcase_430_120_BadRequestBadExperimenter(base_tests.SimpleProtocol):

   
    """
    430.120 - Bad request bad experimenter
    If an unsupported experimenter request is sent to a device, check that the device generates 
    a bad request error with a bad experimenter error.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Bad Experimenter")
        request = ofp.message.experimenter_stats_request(experimenter=0x10111011)
        reply,_ =self.controller.transact(request)
        self.assertIsNotNone(reply, "Didnot get error")
        self.assertEqual(reply.type, ofp.OFPT_ERROR, "The DUT didnot generate OFPT_ERROR")
        self.assertEqual(reply.err_type, ofp.OFPET_BAD_REQUEST,
                             ("Appropriate error type not reported by switch"
                              " got %d.") % reply.err_type)
        self.assertEqual(reply.code,ofp.OFPBRC_BAD_EXPERIMENTER,
                             ("Appropriate error code not reported by switch"
                              " got %d") % reply.code)
        logging.info("The DUT generated error with appropriate type and code")



class Testcase_430_130_BadRequestBadExperimenterType(base_tests.SimpleProtocol):
  
    """
    430.130 - Bad request bad experimenter type
    If an experimenter request with an unsupported experimenter type is sent to a device, check 
    that the device generates a bad request error with a bad experimenter type error.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Bad Experimenter Type")
        request = ofp.message.experimenter_stats_request(experimenter=0x00000001, subtype=0xffffffff)
        reply,_ =self.controller.transact(request)
        self.assertIsNotNone(reply, "Didnot get error")
        self.assertEqual(reply.type, ofp.OFPT_ERROR, "The DUT didnot generate OFPT_ERROR")
        self.assertEqual(reply.err_type, ofp.OFPET_BAD_REQUEST,
                             ("Appropriate error type not reported by switch"
                              " got %d.") % reply.err_type)
        self.assertEqual(reply.code,ofp.OFPBRC_BAD_EXPERIMENTER_TYPE,
                             ("Appropriate error code not reported by switch"
                              " got %d") % reply.code)
        logging.info("The DUT generated error with appropriate type and code")



class Testcase_430_150_ErrorMessageBadLength(base_tests.SimpleDataPlane):

    """
    430.150 - Bad request bad length
    If a request's length is incorrectly specified, verify the device generates a bad request 
    error with a bad length code. 
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Bad Length")
        request = ofp.message.barrier_request(length=7)
        self.controller.message_send(request)
        reply, _  = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_REQUEST, " Error type is not OFPET_BAD_REQUEST")
        logging.info("Received OFPET_BAD_REQUEST")
        self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_LEN, "Error Code is not OFPBRC_BAD_LEN")
        logging.info("Received Error code is OFPBRC_BAD_LEN")

        
        
class Testcase_430_160_BufferEmpty(base_tests.SimpleDataPlane):

    """                                                                                                                                                        
    430.160 - Bad request buffer empty
    If a request specifies a buffer that has already been emptied, verify the device generates 
    a bad request error with a buffer empty code.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Buffer Empty")
        delete_all_flows(self.controller)
        port_a, port_b= openflow_ports(2)
        priority=1
        table_id=test_param_get("table", 0)
        actions=[ofp.action.output(port=ofp.OFPP_CONTROLLER)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([
            ofp.oxm.eth_type(0x0800)
        ])
        req = ofp.message.flow_add(table_id=table_id,
                                   match= match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority)
        logging.info("Installing a flow action output to controller")
        self.controller.message_send(req)
        verify_no_errors(self.controller)
        pkt = str(simple_tcp_packet())
        logging.info("Sending a matching packet")
        self.dataplane.send(port_a,pkt)
        res, _ = self.controller.poll(exp_msg=ofp.const.OFPT_PACKET_IN)
        self.assertIsNotNone(res, "Did not get packet in message")
        msg = ofp.message.packet_out(
                in_port=ofp.OFPP_CONTROLLER,
                actions=[ofp.action.output(port=port_b)],
                buffer_id=res.buffer_id)
        logging.info("Sending PacketOut, port %d", port_b)
        self.controller.message_send(msg)
        verify_packet(self,pkt,port_b)
        logging.info("Received packet on port %s", port_b)
        self.controller.message_send(msg)
        reply, _  = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_REQUEST, " Error type is not OFPET_BAD_REQUEST")
        logging.info("Received OFPET_BAD_REQUEST")
        self.assertEqual(reply.code, ofp.const.OFPBRC_BUFFER_EMPTY, "Error Code is not OFPBRC_BUFFER_EMPTY")
        logging.info("Received Error code is OFPBRC_BUFFER_EMPTY")


class Testcase_430_170_BufferUnknown(base_tests.SimpleDataPlane):

    """                                                                                                                                                        
    430.170 - Bad request buffer unknown
    If a request specified a buffer that does not exist, verify the device generates a 
    bad request error with a buffer unknown code.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Buffer Unknown")
        delete_all_flows(self.controller)
        port_a, = openflow_ports(1)
        invalid_buffer_id = 0xffffff00
        msg = ofp.message.packet_out(
                in_port=ofp.OFPP_CONTROLLER,
                actions=[ofp.action.output(port=port_a,max_len=128)],
                buffer_id=invalid_buffer_id)
        logging.info("Sending PacketOut, port %d", port_a)
        self.controller.message_send(msg)
        reply, _  = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_REQUEST, " Error type is not OFPET_BAD_REQUEST")
        logging.info("Received OFPET_BAD_REQUEST")
        self.assertEqual(reply.code, ofp.const.OFPBRC_BUFFER_UNKNOWN, "Error Code is not OFPBRC_BUFFER_UNKNOWN")
        logging.info("Received Error code is OFPBRC_BUFFER_UNKNOWN")


"""
class Testcase_430_180_BadRequestBadTableID(BII_testgroup150.Testcase_150_10_Invalid_table):

    
    Tested in 150.10
    430.180 - Bad request bad table
    If a request specifies a table_id that does not exist, verify the device generates 
    a bad request error with a bad table id code.
    """



class Testcase_430_200_ErrorMessageBadPort(base_tests.SimpleDataPlane):

    """
    430.200 - Bad request bad port
    If a request specifies a port number that does not exist, verify the device generates 
    a bad request error with a bad port code.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Bad Port")
        invalid_port = 1111
        request = ofp.message.port_stats_request(port_no=invalid_port)
        reply, _ = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Reply from DUT")
        if reply.type == ofp.OFPT_ERROR:
            logging.info("Error Message Received")
            self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_REQUEST, " Error type is not OFPET_BAD_REQUEST")
            logging.info("Received OFPET_BAD_REQUEST")
            self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_PORT, "Error Code is not OFPBRC_BAD_PORT")
            logging.info("Received Error code is OFPBRC_BAD_PORT")
        elif reply.type == ofp.OFPT_STATS_REPLY:
            self.assertTrue(reply.entries==[], "Port stats message was not empty")
        else:
            self.assertEqual(0,1, "Received unexpected message")




class Testcase_430_210_ErrorMessageBadPacket(base_tests.SimpleDataPlane):

    """
    430.210 - Bad request bad packet
    If a ofp_packet_out includes an invalid packet in its datafield, ensure the device returns 
    a bad request error with a bad packet code.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Bad Packet")
        delete_all_flows(self.controller)
        port_a, = openflow_ports(1)
        pkt = str(00)
        msg = ofp.message.packet_out(
                in_port=ofp.OFPP_CONTROLLER,
                actions=[ofp.action.output(port=port_a,max_len=128)],
                buffer_id=ofp.OFP_NO_BUFFER,
                data=pkt)
        logging.info("Sending PacketOut, port %d", port_a)
        self.controller.message_send(msg)
        reply, _  = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_REQUEST, " Error type is not OFPET_BAD_REQUEST")
        logging.info("Received OFPET_BAD_REQUEST")
        self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_PACKET, "Error Code is not OFPBRC_BAD_PACKET")
        logging.info("Received Error code is OFPBRC_BAD_PACKET")



class Testcase_430_230_ErrorMessageBadRequest64Bytes(base_tests.SimpleDataPlane):

    """
    430.230 - Bad request data
    Verify that when a bad request triggers an error message a portion of the request is 
    included in the data field of the resulting ofp_error_message.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Bad Request 64 Bytes")
        request = ofp.message.barrier_request()
        request.version=2
        self.controller.message_send(request)
        reply, _  = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_REQUEST, " Error type is not OFPET_BAD_REQUEST")
        logging.info("Received OFPET_BAD_REQUEST")
        self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_VERSION, "Error Code is not OFPBRC_BAD_VERSION")
        logging.info("Received Error code is OFPBRC_BAD_VERSION")
        if len(request.pack()) >= 64:
            self.assertTrue(len(reply.data) >= 64, "Data field of error message should include at least 64 bytes")
        else:
            self.assertEqual(reply.data , request.pack(), "Data field of error message should include at least 64 bytes")
        logging.info("The DUT generated error with appropriate type and code")



class Testcase_430_250_InvalidActionType(base_tests.SimpleDataPlane):

    """
    430.250 - Bad action bad type
    Verify that when an undefined action type is specified, the device generates 
    a bad action error with a bad type code.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Invalid Action Type")
        delete_all_flows(self.controller)
        InvalidActionType=30
        port_a, = openflow_ports(1)
        pkt = str(simple_tcp_packet())
        act = ofp.action.output(port=port_a,max_len=128)
        act.type = InvalidActionType
        msg = ofp.message.packet_out(
                in_port=ofp.OFPP_CONTROLLER,
                actions=[act],
                buffer_id=ofp.OFP_NO_BUFFER,
                data=pkt)
        logging.info("Sending PacketOut, port %d", port_a)
        self.controller.message_send(msg)
        reply, _  = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_ACTION, " Error type is not OFPET_BAD_ACTION")
        logging.info("Received OFPET_BAD_ACTION")
        self.assertEqual(reply.code, ofp.const.OFPBAC_BAD_TYPE, "Error Code is not OFPBAC_BAD_TYPE")
        logging.info("Received Error code is OFPBAC_BAD_TYPE")



class Testcase_430_260_InvalidActionLen(base_tests.SimpleDataPlane):

    """
    430.260 - Bad action bad length
    Verify that when an ofp_action_header specifies an invalid length field the device 
    generates a bad action error with a bad length code.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Invalid Action Length")
        delete_all_flows(self.controller)
        InvalidActionLength=14
        port_a, = openflow_ports(1)
        pkt = str(simple_tcp_packet())
        act = ofp.action.output(port=port_a,max_len=128, length=InvalidActionLength)
        msg = ofp.message.packet_out(
                in_port=ofp.OFPP_CONTROLLER,
                actions=[act],
                buffer_id=ofp.OFP_NO_BUFFER,
                data=pkt)
        logging.info("Sending PacketOut, port %d", port_a)
        self.controller.message_send(msg)
        reply, _  = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_ACTION, " Error type is not OFPET_BAD_ACTION")
        logging.info("Received OFPET_BAD_ACTION")
        self.assertEqual(reply.code, ofp.const.OFPBAC_BAD_LEN, "Error Code is not OFPBAC_BAD_LEN")
        logging.info("Received Error code is OFPBAC_BAD_LEN")



class Testcase_430_270_BadActionBadExperimenter(base_tests.SimpleDataPlane):

    """
    430.270 - Bad action bad experimenter
    Verify that when an unrecognized experimenter action is received, the device generates 
    a bad action error with a bad experimenter code.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Bad Action Bad Experimenter")
        delete_all_flows(self.controller)
        InvalidExperimenter=0x10111011
        port_a, = openflow_ports(1)
        pkt = str(simple_tcp_packet())
        act = ofp.action.experimenter()
        act.experimenter = InvalidExperimenter
        msg = ofp.message.packet_out(
                in_port=ofp.OFPP_CONTROLLER,
                actions=[act],
                buffer_id=ofp.OFP_NO_BUFFER,
                data=pkt)
        logging.info("Sending PacketOut, port %d", port_a)
        self.controller.message_send(msg)
        reply, _  = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_ACTION, " Error type is not OFPET_BAD_ACTION")
        logging.info("Received OFPET_BAD_ACTION")
        self.assertEqual(reply.code, ofp.const.OFPBAC_BAD_EXPERIMENTER, "Error Code is not OFPBAC_BAD_EXPERIMENTER")
        logging.info("Received Error code is OFPBAC_BAD_EXPERIMENTER")



"""
class Testcase_430_280_BadActionBadExperimenterType(base_tests.SimpleDataPlane):

    """"""
    430.280
    Test the basic implementation of Bad Action Bad Experimenter Type
    """"""
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Bad Action Bad Experimenter Type")
        delete_all_flows(self.controller)
        InvalidExperimenterType=0xff00
        port_a, = openflow_ports(1)
        pkt = str(simple_tcp_packet())
        act = ofp.action.experimenter()
        act.type = InvalidExperimenterType
        msg = ofp.message.packet_out(
                in_port=ofp.OFPP_CONTROLLER,
                actions=[act],
                buffer_id=ofp.OFP_NO_BUFFER,
                data=pkt)
        logging.info("Sending PacketOut, port %d", port_a)
        self.controller.message_send(msg)
        reply, _  = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_ACTION, " Error type is not OFPET_BAD_ACTION")
        logging.info("Received OFPET_BAD_ACTION")
        self.assertEqual(reply.code, ofp.const.OFPBAC_BAD_EXPERIMENTER_TYPE, "Error Code is not OFPBAC_BAD_EXPERIMENTER_TYPE")
        logging.info("Received Error code is OFPBAC_BAD_EXPERIMENTER_TYPE")



class Testcase_430_290_BadActionBadOutPort(BII_testgroup150.Testcase_150_150_Never_valid_port):

    """"""
    Tested in 150.150
    430.290 - Bad action bad out port
    Verify how OFP_FLOW_MOD handles invalid port in output action.
    """"""




class Testcase_430_300_BadActionBadArgument(BII_testgroup150.Testcase_150_180_bad_action):

    """"""
    Tested in 150.180
    430.300 - Bad action bad argument
    Verify how OFP_FLOW_MOD handles an invalid value.
    """"""



class Testcase_430_320_BadActionTooMany(base_tests.SimpleProtocol):
    """ """
    430.320 - Bad action too many
    Verify that if too many actions are included in a request,  the device generates a bad 
    action error with a too many code.
    """ """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Bad Action Too Many")

        delete_all_flows(self.controller)
        port_a, port_b, = openflow_ports(2)

        #Create flow_mod message with lot of actions
        table_id = test_param_get("table", 0)
        priority = 1
        match = ofp.match([
                ofp.oxm.eth_type(0x0800)
                ])
                
        # add a lot of actions
        for action_factor in range(1, 10):
            actions = [ofp.action.set_field(ofp.oxm.ipv4_src(167772361)) for i in range(2**action_factor)]
            act_output = ofp.action.output(port=port_b,max_len=128)
            actions.append(act_output)
            instructions = [ofp.instruction.apply_actions(actions=actions)]
            flow_mod_msg = ofp.message.flow_add(table_id=table_id,
                                           match=match,
                                           buffer_id=ofp.OFP_NO_BUFFER,
                                           instructions=instructions,
                                           priority=priority) 
            logging.info("Sending flow_mod message...")
            rv = self.controller.message_send(flow_mod_msg)
            self.assertTrue(rv != -1, "Error installing flow mod")
            self.assertEqual(do_barrier(self.controller), 0, "Barrier failed")

            logging.info("Waiting for OFPT_ERROR message...")
            (response, pkt) = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=5)
            
            if response is not None:
                break
            
            logging.info("DUT did not return an error. Increase number of actions and try again")
            delete_all_flows(self.controller)
            
        self.assertTrue(response is not None,
                               'Switch did not replay with error messge')
        self.assertTrue(response.type==ofp.OFPET_BAD_ACTION,
                               'Error type is not OFPET_BAD_ACTION')
        self.assertTrue(response.code==ofp.OFPBAC_TOO_MANY,
                               'Error code is not OFPBAC_TOO_MANY')


                               


"""
class Testcase_430_330_BadActionBadQueue(base_tests.SimpleDataPlane):

    """
    430.330 - Bad action bad queue
    Verify that if a bad queue_id is specified in a set-queue action, the device 
    generates a bad action error with a bad queue code.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Bad Action Bad Queue")
        delete_all_flows(self.controller)
        in_port,out_port = openflow_ports(2)
        table_id=test_param_get("table", 0)
        priority = 1
        invalidQueueID = 20
        actions=[ofp.action.set_queue(queue_id = invalidQueueID), ofp.action.output(port=out_port,max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                                   match=match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority )
        self.controller.message_send(req)
        reply, _  = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_ACTION, " Error type is not OFPET_BAD_ACTION")
        logging.info("Received OFPET_BAD_ACTION")
        self.assertEqual(reply.code, ofp.const.OFPBAC_BAD_QUEUE, "Error Code is not OFPBAC_BAD_QUEUE")
        logging.info("Received Error code is OFPBAC_BAD_QUEUE")



"""
class Testcase_430_480_BadActionUnsupportedActionOrder(base_tests.SimpleDataPlane):

    """ """
    Tested in 150.200
    430.480 - Bad action unsupported order
    Verify how OFP_FLOW_MOD handles action list that can't be supported in the specified sequence.
    """ """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case 430.480 - Bad action unsupported order test")
        logging.info("Tested in 150.200")
"""


class Testcase_430_500_BadActionBadSetType(base_tests.SimpleDataPlane):

    """
    430.500 - Bad action bad set type
    Verify that if an invalid set-field action is specified, the device generates a bad action 
    error with a bad set type code.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Bad Action Bad Set Type")
        delete_all_flows(self.controller)
        in_port,out_port = openflow_ports(2)
        table_id=test_param_get("table", 0)
        priority = 1
        actions=[ofp.action.set_field(ofp.oxm.arp_spa(167772361)), ofp.action.output(port=out_port,max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port), ofp.oxm.eth_type(0x0806)])
        req = ofp.message.flow_add(table_id=table_id,
                                   match=match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority )
        self.controller.message_send(req)
        reply, _  = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_ACTION, " Error type is not OFPET_BAD_ACTION")
        logging.info("Received OFPET_BAD_ACTION")
        self.assertEqual(reply.code, ofp.const.OFPBAC_BAD_SET_TYPE, "Error Code is not OFPBAC_BAD_SET_TYPE")
        logging.info("Received Error code is OFPBAC_BAD_SET_TYPE")

        
class Testcase_430_510_BadActionBadSetLength(base_tests.SimpleDataPlane):

    """
    430.510 - Bad action bad set Length
    Verify that if an invalid set-field oxm length is specified, the device generates a bad action error
    with a bad set length code. 
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Bad Action Bad Set Length")
        delete_all_flows(self.controller)
        in_port,out_port = openflow_ports(2)
        table_id=test_param_get("table", 0)
        priority = 1
        actions=[ofp.action.set_field(ofp.oxm.ipv4_src(0xc0a80005,length=3)), ofp.action.output(port=out_port,max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port), ofp.oxm.eth_type(0x0800)])
        req = ofp.message.flow_add(table_id=table_id,
                                   match=match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority )
        self.controller.message_send(req)
        reply, _  = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_ACTION, " Error type is not OFPET_BAD_ACTION")
        logging.info("Received OFPET_BAD_ACTION")
        self.assertEqual(reply.code, ofp.const.OFPBAC_BAD_SET_LEN, "Error Code is not OFPBAC_BAD_SET_LEN")
        logging.info("Received Error code is OFPBAC_BAD_SET_LEN")


class Testcase_430_530_BadActionData(base_tests.SimpleDataPlane):

    """                                                                                                                                                        
    430.530 - Bad action data
    Verify that when an action error is triggered, the data portion of the error message 
    contains a portion of the initial request.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Bad Action Data")
        delete_all_flows(self.controller)
        port_a, = openflow_ports(1)
        InvalidType = 0xff00
        data = str(simple_tcp_packet())
        act = ofp.action.experimenter()
        act.type = InvalidType
        msg = ofp.message.packet_out(
                in_port=ofp.OFPP_CONTROLLER,
                actions=[act],
                data = data,
                buffer_id=ofp.OFP_NO_BUFFER)
        logging.info("Sending PacketOut, port %d", port_a)
        self.controller.message_send(msg)
        reply, _  = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_ACTION, " Error type is not OFPET_BAD_ACTION")
        logging.info("Received OFPET_BAD_ACTION")
        self.assertEqual(reply.code, ofp.const.OFPBAC_BAD_TYPE, "Error Code is not OFPBAC_BAD_TYPE")
        logging.info("Received Error code is OFPBAC_BAD_TYPE")


"""
class Testcase_430_540_BadInstrctionUnknownInst(BII_testgroup150.Testcase_150_40_unknown_instruction):

    """"""
    Tested in 150.40
    430.540 - Bad instruction unknown instruction
    Verify how unknown instructions in "FLOW_MOD" are handled.
    """"""




class Testcase_430_550_BadInstrctionUnsupInst(BII_testgroup150.Testcase_150_50_unsupported_instruction):

    """"""
    Tested in 150.50
    430.550 - Bad instruction unsupported instruction
    Verify how unsupported instructions in "FLOW_MOD" are handled
    """"""




class Testcase_430_560_BadInstrctionBadTableID(BII_testgroup150.Testcase_150_60_Goto_invalidtable):

    """"""
    Tested in 150.60
    430.560 - Bad instruction bad table id
    Verify how invalid table is handled in Goto-Table and next-table-id
    """ """




# class Testcase_430_570_BadInstrctionUnsupMetadata(BII_testgroup150.Testcase_150_70_unsupported_meta_data):

    # """
    # Tested in 150.70
    # 430.570 - Bad instruction unsupported metadata
    # Verify how unsupported metadata value is handled in Write-Metadata
    # """



# class Testcase_430_580_BadInstrctionUnsupMetadataMask(BII_testgroup150.Testcase_150_70_unsupported_meta_data):

    # """
    # Tested in 150.70
    # 430.580 - Bad instruction unsupported metadata mask
    # Verify how unsupported metadata mask values are handled in Write-Metadata
    # """




class Testcase_430_590_BadInstructionBadExperimenter(base_tests.SimpleDataPlane):

    """
    430.590 - Bad instruction bad experimenter
    Verify the correct error message is generated when an unknown experimenter id is used.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Bad Instruction Bad Experimenter")
        delete_all_flows(self.controller)
        in_port,out_port = openflow_ports(2)
        table_id=test_param_get("table", 0)
        priority = 1
        instructions=[ofp.instruction.experimenter(experimenter=0x10111011)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                                   match=match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority )
        self.controller.message_send(req)

        reply, _  = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_INSTRUCTION, " Error type is not OFPET_BAD_INSTRUCTION")
        logging.info("Received OFPET_BAD_INSTRUCTION")
        self.assertEqual(reply.code, ofp.const.OFPBIC_BAD_EXPERIMENTER, "Error Code is not OFPBIC_BAD_EXPERIMENTER")
        logging.info("Received Error code is OFPBIC_BAD_EXPERIMENTER")

class Testcase_430_610_BadInstructionBadLength(base_tests.SimpleDataPlane):

    """
    430.610 - Bad instruction bad length
    Verify the correct error message is generated when an instructions length is incorrect.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Bad Instruction Bad Experimenter")
        delete_all_flows(self.controller)
        in_port,out_port = openflow_ports(2)
        table_id=test_param_get("table", 0)
        priority = 1
        actions=[
            ofp.action.output(
                port=out_port,
                max_len=ofp.OFPCML_NO_BUFFER)]
        inst = ofp.instruction
        #inst.instruction.length = 23
        instructions=[inst.apply_actions(actions,length=23)]
        #instructions.length=23
        match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                                   match=match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority )
        self.controller.message_send(req)
        reply, _  = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_INSTRUCTION, " Error type is not OFPET_BAD_INSTRUCTION")
        logging.info("Received OFPET_BAD_LEN")
        self.assertEqual(reply.code, ofp.const.OFPBIC_BAD_LEN, "Error Code is not OFPBIC_BAD_LEN")
        logging.info("Received Error code is OFPBIC_BAD_LEN")





class Testcase_430_630_BadInstructionData(base_tests.SimpleDataPlane):
    """
    430.630 - Bad instruction data
    Verify bad instruction errors include the first 64 bytes of the offending message.    
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case: Bad Instruction Data")
        
        delete_all_flows(self.controller)
        ingress, egress = openflow_ports(2)

        buffer_id = ofp.OFP_NO_BUFFER
        priority = 1
        table_id = 0
        actions = [ofp.action.output(port=egress, max_len=128)]

        invalid_instruction = ofp.instruction.apply_actions(actions=actions)
        invalid_instruction.type = 0xfff0

        fmod = ofp.message.flow_add(table_id=table_id, buffer_id=buffer_id,
                                    instructions=[invalid_instruction],
                                    priority=priority)
        fmod.match = ofp.match([ofp.oxm.in_port(ingress)])
        self.controller.message_send(fmod)
        
        err, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(err, "The switch failed to generate an OFPT_ERROR.")
        self.assertEqual(err.err_type, ofp.const.OFPET_BAD_INSTRUCTION,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_INSTRUCTION.") % err.err_type)
        self.assertEqual(err.code, ofp.const.OFPBIC_UNKNOWN_INST,
                         ("Bad instruction code %d was received, but we "
                          "expected OFPFBIC_UNKNOWN_INST.") % err.code)
        self.assertTrue(len(err.data) >= 64, "Data field of error message should include at least 64 bytes")
        logging.info("Received correct error message type and code.")




class Testcase_430_640_BadMatchBadType(base_tests.SimpleDataPlane):

    """
    430.640 - Bad match type
    Verify the correct error message is generated when a bad match type is used.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Bad Match Bad Type")
        delete_all_flows(self.controller)
        in_port,out_port,no_port = openflow_ports(3)
        table_id=test_param_get("table", 0)
        priority = 1
        actions=[ofp.action.output(port=out_port,max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                                   match=match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority )
        req.match.type = 40
        self.controller.message_send(req)
        err, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(err, "The switch failed to generate an OFPT_ERROR.")
        self.assertEqual(err.err_type, ofp.const.OFPET_BAD_MATCH,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_MATCH.") % err.err_type)
        self.assertEqual(err.code, ofp.const.OFPBMC_BAD_TYPE,
                         ("Bad match code %d was received, but we "
                          "expected OFPBMC_BAD_TYPE.") % err.code)
        logging.info("Received correct error message type and code.")



class Testcase_430_650_BadMatchLength(base_tests.SimpleDataPlane):

    """ 
    430.650 - Bad match length
    Verify the correct error message is generated when a bad match length is specified.
    """ 
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Bad Match Bad Length")
        delete_all_flows(self.controller)
        in_port,out_port,no_port = openflow_ports(3)
        table_id=test_param_get("table", 0)
        priority = 1
        actions=[ofp.action.output(port=out_port,max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port,length=3)])
        req = ofp.message.flow_add(table_id=table_id,
                                   match=match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority )
        #req.match.len = 3
        self.controller.message_send(req)
        err, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(err, "The switch failed to generate an OFPT_ERROR.")
        self.assertEqual(err.err_type, ofp.const.OFPET_BAD_MATCH,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_MATCH.") % err.err_type)
        self.assertEqual(err.code, ofp.const.OFPBMC_BAD_LEN,
                         ("Bad match code %d was received, but we "
                          "expected OFPBMC_BAD_LEN.") % err.code)
        logging.info("Received correct error message type and code.")



"""
class Testcase_430_670_BadMatchBadDLAddrMask(BII_testgroup150.Testcase_150_110_Bad_network_mask):

    """"""
    Tested in 150.110
    430.670 - Bad dl_addr mask match
    Verify how OFP_FLOW_MOD handles an arbitrary not supported mask in Layer 2 OR 3.
    """"""





class Testcase_430_680_BadMatchBadNWAddrMask(BII_testgroup150.Testcase_150_110_Bad_network_mask):

    """"""
    Tested in 150.110
    430.680 - Bad nw_addr mask match
    Verify how OFP_FLOW_MOD handles an arbitrary not supported mask in Layer 2 OR 3.
    """




class Testcase_430_690_BadMatchBadWildcards(base_tests.SimpleDataPlane):

    """
    430.690 - Bad wildcard match
    When using masking, it is an error for a 0-bit in oxm_mask to have a corresponding 
    1-bit in oxm_value
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Bad Match Bad Wildcards")
        delete_all_flows(self.controller)
        out_port, = openflow_ports(1)
        table_id=test_param_get("table", 0)
        priority=1
        actions=[ofp.action.output(port=out_port,max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        #Match on IPv4 source address subnet mask(Masked)
        match = ofp.match([
                ofp.oxm.eth_type(0x0800),
                # 192.168.0.0/20 (255.255.240.0)
                ofp.oxm.ipv4_src_masked(0xc0a80000, 0x0000ffff),
                ])
        req = ofp.message.flow_add(table_id=table_id,
                                   match= match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority)
        logging.info("Installing a flow to match on IPv4 source address(Subnet Masked) and action output to port %s", out_port)
        delete_all_flows(self.controller)
        self.controller.message_send(req)
        err, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(err, "The switch failed to generate an OFPT_ERROR.")
        self.assertEqual(err.err_type, ofp.const.OFPET_BAD_MATCH,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_MATCH.") % err.err_type)
        self.assertEqual(err.code, ofp.const.OFPBMC_BAD_WILDCARDS,
                         ("Bad match code %d was received, but we "
                          "expected WILDCARDS.") % err.code)
        logging.info("Received correct error message type and code.")



"""
class Testcase_430_700_BadMatchBadMatchField(BII_testgroup150.Testcase_150_80_Bad_match_field):

    """"""
    Tested in 150.80
    430.700 - Bad match field code
    Verify how OXM_TVL with unsupported value in FLOW_MOD is handled.
    """"""



class Testcase_430_710_BadMatchBadValue(BII_testgroup150.Testcase_150_140_illegal_value):

    """"""
    Tested in 150.140
    430.710 - Bad match valid
    Verify how OFP_FLOW_MOD handles value that can't be matched.
    """




# class Testcase_430_720_BadMatchBadMask(BII_testgroup150.Testcase_150_130_unsupported_mask):

    # """
    # Tested in 150.130
    # 430.720 - Bad match mask
    # Verify how OFP_FLOW_MOD handles an arbitrary mask for the fields that don't support it.
    # """


"""
class Testcase_430_730_BadMatchBadPrereq(BII_testgroup80.Testcase_80_180_Missing_Prerequisite):

    """"""
    Tested in 80.180
    430.730 - Bad match prerequisite
    Verify device behavior with missing required pre-requisite field
    """"""



class Testcase_430_740_BadMatchDupField(BII_testgroup80.Testcase_80_200_Multiple_instances_same_OXM_TYPE):

    """"""
    Tested in 80.200
    430.740 - Bad match duplicate field
    Verify behavior when a flow entry repeats an OXM_TYPE
    """
    
