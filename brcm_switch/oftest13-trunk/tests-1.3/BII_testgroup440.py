# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Maple Yip

"""
Test suite 440 verifies the device correctly implements various required error messages. Some devices may be unable 
to trigger specific error messages. The results of these test cases may be marked as not applicable or pass.

To satisfy the basic requirements an OpenFlow enabled device must pass 440.10 - 440.100, 440.240 - 440.430, 440.450, 
440.470, 440.480, 440.580, and 440.600 - 440.680.
"""

from oftest import config
from oftest.parse import parse_ip, parse_ipv6, parse_mac
from oftest.testutils import *
from time import sleep
import oftest.packet as scapy

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
import role_request
from oftest.oflog import *
from oftest import *

import BII_testgroup140
import BII_testgroup150
import BII_testgroup200



class Testcase_440_10_BadMatchData(base_tests.SimpleDataPlane):

    """
    440.10 - Bad match data
    Verify the data field of this ofp_error message includes either the full ofp_flow_mod 
    message, or the first 64 bytes of that message.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Bad Match Data")
        delete_all_flows(self.controller)
        out_port, no_port = openflow_ports(2)
        table_id=test_param_get("table", 0)
        priority=1
        actions=[ofp.action.output(port=out_port,max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        #Match on TCP source Port with missing pre-requisites
        match = ofp.match([
                ofp.oxm.tcp_src(53),
                ])
        req = ofp.message.flow_add(table_id=table_id,
                                    match= match,
                                    buffer_id=ofp.OFP_NO_BUFFER,
                                    instructions=instructions,
                                    priority=priority)
        logging.info("Installing a flow to match on IPv4 TCP source Port (with missing pre-requisites) and action output to port %s", out_port)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch did not generate OFPT_ERROR")
        logging.info("Switch generated an error")
        self.assertEqual(reply.err_type,ofp.const.OFPET_BAD_MATCH,"Reply type is not OFPET_BAD_MATCH")
        logging.info("Error type is OFPET_BAD_MATCH")
        self.assertEqual(reply.code,ofp.const.OFPBMC_BAD_PREREQ, "Reply code is not OFPBMC_BAD_PREREQ")
        logging.info("Error Code is OFPBMC_BAD_PREREQ")
        logging.info("Swtich generated an error and the flow is not installed")
        self.assertTrue(len(reply.data) >= 64, "Data field of error message should include at least 64 bytes")
        logging.info("Received error message contains at least 64 bytes data.")


"""
class Testcase_440_30_FlowmodFailedTableFull(BII_testgroup150.Testcase_150_30_Table_full):


    Tested in 150.30
    440.30 - Flow mod failed table full
    Verify how "OFPFC_ADD" is handled if table has no space.
"""




"""
class Testcase_440_40_FlowmodFailedBadTableID(BII_testgroup150.Testcase_150_10_Invalid_table):

    """"""
    Tested in 150.10
    440.40 - Flow mod failed bad table id
    Verify how "FLOW_MOD" with invalid TABLE-ID is handled. 
    """"""





class Testcase_440_50_FlowmodFailedOverlap(BII_testgroup140.Testcase_140_10_Overlap_Check):

    """"""
    Tested in 140.10
    440.50 - Flow mod failed overlap
    Verify how "FLOW_MOD" with invalid TABLE-ID is handled. 
    """




class Testcase_440_80_FlowmodFailedBadCommand(base_tests.SimpleDataPlane):
    """
    440.80 - Flow mod failed bad command
    Verify a bad flow mod command triggers the correct error message.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Flow Mod Failed Bad Command")
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
        req._command = 9
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_FLOW_MOD_FAILED, " Error type is not OFPET_FLOW_MOD_FAILED")
        logging.info("Received OFPET_FLOW_MOD_FAILED")
        self.assertEqual(reply.code, ofp.const.OFPFMFC_BAD_COMMAND, "Error Code is not OFPFMFC_BAD_COMMAND")
        logging.info("Received Error code is OFPFMFC_BAD_COMMAND")




class Testcase_440_90_FlowmodFailedBadFlags(base_tests.SimpleDataPlane):
    """
    440.90 - Flow mod failed bad flags
    Verify bad flow mod flags trigger the correct error message.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Flow Mod Failed Bad Flags")
        delete_all_flows(self.controller)
        out_port, = openflow_ports(1)
        table_id=test_param_get("table", 0)
        priority = 1
        flags=ofp.OFPFF_BSN_SEND_IDLE
        match = ofp.match([
                ofp.oxm.eth_type(0x0800)
                ])
        actions = [ofp.action.output(port=ofp.OFPP_CONTROLLER, max_len=128)]
        instructions = [ofp.instruction.apply_actions(actions=actions)]
        req = ofp.message.flow_modify(table_id=table_id,
                                       buffer_id=ofp.OFP_NO_BUFFER,
                                       priority=priority,
                                       match=match,
                                       instructions=instructions,
                                       flags=flags)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_FLOW_MOD_FAILED, " Error type is not OFPET_FLOW_MOD_FAILED")
        logging.info("Received OFPET_FLOW_MOD_FAILED")
        self.assertEqual(reply.code, ofp.const.OFPFMFC_BAD_FLAGS, "Error Code is not OFPFMFC_BAD_FLAGS")
        logging.info("Received Error code is OFPFMFC_BAD_FLAGS")




class Testcase_440_100_FlowmodFailedData(base_tests.SimpleDataPlane):
    """
    440.100 - Flow mod failed data
    Verify flow mod failed errors include up to 64 bytes of the offending request.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Flow Mod Failed Data")
        delete_all_flows(self.controller)
        out_port, = openflow_ports(1)
        table_id=test_param_get("table", 0)
        priority1 = 1
        priority2 = 2
        flags=ofp.OFPFF_CHECK_OVERLAP
        match = ofp.match([
                ofp.oxm.eth_type(0x0800)
                ])
        actions = [ofp.action.output(port=ofp.OFPP_CONTROLLER, max_len=128)]
        instructions = [ofp.instruction.apply_actions(actions=actions)]
        req1 = ofp.message.flow_add(table_id=table_id,
                                    buffer_id=ofp.OFP_NO_BUFFER,
                                    priority=priority1,
                                    match=match,
                                    instructions=instructions)
        self.controller.message_send(req1)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow ")

        req2 = ofp.message.flow_add(table_id=table_id,
                                    buffer_id=ofp.OFP_NO_BUFFER,
                                    priority=priority2,
                                    match=match,
                                    instructions=instructions,
                                    flags=flags)
        self.controller.message_send(req2)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "The switch  generated OFPT_ERROR. Could not insert the flow ")

        req3 = ofp.message.flow_add(table_id=table_id,
                                    buffer_id=ofp.OFP_NO_BUFFER,
                                    priority=priority1,
                                    match=match,
                                    instructions=instructions,
                                    flags=flags)
        self.controller.message_send(req3)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_FLOW_MOD_FAILED, " Error type is not OFPET_FLOW_MOD_FAILED")
        logging.info("Received OFPET_FLOW_MOD_FAILED")
        self.assertEqual(reply.code, ofp.const.OFPFMFC_OVERLAP, "Error Code is not OFPFMFC_OVERLAP")
        logging.info("Received Error code is OFPFMFC_OVERLAP")
        self.assertTrue(len(reply.data) >= 64, "Data field of error message should include at least 64 bytes")
        logging.info("Received correct error message contains at least 64 bytes data.")




class Testcase_440_250_GroupModFailedData(base_tests.SimpleDataPlane):

    """
    440.250 - Group mod failed
    Verify group mod failed errors include up to 64 bytes of the offending request.
    """

    def setUp(self):
        base_tests.SimpleDataPlane.setUp(self)
        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
    
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Group Mod Failed Data")
        port1, = openflow_ports(1)

        msg = ofp.message.group_add(
            group_type=ofp.OFPGT_ALL,
            group_id=0,
            buckets=[ofp.bucket(actions=[ofp.action.output(port1)])])
        msg.command = 7
        self.controller.message_send(msg)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_GROUP_MOD_FAILED, " Error type is not OFPET_GROUP_MOD_FAILED")
        logging.info("Received OFPET_GROUP_MOD_FAILED")
        self.assertTrue(len(reply.data) != 0, "Data field of error message should include at least 64 bytes")
        logging.info("Received correct error message contains data.")




class Testcase_440_260_PortModFailedBadPort(base_tests.SimpleDataPlane):
    """
    440.260 - Port mod failed bad port
    Verify the correct error message is generated when a port mod specifies a port number that 
    does not exist.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Port Mod Failed Bad Port")
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")
        self.assertEqual(reply.type, ofp.OFPT_ECHO_REPLY, "Response is not echo reply")
        req = ofp.message.port_mod(port_no=ofp.const.OFPP_MAX)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_PORT_MOD_FAILED, " Error type is not OFPET_PORT_MOD_FAILED")
        logging.info("Received OFPET_PORT_MOD_FAILED")
        self.assertEqual(reply.code, ofp.const.OFPPMFC_BAD_PORT, "Error Code is not OFPPMFC_BAD_PORT")
        logging.info("Received Error code is OFPPMFC_BAD_PORT")



class Testcase_440_270_PortModFailedBadHWAddr(base_tests.SimpleDataPlane):
    """
    440.270 - Port mod failed bad hw address
    Verify the correct error message is generated when a port mod specifies a hardware address 
    that does not match the port numbers hardware address.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Port Mod Failed Bad HW Address")
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")
        self.assertEqual(reply.type, ofp.OFPT_ECHO_REPLY, "Response is not echo reply")
        port1, = openflow_ports(1)
        invalidHWaddr = [0,0,0,0,0,0]
        req = ofp.message.port_mod(port_no=port1,hw_addr=invalidHWaddr)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_PORT_MOD_FAILED, " Error type is not OFPET_PORT_MOD_FAILED")
        logging.info("Received OFPET_PORT_MOD_FAILED")
        self.assertEqual(reply.code, ofp.const.OFPPMFC_BAD_HW_ADDR, "Error Code is not OFPPMFC_BAD_HW_ADDR")
        logging.info("Received Error code is OFPPMFC_BAD_HW_ADDR")




class Testcase_440_280_PortModFailedBadConfig(base_tests.SimpleDataPlane):
    """
    440.280 - Port mod failed bad configuration
    Verify the correct error message is generated when a port mod specifies a bad configuration.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Port Mod Failed Bad Config")
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")
        self.assertEqual(reply.type, ofp.OFPT_ECHO_REPLY, "Response is not echo reply")
        port1, = openflow_ports(1)
        
        request = ofp.message.port_desc_stats_request()
        stats = get_stats(self, request)
        hw_addr=[]
        for item in stats:
            if item.port_no in openflow_ports(1):
                hw_addr.append(item.hw_addr)
        invalidConfig = 256
        mask = 256
        req = ofp.message.port_mod(port_no=port1, 
                                hw_addr=hw_addr[0],
                                config=invalidConfig, 
                                mask=mask)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_PORT_MOD_FAILED, " Error type is not OFPET_PORT_MOD_FAILED")
        logging.info("Received OFPET_PORT_MOD_FAILED")
        self.assertEqual(reply.code, ofp.const.OFPPMFC_BAD_CONFIG, "Error Code is not OFPPMFC_BAD_CONFIG")
        logging.info("Received Error code is OFPPMFC_BAD_CONFIG")




class Testcase_440_290_PortModFailedBadAdvertise(base_tests.SimpleDataPlane):
    """
    440.290 - Port mod failed bad advertise
    Verify the correct error message is generated when a port mod specifies a bad advertise field.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Port Mod Failed Bad Advertise")
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")
        self.assertEqual(reply.type, ofp.OFPT_ECHO_REPLY, "Response is not echo reply")
        port1, = openflow_ports(1)
        
        request = ofp.message.port_desc_stats_request()
        stats = get_stats(self, request)
        hw_addr=[]
        for item in stats:
            if item.port_no in openflow_ports(1):
                hw_addr.append(item.hw_addr)
        invalidAdvertise = 0xffff0000
        req = ofp.message.port_mod(port_no=port1, 
                                hw_addr=hw_addr[0],
                                advertise=invalidAdvertise)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_PORT_MOD_FAILED, " Error type is not OFPET_PORT_MOD_FAILED")
        logging.info("Received OFPET_PORT_MOD_FAILED")
        self.assertEqual(reply.code, ofp.const.OFPPMFC_BAD_ADVERTISE, "Error Code is not OFPPMFC_BAD_ADVERTISE")
        logging.info("Received Error code is OFPPMFC_BAD_ADVERTISE")




class Testcase_440_310_PortModFailedData(base_tests.SimpleDataPlane):
    """
    440.310 - Port mod failed data
    Verify port mod failed errors include up to 64 bytes of the offending request.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Port Mod Failed Data")
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")
        self.assertEqual(reply.type, ofp.OFPT_ECHO_REPLY, "Response is not echo reply")
        req = ofp.message.port_mod(port_no=ofp.const.OFPP_MAX)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_PORT_MOD_FAILED, " Error type is not OFPET_PORT_MOD_FAILED")
        logging.info("Received OFPET_PORT_MOD_FAILED")
        self.assertEqual(reply.code, ofp.const.OFPPMFC_BAD_PORT, "Error Code is not OFPPMFC_BAD_PORT")
        logging.info("Received Error code is OFPPMFC_BAD_PORT")
        self.assertTrue(len(reply.data) != 0, "Data field of error message should include at least 64 bytes")
        logging.info("Received correct error message contains data.")




class Testcase_440_320_TableModFailedBadTable(base_tests.SimpleDataPlane):
    """
    440.320 - Table mod failed bad table
    Verify the correct error message is generated when a table mod specifies a table number 
    that does not exist.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Table Mod Failed Bad Table")
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")
        self.assertEqual(reply.type, ofp.OFPT_ECHO_REPLY, "Response is not echo reply")
        table_id=ofp.const.OFPTT_MAX
        request = ofp.message.table_mod(table_id=table_id,config=ofp.const.OFPTC_DEPRECATED_MASK)
        reply, _ = self.controller.transact(request)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        
        if reply.err_type == ofp.const.OFPET_TABLE_MOD_FAILED:
            logging.info("Received error type was OFPET_TABLE_MOD_FAILED.")
            if reply.code == ofp.OFPTMFC_BAD_TABLE:
                logging.info("Received correct error code OFPTMFC_BAD_TABLE.")
            elif reply.code == ofp.OFPTFMFC_EPERM:
                logging.info("Received correct error code OFPTFMFC_EPERM.")
            else:
                self.assertEqual(0, 1, "Error code was not correct")
        elif reply.err_type == ofp.const.OFPET_BAD_REQUEST:
            logging.info("Received error type was OFPET_BAD_REQUEST.")
            self.assertEqual(reply.code, ofp.OFPBRC_BAD_TYPE,
                              ("Flow mod failed code %d was received, but we "
                               "expected OFPBRC_BAD_TYPE.") % reply.code)
            logging.info("Received correct error code OFPBRC_BAD_TYPE.")
        else:
            self.assertEqual(0, 1, "Error type was not correct")



"""
class Testcase_440_330_TableModFailedBadConfig(BII_testgroup200.Testcase_200_150_basic_OFPT_TABLE_MOD):

    
    Tested in 200.150
    440.330 - Table mod failed bad config
    Verify table modification can recognize lower 2 bits and returns error for others.
    """




class Testcase_440_350_TableModFailedData(base_tests.SimpleDataPlane):
    """
    440.350 - Table mod failed data
    Verify table mod failed errors include up to 64 bytes of the offending request.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Table Mod Failed Data")
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")
        self.assertEqual(reply.type, ofp.OFPT_ECHO_REPLY, "Response is not echo reply")
        table_id=ofp.const.OFPTT_MAX
        request = ofp.message.table_mod(table_id=table_id, config=ofp.const.OFPTC_DEPRECATED_MASK)
        reply, _ = self.controller.transact(request)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        
        if reply.err_type == ofp.const.OFPET_TABLE_MOD_FAILED:
            logging.info("Received error type was OFPET_TABLE_MOD_FAILED.")
            if reply.code == ofp.OFPTMFC_BAD_TABLE:
                logging.info("Received correct error code OFPTMFC_BAD_TABLE.")
                if len(reply.data) < 64:
                    self.assertEqual(request.pack(), reply.data, "Data field of error message should include up to 64 bytes of the offending request")
                else:
                    self.assertEqual(request.pack()[:len(reply.data)], reply.data, "Data field of error message should include up to 64 bytes of the offending request")
            elif reply.code == ofp.OFPTFMFC_EPERM:
                logging.info("Received correct error code OFPTFMFC_EPERM.")
            else:
                self.assertEqual(0, 1, "Error code was not correct")
        elif reply.err_type == ofp.const.OFPET_BAD_REQUEST:
            logging.info("Received error type was OFPET_BAD_REQUEST.")
            self.assertEqual(reply.code, ofp.OFPBRC_BAD_TYPE,
                              ("Flow mod failed code %d was received, but we "
                               "expected OFPBRC_BAD_TYPE.") % reply.code)
            logging.info("Received correct error code OFPBRC_BAD_TYPE.")
        else:
            self.assertEqual(0, 1, "Error type was not correct")




class Testcase_440_360_QueueOPFailedBadPort(base_tests.SimpleDataPlane):
    """
    440.360 - Queue operation failed bad port
    Verify the correct error message is generated when a queue op message specifies a bad port.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Queue OP Failed Bad Port")
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")
        self.assertEqual(reply.type, ofp.OFPT_ECHO_REPLY, "Response is not echo reply")
        invalidPort = ofp.const.OFPP_MAX
        request = ofp.message.queue_stats_request(queue_id=ofp.const.OFPQ_ALL,port_no=invalidPort)
        self.controller.message_send(request)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        self.assertEqual(reply.err_type,ofp.const.OFPET_QUEUE_OP_FAILED, " Error type is not OFPET_QUEUE_OP_FAILED")
        logging.info("Received OFPET_QUEUE_OP_FAILED")
        self.assertEqual(reply.code, ofp.const.OFPQOFC_BAD_PORT, "Error Code is not OFPQOFC_BAD_PORT")
        logging.info("Received Error code is OFPQOFC_BAD_PORT")




class Testcase_440_370_QueueOPFailedBadQueue(base_tests.SimpleDataPlane):
    """
    440.370 - Queue operation failed bad queue
    Verify the correct error message is generated when a queue op message specifies a bad queue.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Queue OP Failed Bad Queue")
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")
        self.assertEqual(reply.type, ofp.OFPT_ECHO_REPLY, "Response is not echo reply")
        
        port1, = openflow_ports(1)
        invalidQueue = 0xfffffffe
        request = ofp.message.queue_stats_request(port_no=port1, queue_id=invalidQueue)
        reply, _ = self.controller.transact(request)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        self.assertTrue(reply.type == ofp.OFPT_ERROR,"The switch failed to generated an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_QUEUE_OP_FAILED, " Error type is not OFPET_QUEUE_OP_FAILED")
        logging.info("Received OFPET_QUEUE_OP_FAILED")
        self.assertEqual(reply.code, ofp.const.OFPQOFC_BAD_QUEUE, "Error Code is not OFPQOFC_BAD_QUEUE")
        logging.info("Received Error code is OFPQOFC_BAD_QUEUE")




class Testcase_440_390_QueueOPFailedData(base_tests.SimpleDataPlane):
    """
    440.390 - Queue operation failed data
    Verify queue op failed errors include up to 64 bytes of the offending request.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Queue OP Failed Data")
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")
        self.assertEqual(reply.type, ofp.OFPT_ECHO_REPLY, "Response is not echo reply")
        invalidPort = ofp.const.OFPP_MAX
        request = ofp.message.queue_stats_request(queue_id=ofp.const.OFPQ_ALL,port_no=invalidPort)
        self.controller.message_send(request)
        err, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(err, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(err.err_type,ofp.const.OFPET_QUEUE_OP_FAILED, " Error type is not OFPET_QUEUE_OP_FAILED")
        logging.info("Received OFPET_QUEUE_OP_FAILED")
        self.assertEqual(err.code, ofp.const.OFPQOFC_BAD_PORT, "Error Code is not OFPQOFC_BAD_PORT")
        logging.info("Received Error code is OFPQOFC_BAD_PORT")
        self.assertTrue(len(err.data) != 0, "Data field of error message should include at least 64 bytes")
        logging.info("Received correct error message contains data.")



class Testcase_440_400_SwitchConfigFailedBadFlags(base_tests.SimpleDataPlane):
    """
    440.400 - Switch config failed bad flags
    Verify the correct error message is generated when a switch config specifies bad flags.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Switch Config Failed Bad Flags")
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")
        self.assertEqual(reply.type, ofp.OFPT_ECHO_REPLY, "Response is not echo reply")
        
        invalidFlags = 16
        req = ofp.message.set_config(flags=invalidFlags)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_SWITCH_CONFIG_FAILED, " Error type is not OFPET_SWITCH_CONFIG_FAILED")
        logging.info("Received OFPET_SWITCH_CONFIG_FAILED")
        self.assertEqual(reply.code, ofp.const.OFPSCFC_BAD_FLAGS, "Error Code is not OFPSCFC_BAD_FLAGS")
        logging.info("Received Error code is OFPSCFC_BAD_FLAGS")


class Testcase_440_410_SwitchConfigFailedBadLength(base_tests.SimpleDataPlane):
    """
    440.410 - Switch config failed bad length
    Verify the correct error message is generated when a switch config specifies a bad length.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Switch Config Failed Bad Length")
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")
        self.assertEqual(reply.type, ofp.OFPT_ECHO_REPLY, "Response is not echo reply")
        
        #invalidFlags = 16
        #req = ofp.message.set_config(length=3)
        #self.controller.message_send(req)
        #reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        #self.assertIsNotNone(reply, "The switch failed to generate an error.")
        #logging.info("Error Message Received")
        #self.assertEqual(reply.err_type,ofp.const.OFPET_SWITCH_CONFIG_FAILED, " Error type is not OFPET_SWITCH_CONFIG_FAILED")
        #logging.info("Received OFPET_SWITCH_CONFIG_FAILED")
        #self.assertEqual(reply.code, ofp.const.OFPSCFC_BAD_LEN, "Error Code is not OFPSCFC_BAD_LEN")
        #logging.info("Received Error code is OFPSCFC_BAD_LEN")



class Testcase_440_430_SwitchConfigFailedData(base_tests.SimpleDataPlane):
    """
    440.430 - Switch config failed date
    Verify switch config failed errors include up to 64 bytes of the offending request.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Switch Config Failed Data")
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")
        self.assertEqual(reply.type, ofp.OFPT_ECHO_REPLY, "Response is not echo reply")
        
        invalidFlags = 18
        req = ofp.message.set_config(flags=invalidFlags)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_SWITCH_CONFIG_FAILED, " Error type is not OFPET_SWITCH_CONFIG_FAILED")
        logging.info("Received OFPET_SWITCH_CONFIG_FAILED")
        self.assertEqual(reply.code, ofp.const.OFPSCFC_BAD_FLAGS, "Error Code is not OFPSCFC_BAD_FLAGS")
        logging.info("Received Error code is OFPSCFC_BAD_FLAGS")
        self.assertTrue(len(reply.data) != 0, "Data field of error message should include at least 64 bytes")
        logging.info("Received correct error message contains data.")




class Testcase_440_450_RoleRequestFailedUnsupported(base_tests.SimpleDataPlane):
    """ 
    440.450 - Role request failed unsupported
    Verify the correct error message is generated when a role request is unsupported.
    """ 
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Role Request Failed Unsupported")
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")
        self.assertEqual(reply.type, ofp.OFPT_ECHO_REPLY, "Response is not echo reply")
        
        role, gen0 = role_request.simple_role_request(self, ofp.OFPCR_ROLE_NOCHANGE)
        self.assertEqual(role, ofp.OFPCR_ROLE_EQUAL)
        # Smallest greater generation ID
        req = ofp.message.role_request(role=ofp.OFPCR_ROLE_SLAVE, generation_id=role_request.add_mod64(gen0, 1))
	self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        if reply.err_type == ofp.const.OFPET_ROLE_REQUEST_FAILED:
            logging.info("Received error type was OFPET_ROLE_REQUEST_FAILED.")
            self.assertEqual(reply.code, ofp.const.OFPRRFC_UNSUP, "Error Code is not OFPRRFC_UNSUP")
            logging.info("Received Error code is OFPRRFC_UNSUP")
        elif reply.err_type == ofp.const.OFPET_BAD_REQUEST:
            logging.info("Received error type was OFPET_BAD_REQUEST.")
            self.assertEqual(reply.code, ofp.OFPBRC_BAD_TYPE,
                              ("Flow mod failed code %d was received, but we "
                               "expected OFPBRC_BAD_TYPE.") % reply.code)
            logging.info("Received correct error code OFPBRC_BAD_TYPE.")
        else:
            self.assertEqual(0, 1, "Error type was not correct")
            




class Testcase_440_470_RoleRequestFailedData(base_tests.SimpleDataPlane):
    """
    440.470 - Role request failed data
    Verify role request failed errors include up to 64 bytes of the offending request.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Role Request Failed Data")
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")
        self.assertEqual(reply.type, ofp.OFPT_ECHO_REPLY, "Response is not echo reply")
        invalidRole = 4
        req = ofp.message.role_request(role=invalidRole)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        
        if reply.err_type == ofp.const.OFPET_ROLE_REQUEST_FAILED:
            logging.info("Received error type was OFPET_ROLE_REQUEST_FAILED.")
            self.assertEqual(reply.code, ofp.const.OFPRRFC_BAD_ROLE,
                              ("Role Request code %d was received, but we "
                               "expected OFPRRFC_BAD_ROLE.") % reply.code)
            logging.info("Received correct error code OFPRRFC_BAD_ROLE.")
            if len(reply.data) < 64:
                self.assertEqual(req.pack(), reply.data, "Data field of error message should include up to 64 bytes of the offending request")
            else:
                self.assertEqual(req.pack()[:len(reply.data)], reply.data, "Data field of error message should include up to 64 bytes of the offending request")
        elif reply.err_type == ofp.const.OFPET_BAD_REQUEST:
            logging.info("Received error type was OFPET_BAD_REQUEST.")
            self.assertEqual(reply.code, ofp.OFPBRC_BAD_TYPE,
                              ("Bad request code %d was received, but we "
                               "expected OFPBRC_BAD_TYPE.") % reply.code)
            logging.info("Received correct error code OFPBRC_BAD_TYPE.")
        else:
            self.assertEqual(0, 1, "Error type was not correct")
            




class Testcase_440_580_MeterModFailedOutofMeter(base_tests.SimpleDataPlane):
    """ 
    440.580 - Meter mod failed out of meters
    When the device is out of meters verify the correct error message is generated.
    """ 
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Meter Mod Failed Out of Meter")
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")
        self.assertEqual(reply.type, ofp.OFPT_ECHO_REPLY, "Response is not echo reply")
        logging.info("Delete metermod")
        req = ofp.message.meter_mod()
        req.command = ofp.OFPMC_DELETE
        req.meter_id = ofp.const.OFPM_ALL
        self.controller.message_send(req)
        logging.info("Insert metermod")
        no = 2500
        band1 = ofp.meter_band.drop()
        band1.rate = 1024
        band1.burst_size = 12
        for i in range(1, no):
            msg = ofp.message.meter_mod()
            msg.command = ofp.OFPMC_ADD
            msg.meter_id = i
            msg.flags = ofp.OFPMF_KBPS
            msg.meters = [band1]
            self.controller.message_send(msg)
            reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
            if reply is not None:
                logging.info("Error Message Received")
                if reply.err_type == ofp.const.OFPET_METER_MOD_FAILED:
                    logging.info("Received error type was OFPET_METER_MOD_FAILED.")
                    self.assertEqual(reply.code, ofp.const.OFPMMFC_OUT_OF_METERS,
                                      ("Meter mod failed code %d was received, but we "
                                       "expected OFPMMFC_OUT_OF_METERS.") % reply.code)
                    logging.info("Received correct error code OFPMMFC_OUT_OF_METERS.")
                    return
                elif reply.err_type == ofp.const.OFPET_BAD_REQUEST:
                    logging.info("Received error type was OFPET_BAD_REQUEST.")
                    self.assertEqual(reply.code, ofp.OFPBRC_BAD_TYPE,
                                      ("Bad request code %d was received, but we "
                                       "expected OFPBRC_BAD_TYPE.") % reply.code)
                    logging.info("Received correct error code OFPBRC_BAD_TYPE.")
                    return
        self.assertIsNotNone(reply, "The switch failed to generate an error.")



class Testcase_440_600_MeterModFailedData(base_tests.SimpleDataPlane):
    """
    440.600 - Meter mod failed data
    Verify meter mod failed errors include up to 64 bytes of the offending request.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Meter Mod Failed Data")
        #Send Echo request to check that the control channel is up.
        request = ofp.message.echo_request()
        logging.info("Sending a Echo Request")
        reply, pkt = self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Echo Reply")
        self.assertEqual(reply.type, ofp.OFPT_ECHO_REPLY, "Response is not echo reply")
        logging.info("Delete metermod")
        req = ofp.message.meter_mod()
        req.command = ofp.OFPMC_DELETE
        req.meter_id = ofp.const.OFPM_ALL
        self.controller.message_send(req)                   
        logging.info("Insert metermod")
        no = 2500
        band1 = ofp.meter_band.drop()
        band1.rate = 1024
        band1.burst_size = 12
        for i in range(1, no):
            msg = ofp.message.meter_mod()
            msg.command = ofp.OFPMC_ADD
            msg.meter_id = i
            msg.flags = ofp.OFPMF_KBPS
            msg.meters = [band1]
            self.controller.message_send(msg)
            reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
            if reply is not None:
                logging.info("Error Message Received")
                if reply.err_type == ofp.const.OFPET_METER_MOD_FAILED:
                    logging.info("Received error type was OFPET_METER_MOD_FAILED.")
                    self.assertEqual(reply.code, ofp.const.OFPMMFC_OUT_OF_METERS,
                                      ("Meter Mod failed code %d was received, but we "
                                       "expected OFPMMFC_OUT_OF_METERS.") % reply.code)
                    if len(reply.data) < 64:
                        self.assertEqual(msg.pack(), reply.data, "Data field of error message should include up to 64 bytes of the offending request")
                    else:
                        self.assertEqual(msg.pack()[:len(reply.data)], reply.data, "Data field of error message should include up to 64 bytes of the offending request")
                    logging.info("Received correct error code OFPMMFC_OUT_OF_METERS.")
                    return
                elif reply.err_type == ofp.const.OFPET_BAD_REQUEST:
                    logging.info("Received error type was OFPET_BAD_REQUEST.")
                    self.assertEqual(reply.code, ofp.OFPBRC_BAD_TYPE,
                                      ("Bad request code %d was received, but we "
                                       "expected OFPBRC_BAD_TYPE.") % reply.code)
                    logging.info("Received correct error code OFPBRC_BAD_TYPE.")
                    return
        self.assertIsNotNone(reply, "The switch failed to generate an error.")




class Testcase_440_610_TableFeaturesFailedBadTable(base_tests.SimpleDataPlane):
    """
    440.610 - Table features failed bad table
    Verify the correct error message is generated when a table features request specifies a bad table id.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case Table Features Failed Bad Table")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        tables_no = reply.n_tables 
        bad_table = tables_no + 1
        
        req = ofp.message.table_features_stats_request()
        reply, _ = self.controller.transact(req)
        self.assertIsNotNone(reply, "Did not receive table_features_stats_reply")
        self.assertFalse(reply.type == ofp.OFPT_ERROR,"The switch generated an error.")
        self.assertTrue(reply.type == ofp.OFPT_STATS_REPLY,"The switch responded an reply with wrong type.")
        self.assertTrue(len(reply.entries) > 0,"No entry included in table features reply")
        reply.entries[0].table_id = bad_table
        entry = [reply.entries[0]]
        req = ofp.message.table_features_stats_request(entries=entry) 
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_TABLE_FEATURES_FAILED, " Error type is not OFPET_TABLE_FEATURES_FAILED")
        logging.info("Received OFPET_TABLE_FEATURES_FAILED")
        self.assertEqual(reply.code, ofp.const.OFPTFFC_BAD_TABLE, "Error Code is not OFPTFFC_BAD_TABLE")
        logging.info("Received Error code is OFPTFFC_BAD_TABLE")
        
        
        
        
class Testcase_440_620_TableFeaturesFailedBadMetadata(base_tests.SimpleDataPlane):
    """
    440.620 - Table features failed bad metadata
    Verify the correct error message is generated when a table features request specifies a bad property type.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case 440.620 - Table Features Failed Bad Metadata")       
        req = ofp.message.table_features_stats_request()
        reply, _ = self.controller.transact(req)
        self.assertIsNotNone(reply, "Did not receive table_features_stats_reply")
        self.assertFalse(reply.type == ofp.OFPT_ERROR,"The switch generated an error when receiving table feature stats request.")
        self.assertTrue(reply.type == ofp.OFPT_STATS_REPLY,"The switch responded an reply with wrong type.")
        self.assertTrue(len(reply.entries) > 0,"No entry included in table features reply")
        reply.entries[0].metadata_match = 0xffffffffffffffff ^ reply.entries[0].metadata_match
        reply.entries[0].metadata_write = 0xffffffffffffffff ^ reply.entries[0].metadata_write
        entry = [reply.entries[0]]
        req = ofp.message.table_features_stats_request(entries=entry) 
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
	if reply.err_type==ofp.const.OFPET_TABLE_FEATURES_FAILED:
            logging.info("Received OFPET_TABLE_FEATURES_FAILED")
            if reply.code == ofp.const.OFPTFFC_BAD_METADATA:
                logging.info("Received correct error code OFPTFFC_BAD_METADATA.")
            elif reply.code == ofp.const.OFPTFFC_EPERM:
                logging.info("Received correct error code OFPTFFC_EPERM. Multipart ofp_table_features requests were disabled")
            else:
                self.assertEqual(0, 1, "Error code was not correct")
	elif reply.err_type==ofp.const.OFPET_BAD_REQUEST:
          self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_LEN, "Error Code is not OFPBRC_BAD_LEN")
	else:
	    self.assertEqual(0,1, "Error type is not correct")


        
        
        
class Testcase_440_630_TableFeaturesFailedBadType(base_tests.SimpleDataPlane):
    """
    440.630 - Table features failed bad type
    Verify the correct error message is generated when a table features request specifies a bad property type.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case 440.630 - Table Features Failed Bad Type")       
        req = ofp.message.table_features_stats_request()
        reply, _ = self.controller.transact(req)
        self.assertIsNotNone(reply, "Did not receive table_features_stats_reply")
        self.assertFalse(reply.type == ofp.OFPT_ERROR,"The switch generated an error.")
        self.assertTrue(reply.type == ofp.OFPT_STATS_REPLY,"The switch responded an reply with wrong type.")
        self.assertTrue(len(reply.entries) > 0,"No entry included in table features reply")
        reply.entries[0].properties[0].type = 16
        entry = [reply.entries[0]]
        req = ofp.message.table_features_stats_request(entries=entry) 
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        self.assertEqual(reply.err_type,ofp.const.OFPET_TABLE_FEATURES_FAILED, " Error type is not OFPET_TABLE_FEATURES_FAILED")
        logging.info("Received OFPET_TABLE_FEATURES_FAILED")
        self.assertEqual(reply.code, ofp.const.OFPTFFC_BAD_TYPE, "Error Code is not OFPTFFC_BAD_TYPE")
        logging.info("Received Error code is OFPTFFC_BAD_TYPE")

        
        
class Testcase_440_640_TableFeaturesFailedBadLength(base_tests.SimpleDataPlane):
    """
    440.640 - Table features failed bad length
    Verify the correct error message is generated when a table features request specifies a bad length.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case 440.640 - Table features failed bad length")
        
        req = ofp.message.table_features_stats_request()
        reply, _ = self.controller.transact(req)
        self.assertIsNotNone(reply, "Did not receive table_features_stats_reply")
        self.assertFalse(reply.type == ofp.OFPT_ERROR,"The switch generated an error.")
        self.assertTrue(reply.type == ofp.OFPT_STATS_REPLY,"The switch responded an reply with wrong type.")
        self.assertTrue(len(reply.entries) > 0,"No entry included in table features reply")
        reply.entries[0].properties[0].length = 2
        entry = [reply.entries[0]]
        req = ofp.message.table_features_stats_request(entries=entry) 
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
	if reply.err_type==ofp.const.OFPET_TABLE_FEATURES_FAILED:
            logging.info("Received OFPET_TABLE_FEATURES_FAILED")
            self.assertEqual(reply.code, ofp.const.OFPTFFC_BAD_LEN, "Error Code is not OFPTFFC_BAD_LEN")
            logging.info("Received Error code is OFPTFFC_BAD_LEN")
	elif reply.err_type==ofp.const.OFPET_BAD_REQUEST:
	    self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_LEN, "Error Code is not OFPBRC_BAD_LEN")
	else:
	    self.assertEqual(0,1, "Error type is not correct")
        
        
        
class Testcase_440_650_TableFeaturesFailedBadAgument(base_tests.SimpleDataPlane):
    """
    440.650 - Table features failed bad argument
    Verify the correct error message is generated when a table features request specifies a bad argument.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case 440.650 - Table features failed bad argument")
        
        req = ofp.message.table_features_stats_request()
        reply, _ = self.controller.transact(req)
        self.assertIsNotNone(reply, "Did not receive table_features_stats_reply")
        self.assertFalse(reply.type == ofp.OFPT_ERROR,"The switch generated an error.")
        self.assertTrue(reply.type == ofp.OFPT_STATS_REPLY,"The switch responded an reply with wrong type.")
        self.assertTrue(len(reply.entries) > 0,"No entry included in table features reply")
        for i in range(len(reply.entries[0].properties)):
            if reply.entries[0].properties[i].type == ofp.const.OFPTFPT_WRITE_ACTIONS:
                action_ids = []
                action_ids.append(ofp.action_id.copy_ttl_in())
                action_ids.append(ofp.action_id.copy_ttl_out())
                action_ids.append(ofp.action_id.dec_mpls_ttl())
                action_ids.append(ofp.action_id.dec_nw_ttl())
                action_ids.append(ofp.action_id.group())
                action_ids.append(ofp.action_id.pop_mpls())
                action_ids.append(ofp.action_id.pop_pbb())
                action_ids.append(ofp.action_id.pop_vlan())
                action_ids.append(ofp.action_id.set_mpls_ttl())
                action_ids.append(ofp.action_id.set_queue())
                action_ids.append(ofp.action_id.set_field())
                reply.entries[0].properties[i].action_ids = action_ids
        entry = [reply.entries[0]]
        req = ofp.message.table_features_stats_request(entries=entry)   
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
	if reply.err_type==ofp.const.OFPET_TABLE_FEATURES_FAILED:
            logging.info("Received OFPET_TABLE_FEATURES_FAILED")
            if reply.code == ofp.const.OFPTFFC_BAD_ARGUMENT:
                logging.info("Received correct error code OFPTFFC_BAD_ARGUMENT.")
            elif reply.code == ofp.const.OFPTFFC_EPERM:
                logging.info("Received correct error code OFPTFFC_EPERM. Multipart ofp_table_features requests were disabled")
            else:
                self.assertEqual(0, 1, "Error code was not correct")
	elif reply.err_type==ofp.const.OFPET_BAD_REQUEST:
	    self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_LEN, "Error Code is not OFPBRC_BAD_LEN")
	else:
	    self.assertEqual(0,1, "Error type is not correct")       
        
        
class Testcase_440_670_TableFeaturesFailedData(base_tests.SimpleDataPlane):
    """
    440.610 - Table features failed bad table
    Verify table features failed errors include up to 64 bytes of the offending request.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case 440.670 - Table features failed data")
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        tables_no = reply.n_tables 
        bad_table = tables_no + 1
        
        req = ofp.message.table_features_stats_request()
        reply, _ = self.controller.transact(req)
        self.assertIsNotNone(reply, "Did not receive table_features_stats_reply")
        self.assertFalse(reply.type == ofp.OFPT_ERROR,"The switch generated an error.")
        self.assertTrue(reply.type == ofp.OFPT_STATS_REPLY,"The switch responded an reply with wrong type.")
        self.assertTrue(len(reply.entries) > 0,"No entry included in table features reply")
        reply.entries[0].table_id = bad_table
        entry = [reply.entries[0]]
        req = ofp.message.table_features_stats_request(entries=entry)   
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        if reply.err_type==ofp.const.OFPET_TABLE_FEATURES_FAILED:
	    logging.info("Received OFPET_TABLE_FEATURES_FAILED")
            if reply.code == ofp.const.OFPTFFC_BAD_TABLE:
                logging.info("Received correct error code ofp.const.OFPTFFC_BAD_TABLE.")
            elif reply.code == ofp.const.OFPTFFC_EPERM:
                logging.info("Received correct error code OFPTFFC_EPERM. Multipart ofp_table_features requests were disabled")
            else:
                self.assertEqual(0, 1, "Error code was not correct")
	elif reply.err_type==ofp.const.OFPET_BAD_REQUEST:
	    self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_LEN, "Error Code is not OFPBRC_BAD_LEN")
	else:
	    self.assertEqual(0,1, "Error type is not correct")       
        err_len = len(reply.data)
        if len(reply.data) < 64:
            self.assertEqual(req.pack(), reply.data, "Incorrect data field")
        else:
            self.assertEqual(req.pack()[:len(reply.data)], reply.data, "Incorrect data field")
        

        
class Testcase_440_680_ExperimenterErrorMsg(base_tests.SimpleDataPlane):
    """
    440.680 - Experimenter error message
    Verify the correct error message is generated when a bad experimenter type is specified.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running test case 440.680 - Experimenter error message")
        experimenter = test_param_get("experimenter", 0x4f4e4600)
        experimenter_type = 0xffff00ff 
        req = ofp.message.experimenter(experimenter=experimenter,subtype=experimenter_type)
        self.controller.message_send(req)      
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch failed to generate an error.")
        logging.info("Error Message Received")
        if reply.err_type == ofp.OFPET_BAD_REQUEST :
            self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_EXPERIMENTER, "Error Code is not OFPBRC_BAD_EXPERIMENTER")
            logging.info("Switch did not support experimenter")
        else :
            self.assertEqual(reply.err_type,ofp.const.OFPET_EXPERIMENTER, " Error type is not OFPET_EXPERIMENTER")
            logging.info("Received error type was correct")
