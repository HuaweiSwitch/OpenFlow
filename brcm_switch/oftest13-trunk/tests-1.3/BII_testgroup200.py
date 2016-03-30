# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Pan Zhang
"""
Test suite 200 verifies the basic behavior of each OpenFlow message type.
Basic conformance
To satisfy the basic requirements an OpenFlow enabled device must pass 200.10 - 200.30, 200.50 - 200.170, 200.210, and 200.230.

"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
import BII_testgroup140
import BII_testgroup40
import oftest.packet as scapy
from loxi.pp import pp

from oftest.testutils import *
from oftest.parse import parse_ipv6
from oftest.oflog import *
from time import sleep
import BII_testgroup10
import BII_testgroup40
import BII_testgroup50
import BII_testgroup60

"""
class Testcase_200_10_basic_OFPT_HELLO(BII_testgroup10.Testcase_10_70_VersionNegotiationSuccess):
    
    Purpose
    Check the switch negotiates the correct version with the controller, based on the version field.

    Methodology
    10.70


    
        
        

class Testcase_200_20_basic_OFPT_ERROR(base_tests.SimpleDataPlane):
    
    Purpose
    Verify correct behavior in case of version negotiation failure.

    Methodology
    10.80

    
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
        
class Testcase_200_30_basic_ECHO_REQUEST(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify response to ECHO

    Methodology
    sent echo verify reply

    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 200.30 basic ECHO REQUEST")
        delete_all_flows(self.controller)
        request = ofp.message.echo_request()
        self.controller.message_send(request)
        reply,_= self.controller.poll(exp_msg = ofp.OFPT_ECHO_REPLY, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive echo_reply messge")

"""class Testcase_200_50_basic_OFPT_PACKET_IN(base_tests.SimpleDataPlane):
    """ """
    Purpose
    Verify that an entry with all wildcards, priority 0 and action send to the controller can be created in all tables.

    Methodology
    50.20


    """ """
    @wireshark_capture
    def runTest(self):
        logging.info("Running 200.50 - Basic Packet in test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
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

        timeout = 5
        port1, = openflow_ports(1)
        pkt = str(simple_tcp_packet())
        self.dataplane.send(port1, pkt)
        logging.info("Sending a dataplane packet")
        verify_packets(self, pkt, [])
        rv, raw=self.controller.poll(exp_msg=ofp.const.OFPT_PACKET_IN, timeout=timeout)
        self.assertTrue(rv is not None, 'Packet in message not received')
        self.assertEqual(str(rv.data), pkt, ("Received pkt did not match sending pkt."))
        logging.info("Packet In received as expected")
        """
"""
class Testcase_200_60_basic_OFPT_FLOW_REMOVED(BII_testgroup140.Testcase_140_110_Delete_Flow_removed):
    
    Purpose
    Check a flow is deleted while "OFPFF_SEND_FLOW_REM" flag is set

    Methodology
    140.110


    """


class Testcase_200_70_basic_OFPT_PORT_STATUS(base_tests.SimpleDataPlane):
    """
    Purpose
    Test the Port Status is forwarded correctly by the switch.

    Methodology
    Change the port status through a method outside the openflow protocol (cli, disconnect cable), and verify the switch sends the correct port status message to the controller, informing about the state change.

    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 200.70 basic OFPT_PORT_STATUS")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        default_port, = openflow_ports(1)
              
        #Bring down the port by shutting the interface connected 
        try:
            logging.info("Bringing down the interface ..")
            print "Manually bring down the first port"
        
            #Verify Port Status message is recieved with reason-- Port Deleted
            logging.info("Verify PortStatus-Down message is recieved on the control plane ")
            (response, raw) = self.controller.poll(ofp.OFPT_PORT_STATUS, timeout=30)
            self.assertTrue(response is not None,
                        'Port Status Message not generated')
                                   
        #Bring up the port by starting the interface connected
        finally:
            logging.info("Bringing up the interface ...")
            print "Manually bring up the first port"
            logging.info("Verify PortStatus-Up message is received on the control plane ")
            (response, raw) = self.controller.poll(ofp.OFPT_PORT_STATUS, timeout=30)
            self.assertTrue(response is not None,
                        'Port Status Message not generated')
"""
class Testcase_200_80_basic_OFPT_FEATURES_REQUEST(BII_testgroup40.Testcase_40_10_FeaturesReplyDatapathID):
    
    Purpose
    Verify that an OFPT_FEATURES_REQUEST message generates an OFPT_FEATURES_REPLY from the switch containing a valid datapath ID.

    Methodology
    40.10

    """


"""
class Testcase_200_90_basic_OFPT_GET_CONFIG_REQUEST(BII_testgroup40.Testcase_40_120_GetConfigMissSendLen):
    

    Purpose
    Check the miss_send_len value returned by the switch.

    Methodology
    40.120


    """



class Testcase_200_100_basic_OFPT_SET_CONFIG(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify MISS_SEND_LEN is set correctly 

    Methodology
    Set miss send length to value x, and verify the value was set using a get configuration request.


    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 200.100 basic OFPT_SET_CONFIG")
        delete_all_flows(self.controller)
        request = ofp.message.set_config(miss_send_len = 100)
        self.controller.message_send(request)
        do_barrier(self.controller)
        request = ofp.message.get_config_request()
        self.controller.message_send(request)
        reply,_= self.controller.poll(exp_msg = ofp.OFPT_GET_CONFIG_REPLY, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive get_config_reply messge")
        self.assertEqual(reply.miss_send_len, 100 ,"Did not set miss_send_len value")


class Testcase_200_110_basic_OFPT_PACKET_OUT(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify packets sent via packet_out are received

    Methodology
    Send packet via packet_out, verify received packet



    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 200.110 basic OFPT_PACKET_OUT")
        in_port, out_port = openflow_ports(2)

        pkt = simple_tcp_packet()
        delete_all_flows(self.controller)
        request = ofp.message.packet_out(in_port = ofp.OFPP_CONTROLLER,
            actions = [ofp.action.output(port = out_port)], buffer_id = ofp.OFP_NO_BUFFER,
            data = str(pkt))

        self.controller.message_send(request)
        verify_packet(self, pkt, out_port)


"""
class Testcase_200_120_basic_OFPT_FLOW_MOD(BII_testgroup60.Testcase_60_20_OXM_OF_IN_PORT):
    

    Purpose
    Verify the switch is able to match on the previously named field as a single header field match (under the given Pre-requisites for the match).

    Methodology
    60.20



    """

class Testcase_200_130_basic_OFPT_GROUP_MOD(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify group processes message correctly.

    Methodology
    Try to create a group, verify message gets processed as expected. If device does not suport groups verify OFPET_BAD_REQUEST error is received with code OFPBRC_BAD_TYPE.

    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 200.130 basic OFPT_GROUP_MOD")

        in_port, out_port = openflow_ports(2)
        delete_all_flows(self.controller)
	delete_all_groups(self.controller)
        request = ofp.message.group_add(group_type = ofp.OFPGT_ALL, group_id = 0, buckets = [ofp.bucket(actions = [ofp.action.output(out_port)],
                                                                                                watch_port = ofp.OFPP_ANY,
                                                                                                watch_group = ofp.OFPG_ANY)])

        self.controller.message_send(request)

        reply,_= self.controller.poll(exp_msg = ofp.OFPT_ERROR, timeout = 3)
        if reply:
            logging.info("The device does not support group")
            self.assertEqual(reply.err_type, ofp.const.OFPET_BAD_REQUEST,
                              ("Error type %d was received, but we expected "
                               "OFPET_BAD_REQUEST.") % reply.err_type)
            self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_TYPE,
                              ("Flow mod failed code %d was received, but we "
                               "expected OFPBRC_BAD_TYPE.") % reply.code)
        else:
            logging.info("Created a group")
            group_stats = get_stats(self, ofp.message.group_desc_stats_request())
            self.assertIsNotNone(group_stats, "Can not get the information of the group created")

      
class Testcase_200_140_basic_OFPT_PORT_MOD(base_tests.SimpleDataPlane):
    """
    TODO: Can not set up the port again. Need update

    Purpose
    Verify port status msg is received in response to OFPT_PORT_MOD

    Methodology
    Bring one of the data plane ports down.

    """

    def tearDown(self):
        in_port, out_port = openflow_ports(2)
        rv = port_config_set(self.controller, port_no=out_port, config = 0, mask = ofp.OFPPC_PORT_DOWN)
        self.assertTrue(rv != 1, "Error")
        sleep(2)
        self.controller.clear_queue()
        base_tests.SimpleDataPlane.tearDown(self)


    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 200.140 basic OFPT_PORT_MOD")
        in_port, out_port = openflow_ports(2)
        #pkt = simple_tcp_packet()
        delete_all_flows(self.controller)
        (_, init_config, _) = port_config_get(self.controller, out_port)
        self.assertIsNotNone(init_config , "Did not get port config")
        print init_config
        config =init_config^ofp.OFPPC_PORT_DOWN
        mask = ofp.OFPPC_PORT_DOWN
        port_config_set(self.controller, port_no = out_port, config = config, mask = mask)
        reply,_= self.controller.poll(exp_msg = ofp.OFPT_PORT_STATUS, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive OFPT_PORT_STATUS message")



class Testcase_200_150_basic_OFPT_TABLE_MOD(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify table modification can recognize lower 2 bits and returns error for others.

    Methodology
    Sent a tablemod with a config bitmap not equal to ofptc_deprecated_mask (3). Verify OFPET_TABLE_MOD_FAILED error is received with error code OFPTMFC_BAD_CONFIG.

    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 200.150 basic OFPT_TABLE_MOD")

        in_port, out_port = openflow_ports(2)
        delete_all_flows(self.controller)
        config = ofp.OFPTC_DEPRECATED_MASK + 1
        request = ofp.message.table_mod(table_id = 0, config = config)
        self.controller.message_send(request)

        reply,_= self.controller.poll(exp_msg = ofp.OFPT_ERROR, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive error message")
        
        if reply.err_type == ofp.const.OFPET_TABLE_MOD_FAILED:
            logging.info("Received error type was OFPET_TABLE_MOD_FAILED.")
            self.assertEqual(reply.code, ofp.OFPTMFC_BAD_CONFIG,
                              ("Table mod failed code %d was received, but we "
                               "expected OFPTMFC_BAD_CONFIG.") % reply.code)
            logging.info("Received correct error code OFPTMFC_BAD_CONFIG.")
        elif reply.err_type == ofp.const.OFPET_BAD_REQUEST:
            logging.info("Received error type was OFPET_BAD_REQUEST.")
            self.assertEqual(reply.code, ofp.OFPTMFC_EPERM,
                              ("Flow mod failed code %d was received, but we "
                               "expected OFPTMFC_EPERM.") % reply.code)
            logging.info("Received correct error code OFPTMFC_EPERM.")
        else:
            self.assertEqual(0, 1, "Error type was not correct")


"""
class Testcase_200_160_basic_OFPT_MULTIPART_REQUEST(BII_testgroup40.Testcase_40_60_FeaturesReplyTableStats):
    

    Purpose
    Check whether the switch supports table statistics 

    Methodology
    40.60



    """



class Testcase_200_170_basic_OFPT_BARRIER_REQUEST(base_tests.SimpleDataPlane):
    """
    Purpose
    Check switch replies to controller with Barrier Reply following all commands execution after Barrier Request received

    Methodology
    insert x flows, verify on data plane when active, check that barrier reply sent after that


    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 200.170 basic OFPT_BARRIER_REQUEST")
        flags = ofp.OFPFF_SEND_FLOW_REM
        in_port, out_port = openflow_ports(2)
        match = ofp.match([
                ofp.oxm.eth_type(0x0800)
                ])
        delete_all_flows(self.controller)
        pkt = simple_tcp_packet()
        actions = [ofp.action.output(out_port)]
        logging.info("Inserting flows")
        for priority in range(10):
            request = ofp.message.flow_add(
                    table_id=test_param_get("table", 0),
                    #match=packet_to_flow_match(self, pkt),
                    match = match,
                    instructions=[
                        ofp.instruction.apply_actions(actions)],
                    buffer_id=ofp.OFP_NO_BUFFER,
                    priority=priority,
                    flags=flags)
            self.controller.message_send(request)

        logging.info("Inserting a flows successfully")
        delete_all_flows(self.controller)
        request = ofp.message.barrier_request()




class Testcase_200_210_basic_OFPT_GET_ASYNC_REQUEST(base_tests.SimpleDataPlane):
    """
    Purpose
    Check switch replies to OFPT_GET_ASYNC_REQUEST with _REPLY and not to request to send configuration

    Methodology
    send async config, get reply or "not supported" error see also 20.30



    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 200.170 basic OFPT_BARRIER_REQUEST")

        in_port, out_port = openflow_ports(2)
        delete_all_flows(self.controller)
        request = ofp.message.async_get_request()
        #self.controller.message_send(request)
        reply, _ = self.controller.transact(request)
        #reply, _ = self.controller.poll(exp_msg = ofp.OFPT_GET_ASYNC_REPLY, timeout = 3)
        #self.assertIsNotNone(reply, "Did not receive get async reply message")
        if reply.type == ofp.const.OFPT_ERROR:
            self.assertEqual(reply.err_type, ofp.const.OFPET_BAD_REQUEST, 
                             ("Appropriate error type not reported by switch"
                              " got %d.") % reply.err_type)
            self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_TYPE, 
                             ("Appropriate error code not reported by switch"
                              " got %d") % reply.code)
        else:
            self.assertEqual(reply.type,ofp.const.OFPT_GET_ASYNC_REPLY,
                                ("Expected OFPT_GET_ASYNC_REPLY."
                                 "Got %d") % reply.type)

class Testcase_200_230_basic_OFPT_SET_ASYNC(base_tests.SimpleDataPlane):
    """
    Purpose
    Check switch replies to OFPT_GET_ASYNC_REQUEST with _REPLY and not to request to send configuration

    Methodology
    send async config, get reply or "not supported" error see also 20.30



    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 200.230 basic OFPT_SET_ASYNC")

        in_port, out_port = openflow_ports(2)
        delete_all_flows(self.controller)
        request = ofp.message.async_set(flow_removed_mask_slave = 1)
        reply, _ = self.controller.transact(request)
        if reply is None:
            request = ofp.message.async_get_request()
            self.controller.message_send(request)
            reply1, _ = self.controller.poll(exp_msg = ofp.OFPT_GET_ASYNC_REPLY, timeout = 3)
            self.assertIsNotNone(reply1, "Did not receive get async reply message")
            self.assertEqual(reply1.flow_removed_mask_slave, 1, "Did not process async set message")
        else:
            self.assertEqual(reply.type, ofp.OFPT_ERROR , "Did not receive error message")

            
        request = ofp.message.async_set(flow_removed_mask_slave = 0)
        self.controller.message_send(request)




class Testcase_200_250__Reserved_Value_error(base_tests.SimpleDataPlane):
    """
    Purpose
    Check that the switch rejects requests containing a reserved value.

    Methodology
    Send to the DUT a request containing a reserved value or an optional value it does not support, it must reject the request and return an appropriate error message. 

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 200.250 - Reserved_Value_error")
        delete_all_flows(self.controller)
        table_id = test_param_get("table",0)
        
        logging.info("Inserting a flow")
        request = ofp.message.flow_add(
            table_id=table_id,
            instructions=[
                ofp.instruction.apply_actions(
                    actions=[
                        ofp.action.output(
                            port=ofp.const.OFPP_ANY,
                            max_len=ofp.OFPCML_NO_BUFFER)])],
            buffer_id=ofp.OFP_NO_BUFFER,
            priority=1000)
        self.controller.message_send(request)
        reply, _ = self.controller.poll(exp_msg = ofp.OFPT_ERROR, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive error message.")
        logging.info("Received error message.")
        self.assertEqual(reply.err_type, ofp.const.OFPET_BAD_ACTION,"Error type was not OFPET_BAD_ACTION.") 
        logging.info("Error type was correct.")
        self.assertEqual(reply.code, ofp.const.OFPBAC_BAD_OUT_PORT,"Error code was not OFPBAC_BAD_OUT_PORT.")
        logging.info("Received correct error code.")

   

class Testcase_200_270__Reserved_bit_position_error(base_tests.SimpleDataPlane):
    """
    Purpose
    Check that the switch rejects requests containing a reserved bit position.

    Methodology
    Send to the DUT a request containing a reserved bit position or an optional bit position it does not support set to 1, it must reject the request and return an appropriate error message.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 200.270 - Reserved_bit_position_error")
        delete_all_flows(self.controller)
        
        table_id = test_param_get("table", 0)
        logging.info("Sending table_mod msg")
        request = ofp.message.table_mod(table_id=table_id, config=ofp.const.OFPTC_DEPRECATED_MASK)
        self.controller.message_send(request)
        reply, _ = self.controller.poll(exp_msg = ofp.OFPT_ERROR, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive error message.")
        logging.info("Received error message.")
        self.assertEqual(reply.err_type, ofp.const.OFPET_TABLE_MOD_FAILED,"Error type was not OFPET_TABLE_MOD_FAILED.") 
        logging.info("Error type was correct.")




class Testcase_200_290__Reserved_TLV_error(base_tests.SimpleDataPlane):
    """
    Purpose
    Check that the switch rejects requests containing a reserved TLV.

    Methodology
    Send to the DUT a request containing a reserved TLV type or an optional TLV type it does not support, it must reject the request and return an appropriate error message. 

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 200.290 - Reserved_TLV_error")
        delete_all_flows(self.controller)

        table_id = test_param_get("table",0)
        in_port, out_port, = openflow_ports(2)
        
        logging.info("Sending a flow - matching on icmpv6_code")
        match = ofp.match([
                    ofp.oxm.eth_type(0x86dd),
                    ofp.oxm.ip_proto(58),
                    ofp.oxm.icmpv6_code(4),
                    ])  # Assume icmpv6 code is not supported by DUT
        request = ofp.message.flow_add(
                table_id=table_id,
                match=match,
                instructions=[
                    ofp.instruction.apply_actions(
                        actions=[
                            ofp.action.output(
                                port=out_port,
                                max_len=ofp.OFPCML_NO_BUFFER)])],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        reply, _ = self.controller.poll(exp_msg = ofp.OFPT_ERROR, timeout = 3)
        if reply is None:
            logging.warn("ICMPv6 code may be supported by DUT. Cannot trigger the error")
        else:
            logging.info("Received error message.")
            #self.assertEqual(reply.err_type, ofp.const.OFPET_BAD_MATCH,"Error type was not OFPET_BAD_MATCH.") 
            #logging.info("Error type was correct.")
            #self.assertEqual(reply.code, ofp.const.OFPBMC_BAD_TYPE,"Error code was not OFPBMC_BAD_TYPE.") 
            #logging.info("Error code was correct.")
