# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Pan Zhang

"""
Test suite 390 verifies the device correctly implements the packet out message type.

Basic conformance
To satisfy the basic requirements an OpenFlow enabled device must pass 390.10 - 390.40, and 390.60 - 390.120.
"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
import BII_testgroup200
import oftest.packet as scapy
from loxi.pp import pp

from oftest.testutils import *
from oftest.parse import parse_ipv6
from oftest.oflog import *
from time import sleep
"""
class Testcase_390_10_packet_out(BII_testgroup200.Testcase_200_110_basic_OFPT_PACKET_OUT):
    """"""
    Purpose
    Verify packets sent via packet_out are received.

    Methodology
    200.110


    """"""



class Testcase_390_20_packet_out_buffer_id(base_tests.SimpleDataPlane):
    """"""
    Purpose
    Verify packets sent via packet_out are received.

    Methodology
    200.110


    """"""
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 390.20 - packet out buffer")
        in_port, out_port = openflow_ports(2)
        actions = [ofp.action.output(ofp.OFPP_CONTROLLER, max_len = 0)]
        pkt = simple_tcp_packet()

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                #match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=0)
        self.controller.message_send(request)
        logging.info("Inserting a table miss flow to forward packet to controller")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)

        self.dataplane.send(in_port, str(pkt))
        reply, _ = self.controller.poll(exp_msg = ofp.const.OFPT_PACKET_IN, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive packet in message")
        buffer_id = reply.buffer_id
        
        request = ofp.message.packet_out(in_port = ofp.OFPP_CONTROLLER,
            actions = [ofp.action.output(port = out_port)], buffer_id = buffer_id,
            data = str(pkt))

        self.controller.message_send(request)
        verify_packet(self, pkt, out_port)
"""
class Testcase_390_30_packet_out_in_port(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify that flow matching on in_port OFPP_CONTROLLER and output action data plane port is matched against when a packet_out message is sent with in_port as OFPP_CONTROLLER and output action OFPP_TABLE.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on in_port OFPP_CONTROLLER with an output action to a data plane test port. Send and receive a barrier request and reply. Generate a non-buffered ofp_packet_out message with an in_port set to OFPP_CONTROLLER, and an output action of OFPP_TABLE. Verify packet matches on the installed flow.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 390.30 packet out in port")
        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(out_port)]
        match = ofp.match([ofp.oxm.in_port(ofp.OFPP_CONTROLLER)])

        pkt = simple_tcp_packet()

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a table miss flow to forward packet to controller")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)

        request = ofp.message.packet_out(in_port = ofp.OFPP_CONTROLLER, data = str(pkt), buffer_id = ofp.OFP_NO_BUFFER, actions = [ofp.action.output(ofp.OFPP_TABLE)])
        self.controller.message_send(request)
        verify_packet(self, str(pkt), out_port)





"""
class Testcase_390_60_packet_out_data(BII_testgroup200.Testcase_200_110_basic_OFPT_PACKET_OUT):
    
    Purpose
    Verify packets sent via packet_out are received.

    Methodology
    200.110

    """


class Testcase_390_70_packet_out_no_buffer(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify that all data included in packet_out with buffer_id of OFP_NO_BUFFER is forwarded correctly

    Methodology
    Configure and connect DUT to controller. Generate a non-buffered ofp_packet_out including a tcp packet, and an output action to a valid data plane test port. Verify the tcp packet is received on the correct port.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 390.70 packet out no buffer")
        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(out_port)]
        match = ofp.match([ofp.oxm.in_port(ofp.OFPP_CONTROLLER)])

        pkt = simple_tcp_packet()

        delete_all_flows(self.controller)
        """
        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=0)
        self.controller.message_send(request)
        logging.info("Inserting a table miss flow to forward packet to controller")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)
        """
        request = ofp.message.packet_out(in_port = ofp.OFPP_CONTROLLER, data = str(pkt), buffer_id = ofp.OFP_NO_BUFFER, actions = actions)
        self.controller.message_send(request)
        verify_packet(self, str(pkt), out_port)


class Testcase_390_80_packet_out_buffer(base_tests.SimpleDataPlane):
    """
    TODO: Verify the correctness of the testcase by using another DUT
    Purpose
    Verify that all data included in packet_out with buffer_id not equal to OFP_NO_BUFFER and valid is forwarded correctly

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the Pre-requisites for the match) with action as output port CONTROLLER. Forward traffic on a data plane port, and verify an ofp_packet_in message is received on the control plane. Generate an ofp_packet_out with buffer_id equal to the buffer_id of the received ofp_packet_in, and an output action to a second valid data plane test port. Verify the tcp packet is received on the correct port.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 390.80 packet out buffer")
        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(out_port)]
        actions_out_controller = [ofp.action.output(ofp.OFPP_CONTROLLER, max_len = 128)]
        #match = ofp.match([ofp.oxm.in_port(ofp.OFPP_CONTROLLER)])

        pkt = simple_tcp_packet()

        delete_all_flows(self.controller)
        
        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                #match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions_out_controller)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a table miss flow to forward packet to controller")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)

        self.dataplane.send(in_port, str(pkt))
        reply, _ = self.controller.poll(exp_msg = ofp.OFPT_PACKET_IN, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive packet in message")
        if reply.buffer_id == ofp.OFP_NO_BUFFER:
            self.assertEqual(str(pkt), str(reply.data), "Data of packet in message is not as same as packet sent")
        else:
            request = ofp.message.packet_out(in_port = ofp.OFPP_CONTROLLER, data = str(pkt), buffer_id = reply.buffer_id, actions = actions)
            self.controller.message_send(request)
            reply, _ = self.controller.poll(exp_msg = ofp.OFPT_ERROR, timeout = 3)
            self.assertIsNone(reply, "Switch generated an error messsage when receiving the packet out message")
            verify_packet(self, str(pkt), out_port)


class Testcase_390_90_packet_out_invalid_in_port(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify that a packet_out message with an invalid in_port generates an OFPT_ERROR with appropriate type and code.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on in_port N with an output action to a data plane test port. Generate a non-buffered ofp_packet_out message with an in_port set to N, and an output action of OFPP_TABLE. Verify packet matches on the installed flow. Generate a non-buffered ofp_packet_out message with an invalid in_port, and an output action of OFPP_TABLE. Verify OFPET_BAD_REQUEST error is received with an error code of OFPBRC_BAD_PORT

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 390.90 packet out invalid in port")
        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(out_port)]

        match = ofp.match([ofp.oxm.in_port(in_port)])

        pkt = simple_tcp_packet()
        #verify_pkt = simple_tcp_packet(ip_src = '192.168.0.5') #0xc0a80105

        delete_all_flows(self.controller)
        
        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a table miss flow to forward packet to controller")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)
        
        request = ofp.message.packet_out(in_port = in_port, data = str(pkt), buffer_id = ofp.OFP_NO_BUFFER, actions = [ofp.action.output(ofp.OFPP_TABLE)])
        self.controller.message_send(request)
        reply, _ = self.controller.poll(exp_msg = ofp.OFPT_ERROR, timeout = 3)
        self.assertIsNone(reply, "Received an error")
        verify_packet(self, str(pkt), out_port)

        request = ofp.message.packet_out(in_port = ofp.OFPP_MAX, data = str(pkt), buffer_id = ofp.OFP_NO_BUFFER, actions = [ofp.action.output(ofp.OFPP_TABLE)])
        self.controller.message_send(request)
        reply, _ = self.controller.poll(exp_msg = ofp.OFPT_ERROR, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive error message")
        self.assertEqual(reply.err_type, ofp.OFPET_BAD_REQUEST,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_REQUEST.") % reply.err_type)
        self.assertEqual(reply.code, ofp.OFPBRC_BAD_PORT,
                         ("Flow mod failed code %d was received, but we "
                          "expected OFPBRC_BAD_PORT.") % reply.code)

        

class Testcase_390_100_packet_out_actions(base_tests.SimpleDataPlane):
    """
    TODO : Can not send the packet_out message because of the Pre-requisites for set-field actions. Need to update.

    Purpose
    Verify that packet_out message with action list is supported by the switch.

    Methodology
    Configure and connect DUT to controller. Generate a non-buffered ofp_packet_out including a TCP packet, a set-field action, an output action to port X, and if supported a group action to a group with an output action to port Y. Verify the modified TCP packet is received on ports X and if groups are supported port Y

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 390.100 packet out actions")
        in_port, out_port1, out_port2 = openflow_ports(3)

        pkt = simple_tcp_packet()
        verify_pkt = simple_tcp_packet(ip_src = '192.168.0.5') #0xc0a80105

        delete_all_flows(self.controller)
        delete_all_groups(self.controller)
        msg = ofp.message.group_add(
        group_type=ofp.OFPGT_ALL,
        group_id=1,
        buckets=[
            ofp.bucket(actions=[ofp.action.output(out_port2)])])
        self.controller.message_send(msg)
        reply, _ = self.controller.poll(exp_msg = ofp.OFPT_ERROR, timeout = 3)
        self.assertIsNone(reply, "Received an error")
        
        request = ofp.message.group_features_stats_request()
        reply, _= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive group features reply")
        if reply.type == ofp.const.OFPT_ERROR:
            self.assertEqual(reply.err_type, ofp.const.OFPET_BAD_REQUEST, "Error type is not OFPET_BAD_REQUEST")
            self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_STAT, "Error code is not OFPBRC_BAD_STAT")
            logging.info("DUT does not support group features and returned error msg as expected")
            out_port = out_port1
            no_port = out_port2
            actions = [ofp.action.set_field(ofp.oxm.ipv4_src(0xc0a80105)),ofp.action.output(out_port1)]
            request = ofp.message.packet_out(in_port = in_port, data = str(pkt), buffer_id = ofp.OFP_NO_BUFFER, actions = actions)
            self.controller.message_send(request)
            verify_packet(self, str(simple_tcp_packet(ip_src = '192.168.1.5')), out_port)
            verify_no_packet(self, str(simple_tcp_packet(ip_src = '192.168.1.5')), no_port)
            reply, _ = self.controller.poll(exp_msg = ofp.OFPT_ERROR, timeout = 3)
            self.assertIsNone(reply, "Received an error")


        else:
            self.assertEqual(reply.stats_type,ofp.const.OFPST_GROUP_FEATURES,"Received msg is not group features")
            self.assertNotEqual(reply.max_groups_all,0,"Group is not supported by DUT")
            out_port = [out_port1,out_port2]
            #no_port = out_port1
            actions = [ofp.action.set_field(ofp.oxm.ipv4_src(0xc0a80105)), ofp.action.group(group_id = 1), ofp.action.output(out_port1)]
            request = ofp.message.packet_out(in_port = in_port, data = str(pkt), buffer_id = ofp.OFP_NO_BUFFER, actions = actions)
            self.controller.message_send(request)
            verify_packets(self, str(simple_tcp_packet(ip_src = '192.168.1.5')), out_port)
            #verify_packet(self, str(simple_tcp_packet(ip_src = '192.168.1.5')), out_port1)
            reply, _ = self.controller.poll(exp_msg = ofp.OFPT_ERROR, timeout = 3)
            self.assertIsNone(reply, "Received an error")
        

"""     
class Testcase_390_40_packet_out_action_field(Testcase_390_100_packet_out_actions):
    
    Purpose
    Verify that packet_out message with action list is supported by the switch.

    Methodology
    390.100

    """
        
        
class Testcase_390_110_packet_out_action_table(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify that packet_out message with action outport OFPP_TABLE is supported by the switch.

    Methodology
    Configure and connect DUT to controller. Install a high priority flow (flow-1) matching on in_port and eth_src with an output action to OFPP_CONTROLLER. Install a second low priority flow (flow-2)entry with a match on eth_src, output to a data plane test port. Generate and forward a matching data plane packet to the device on in_port. Verify an ofp_packet_in message is received. Based on the ofp_packet_in's buffer_id, generate an ofp_packet_out using the buffered packet, the in_port set to OFPP_Controller, and an output action of OFPP_TABLE. Verify packet matches on the installed flow-2 and is forwarded correctly

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 390.80 packet out buffer")
        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(out_port)]
        actions_out_controller = [ofp.action.output(ofp.OFPP_CONTROLLER, max_len = 128)]
        match1 = ofp.match([ofp.oxm.in_port(in_port), ofp.oxm.eth_src([0,6,7,8,9,10])])
        match2 = ofp.match([ofp.oxm.eth_src([0,6,7,8,9,10])])

        pkt = simple_tcp_packet()

        delete_all_flows(self.controller)
        
        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match1,
                instructions=[
                    ofp.instruction.apply_actions(actions_out_controller)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a table miss flow to forward packet to controller")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)


        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match2,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=800)
        self.controller.message_send(request)
        logging.info("Inserting a table miss flow to forward packet to controller")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")


        self.dataplane.send(in_port, str(pkt))
        reply, _ = self.controller.poll(exp_msg = ofp.OFPT_PACKET_IN, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive packet in message")
        if reply.buffer_id == ofp.OFP_NO_BUFFER:
            request = ofp.message.packet_out(in_port = ofp.OFPP_CONTROLLER, data = str(pkt), buffer_id = reply.buffer_id, actions = [ofp.action.output(ofp.OFPP_TABLE)])
            self.controller.message_send(request)
            reply, _ = self.controller.poll(exp_msg = ofp.OFPT_ERROR, timeout = 3)
            self.assertIsNone(reply, "Switch generated an error messsage when receiving the packet out message")
            #self.assertEqual(str(pkt), str(reply.data), "Data of packet in message is not as same as packet sent")
            verify_packet(self, str(pkt), out_port)
        else:
            request = ofp.message.packet_out(in_port = ofp.OFPP_CONTROLLER, data = str(pkt), buffer_id = reply.buffer_id, actions = actions)
            self.controller.message_send(request)
            reply, _ = self.controller.poll(exp_msg = ofp.OFPT_ERROR, timeout = 3)
            self.assertIsNone(reply, "Switch generated an error messsage when receiving the packet out message")
            verify_packet(self, str(pkt), out_port)