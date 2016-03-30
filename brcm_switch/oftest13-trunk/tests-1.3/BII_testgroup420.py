# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Pan Zhang

"""
Test suite 420 verifies the device correctly implements port status and flow removed message types.

Basic conformance
To satisfy the basic requirements an OpenFlow enabled device must pass 420.10 - 420.50, and 420.70 - 420.120.

"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
import oftest.packet as scapy
from loxi.pp import pp
import BII_testgroup140
from oftest.testutils import *
from oftest.parse import parse_ipv6
from oftest.oflog import *
from time import sleep
"""
class Testcase_420_10_flow_removed_message(BII_testgroup140.Testcase_140_110_Delete_Flow_removed):
    
    Purpose
    Check a flow is deleted while "OFPFF_SEND_FLOW_REM" flag is set, and verify a flow removed message is generated.

    Methodology
    140.110

    """



class Testcase_420_20_flow_removed_message_fields(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify the match, cookie, and priority fields are the same as those used in the flow mod request. 

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the Pre-requisites for the match) with OFPFF_SEND_FLOW_REM flag set and with action as output port X. Send a packet for matching field and verify packet is received on port X. Send a OFPFC_DELETE request for previous flow. Send same packet as earlier and verify packet is not received by output port and dropped by the switch. Verify the controller receives the flow removed message with match, cookie and priority to that of original flow_mod

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 420.20 flow removed message fields")

        in_port, out_port = openflow_ports(2)
        flags = ofp.OFPFF_SEND_FLOW_REM

        actions = [ofp.action.output(out_port)]
        pkt = simple_tcp_packet()
        match = packet_to_flow_match(self, pkt)

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 1000, flags = flags, cookie = 1001)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_port)
        request = ofp.message.flow_delete(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                out_port = ofp.OFPP_ANY,
                out_group = ofp.OFPG_ANY,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 1000)
        self.controller.message_send(request)
        logging.info("deleting the previous flow")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_FLOW_REMOVED, timeout=3)
        self.assertIsNotNone(reply, "Switch did not generate flow removed message")
        self.assertEqual(reply.cookie, 1001, "The cookie field is not equal")
        self.assertEqual(reply.priority, 1000, "The priority field is not equal")
        #self.assertEqual(cmp(reply.match, match),0, "The match field is not equal")



class Testcase_420_30_flow_removed_message_reason_idle_timeout(base_tests.SimpleDataPlane):
    """    
    Purpose
    Verify when a flow is removed because of an idle timeout, the reason field of a flow removed message is OFPRR_IDLE_TIMEOUT.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the Pre-requisites for the match) with OFPFF_SEND_FLOW_REM flag set, and idle_timeout of 3 seconds, and an action output port X. Send a packet for matching field and verify packet is received on port X. After 3 seconds verify the controller receives the flow removed message, and the reason field is set to OFPRR_IDLE_TIMEOUT. Send a the same packet as earlier and verify packet is not received by output port and dropped by the switch.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 420.30 flow removed message reason idle timeout")

        in_port, out_port = openflow_ports(2)
        flags = ofp.OFPFF_SEND_FLOW_REM

        actions = [ofp.action.output(out_port)]
        pkt = simple_tcp_packet()
        match = packet_to_flow_match(self, pkt)

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 1000, flags = flags, idle_timeout = 3)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=1)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_port)


        logging.info("polling for flow removed message")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_FLOW_REMOVED, timeout=4)
        self.assertIsNotNone(reply, "Switch did not generate flow removed message")
        self.assertEqual(reply.reason, ofp.OFPRR_IDLE_TIMEOUT, "The reason field is not equal")
        self.dataplane.send(in_port, str(pkt))
        verify_no_packet(self, str(pkt),out_port)

class Testcase_420_40_flow_removed_message_reason_hard_timeout(base_tests.SimpleDataPlane):
    """    
    Purpose
    Verify when a flow is removed because of a hard timeout, the reason field of a flow removed message is OFPRR_HARD_TIMEOUT.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the Pre-requisites for the match) with OFPFF_SEND_FLOW_REM flag set, and hard_timeout of 3 seconds, and an action output port X. Send a packet for matching field and verify packet is received on port X. After 3 seconds verify the controller receives the flow removed message, and the reason field is set to OFPRR_HARD_TIMEOUT. Send a the same packet as earlier and verify packet is not received by output port and dropped by the switch

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 420.30 flow removed message reson hard timeout")

        in_port, out_port = openflow_ports(2)
        flags = ofp.OFPFF_SEND_FLOW_REM

        actions = [ofp.action.output(out_port)]
        pkt = simple_tcp_packet()
        match = packet_to_flow_match(self, pkt)

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 1000, flags = flags, hard_timeout = 3)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_port)


        logging.info("polling for flow removed message")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_FLOW_REMOVED, timeout=3)
        self.assertIsNotNone(reply, "Switch did not generate flow removed message")
        self.assertEqual(reply.reason, ofp.OFPRR_HARD_TIMEOUT, "The reason field is not equal")
        self.dataplane.send(in_port, str(pkt))
        verify_no_packet(self, str(pkt),out_port)



class Testcase_420_50_flow_removed_message_reason_delete(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify when a flow is removed because of a delete message, the reason field of a flow removed message is OFPRR_DELETE.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the Pre-requisites for the match) with OFPFF_SEND_FLOW_REM flag set and with action as output port X. Send a packet for matching field and verify packet is received on port X. Send a OFPFC_DELETE request for previous flow. Send a the same packet as earlier and verify packet is not received by output port and dropped by the switch. Verify the controller receives the flow removed message, and the reason field is set to OFPRR_DELETE.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 420.50 flow removed message reason delete")

        in_port, out_port = openflow_ports(2)
        flags = ofp.OFPFF_SEND_FLOW_REM

        actions = [ofp.action.output(out_port)]
        pkt = simple_tcp_packet()
        match = packet_to_flow_match(self, pkt)

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 1000, flags = flags, cookie = 1001)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_port)
        request = ofp.message.flow_delete(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                out_port = ofp.OFPP_ANY,
                out_group = ofp.OFPG_ANY,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 1000)
        self.controller.message_send(request)
        logging.info("deleting the previous flow")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_FLOW_REMOVED, timeout=3)
        self.assertIsNotNone(reply, "Switch did not generate flow removed message")
        self.assertEqual(reply.reason, ofp.OFPRR_DELETE, "The reason field is not equal")
        self.dataplane.send(in_port, str(pkt))
        verify_no_packet(self, str(pkt),out_port)


class Testcase_420_70_flow_removed_message_duration(base_tests.SimpleDataPlane):
    """    
    Purpose
    Verify that a flow removed message reports the correct flow duration.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the Pre-requisites for the match) with OFPFF_SEND_FLOW_REM flag set, and hard_timeout of 3 seconds, and an action output port X. Send a packet for matching field and verify packet is received on port X. After 3 seconds verify the controller receives the flow removed message, and that duration_sec (mandatory for basic conformance) and duration_nsec (optional for basic conformance) fields are correct . Send a the same packet as earlier and verify packet is not received by output port and dropped by the switch. 

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 420.70 flow removed message duration")

        in_port, out_port = openflow_ports(2)
        flags = ofp.OFPFF_SEND_FLOW_REM

        actions = [ofp.action.output(out_port)]
        pkt = simple_tcp_packet()
        match = packet_to_flow_match(self, pkt)

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 1000, flags = flags, hard_timeout = 3)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_port)


        logging.info("polling for flow removed message")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_FLOW_REMOVED, timeout=3)
        self.assertIsNotNone(reply, "Switch did not generate flow removed message")
        self.assertEqual(reply.duration_sec, 3, "The duration is not correct")
        self.dataplane.send(in_port, str(pkt))
        verify_no_packet(self, str(pkt),out_port)

class Testcase_420_80_flow_removed_message_reason_timeout(base_tests.SimpleDataPlane):
    """    
    Purpose
    Verify the idle and hard timeout fields in a flow removed message are equal to the flow which was installed.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the Pre-requisites for the match) with OFPFF_SEND_FLOW_REM flag set, idle_timeout of 2 seconds, hard_timeout of 3 seconds, and an action output port X. Send a packet for matching field and verify packet is received on port X. Verify the controller receives the flow removed message, and that duration_sec and duration_nsec fields are correct. Also verify that the idle and hard timeout fields are equal to the idle and hard timeout fields included in the installed flow_mod.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 420.80 flow removed message reson timeout")

        in_port, out_port = openflow_ports(2)
        flags = ofp.OFPFF_SEND_FLOW_REM

        actions = [ofp.action.output(out_port)]
        pkt = simple_tcp_packet()
        match = packet_to_flow_match(self, pkt)

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 1000, flags = flags, hard_timeout = 3, idle_timeout = 2)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_port)
        #reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        #self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
	sleep(1)
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_port)


        logging.info("polling for flow removed message")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_FLOW_REMOVED, timeout=5)
        self.assertIsNotNone(reply, "Switch did not generate flow removed message")
        self.assertEqual(reply.duration_sec, 3, "The duration is not correct") # hard time
        self.assertEqual(reply.idle_timeout, 2, "The idle_timeout is not correct")
        self.assertEqual(reply.hard_timeout, 3, "The hard_timeout is not correct")
        self.dataplane.send(in_port, str(pkt))
        verify_no_packet(self, str(pkt),out_port)


class Testcase_420_90_flow_removed_message_counter(base_tests.SimpleDataPlane):
    """    
    Purpose
    Verify the packet and byte counters are correctly reported in a flow removed message.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the Pre-requisites for the match) with OFPFF_SEND_FLOW_REM flag set, hard_timeout of 5 seconds, and an action output port P. Send a N packets of length X for matching field and verify packet is received on port P. Verify the controller receives the flow removed message, and that packet_count is equal to N, and that byte_count, if supported, is equal to (N*X) or -1 if it is not supported.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 420.90 flow removed message counter")

        in_port, out_port = openflow_ports(2)
        flags = ofp.OFPFF_SEND_FLOW_REM

        actions = [ofp.action.output(out_port)]
        pkt = simple_tcp_packet()
        match = packet_to_flow_match(self, pkt)

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 1000, flags = flags, hard_timeout = 5)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        do_barrier(self.controller)
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_port)
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_port)
        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_port)


        logging.info("polling for flow removed message")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_FLOW_REMOVED, timeout=3)
        self.assertIsNotNone(reply, "Switch did not generate flow removed message")
        self.assertEqual(reply.packet_count, 3, "The packet count is not 3")
        self.assertEqual(reply.byte_count, 300, "The byte count is not 300")


class Testcase_420_100_port_status_reason_add(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify a port status message is correctly received when adding ports.

    Methodology
    Prior to control channel establishment, remove a data plane test port from the OpenFlow instance. Configure and connect DUT to controller. After control channel establishment, add the previously removed data plane test port to the OpenFlow instance. Verify the device generates an ofp_port_stats message with a reason field of OFPPR_ADD.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 420.100 port status reason add")
        logging.info("Require manual testing")


class Testcase_420_110_port_status_reason_delete(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify a port status message is correctly received when removing ports.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, remove a data plane test port from the OpenFlow instance. Verify the device generates an ofp_port_stats message with a reason field of OFPPR_DELETE. Add the previously removed data plane test port to the OpenFlow instance.


    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 420.110 port status reason delete")
        logging.info("Require manual testing")



class Testcase_420_120_port_status_reason_modify(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify a port status message is correctly received when modifying ports.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, administratively turn down a data plane test port from the OpenFlow instance. Verify the device generates an ofp_port_stats message with a reason field of OFPPR_MODIFY. Administratively turn up the previously downed data plane test port.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 420.120 port status reason modify")
        logging.info("Require manual testing")
