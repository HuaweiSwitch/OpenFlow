# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Pan Zhang
"""
Test suite 180 verifies the behavior of counters marked as required in table 5 of the v1.3 OpenFlow Specification.
Remarks
Logical ports
As with physical ports it is required that unsupported counters have a reported value of -1. For mandatory port counters, documentation describing the counter mapping from physical ports to logical ports must be provided by the device vendor. Logical port counters, and their correct values must be manually verified by the tester if the test tool is unable to perform the required operations.
Basic conformance
To satisfy the basic requirements an OpenFlow enabled device must pass all test cases in this test suite.

"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
import oftest.packet as scapy
from loxi.pp import pp

from oftest.testutils import *
from oftest.parse import parse_ipv6
from oftest.oflog import *
from time import sleep

import BII_testgroup340

class Testcase_180_10_reference_count(base_tests.SimpleDataPlane):
    """
    TODO: Verify the correctness of this testcase by using another DUT
    Purpose
    Test Reference Count of active entries counter

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the given pre-requisites for the match) with an output action to a data plane test port. Generate N matching and M non-matching packets on the data plane. Send an ofp_multipart_request of type OFPMP_TABLE. From the response verify active_count==1, lookup_count==N+M, and matched_count==N.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 180.10 reference count")

        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(out_port)]
        match = ofp.match([ofp.oxm.eth_type(0x0800),ofp.oxm.ipv4_src(0xc0a80001),ofp.oxm.ip_proto(6),ofp.oxm.tcp_src(1234)])
        pkt = simple_tcp_packet()
        pkt1 = simple_tcp_packet(tcp_sport = 10)


        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)
        
        table_stats = get_stats(self, ofp.message.table_stats_request())
        self.assertIsNotNone(table_stats,"Did not receive flow stats reply messsage")
        orig_active_count=table_stats[test_param_get("table", 0)].active_count
        orig_lookup_count=table_stats[test_param_get("table", 0)].lookup_count
        orig_matched_count=table_stats[test_param_get("table", 0)].matched_count

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
        logging.info("Inserting a flow to forward packet to port %d ", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)

        self.dataplane.send(in_port, str(pkt))
        self.dataplane.send(in_port, str(pkt))
        self.dataplane.send(in_port, str(pkt1))

	sleep(2)
        table_stats = get_stats(self, ofp.message.table_stats_request())
        self.assertIsNotNone(table_stats,"Did not receive flow stats reply messsage")

        self.assertEqual(table_stats[test_param_get("table", 0)].active_count, orig_active_count+1, "The active_count counter is not increased by 1")
        self.assertEqual(table_stats[test_param_get("table", 0)].lookup_count, orig_lookup_count+3, "The lookup_count counter is not increased by 3")
        self.assertEqual(table_stats[test_param_get("table", 0)].matched_count, orig_matched_count+2, "The matched_count counter is not increased by 2")
        
        
        
class Testcase_180_60_Per_Flow_Duration_Counter(base_tests.SimpleDataPlane):
    """
    Purpose
    Test Duration counter

    Methodology
    Configure and connect DUT to controller. After control channel establishment, send a multipart_request for flow_stats. Verify that the switch sends a multipart_reply for flow_stats. Record the value in the duration field. Wait 5 seconds. Send another multipart_request for flow_stats. Verify that the switch sends a multipart_reply for flow_stats. Record the value in the duration field. Verify that the duration field has increased by 5.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 180.60 Per Flow Duration Counter")

        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(out_port)]
        match = ofp.match([
            ofp.oxm.eth_type(0x0800)
        ])
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
        logging.info("Inserting a flow to forward packet to port %d ", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)
        flow_stats = get_stats(self, ofp.message.flow_stats_request(table_id = test_param_get("table", 0), out_group = ofp.OFPG_ANY, out_port = ofp.OFPP_ANY))
        self.assertIsNotNone(flow_stats,"Did not receive flow stats reply messsage")
        init_duration_sec = flow_stats[0].duration_sec
        
        time.sleep(5)
        flow_stats = get_stats(self, ofp.message.flow_stats_request(table_id = test_param_get("table", 0), out_group = ofp.OFPG_ANY, out_port = ofp.OFPP_ANY))
        self.assertIsNotNone(flow_stats,"Did not receive flow stats reply messsage")
        self.assertTrue(flow_stats[0].duration_sec==(init_duration_sec + 5),"Duration counter did not increase correctly")
        


"""
class Testcase_180_80_per_port_received_packets_counter(BII_testgroup340.Testcase_340_50_MultipartPortStatsRxPackets):
    
    Purpose
    Test Received Packet counter

    Methodology
    340,50

    



class Testcase_180_90_per_port_transmitted_packets_counter(BII_testgroup340.Testcase_340_60_MultipartPortStatsTxPackets):
    
    Purpose
    Test Transmitted Packet counter

    Methodology
    340, 60

    """

      
class Testcase_180_100_per_port_duration_seconds(BII_testgroup340.Testcase_340_170_MultipartPortStatsDurationSec):
    """
    Purpose
    Test duration counter

    Methodology
    340, 170

    """


class Testcase_180_230_correct_packet_drop_counters(base_tests.SimpleDataPlane):
    """
    Purpose
    Counters_packet dropped_Port_down

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the given pre-requisites for the match) with an output action to a data plane test port which is administratively down. Send N matching data plane packets to the switch. Verify the flow's packet counter is incremented correctly.

    """
    def tearDown(self):
        in_port, out_port = openflow_ports(2)
        request = ofp.message.port_desc_stats_request()
        #self.controller.message_send(request)
        #reply, _ = self.controller.poll(exp_msg=ofp.OFPMP_PORT_DESCRIPTION, timeout=3)
        port_stats = get_stats(self, req = request)
        hard_addr = port_stats[3].hw_addr
        request = ofp.message.port_mod(port_no = out_port, hw_addr = hard_addr, config = 0)
        self.controller.message_send(request)
        logging.info("Set up port %d ", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when setting up the port")
        sleep(2)
        self.controller.clear_queue()
        base_tests.SimpleDataPlane.tearDown(self)


    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 180.230 correct packet drop counters")

        in_port, out_port = openflow_ports(2)
        print out_port
        actions = [ofp.action.output(out_port)]

        pkt = simple_tcp_packet()
        pkt1 = simple_tcp_packet(tcp_sport = 10)


        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)
        
        table_stats = get_stats(self, ofp.message.table_stats_request())
        self.assertIsNotNone(table_stats,"Did not receive flow stats reply messsage")
        initial_matched_count = table_stats[test_param_get("table", 0)].matched_count

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d ", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)

        request = ofp.message.port_desc_stats_request()
        #self.controller.message_send(request)
        #reply, _ = self.controller.poll(exp_msg=ofp.OFPMP_PORT_DESCRIPTION, timeout=3)
        port_stats = get_stats(self, req = request)
        hard_addr = port_stats[3].hw_addr
        print hard_addr
        
        request = ofp.message.port_mod(port_no = out_port, hw_addr = hard_addr, config = ofp.OFPPC_PORT_DOWN)
        self.controller.message_send(request)
        logging.info("Set down port %d ", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when setting down the port")
        
        self.dataplane.send(in_port, str(pkt))
        self.dataplane.send(in_port, str(pkt))

        time.sleep(2)
        table_stats = get_stats(self, ofp.message.table_stats_request())
        self.assertIsNotNone(table_stats,"Did not receive flow stats reply messsage")

        #self.assertEqual(table_stats[0].active_count, 1, "The active_count counter is not 1")
        #self.assertEqual(table_stats[0].lookup_count, 3, "The lookup_count counter is not 3")
        self.assertEqual(table_stats[test_param_get("table", 0)].matched_count, initial_matched_count+2, "The matched_count counter is not increased by 2")


        
class Testcase_180_410_reference_count(base_tests.SimpleDataPlane):
    """
    Purpose
    Test Duration is always metered in second precision.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the given Pre-requisites for the match). Request the duration counter every 5 seconds for 120 seconds, and verify the returned value is correct with second precision ( expected duration +- .5 sec)

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 180.10 reference count")

        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(out_port)]
        match = ofp.match([
            ofp.oxm.eth_type(0x0800)
        ])
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
        logging.info("Inserting a flow to forward packet to port %d ", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)
        flow_stats = get_stats(self, ofp.message.flow_stats_request(table_id = test_param_get("table", 0), out_group = ofp.OFPG_ANY, out_port = ofp.OFPP_ANY))
        self.assertIsNotNone(flow_stats,"Did not receive flow stats reply messsage")
        init_duration_sec = flow_stats[0].duration_sec
        print init_duration_sec

        for i in range(0, 23):
            flow_stats = get_stats(self, ofp.message.flow_stats_request(table_id = test_param_get("table", 0), out_group = ofp.OFPG_ANY, out_port = ofp.OFPP_ANY))
            self.assertIsNotNone(flow_stats,"Did not receive flow stats reply messsage")
            duration_sec = flow_stats[0].duration_sec
            #if(duration_sec >= (init_duration_sec+i*5 - 0.5) and duration_sec <= (init_duration_sec+ i*5 + 0.5)):
            if(duration_sec >= (init_duration_sec+i*5 - 0.5) and duration_sec <= (init_duration_sec+ i*5 + 1)):
                pass
            else:
                print " At %d seconds" % (i*5)
                self.assertEqual(duration_sec, init_duration_sec+i*5, "The duration counter is not incremented correctly ")
                break
            sleep(5)



class Testcase_180_430_counter_wrap_around(base_tests.SimpleDataPlane):
    """
    Purpose
    Test Duration is always metered in second precision.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the given Pre-requisites for the match). Request the duration counter every 5 seconds for 120 seconds, and verify the returned value is correct with second precision ( expected duration +- .5 sec)

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 180.10 reference count")

        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(out_port)]
        match = ofp.match([
            ofp.oxm.eth_type(0x0800)
        ])
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
        logging.info("Inserting a flow to forward packet to port %d ", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)
        flow_stats = get_stats(self, ofp.message.flow_stats_request(table_id = test_param_get("table", 0), out_group = ofp.OFPG_ANY, out_port = ofp.OFPP_ANY))
        self.assertIsNotNone(flow_stats,"Did not receive flow stats reply messsage")
        init_duration_nsec = flow_stats[test_param_get("table", 0)].duration_nsec
        print init_duration_nsec

        for i in range(0, 11):
            flow_stats = get_stats(self, ofp.message.flow_stats_request(table_id = test_param_get("table", 0), out_group = ofp.OFPG_ANY, out_port = ofp.OFPP_ANY))
            self.assertIsNotNone(flow_stats,"Did not receive flow stats reply messsage")
            duration_nsec = flow_stats[0].duration_nsec
            if duration_nsec <= init_duration_nsec:
                break
            else:
                self.assertIsNotNone(duration_nsec,"The nsec counter did not wrap around")
            sleep(0.5)

