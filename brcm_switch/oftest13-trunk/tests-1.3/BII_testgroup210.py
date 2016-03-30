# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Pan Zhang
import logging

from oftest import config
import oftest.base_tests as base_tests
import ofp
import BII_testgroup100
import oftest.packet as scapy
from loxi.pp import pp

from oftest.testutils import *
from oftest.parse import parse_ipv6
from oftest.oflog import *
from time import sleep

import BII_testgroup340
"""
class Testcase_210_10_port_structures_port_no(BII_testgroup340.Testcase_340_200_MultipartPortDescUniquePort):
    
    Purpose
    Verify that all ports reported in response to an OFPMP_PORT_DESC have a unique non-negative port number.

    Methodology
    340.200

    



class Testcase_210_20_port_structures_hw_addr(BII_testgroup340.Testcase_340_220_MultipartPortDescUniqueHWAddress):
    
    Purpose
    Check the HW_ADDR is unique. 

    Methodology
    340.220

    


class Testcase_210_30_port_structures_name(BII_testgroup340.Testcase_340_240_MultipartPortDescPortName):
    
    Purpose
    Verify the length of OFP_MAX_PORT_NAME is less than 16

    Methodology
    340.240

    


class Testcase_210_40_correct_bitmap_OFPPC_flags(BII_testgroup100.Testcase_100_60_ALL_OFPPC_NO_FWD):
    
    Purpose
    Verify the current config  (default config) is correctly returned

    Methodology
    100.60


    """



class Testcase_210_50_port_administratively_down(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify a port status change message is received, and the bitmap reflects the change in the port config.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, install a table_miss flow entry to generate ofp_packet_in messages. Send an ofp_port_mod message that sets the all configuration bits to zero except OFPPC_PORT_DOWN, for a data plane port X. Verify that the port config bits are correctly set. Send traffic on data plane port X. Verify no ofp_packet_in message is received. Send an ofp_packet_out message with an output action to port X. Verify no traffic is forwarded.

    """
    def tearDown(self):
        in_port, out_port = openflow_ports(2)
        request = ofp.message.port_desc_stats_request()
        #self.controller.message_send(request)
        #reply, _ = self.controller.poll(exp_msg=ofp.OFPMP_PORT_DESCRIPTION, timeout=3)
        port_stats = get_stats(self, req = request)
        #hard_addr = port_stats[1].hw_addr
        #request = ofp.message.port_mod(port_no = out_port, hw_addr = hard_addr, config = 0, mask = ofp.OFPPC_PORT_DOWN)
        #self.controller.message_send(request)
        port_config_set(self.controller, port_no=out_port, config=0, mask = ofp.OFPPC_PORT_DOWN)
        logging.info("Set up port %d ", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when setting up the port")
        sleep(2)
        self.controller.clear_queue()
        base_tests.SimpleDataPlane.tearDown(self)


    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 210.50 port administrtively down")

        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(ofp.OFPP_CONTROLLER)]
        actions_out =  [ofp.action.output(out_port)]

        pkt = simple_tcp_packet()

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
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

        request = ofp.message.port_desc_stats_request()
        #self.controller.message_send(request)
        #reply, _ = self.controller.poll(exp_msg=ofp.OFPMP_PORT_DESCRIPTION, timeout=3)
        port_stats = get_stats(self, req = request)
        #hard_addr = port_stats[1].hw_addr
        #print hard_addr
        
        #request = ofp.message.port_mod(port_no = out_port, hw_addr = hard_addr, config = ofp.OFPPC_PORT_DOWN, mask = ofp.OFPPC_PORT_DOWN)
        #self.controller.message_send(request)
        port_config_set(self.controller, port_no=out_port, config=ofp.OFPPC_PORT_DOWN, mask = ofp.OFPPC_PORT_DOWN)
        logging.info("Set down port %d ", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when setting down the port")

        self.dataplane.send(out_port, str(pkt)) # send traffic to the port administratively down

        verify_no_packet_in(self, str(pkt), out_port)

        request = ofp.message.packet_out(in_port = ofp.OFPP_CONTROLLER, data = str(pkt), buffer_id = ofp.OFP_NO_BUFFER, actions = actions_out)
        self.controller.message_send(request)
        verify_no_packet(self, str(pkt), out_port)
        
        #bring the port back up
        #request = ofp.message.port_mod(port_no = out_port, hw_addr = hard_addr, config = 0, mask = 0)
        #self.controller.message_send(request)


"""
class Testcase_210_60_Drop_all_packets_received(base_tests.SimpleDataPlane):
    
    Purpose
    Verify a port status change message is received, and the bitmap reflects the change in the port config.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, install a table_miss flow entry to generate ofp_packet_in messages. Send an ofp_port_mod message that sets the all configuration bits to zero except OFPPC_NO_RECV, for a data plane port X. Verify that the port config bits are correctly set. Send traffic on data plane port X. Verify no ofp_packet_in message is received. Send an ofp_packet_out message with an output action to port X. Verify traffic is forwarded out data plane port X.

    
    def tearDown(self):
        in_port, out_port = openflow_ports(2)
        request = ofp.message.port_desc_stats_request()
        #self.controller.message_send(request)
        #reply, _ = self.controller.poll(exp_msg=ofp.OFPMP_PORT_DESCRIPTION, timeout=3)
        port_stats = get_stats(self, req = request)
        hard_addr = port_stats[out_port - 1].hw_addr
        request = ofp.message.port_mod(port_no = out_port, hw_addr = hard_addr, config = 0, mask = ofp.OFPPC_NO_RECV)
        self.controller.message_send(request)
        logging.info("Set up port %d ", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when setting up the port")
        sleep(2)
        self.controller.clear_queue()
        base_tests.SimpleDataPlane.tearDown(self)


    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 210.60 drop all pckets received by port")

        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(ofp.OFPP_CONTROLLER)]
        actions_out =  [ofp.action.output(out_port)]

        pkt = simple_tcp_packet()
        #pkt1 = simple_tcp_packet(tcp_sport = 10)


        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
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

        request = ofp.message.port_desc_stats_request()
        #self.controller.message_send(request)
        #reply, _ = self.controller.poll(exp_msg=ofp.OFPMP_PORT_DESCRIPTION, timeout=3)
        port_stats = get_stats(self, req = request)
        hard_addr = port_stats[out_port - 1].hw_addr
        print hard_addr
        
        request = ofp.message.port_mod(port_no = out_port, hw_addr = hard_addr, config = ofp.OFPPC_NO_RECV, mask = ofp.OFPPC_NO_RECV)
        self.controller.message_send(request)
        logging.info("Setting OFPPC_NO_RECV flag for port %d ", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when setting the flag")
        
        self.dataplane.send(out_port, str(pkt))

        verify_no_packet_in(self, str(pkt), out_port)

        request = ofp.message.packet_out(in_port = ofp.OFPP_CONTROLLER, data = str(pkt), buffer_id = ofp.OFP_NO_BUFFER, actions = actions_out)
        self.controller.message_send(request)

        verify_packet(self, str(pkt), out_port)
"""

"""
class Testcase_210_70_drop_packets_forwarded(base_tests.SimpleDataPlane):
    
    Purpose
    Verify a port status change message is received, and the bitmap reflects the change in the port config.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, install a table_miss flow entry to generate ofp_packet_in messages. Send an ofp_port_mod message that sets the all configuration bits to zero except OFPPC_NO_FWD, for a data plane port X. Verify that the port config bits are correctly set. Send traffic on data plane port X. Verify that ofp_packet_in messages are received. Send an ofp_packet_out message with an output action to port X. Verify no traffic is forwarded

    
    def tearDown(self):
        in_port, out_port = openflow_ports(2)
        request = ofp.message.port_desc_stats_request()
        #self.controller.message_send(request)
        #reply, _ = self.controller.poll(exp_msg=ofp.OFPMP_PORT_DESCRIPTION, timeout=3)
        port_stats = get_stats(self, req = request)
        hard_addr = port_stats[out_port - 1].hw_addr
        request = ofp.message.port_mod(port_no = out_port, hw_addr = hard_addr, config = 0, mask = ofp.OFPPC_NO_FWD)
        self.controller.message_send(request)
        logging.info("Set up port %d ", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when setting up the port")
        sleep(2)
        self.controller.clear_queue()
        base_tests.SimpleDataPlane.tearDown(self)


    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 210.70 drop packets forwarded to port")

        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(ofp.OFPP_CONTROLLER)]
        actions_out =  [ofp.action.output(out_port)]

        pkt = simple_tcp_packet()
        #pkt1 = simple_tcp_packet(tcp_sport = 10)


        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
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

        request = ofp.message.port_desc_stats_request()
        #self.controller.message_send(request)
        #reply, _ = self.controller.poll(exp_msg=ofp.OFPMP_PORT_DESCRIPTION, timeout=3)
        port_stats = get_stats(self, req = request)
        hard_addr = port_stats[out_port - 1].hw_addr
        print hard_addr
        
        request = ofp.message.port_mod(port_no = out_port, hw_addr = hard_addr, config = ofp.OFPPC_NO_FWD, mask = ofp.OFPPC_NO_FWD)
        self.controller.message_send(request)
        logging.info("Setting OFPPC_NO_FWD flag for port %d ", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when setting the flag")
        
        self.dataplane.send(out_port, str(pkt))

        verify_no_packet_in(self, str(pkt), out_port)

        request = ofp.message.packet_out(in_port = ofp.OFPP_CONTROLLER, data = str(pkt), buffer_id = ofp.OFP_NO_BUFFER, actions = actions_out)
        self.controller.message_send(request)

        verify_no_packet(self, str(pkt), out_port)


class Testcase_210_80_do_not_send_packet_in(base_tests.SimpleDataPlane):
    
    Purpose
    Verify a port status change message is received, and the bitmap reflects the change in the port config.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, install a table_miss flow entry to generate ofp_packet_in messages. Send an ofp_port_mod message that sets the all configuration bits to zero except OFPPC_NO_PACKET_IN, for a data plane port X. Verify that the port config bits are correctly set. Send traffic on data plane port X. Verify no ofp_packet_in message is received. Install a second fully wildcarded flow with priority 100 with an output action to OFPP_CONTROLLER. Send traffic on data plane port X. Verify that ofp_packet_in messages are not received.

    
    def tearDown(self):
        in_port, out_port = openflow_ports(2)
        request = ofp.message.port_desc_stats_request()
        #self.controller.message_send(request)
        #reply, _ = self.controller.poll(exp_msg=ofp.OFPMP_PORT_DESCRIPTION, timeout=3)
        port_stats = get_stats(self, req = request)
        hard_addr = port_stats[out_port - 1].hw_addr
        request = ofp.message.port_mod(port_no = out_port, hw_addr = hard_addr, config = 0, mask = ofp.OFPPC_NO_PACKET_IN)
        self.controller.message_send(request)
        logging.info("Set up port %d ", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when setting up the port")
        sleep(2)
        self.controller.clear_queue()
        base_tests.SimpleDataPlane.tearDown(self)


    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 210.70 drop packets forwarded to port")

        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(ofp.OFPP_CONTROLLER)]
        actions_out =  [ofp.action.output(out_port)]

        pkt = simple_tcp_packet()
        #pkt1 = simple_tcp_packet(tcp_sport = 10)


        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
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

        request = ofp.message.port_desc_stats_request()
        #self.controller.message_send(request)
        #reply, _ = self.controller.poll(exp_msg=ofp.OFPMP_PORT_DESCRIPTION, timeout=3)
        port_stats = get_stats(self, req = request)
        hard_addr = port_stats[out_port - 1].hw_addr
        print hard_addr
        
        request = ofp.message.port_mod(port_no = out_port, hw_addr = hard_addr, config = ofp.OFPPC_NO_PACKET_IN, mask = ofp.OFPPC_NO_PACKET_IN)
        self.controller.message_send(request)
        logging.info("Setting OFPPC_NO_PACKET_IN flag for port %d ", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when setting the flag")
        
        self.dataplane.send(out_port, str(pkt))

        verify_no_packet_in(self, str(pkt), out_port)

        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=100)
        self.controller.message_send(request)
        logging.info("Inserting a table miss flow to forward packet to controller")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")

        self.dataplane.send(out_port, str(pkt))

        verify_no_packet_in(self, str(pkt), out_port)

        #request = ofp.message.packet_out(in_port = ofp.OFPP_CONTROLLER, data = str(pkt), buffer_id = ofp.OFP_NO_BUFFER, actions = actions_out)
        #self.controller.message_send(request)

        #verify_no_packet(self, str(pkt), out_port)

class Testcase_210_90_correct_bitmap_OFPPS_flags(BII_testgroup340.Testcase_340_260_MultipartPortDescSetPortState):
    
    Purpose
    Verify the current state  (default state) is correctly returned

    Methodology
    340.260


    


class Testcase_210_130_correct_features(BII_testgroup340.Testcase_340_270_MultipartPortDescCurrFeatures):
    
    Purpose
    Verify current port features are correctly reported.

    Methodology
    340.270

    


class Testcase_210_140_features_being_advertised_by_port(BII_testgroup340.Testcase_340_280_MultipartPortDescAdvertisedFeatures):
    
    Purpose
    Verify the  features advertised by the port are correctly returned

    Methodology
    340.280

    



class Testcase_210_150_features_supported_by_port(BII_testgroup340.Testcase_340_290_MultipartPortDescSupportedFeatures):
    
    Purpose
    Verify the features supported  by the port are correctly returned

    Methodology
    340.290


    


class Testcase_210_160_features_advertised_by_port(BII_testgroup340.Testcase_340_300_MultipartPortDescPeerFeatures):
    
    Purpose
    Verify the features supported  by the peer port are correctly returned

    Methodology
    340.300

    


class Testcase_210_170_current_port_bitrate_kbps(BII_testgroup340.Testcase_340_310_MultipartPortDescCurrSpeed):
    
    Purpose
    Verify the current bit rate is correctly returned

    Methodology
    340.310


    


class Testcase_210_180_max_port_bitrate(BII_testgroup340.Testcase_340_320_MultipartPortDescMaxSpeed):
    
    Purpose
    Verify the maximum bitrate for the port is correctly returned

    Methodology
    340.320

    """
