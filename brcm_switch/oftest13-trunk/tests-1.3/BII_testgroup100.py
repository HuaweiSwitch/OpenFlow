# Distributed under the OpenFlow Software License (see LICENSE)
# Copyright (c) 2010 The Board of Trustees of The Leland Stanford Junior University
# Copyright (c) 2012, 2013 Big Switch Networks, Inc.
# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Pan Zhang
"""
Test suite 100 verifies that all actions a device must support are correctly implemented. The output action is the only action type required for basic conformance. Basic conformance requires the output action to work with the following reserved ports; OFPP_IN_PORT, OFPP_ALL, OFPP_TABLE (for packet out messages only), and OFPP_CONTROLLER.
Basic conformance
To satisfy the basic requirements an OpenFlow enabled device must pass test cases 100.10 - 100.90.


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

class Testcase_100_10_Drop(base_tests.SimpleDataPlane):
    """
   
    Purpose
    Verify that a packet matching a flow with no associated output action gets dropped

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the given Pre-requisites for the match), make sure there is no associated-action in this flow. Send a matching packet on the data plane. Verify the packet is dropped.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 100.10 Drop")
        
		
        delete_all_flows(self.controller)
        in_port, out_port, bad_port = openflow_ports(3)
        table_id = test_param_get("table", 0)
        priority=1
        #actions=[ofp.action.output(port=out_port,max_len=128)]
        #instructions=[ofp.instruction.apply_actions(actions=actions)]
        #Match on Ethernet Type 0x0800
        match = ofp.match([
                ofp.oxm.eth_type(0x0800)
                ])
        req = ofp.message.flow_add(table_id=table_id,
                                   match= match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   priority=priority)
        logging.info("Inserting a flow to match on Ethernet type without associated action")
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")
        pkt = simple_tcp_packet()
        self.dataplane.send(in_port, str(pkt))
        verify_no_other_packets(self)
        verify_no_packet_in(self, str(pkt), in_port)

     
 

class Testcase_100_20_SinglePort(base_tests.SimpleDataPlane):
    """
    
    Purpose
    Verify that a packet matching a flow with an associated single port output action gets forwarded

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the given Pre-requisites for the match), action is output to a single specific port. Send a matching packet on the data plane. Verify the packet is forwarded only to this specific port.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 100.20 Single Port")
        #in_port, out_port = openflow_ports(2)
        ports = openflow_ports(4)
        in_port = ports[0]
        out_ports = ports[1:4]
        
        actions = [ofp.action.output(ports[1])]
        match = ofp.match([
            ofp.oxm.eth_type(0x0800)
        ])
        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

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
        logging.info("Inserting a flow to forwarded packet to port %d", ports[1])
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)

        pktstr = str(pkt)

        logging.info("Sending packet, expecting output to port %d", ports[1])
        self.dataplane.send(in_port, pktstr)
        verify_packets(self, pktstr, [ports[1]])
        """
        actions = [ofp.action.output(port = ofp.OFPP_ALL, max_len = 128)]

        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))
        
        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forwarded packet to port %r", out_ports)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)

        pktstr = str(pkt)

        logging.info("Sending packet, expecting output to port %r", out_ports)
        self.dataplane.send(in_port, pktstr)
        verify_packets(self, pktstr,[ports[1],ports[2],ports[3]])
        """
        
class Testcase_100_30_OutputMultiple(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify that a packet matching a flow with multiple associated single port output actions gets forwarded

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the given Pre-requisites for the match), action is output to two specific ports. Send a matching packet on the data plane. Verify the packet is forwarded only to the specified ports.


    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 100.30 output to multiple ports")
        ports = openflow_ports(4)
        in_port = ports[0]
        out_ports = ports[1:4]
        match = ofp.match([
            ofp.oxm.eth_type(0x0800)
        ])
        actions = [ofp.action.output(x) for x in out_ports]

        pkt = simple_tcp_packet()

        logging.info("Running actions test for %s", pp(actions))

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
        logging.info("Inserting a flow to forwarded packet to port %r", out_ports)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")
        do_barrier(self.controller)

        pktstr = str(pkt)

        logging.info("Sending packet, expecting output to ports %r", out_ports)
        self.dataplane.send(in_port, pktstr)
        verify_packets(self, pktstr, out_ports)

class Testcase_100_40_Single_OutputMultiple(base_tests.SimpleDataPlane):
    """
    TODO: Verify the correctness of this testcase code by using another DUT

    Purpose
    Verify that a packet matching a flow with multiple associated output actions using reserved ports is forwarded to all listed ports.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the given Pre-requisites for the match), with action output to OFPP_ALL and action output to OFPP_IN_PORT. Send a matching packet on the data plane. Verify the packet is forwarded to all ports including the original ingress port.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 100.40 Single Action output to multiple ports")
        ports = openflow_ports(4)
        in_port = ports[0]
        out_ports = ports[1:4]
        match = ofp.match([
            ofp.oxm.eth_type(0x0800)
        ])
        #actions = [ofp.action.output(x) for x in out_ports]
        actions=[ofp.action.output(port = ofp.OFPP_ALL, max_len = 128),
                 ofp.action.output(port = ofp.OFPP_IN_PORT, max_len = 128),
                 ofp.action.output(port = ofp.OFPP_CONTROLLER, max_len = 128)
                ]

        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow to forward packets to all listed ports")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %r", out_ports)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")
        do_barrier(self.controller)

        pktstr = str(pkt)

        logging.info("Sending packet, expecting output to ports %r", out_ports)
        self.dataplane.send(in_port, pktstr)
        verify_packets(self, pktstr, ports)
        verify_packet_in(self,pktstr,in_port,ofp.OFPR_ACTION,self.controller)



class Testcase_100_50_ALL(base_tests.SimpleDataPlane):
    """
    TODO: Verify the correctness of this testcase code by using another DUT

    Purpose
    Verify that a packet matching a flow with an associated  output:ALL action gets forwarded to all ports except the ingress port

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), action is output to port ALL. Send a matching packet on the data plane. Verify the packet is forwarded to all ports except the ingress port

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 100.50 ALL")
        ports = openflow_ports(4)
        in_port = ports[0]
        out_ports = ports[1:4]

        #actions = [ofp.action.output(x) for x in out_ports]
        actions=[ofp.action.output(port = ofp.OFPP_ALL, max_len = 128)]
        match = ofp.match([
            ofp.oxm.eth_type(0x0800)
        ])
        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow to forward packets to all listed ports")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %r", out_ports)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")
        do_barrier(self.controller)

        pktstr = str(pkt)

        logging.info("Sending packet, expecting output to ports %r", out_ports)
        self.dataplane.send(in_port, pktstr)
        verify_packets(self, pktstr, out_ports)

class Testcase_100_60_ALL_OFPPC_NO_FWD(base_tests.SimpleDataPlane):
    """
    TODO: Verify the correctness of this testcase code by using another DUT
    Purpose
    Verify that a packet matching a flow with an associated  output:ALL action gets forwarded to all ports except the ingress port and except ports configured for OFPPC_NO_FWD

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), action is output to port ALL. Send OFPT_PORT_MOD message to make certain port(s) configured for OFPPC_NO_FWD. Send a matching packet on the data plane. Verify the packet is forwarded to all ports except the ingress port and ports configured for OFPPC_NO_FWD

    """
    def tearDown(self):
        mask = ofp.OFPPC_NO_FWD
        config = 0
        ports = openflow_ports(4)
        port_no_fwd = ports[1]
        port_config_set(self.controller, port_no = port_no_fwd, config = config, mask = mask)
        sleep(2)
        self.controller.clear_queue()
        base_tests.SimpleDataPlane.tearDown(self)


    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 100.60 ALL excludes OFPPC_NO_FWD")
        ports = openflow_ports(4)
        in_port = ports[0]
        no_fwd_port = ports[1]
        out_ports = ports[2:4]

        #actions = [ofp.action.output(x) for x in out_ports]
        actions=[ofp.action.output(port = ofp.OFPP_ALL, max_len = 128)]
        match = ofp.match([
            ofp.oxm.eth_type(0x0800)
        ])
        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow to forward packets to all listed ports")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %r", out_ports)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")
        do_barrier(self.controller)

        #port_config_set(self.controller, port_no = no_fwd_port, config = 0, mask = ofp.OFPPC_NO_FWD)

        (_, config1, _) = port_config_get(self.controller, no_fwd_port)
        self.assertIsNotNone(config1 , "Did not get port config")
        #Verify that no_fwd is not already set
        self.assertNotEqual(config1,32, "The initial config for NO_FWD is not set 0")
        config = config1 ^ ofp.OFPPC_NO_FWD
        mask= ofp.OFPPC_NO_FWD
        self.controller.clear_queue()
        port_config_set(self.controller, port_no=no_fwd_port, config=config, mask=mask)
        reply, pkt = self.controller.poll(exp_msg=ofp.OFPT_ERROR)
        self.assertIsNone(reply, "Received OFPT_ERROR.port_mod failed")
        logging.info("Successfully sent port_mod message")
        #Check if the port_mod is successful
        #status,_ =self.controller.poll(exp_msg=ofp.OFPT_PORT_STATUS)
        #self.assertIsNotNone(status,"Did not get a OFPT_PORT_STATUS for a port_mod message")
        #self.assertEqual(status.desc.config,config,"Port config not set to initial config")
        #sleep(5)
        pkt = simple_tcp_packet()
        pktstr = str(pkt)

        logging.info("Sending packet, expecting output to ports %r", out_ports)
        self.dataplane.send(in_port, pktstr)
        verify_packets(self, pktstr, out_ports)
        verify_no_packet(self,pktstr,no_fwd_port)

class Testcase_100_70_Controller(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify that a packet matching a flow with an associated output:controller action generates a packet_in to the controller

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), action is output to port OFPP_CONTROLLER. Send a matching packet on the data plane. Verify a packet_in message encapsulates the matching packet that is triggered.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 100.70 Controller")
        ports = openflow_ports(4)
        in_port = ports[0]
        out_ports = ports[1:4]

        #actions = [ofp.action.output(x) for x in out_ports]
        actions=[ofp.action.output(port = ofp.OFPP_CONTROLLER, max_len = 128)]
        match = ofp.match([
            ofp.oxm.eth_type(0x0800)
        ])
        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow to forward packets to controller(packet_in)")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to controller")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")
        do_barrier(self.controller)

        pktstr = str(pkt)

        logging.info("Sending packet, expecting output to controller")
        self.dataplane.send(in_port, pktstr)
        verify_packet_in(self,pktstr,in_port,ofp.OFPR_ACTION,self.controller)

class Testcase_100_80_Table(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify that a packet_out with output:table gets submitted to the flow table.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), action is output to a specific port. Generate a matching packet and send it via packet_out message with output action to port TABLE in its action list. Verify the packet gets forwarded to the specific port.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 100.80 Table")
        ports = openflow_ports(4)
        in_port = ports[0]
        out_port = ports[1]

        #actions = [ofp.action.output(x) for x in out_ports]
        actions=[ofp.action.output(port = out_port, max_len = 128)]
        match = ofp.match([
            ofp.oxm.eth_type(0x0800)
        ])
        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow to forward packets to controller(packet_in)")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to controller")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")
        do_barrier(self.controller)

        pktstr = str(pkt)
        msg = ofp.message.packet_out(buffer_id = ofp.OFP_NO_BUFFER,
                                     in_port = ofp.OFPP_CONTROLLER,
                                     actions = [ofp.action.output(port=ofp.OFPP_TABLE)],
                                     data = pktstr)
        self.controller.message_send(msg)
        logging.info("Sending the output message")
        verify_packet(self,pktstr,out_port)
        #logging.info("Sending packet, expecting output to controller")
        #self.dataplane.send(in_port, pktstr)
        #verify_packet_in(self,pktstr,in_port,ofp.OFPR_ACTION,self.controller)
class Testcase_100_90_INPORT(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify that a packet matching a flow with an associated output:IN_PORT action gets forwarded back to the receiving port

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), action is output to port IN_PORT. Send a matching packet on the data plane via a certain ingress port. Verify the packet gets forwarded to the ingress port.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running Testcase 100.70 Controller")
        ports = openflow_ports(4)
        in_port = ports[0]
        out_ports = ports[1:4]

        #actions = [ofp.action.output(x) for x in out_ports]
        actions=[ofp.action.output(port = ofp.OFPP_IN_PORT, max_len = 128)]
        match = ofp.match([
            ofp.oxm.eth_type(0x0800)
        ])
        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow to forward packets to controller(packet_in)")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to controller")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")
        do_barrier(self.controller)

        pktstr = str(pkt)

        logging.info("Sending packet, expecting output to controller")
        self.dataplane.send(in_port, pktstr)
        verify_packet(self, pktstr, in_port)
