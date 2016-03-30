# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Maple Yip

"""
Test suite 340 verifies the correct implementation of the fields contained in each of the following message 
structs; ofp_port_stats_request, ofp_port_stats, and ofp_port.

To satisfy the basic requirements an OpenFlow enabled device must pass 340.20, 340.40 - 340.180, 340.200, 
340.220, and 340.240 - 340.320.
"""

import logging
import time
import sys
import os

import unittest
import random
from oftest import config
import oftest.controller as controller
import ofp
import oftest.dataplane as dataplane
import oftest.parse as parse
import oftest.base_tests as base_tests
import oftest.illegal_message as illegal_message
import BII_testgroup100


from oftest.oflog import *
from oftest.testutils import *
from time import sleep


class Testcase_340_20_MultipartPortFilter(base_tests.SimpleDataPlane):
    """
    340.20 - Port filter reserved
    The port_no field optionally filters the stats request to the given port. To request all port statistics, 
    port_no must be set to OFPP_ANY. The response is reported in ofp_port_stats structs.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.20 - Port filter reserved test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.port_stats_request(port_no=ofp.const.OFPP_ANY)
        stats = get_stats(self, request)
        self.assertTrue(len(stats) >= 4, "Reported ports in port stats is not correct")

        for port in openflow_ports(4):
            request = ofp.message.port_stats_request(port_no=port)
            stats = get_stats(self, request)
            self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(port))

        logging.info("Reported ports in port stats is correct")



class Testcase_340_40_MultipartPortFilterStandard(base_tests.SimpleDataPlane):
    """
    340.40 - Port filter standard
    Verify the port_no field optionally filters the stats request to the given port.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.40 - Port filter standard test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.port_stats_request(port_no=ofp.const.OFPP_ANY)
        stats = get_stats(self, request)
        self.assertTrue(len(stats) >= 4, "Reported ports in port stats is not correct")

        for port in openflow_ports(4):
            request = ofp.message.port_stats_request(port_no=port)
            stats = get_stats(self, request)
            self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(port))
            self.assertEqual(stats[0].port_no, port, "Received port_no %d in port stats is not correct"%(port))

        logging.info("Reported port_no in port stats is correct")



class Testcase_340_50_MultipartPortStatsRxPackets(base_tests.SimpleDataPlane):
    """
    340.50 - Received packets
    Verify that the received packets counter increments correctly.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.50 - Received packets test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        port, = openflow_ports(1)
        pkt_no = 5

        request = ofp.message.port_stats_request(port_no=port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(port))
        init_rx_pkt = stats[0].rx_packets

        pkt = str(simple_tcp_packet())
        for i in range(pkt_no):
            self.dataplane.send(port,pkt)

        time.sleep(2)
        request = ofp.message.port_stats_request(port_no=port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(port))
        self.assertEqual(stats[0].rx_packets-init_rx_pkt, pkt_no, "Received packets in port stats is not correct")
        logging.info("Reported received packets in port stats is correct")



class Testcase_340_60_MultipartPortStatsTxPackets(base_tests.SimpleDataPlane):
    """
    340.60 - Transmitted packets
    Verify that the transmitted packets counter increments correctly.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.60 - Transmitted packets test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port, = openflow_ports(2)
        pkt_no = 5

        table_id=0
        priority = 100
        actions=[ofp.action.output(port=out_port,max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        request = ofp.message.flow_add(table_id=table_id,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   match=match,
                                   instructions=instructions,
                                   priority=priority)
        logging.info("Installing a flow")
        self.controller.message_send(request)
        verify_no_errors(self.controller)

        request = ofp.message.port_stats_request(port_no=out_port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(out_port))
        init_tx_pkt = stats[0].tx_packets

        pkt = str(simple_tcp_packet())
        for i in range(pkt_no):
            self.dataplane.send(in_port,pkt)

        time.sleep(2)
        request = ofp.message.port_stats_request(port_no=out_port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(out_port))
        if stats[0].tx_packets==0xffffffffffffffff:
            logging.warn("Transmitted packets counter is not supported")
        else:
            self.assertEqual(stats[0].tx_packets-init_tx_pkt, pkt_no, "Transmitted packets in port stats is not correct")
            logging.info("Reported transmitted packets in port stats is correct")



class Testcase_340_70_MultipartPortStatsRxBytes(base_tests.SimpleDataPlane):
    """
    340.70 - Received bytes
    Verify that the received packets counter increments correctly.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.70 - Received bytes test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        port, = openflow_ports(1)
        pkt_no = 5

        request = ofp.message.port_stats_request(port_no=port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(port))
        init_rx_bytes = stats[0].rx_bytes

        pkt = str(simple_tcp_packet())
        for i in range(pkt_no):
            self.dataplane.send(port,pkt)

        time.sleep(2)
        request = ofp.message.port_stats_request(port_no=port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(port))
        self.assertEqual(stats[0].rx_bytes-init_rx_bytes, pkt_no*100, "Received bytes in port stats is not correct")
        logging.info("Reported received bytes in port stats is correct")



class Testcase_340_80_MultipartPortStatsTxBytes(base_tests.SimpleDataPlane):
    """
    340.80 - Transmitted bytes
    Verify that the transmitted bytes counter increments correctly.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.80 - Transmitted bytes test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port, = openflow_ports(2)
        pkt_no = 5

        table_id=0
        priority = 100
        actions=[ofp.action.output(port=out_port,max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        request = ofp.message.flow_add(table_id=table_id,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   match=match,
                                   instructions=instructions,
                                   priority=priority)
        logging.info("Installing a flow")
        self.controller.message_send(request)
        verify_no_errors(self.controller)

        request = ofp.message.port_stats_request(port_no=out_port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(out_port))
        init_tx_bytes = stats[0].tx_bytes

        pkt = str(simple_tcp_packet())
        for i in range(pkt_no):
            self.dataplane.send(in_port,pkt)

        time.sleep(2)
        request = ofp.message.port_stats_request(port_no=out_port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(out_port))
        if stats[0].tx_bytes==0xffffffffffffffff:
            logging.warn("Transmitted bytes counter is not supported")
        else:
            self.assertEqual(stats[0].tx_bytes-init_tx_bytes, pkt_no*100, "Transmitted bytes in port stats is not correct")
            logging.info("Reported transmitted bytes in port stats is correct")



class Testcase_340_90_MultipartPortStatsRxDropped(base_tests.SimpleDataPlane):
    """
    340.90 - Received dropped
    Verify that the received drops counter increments correctly.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.90 - Received dropped test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        port, = openflow_ports(1)
        pkt_no = 5

        config = 4
        mask= ofp.OFPPC_NO_RECV
        self.controller.clear_queue()
        port_config_set(self.controller, port_no=port, config=config, mask=mask)
        reply, pkt = self.controller.poll(exp_msg=ofp.OFPT_ERROR)
        self.assertIsNone(reply, "Received OFPT_ERROR.port_mod failed")
        logging.info("Configuring port to OFPPC_NO_RECV")

        request = ofp.message.port_stats_request(port_no=port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(port))
        init_rx_dropped = stats[0].rx_dropped

        pkt = str(simple_tcp_packet())
        for i in range(pkt_no):
            self.dataplane.send(port,pkt)

        time.sleep(2)
        request = ofp.message.port_stats_request(port_no=port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(port))
        if stats[0].rx_dropped==0xffffffffffffffff:
            logging.warn("Rx_dropped counter is not supported")
        else:
            self.assertEqual(stats[0].rx_dropped-init_rx_dropped, pkt_no, "Received dropped in port stats is not correct")
            logging.info("Reported received dropped in port stats is correct")



class Testcase_340_100_MultipartPortStatsTxDropped(base_tests.SimpleDataPlane):
    """
    340.100 - Transmitted dropped
    Verify that the transmitted drops counter increments correctly.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.100 - Transmitted dropped test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        port, in_port= openflow_ports(2)
        pkt_no = 5

        config = 32
        mask= ofp.OFPPC_NO_FWD
        self.controller.clear_queue()
        port_config_set(self.controller, port_no=port, config=config, mask=mask)
        reply, pkt = self.controller.poll(exp_msg=ofp.OFPT_ERROR)
        self.assertIsNone(reply, "Received OFPT_ERROR.port_mod failed")
        logging.info("Configuring port to OFPPC_NO_RECV")

        table_id=0
        priority = 100
        actions=[ofp.action.output(port=port,max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        request = ofp.message.flow_add(table_id=table_id,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   match=match,
                                   instructions=instructions,
                                   priority=priority)
        logging.info("Installing a flow")
        self.controller.message_send(request)
        verify_no_errors(self.controller)

        request = ofp.message.port_stats_request(port_no=port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(port))
        init_tx_dropped = stats[0].tx_dropped

        pkt = str(simple_tcp_packet())
        for i in range(pkt_no):
            self.dataplane.send(in_port,pkt)

        time.sleep(2)
        request = ofp.message.port_stats_request(port_no=port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(port))
        if stats[0].tx_dropped==0xffffffffffffffff:
            logging.warn("tx_dropped counter is not supported")
        else:
            self.assertEqual(stats[0].tx_dropped-init_tx_dropped, pkt_no, "Tx_dropped in port stats is not correct")
            logging.info("Reported tx_dropped in port stats is correct")


class Testcase_340_110_MultipartPortStatsRxErrors(base_tests.SimpleDataPlane):
    """
    340.110 - Received errors
    Verify that the received errors counter increments correctly.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.110 - Received errors test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        port, = openflow_ports(1)

        request = ofp.message.port_stats_request(port_no=port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(port))
        if stats[0].rx_errors==0xffffffffffffffff:
            logging.warn("rx_errors counter is not supported")
        else:
            logging.info("Received Rx_errors is %d", stats[0].rx_errors)



class Testcase_340_120_MultipartPortStatsTxErrors(base_tests.SimpleDataPlane):
    """
    340.120 - Transmitted errors
    Verify that the transmitted errors counter increments correctly.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.120 - Transmitted errors test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        port, = openflow_ports(1)

        request = ofp.message.port_stats_request(port_no=port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(port))
        if stats[0].tx_errors==0xffffffffffffffff:
            logging.warn("tx_errors counter is not supported")
        else:
            logging.info("Received tx_errors is %d", stats[0].tx_errors)



class Testcase_340_130_MultipartPortStatsRxFrameErrors(base_tests.SimpleDataPlane):
    """
    340.130 - Received frame errors
    Verify that the received frame alignment errors counter increments correctly.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.130 - Received frame errors test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        port, = openflow_ports(1)

        request = ofp.message.port_stats_request(port_no=port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(port))
        if stats[0].rx_frame_err==0xffffffffffffffff:
            logging.warn("rx_frame_err counter is not supported")
        else:
            logging.info("Received rx_frame_err is %d", stats[0].rx_frame_err)



class Testcase_340_140_MultipartPortStatsRxOverrunErrors(base_tests.SimpleDataPlane):
    """
    340.140 - Received overrun errors
    Verify that the received overrun errors counter increments correctly.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.140 - Received overrun errors test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        port, = openflow_ports(1)

        request = ofp.message.port_stats_request(port_no=port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(port))
        if stats[0].rx_over_err==0xffffffffffffffff:
            logging.warn("rx_over_err counter is not supported")
        else:
            logging.info("Received rx_over_err is %d", stats[0].rx_over_err)



class Testcase_340_150_MultipartPortStatsRxCRCErrors(base_tests.SimpleDataPlane):
    """
    340.150 - Received CRC errors
    Verify that the received CRC errors counter increments correctly.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.150 - Received CRC errors test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        port, = openflow_ports(1)

        request = ofp.message.port_stats_request(port_no=port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(port))
        if stats[0].rx_crc_err==0xffffffffffffffff:
            logging.warn("rx_crc_err counter is not supported")
        else:
            logging.info("Received rx_crc_err is %d", stats[0].rx_crc_err)



class Testcase_340_160_MultipartPortStatsCollisionErrors(base_tests.SimpleDataPlane):
    """
    340.160 - Collision errors
    Verify that the collisions counter increments correctly.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.160 - Collision errors test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        port, = openflow_ports(1)

        request = ofp.message.port_stats_request(port_no=port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(port))
        if stats[0].collisions==0xffffffffffffffff:
            logging.warn("collisions counter is not supported")
        else:
            logging.info("Received collisions is %d", stats[0].collisions)



class Testcase_340_170_MultipartPortStatsDurationSec(base_tests.SimpleDataPlane):
    """
    340.170 - Port duration in seconds
    Verify that the duration in seconds counter increments correctly.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.170 - Port duration in seconds test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        port, = openflow_ports(1)

        request = ofp.message.port_stats_request(port_no=port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(port))
        duration_sec_orig=stats[0].duration_sec

        time.sleep(2)
        request = ofp.message.port_stats_request(port_no=port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(port))
        duration_sec=stats[0].duration_sec

        if stats[0].duration_sec==0xffffffff:
            logging.warn("duration_sec is not supported")
        else:
            self.assertTrue(duration_sec > duration_sec_orig, "Duration_sec is not increased as expected")

        logging.info("Duration_sec is increased as expected")



class Testcase_340_180_MultipartPortStatsDurationNsec(base_tests.SimpleDataPlane):
    """
    340.180 - Port duration in nanoseconds
    Verify that the duration in nanoseconds counter increments correctly.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.180 - Port duration in nanoseconds test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        port, = openflow_ports(1)

        request = ofp.message.port_stats_request(port_no=port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(port))
        duration_nsec_orig=stats[0].duration_nsec
        duration_sec_orig=stats[0].duration_sec

        request = ofp.message.port_stats_request(port_no=port)
        stats = get_stats(self, request)
        self.assertEqual(len(stats), 1, "Port %d is not reported in port stats" %(port))
        duration_nsec=stats[0].duration_nsec
        duration_sec=stats[0].duration_sec

        if stats[0].duration_nsec==0xffffffff:
            logging.warn("duration_nsec is not supported")
        else:
            self.assertTrue(duration_sec >= duration_sec_orig, "Duration_sec is not increased as expected")  
            if duration_sec == duration_sec_orig:
                self.assertTrue(duration_nsec >= duration_nsec_orig, "Duration_nsec is not increased as expected") 
                logging.info("Duration_nsec is increased as expected")




class Testcase_340_200_MultipartPortDescUniquePort(base_tests.SimpleDataPlane):
    """
    340.200 - Unique port number
    Verify that all ports reported in response to an OFPMP_PORT_DESC have a unique non-negative port number.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.200 - Unique port number test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.port_desc_stats_request()
        stats = get_stats(self, request)
        self.assertTrue(len(stats) >= 4, "Reported ports in port desc is not correct")

        ports=[]
        for item in stats:
            self.assertNotIn(item.port_no, ports, "Reported port_no is not unique")
            ports.append(item.port_no)
        logging.info("Reported ports in port desc is correct")



class Testcase_340_220_MultipartPortDescUniqueHWAddress(base_tests.SimpleDataPlane):
    """
    340.220 - Unique hardware address
    Verify that all ports reported in response to an OFPMP_PORT_DESC have a unique hardware address.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.220 - Unique hardware address test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        port, = openflow_ports(1)
        request = ofp.message.port_desc_stats_request()
        stats = get_stats(self, request)
        self.assertTrue(len(stats) >= 4, "Reported ports in port desc is not correct")

        MAC_Addr=[]
        for item in stats:
            self.assertNotIn(item.hw_addr, MAC_Addr, "Reported HW_Addr is not unique")
            MAC_Addr.append(item.hw_addr)
        logging.info("Reported HW_Addr in port desc is correct")
        
        request = ofp.message.port_mod(port_no=port, hw_addr=MAC_Addr[0])
        self.controller.message_send(request)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        if reply is not None:
            logging.info("Switch did not return an error message")
        else:
            request = ofp.message.port_desc_stats_request()
            stats = get_stats(self, request)
            self.assertEqual(stats[0].hw_addr, MAC_Addr[0], "Reported HW_Addr is changed")
            logging.info("Reported HW_Addr is not changed")

        



class Testcase_340_240_MultipartPortDescPortName(base_tests.SimpleDataPlane):
    """
    340.240 - Port name
    Verify that an OFPMP_PORT_DESC message can be used to set the name field on a port.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.240 - Port name test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.port_desc_stats_request()
        stats = get_stats(self, request)
        self.assertTrue(len(stats) >= 4, "Reported ports in port desc is not correct")

        for item in stats:
            self.assertIsNotNone(item.name, "Reported port_name is none")

        logging.info("Reported port_name in port desc is correct")


"""
class Testcase_340_250_MultipartPortDescSetPortConfig(BII_testgroup100.Testcase_100_60_ALL_OFPPC_NO_FWD):
    
    340.250 - Set port configuration
    Verify that a packet matching a flow with an associated  output:ALL action gets forwarded to all ports except the 
    ingress port and except ports configured for OFPPC_NO_FWD
    """



class Testcase_340_260_MultipartPortDescSetPortState(base_tests.SimpleDataPlane):
    """
    340.260 - Port state
    Verify that each ports' state is correctly reported.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.260 - Port state test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        default_port, = openflow_ports(1)
        print default_port
        
        request = ofp.message.port_desc_stats_request()
        stats = get_stats(self, request)
        self.assertTrue(len(stats) >= 4, "Reported ports in port desc is not correct")

        for item in stats:
            if item.port_no in openflow_ports(4):
                self.assertEqual((item.state & 1),0, "Reported port state is not correct.")
            
        logging.info("Reported port state in port desc is correct")
        
        #Bring down the port by shutting the interface connected 
        try:
            logging.info("Bringing down the interface ..")
            print "Manually bring down the first port"
        
            #Verify Port Status message is recieved with reason-- Port Deleted
            logging.info("Verify PortStatus-Down message is recieved on the control plane ")
            (response, raw) = self.controller.poll(ofp.OFPT_PORT_STATUS, timeout=180)
            self.assertTrue(response is not None,
                        'Port Status Message not generated')
            
            request = ofp.message.port_desc_stats_request()
            stats = get_stats(self, request)
            self.assertTrue(len(stats) >= 4, "Reported ports in port desc is not correct")

            for item in stats:
                if item.port_no in openflow_ports(4):
                    if item.port_no == 304:
                        self.assertEqual((item.state & 1),1, "Reported port state is not correct.")
                    else:
                        self.assertEqual((item.state & 1),0, "Reported port state is not correct.")
                        
        #Bring up the port by starting the interface connected
        finally:
            logging.info("Bringing up the interface ...")
            print "Manually bring up the first port"
            logging.info("Verify PortStatus-Up message is recieved on the control plane ")
            (response, raw) = self.controller.poll(ofp.OFPT_PORT_STATUS, timeout=180)
            self.assertTrue(response is not None,
                        'Port Status Message not generated')



class Testcase_340_270_MultipartPortDescCurrFeatures(base_tests.SimpleDataPlane):
    """
    340.270 - Current features
    Verify that curr is set to the features negotiated on a port's link.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.270 - Current features test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.port_desc_stats_request()
        stats = get_stats(self, request)
        self.assertTrue(len(stats) >= 4, "Reported ports in port desc is not correct")

        for item in stats:
            if item.port_no in openflow_ports(4):
                self.assertEqual(item.curr, 12352, "Reported current features is not correct.") 	#10272
            
        logging.info("Reported current features in port desc is correct")



class Testcase_340_280_MultipartPortDescAdvertisedFeatures(base_tests.SimpleDataPlane):
    """
    340.280 - Advertised features
    Verify that advertised is set to the features configured to be advertised by the device's port.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.280 - Advertised features test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.port_desc_stats_request()
        stats = get_stats(self, request)
        self.assertTrue(len(stats) >= 4, "Reported ports in port desc is not correct")

        for item in stats:
            if item.port_no in openflow_ports(4):
                self.assertEqual(item.advertised, 12352, "Reported advertised features is not correct.")		#2080
            
        logging.info("Reported advertised features in port desc is correct")



class Testcase_340_290_MultipartPortDescSupportedFeatures(base_tests.SimpleDataPlane):
    """
    340.290 - Supported features
    Verify that supported is set to the features supported by the device's port.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.290 - Supported features test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.port_desc_stats_request()
        stats = get_stats(self, request)
        self.assertTrue(len(stats) >= 4, "Reported ports in port desc is not correct")

        for item in stats:
            if item.port_no in openflow_ports(4):
                self.assertEqual(item.supported, 12352, "Reported supported features is not correct.")		#2080

            
        logging.info("Reported supported features in port desc is correct")



class Testcase_340_300_MultipartPortDescPeerFeatures(base_tests.SimpleDataPlane):
    """
    340.300 - Peer's features
    Verify that peer is set to the features advertised by the peer's port.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.300 - Peer's features test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.port_desc_stats_request()
        stats = get_stats(self, request)
        self.assertTrue(len(stats) >= 4, "Reported ports in port desc is not correct")

        for item in stats:
            if item.port_no in openflow_ports(4):
                self.assertEqual(item.peer, 0, "Reported peer features is not correct.")
            
        logging.info("Reported peer features in port desc is correct")



class Testcase_340_310_MultipartPortDescCurrSpeed(base_tests.SimpleDataPlane):
    """
    340.310 - Current bit rate
    Verify the port's current bit rate is correctly reported.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.310 - Current bit rate test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.port_desc_stats_request()
        stats = get_stats(self, request)
        self.assertTrue(len(stats) >= 4, "Reported ports in port desc is not correct")

        for item in stats:
            if item.port_no in openflow_ports(4):
                self.assertTrue((item.curr_speed>=800000) and (item.curr_speed<=1200000), "Reported current speed is not correct.")
            
        logging.info("Reported current speed in port desc is correct")



class Testcase_340_320_MultipartPortDescMaxSpeed(base_tests.SimpleDataPlane):
    """
    340.320 - Max bitrate
    Verify the port's maximum bit rate is correctly reported.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 340.320 - Max bitrate test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        request = ofp.message.port_desc_stats_request()
        stats = get_stats(self, request)
        self.assertTrue(len(stats) >= 4, "Reported ports in port desc is not correct")

        for item in stats:
            if item.port_no in openflow_ports(4):
                self.assertTrue((item.max_speed>=800000) and (item.max_speed<=1200000), "Reported max_speed is not correct.")
            
        logging.info("Reported max_speed in port desc is correct")
