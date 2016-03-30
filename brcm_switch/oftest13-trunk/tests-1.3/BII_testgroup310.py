# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Maple Yip

"""
Test suite 310 verifies the correct implementation of the fields contained in each of the following message structs
ofp_desc, ofp_flow_stats_request, ofp_flow_stats, ofp_aggregate_stats_request, and ofp_aggregate_stats_reply.

To satisfy the basic requirements an OpenFlow enabled device must pass 310.10 - 310.80, 310.100 - 310.110, 310.130 
- 310.200, 310.230 - 310.260, and 310.280 - 310.330.
"""

import logging
import time
import sys

import unittest
import random
from oftest import config
import oftest.controller as controller
import ofp
import oftest.dataplane as dataplane
import oftest.parse as parse
import oftest.base_tests as base_tests
import oftest.illegal_message as illegal_message
import BII_testgroup300
import BII_testgroup310
import BII_testgroup40


from oftest.oflog import *
from oftest.testutils import *
from time import sleep
"""
class Testcase_310_10_MultipartManufacturerDescription(BII_testgroup40.Testcase_40_170_ManufacturerDescription):
    """"""
    Tested in 40.170
    310.10 - Manufacturer description
    Verify the information about the switch manufacturer is available from the OFPMP_DESC multipart reply message
    """"""



class Testcase_310_20_MultipartHWDescription(BII_testgroup40.Testcase_40_180_HWDescription):
    """"""
    Tested in 40.180
    310.20 - Hardware description
    Verify the information about the switch hardware revision is available from the OFPMP_DESC multipart reply message
    """"""



class Testcase_310_30_MultipartSoftwareDescription(BII_testgroup40.Testcase_40_190_SoftwareDescription):
    """"""
    Tested in 40.190
    310.30 - Software description
    Verify the information about the switch software revision is available from the OFPMP_DESC multipart reply message
    """"""



class Testcase_310_40_MultipartSNDescription(BII_testgroup40.Testcase_40_200_SNDescription):
    """"""
    Tested in 40.200
    310.40 - Serial number
    Verify the information about the switch serial number is available from the OFPMP_DESC multipart reply message
    """"""



class Testcase_310_50_MultipartDPDescription(BII_testgroup40.Testcase_40_210_DPDescription):
    """"""
    Tested in 40.210
    310.50 - Datapath description
    Verify the information about the switch description of datapath is available from the OFPMP_DESC multipart reply message
    """



class Testcase_310_60_MultipartFlowStats(base_tests.SimpleDataPlane):
    """
    Tested in 300.140
    310.60 - Flow statistics
    Verify the switch can reply to the OFPMP_FLOW multipart request.
    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running 300.140 - Multipart type flow statistics test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port1, in_port2, in_port3, out_port, = openflow_ports(4)
        table_id=0
        priority=100
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port1)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow 1")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 1")
        
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port2)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow 2")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 2")

        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port3)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority) 
        logging.info("Insert flow 3")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 3") 

        stats = get_flow_stats(self,match=ofp.match())
        self.assertEqual(len(stats), 3, "Incorrect flow stats.")
        logging.info("Received multipart reply as expected")



class Testcase_310_70_MultipartFlowStatsTableID(base_tests.SimpleDataPlane):
    """
    310.70 - Flow statistics table id
    Verify the switch can reply to the OFPMP_FLOW multipart request,according to the table_id field.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 310.70 - Flow statistics table id test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port, = openflow_ports(2)
        
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        tables_no = reply.n_tables
  
        table_id = test_param_get("table",0)
        priority=100
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow 1")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")
                 
        stats = get_flow_stats(self,table_id=table_id,match=req.match)
        self.assertEqual(len(stats), 1, "Incorrect flow stats.")
        self.assertEqual(stats[0].table_id,table_id, "Incorrect table ID")
        logging.info("Received multipart reply as expected")
        stats = get_flow_stats(self,table_id=ofp.const.OFPTT_ALL,match=req.match)
        self.assertEqual(len(stats), 1, "Incorrect flow stats.")
        self.assertEqual(stats[0].table_id, table_id, "Incorrect table id.") 
        logging.info("Received multipart reply as expected")
        stats = get_flow_stats(self,table_id=tables_no-1,match=req.match)
        self.assertEqual(len(stats), 0, "Incorrect flow stats.")
        logging.info("Received multipart reply as expected")



class Testcase_310_80_MultipartFlowStatsOutport(base_tests.SimpleDataPlane):
    """
    310.80 - Flow statistics out port
    Verify the switch can reply to the OFPMP_FLOW multipart request, according to the out_port field.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 310.80 - Flow statistics out port test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        port1,port2,port3,port4, = openflow_ports(4)
        table_id=0
        priority=100
        actions=[ofp.action.output(port=port3, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(port1)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow 1")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 1")

        actions=[ofp.action.output(port=port4, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(port2)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow 2")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 2")

        actions=[ofp.action.output(port=port3, max_len=128),ofp.action.output(port=port4, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(port3)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow 3")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 3")

        pkt = str(simple_tcp_packet())
        logging.info("Sending a packet to match on port %s.", port1)
        self.dataplane.send(port1, pkt)
        verify_packet(self, pkt, port3)

        logging.info("Sending a packet to match on port %s.", port2)
        self.dataplane.send(port2, pkt)
        verify_packet(self, pkt, port4)

        logging.info("Sending a packet to match on port %s.", port3)
        self.dataplane.send(port3, pkt)
        verify_packet(self, pkt, port4)

        stats = get_flow_stats(self,table_id=table_id,match=ofp.match(),out_port=ofp.const.OFPP_ANY)
        self.assertEqual(len(stats), 3 , "Incorrect flow stats")
        logging.info("Received multipart reply as expected")
        sleep(2)
        stats = get_flow_stats(self,table_id=table_id,match=ofp.match(),out_port=port4)
        self.assertEqual(len(stats), 2 ,"Incorrect flow stats")
        logging.info("Received multipart reply as expected")



class Testcase_310_100_MultipartFlowStatsCookie(base_tests.SimpleDataPlane):
    """
    310.100 - Flow statistics cookie
    Verify the switch can reply to the OFPMP_FLOW multipart request, according to the cookie field.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 310.100 - Flow statistics cookie test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port1, in_port2, out_port, = openflow_ports(3)
        table_id=0
        priority=100
        cookie1=1
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port1)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               cookie=cookie1,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow 1")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 1")

        cookie2=2
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port2)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               cookie=cookie2,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow 2")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 2")
        
        cookie_mask=0xffffffffffffffff
        stats = get_flow_stats(self,table_id=table_id,match=ofp.match(),cookie=cookie1,cookie_mask=cookie_mask)
        self.assertEqual(len(stats), 1, "Incorrect flow stats.")
        self.assertEqual(stats[0].cookie,cookie1, "Incorrect cookie")
        logging.info("Received multipart reply as expected")



class Testcase_310_110_MultipartFlowStatsCookieMask(base_tests.SimpleDataPlane):
    """
    310.110 - Flow statistics cookie mask
    Verify the switch can reply to the OFPMP_FLOW multipart request,according to the cookie_mask field.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 310.110 - Flow statistics cookie mask test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port1, in_port2, in_port3, out_port, = openflow_ports(4)
        table_id=0
        priority=100
        cookie1=1
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port1)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               cookie=cookie1,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow 1")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 1")

        cookie2=2
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port2)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               cookie=cookie2,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow 2")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 2")
        
        cookie3=3
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port3)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               cookie=cookie3,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow 3")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 3")

        cookie_mask=0xfffffffffffffffe
        cookie_list=[cookie2, cookie3]
        stats = get_flow_stats(self,table_id=table_id,match=ofp.match(),cookie=cookie2,cookie_mask=cookie_mask)
        self.assertEqual(len(stats), 2, "Incorrect flow stats.")
        self.assertIn(stats[0].cookie,cookie_list, "Incorrect cookie")
        cookie_list.remove(stats[0].cookie)
        self.assertIn(stats[1].cookie,cookie_list, "Incorrect cookie")
        logging.info("Received multipart reply as expected")


"""
class Testcase_310_130_MultipartFlowStatsTableIDField(BII_testgroup310.Testcase_310_70_MultipartFlowStatsTableID):
    """"""
    Tested in 310.70
    310.130 - Flow statistics table id field
    Verify the switch can send the OFPMP_FLOW multipart reply with the right table_id field.
    """"""



class Testcase_310_140_MultipartFlowStatsDuration(base_tests.SimpleDataPlane):
    """"""
    310.140 - Flow statistics duration
    Verify the switch can send the OFPMP_FLOW multipart reply with the right duration_sec field.
    

    @wireshark_capture
    def runTest(self):
        logging.info("Running 310.140 - Flow statistics duration test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port, = openflow_ports(2)
        table_id=0
        priority=100
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")
        
        time.sleep(2)
        stats = get_flow_stats(self,table_id=table_id,match=req.match)
        self.assertEqual(len(stats), 1, "Incorrect flow stats.")
        self.assertNotEqual(stats[0].duration_sec,0, "Invalid duration")
        logging.info("Received multipart reply as expected")
"""


class Testcase_310_150_MultipartFlowStatsNanoDuration(base_tests.SimpleDataPlane):
    """
    310.150 - Flow statistics nano duration
    Verify the switch can send the OFPMP_FLOW multipart reply with the right duration_nsec field.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 310.150 - Flow statistics nano duration test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port, = openflow_ports(2)
        table_id=0
        priority=100
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")
        
        time.sleep(2)
        for i in range(5):
            stats = get_flow_stats(self,table_id=table_id,match=req.match)
            self.assertEqual(len(stats), 1, "Incorrect flow stats.")
            if i==0 :
                duration_sec=stats[0].duration_sec
                duration_nsec=stats[0].duration_nsec
            else:
                if stats[0].duration_sec == duration_sec:
                    self.assertTrue(stats[0].duration_nsec > duration_nsec, "Invalid duration nsec")
                else:
                    self.assertTrue(stats[0].duration_nsec < duration_nsec, "Invalid duration nsec")
            duration_sec=stats[0].duration_sec
            duration_nsec=stats[0].duration_nsec
            logging.info("Received multipart reply as expected")
            time.sleep(0.1)



class Testcase_310_160_MultipartFlowStatsPriority(base_tests.SimpleDataPlane):
    """
    310.160 - Flow statistics priority
    Verify the switch can send the OFPMP_FLOW multipart reply with the right priority field.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 310.160 - Flow statistics priority test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port, = openflow_ports(2)
        table_id=0
        priority=100
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")
        
        time.sleep(2)
        stats = get_flow_stats(self,table_id=table_id,match=req.match)
        self.assertEqual(len(stats), 1, "Incorrect flow stats.")
        self.assertEqual(stats[0].priority,priority, "Incorrect priority")
        logging.info("Received multipart reply as expected")



class Testcase_310_170_MultipartFlowStatsIdleTimeout(base_tests.SimpleDataPlane):
    """
    310.170 - Flow statistics idle timeout
    Verify the switch can send the OFPMP_FLOW multipart reply with the right idle_timeout field.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 310.170 - Flow statistics idle timeout test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port, = openflow_ports(2)
        table_id=0
        priority=100
        hard_timeout=0
        idle_timeout=5
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority,
                               hard_timeout=hard_timeout,
                               idle_timeout=idle_timeout)
        logging.info("Insert flow")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")
        
        time.sleep(2)
        stats = get_flow_stats(self,table_id=table_id,match=req.match)
        self.assertEqual(len(stats), 1, "Incorrect flow stats.")
        self.assertEqual(stats[0].idle_timeout,idle_timeout, "Incorrect idle_timeout")
        logging.info("Received multipart reply as expected")



class Testcase_310_180_MultipartFlowStatsHardTimeout(base_tests.SimpleDataPlane):
    """
    310.180 - Flow statistics hard timeout
    Verify the switch can send the OFPMP_FLOW multipart reply with the right hard_timeout field.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 310.180 - Flow statistics hard timeout test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port, = openflow_ports(2)
        table_id=0
        priority=100
        hard_timeout=5
        idle_timeout=0
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority,
                               hard_timeout=hard_timeout,
                               idle_timeout=idle_timeout)
        logging.info("Insert flow")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")
        
        time.sleep(2)
        stats = get_flow_stats(self,table_id=table_id,match=req.match)
        self.assertEqual(len(stats), 1, "Incorrect flow stats.")
        self.assertEqual(stats[0].hard_timeout,hard_timeout, "Incorrect hard_timeout")
        logging.info("Received multipart reply as expected")



class Testcase_310_190_MultipartFlowStatsFlags(base_tests.SimpleDataPlane):
    """
    310.190 - Flow statistics OFPFF_* flags
    Verify the switch can send the OFPMP_FLOW multipart reply with the right flags field.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 310.190 - Flow statistics OFPFF_* flags test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port, = openflow_ports(2)
        table_id=0
        priority=100
        flags = ofp.const.OFPFF_SEND_FLOW_REM
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority,
                               flags=flags)
        logging.info("Insert flow")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")
        
        time.sleep(2)
        stats = get_flow_stats(self,table_id=table_id,match=req.match)
        self.assertEqual(len(stats), 1, "Incorrect flow stats.")
        self.assertEqual(stats[0].flags,flags, "Incorrect flags")
        logging.info("Received multipart reply as expected")   


"""
class Testcase_310_200_MultipartFlowStatsOpaqueCookie(BII_testgroup310.Testcase_310_110_MultipartFlowStatsCookieMask):
    
    Tested in 310.110
    310.200 - Flow statistics opaque cookie
    Verify the switch can send the OFPMP_FLOW multipart reply with the right cookie field.
    """  



class Testcase_310_230_MultipartFlowStatsMatch(base_tests.SimpleDataPlane):
    """
    310.230 - Flow statistics match
    Verify the switch can send the OFPMP_FLOW multipart reply with the right match field.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 310.230 - Flow statistics match test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port, = openflow_ports(2)
        table_id=0
        priority=100
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")
        
        time.sleep(2)
        stats = get_flow_stats(self,table_id=table_id,match=req.match)
        self.assertEqual(len(stats), 1, "Incorrect flow stats.")
        self.assertEqual(stats[0].match,req.match, "Incorrect match")
        logging.info("Received multipart reply as expected") 



class Testcase_310_240_MultipartAggStats(base_tests.SimpleDataPlane):
    """
    310.240 - Aggregate statistics
    verify the switch can reply to the OFPMP_AGGREGATE multipart request.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 310.240 - Aggregate statistics test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port, = openflow_ports(2)
        table_id=0
        priority=100
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")
        
        time.sleep(2)
        request = ofp.message.aggregate_stats_request(table_id=table_id,match=ofp.match())
        reply, _=self.controller.transact(request)
        self.assertEqual(reply.type, ofp.const.OFPT_STATS_REPLY, "Type of multipart reply is not correct")
        logging.info("Received multipart reply as expected") 



class Testcase_310_250_MultipartAggStatsTableID(base_tests.SimpleDataPlane):
    """
    310.250 - Aggregate statistics table id
    Verify the switch can reply to the OFPMP_AGGREGATE multipart request,according to the table_id field.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 310.250 - Aggregate statistics table id test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        tables_no = reply.n_tables

        in_port, out_port, = openflow_ports(2)
        
        table_id = test_param_get("table",0)
        priority=100
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")
        
        time.sleep(2)
        request = ofp.message.aggregate_stats_request(table_id=0,match=ofp.match(),out_port=ofp.OFPP_ANY,out_group=ofp.OFPG_ANY)
        reply, _=self.controller.transact(request)
        self.assertEqual(reply.flow_count,1, "Incorrect flow_stats entry")
        logging.info("Received multipart reply as expected") 
        request = ofp.message.aggregate_stats_request(table_id=ofp.const.OFPTT_ALL,match=ofp.match(),out_port=ofp.OFPP_ANY,out_group=ofp.OFPG_ANY)
        reply, _=self.controller.transact(request)
        self.assertEqual(reply.flow_count,1, "Incorrect flow_stats entry")
        logging.info("Received multipart reply as expected") 
        request = ofp.message.aggregate_stats_request(table_id=tables_no-1,match=ofp.match(),out_port=ofp.OFPP_ANY,out_group=ofp.OFPG_ANY)
        reply, _=self.controller.transact(request)
        self.assertEqual(reply.flow_count,0, "Incorrect flow_stats entry")
        logging.info("Received multipart reply as expected") 


class Testcase_310_260_MultipartAggStatsOutport(base_tests.SimpleDataPlane):
    """
    310.260 - Aggregate statistics outport
    Verify the switch can reply to the OFPMP_AGGREGATE multipart request, according to the out_port field.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 310.260 - Aggregate statistics outport test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        port1, port2, port3, port4, = openflow_ports(4)
        table_id=test_param_get("table", 0)
        priority=100
        actions=[ofp.action.output(port=port2, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(port1)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow 1")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 1")

        actions=[ofp.action.output(port=port4, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(port2)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow 2")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 2") 
        
        actions=[ofp.action.output(port=port2, max_len=128),ofp.action.output(port=port4, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        match = ofp.match([ofp.oxm.in_port(port3)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow 3")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 3") 
        
        pkt = simple_tcp_packet()
        strpkt=str(pkt)
        self.dataplane.send(port1, strpkt)
        verify_packets(self, strpkt,[port2])
        logging.info("Received packet on outport %d", port3)
        self.dataplane.send(port2, strpkt)
        verify_packets(self, strpkt,[port4])
        logging.info("Received packet on outport %d", port3)
        self.dataplane.send(port3, strpkt)
        verify_packets(self, strpkt,[port2,port4])
        logging.info("Received packet on outport")
        
        time.sleep(2)
        request = ofp.message.aggregate_stats_request(table_id=table_id,match=ofp.match(),out_port=port2,out_group=ofp.OFPG_ANY)
        reply, _=self.controller.transact(request)
        self.assertEqual(reply.flow_count,2, "Incorrect flow_stats entry")
        logging.info("Received multipart reply as expected") 
        request = ofp.message.aggregate_stats_request(table_id=table_id,match=ofp.match(),out_port=ofp.OFPP_ANY,out_group=ofp.OFPG_ANY)
        reply, _=self.controller.transact(request)
        self.assertEqual(reply.flow_count,3, "Incorrect flow_stats entry")
        logging.info("Received multipart reply as expected") 



class Testcase_310_280_MultipartAggStatsCookie(base_tests.SimpleDataPlane):
    """
    310.280 - Aggregate statistics cookie
    Verify the switch can reply to the OFPMP_AGGREGATE multipart request, according to the cookie field.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 310.280 - Aggregate statistics cookie test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port1, out_port2, = openflow_ports(3)
        table_id=0
        priority=100
        cookie1 = 1
        actions=[ofp.action.output(port=out_port1, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority,
                               cookie=cookie1)
        logging.info("Insert flow 1")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 1")

        priority=200
        cookie2 = 2
        actions=[ofp.action.output(port=out_port2, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority,
                               cookie=cookie2)
        logging.info("Insert flow 2")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 2") 
        
        time.sleep(5)
        cookie_mask = 0xffffffffffffffff
        request = ofp.message.aggregate_stats_request(table_id=table_id,match=ofp.match(),cookie=cookie1,cookie_mask=cookie_mask,out_port=ofp.OFPP_ANY,out_group=ofp.OFPG_ANY)
        reply, _=self.controller.transact(request)
        self.assertEqual(reply.flow_count,1, "Incorrect flow_stats entry")
        logging.info("Received multipart reply as expected") 



class Testcase_310_290_MultipartAggStatsCookieMask(base_tests.SimpleDataPlane):
    """
    310.290 - Aggregate statistics cookie mask
    Verify the switch can reply to the OFPMP_AGGREGATE multipart request,according to the cookie_mask field.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 310.290 - Aggregate statistics cookie mask test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port1, out_port2, out_port3, = openflow_ports(4)
        table_id=0
        priority=100
        cookie1 = 1
        actions=[ofp.action.output(port=out_port1, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority,
                               cookie=cookie1)
        logging.info("Insert flow 1")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 1")

        priority=200
        cookie2 = 2
        actions=[ofp.action.output(port=out_port2, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority,
                               cookie=cookie2)
        logging.info("Insert flow 2")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 2") 

        priority=300
        cookie3 = 3
        actions=[ofp.action.output(port=out_port3, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority,
                               cookie=cookie3)
        logging.info("Insert flow 2")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow 2") 
        
        time.sleep(2)
        cookie_mask = 0xfffffffffffffffe
        request = ofp.message.aggregate_stats_request(table_id=table_id,match=ofp.match(),cookie=cookie2,cookie_mask=cookie_mask,out_port=ofp.OFPP_ANY,out_group=ofp.OFPG_ANY)
        reply, _=self.controller.transact(request)
        self.assertEqual(reply.flow_count,2, "Incorrect flow_stats entry")
        logging.info("Received multipart reply as expected")


"""
class Testcase_310_300_MultipartAggStatsReply(BII_testgroup310.Testcase_310_240_MultipartAggStats):
    
    Tested in 310.240
    310.300 - Aggregate statistics reply
    Verify the switch can send the OFPMP_AGGREGATE multipart reply.
    """



class Testcase_310_310_MultipartAggStatsPacketCount(base_tests.SimpleDataPlane):
    """
    310.310 - Aggregate statistics packet count
    Verify the switch can send the OFPMP_AGGREGATE multipart reply with the right packet_count field.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 310.310 - Aggregate statistics packet count test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port, = openflow_ports(2)
        table_id=0
        priority=100
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")

        pkt= str(simple_tcp_packet())        
        for i in range(5):
            logging.info("Sending a dataplane packet")
            self.dataplane.send(in_port,pkt)
            print "ready to send packet to port %d" % in_port
            time.sleep(5)
            verify_packet(self,pkt,out_port)
        
        time.sleep(2)
        request = ofp.message.aggregate_stats_request(table_id=table_id,match=ofp.match(),out_port=ofp.OFPP_ANY,out_group=ofp.OFPG_ANY)
        reply, _=self.controller.transact(request)
        self.assertEqual(reply.packet_count,5, "Incorrect packet_count")
        logging.info("Received multipart reply as expected")



class Testcase_310_320_MultipartAggStatsByteCount(base_tests.SimpleDataPlane):
    """
    310.320 - Aggregate statistics byte count
    Verify the switch can send the OFPMP_AGGREGATE multipart reply with the right byte_count field.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 310.320 - Aggregate statistics byte count test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port, = openflow_ports(2)
        table_id=0
        priority=100
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")

        pkt= str(simple_tcp_packet())        
        for i in range(5):
            logging.info("Sending a dataplane packet")
            self.dataplane.send(in_port,pkt)
            verify_packet(self,pkt,out_port)
        
        time.sleep(2)
        request = ofp.message.aggregate_stats_request(table_id=table_id,match=ofp.match(),out_port=ofp.OFPP_ANY,out_group=ofp.OFPG_ANY)
        reply, _=self.controller.transact(request)
        self.assertEqual(reply.byte_count,500, "Incorrect byte_count")
        logging.info("Received multipart reply as expected") 



class Testcase_310_330_MultipartAggStatsFlowCount(base_tests.SimpleDataPlane):
    """
    310.330 - Aggregate statistics flow count
    Verify the switch can send the OFPMP_AGGREGATE multipart reply with the right flow_count field.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 310.330 - Aggregate statistics flow count test")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        in_port, out_port, = openflow_ports(2)
        table_id=0
        priority=100
        actions=[ofp.action.output(port=out_port, max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
       	match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id=table_id,
                               match= match,
                               buffer_id=ofp.OFP_NO_BUFFER,
                               instructions=instructions,
                               priority=priority)
        logging.info("Insert flow")
        rv = self.controller.message_send(req)
        self.assertTrue(rv != -1, "Failed to insert flow")
        
        time.sleep(2)
        request = ofp.message.aggregate_stats_request(table_id=table_id,match=ofp.match(),out_port=ofp.OFPP_ANY,out_group=ofp.OFPG_ANY)
        reply, _=self.controller.transact(request)
        self.assertEqual(reply.flow_count,1, "Incorrect flow_count")
        logging.info("Received multipart reply as expected") 
