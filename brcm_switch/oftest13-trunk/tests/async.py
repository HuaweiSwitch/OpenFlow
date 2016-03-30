"""
text purpose:        testing set_async_request/get_async_request/get_async_reply
test case number: 8 (otherwise:1 in group.py named AsyncGroupDelNoFlowRemoved)
anthor:                zhaoxiuchu
date:                  2012-12-20
"""

import sys
import logging
import unittest
import random

import oftest.match as match
import oftest.controller as controller
import oftest.cstruct as ofp
import oftest.message as message
import oftest.dataplane as dataplane
import oftest.action as action
import oftest.instruction as instruction
import oftest.parse as parse
from oftest.match_list import match_list

import testutils
from time import sleep
import ipaddr
import basic
import groups

try:
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import *
    load_contrib("mpls")
    #TODO This should really be in scapy!
    bind_layers(MPLS, MPLS, s=0)
except:
    sys.exit("Need to install scapy for packet parsing")

#@var async_port_map Local copy of the configuration map from OF port
# numbers to OS interfaces
async_port_map = None
#@var async_logger Local logger object
async_logger = None
#@var async_config Local copy of global configuration data
async_config = None
OFPFW_ALL = 1023
test_prio = {}



def test_set_init(config):
    """
    Set up function for basic test classes

    @param config The configuration dictionary; see oft
    """

    global async_port_map
    global async_logger
    global async_config

    async_logger = logging.getLogger("async")
    async_logger.info("Initializing test set")
    async_port_map = config["port_map"]
    async_config = config

def create_set_async(**kwargs):
    msg = message.set_async()
    if 'pkt_in_mstr' in kwargs:
        msg.packet_in_mask[0] = kwargs['pkt_in_mstr']
    if 'pkt_in_slv' in kwargs:
        msg.packet_in_mask[1] = kwargs['pkt_in_slv']
    if 'port_st_mstr' in kwargs:
        msg.port_status_mask[0] = kwargs['port_st_mstr']
    if 'port_st_slv' in kwargs:
        msg.port_status_mask[1] = kwargs['port_st_slv']
    if 'flow_rm_mstr' in kwargs:
        msg.flow_removed_mask[0] = kwargs['flow_rm_mstr']
    if 'flow_rm_slv' in kwargs:
        msg.flow_removed_mask[1] = kwargs['flow_rm_slv']
    return msg

def set_async_verify(parent, msg):
    async_logger.info("Sending set_async_request")
    testutils.ofmsg_send(parent, msg)

    #step 2:controller sends get_async_request msg 
    async_logger.info("Sending get_async_request")
    request = message.get_async_request()
    response, _ = parent.controller.transact(request, timeout=2)
    #print(response.show())
    #result 2: contrller receives msg successfully,set==get
    parent.assertTrue(response is not None, "Did not get response")
    async_logger.debug(response.show())
    parent.assertEqual(response.header.type, ofp.OFPT_GET_ASYNC_REPLY,
                     'response is not OFPT_GET_ASYNC_REPLY')
    parent.assertEqual(msg.packet_in_mask, response.packet_in_mask,
                     'request.packet_in_mask != response.packet_in_mask')
    parent.assertEqual(msg.port_status_mask, response.port_status_mask,
                     'request.port_status_mask != response.port_status_mask')
    parent.assertEqual(msg.flow_removed_mask, response.flow_removed_mask,
                     'request.flow_removed_mask != response.flow_removed_mask')

#zhaoxiuchu 20121220---1
class AsyncSet(basic.SimpleProtocol):
    """
    Set async successfully

    1)set_async
    2)get_async_request
    3)get_async_reply
    """
    def runTest(self):
        #async_logger.info("Running AsyncSet")
        msg = create_set_async(pkt_in_mstr = random.randint(0,7),
                                   pkt_in_slv = random.randint(0,7),
                                   port_st_mstr = random.randint(0,7),
                                   port_st_slv = random.randint(0,7),
                                   flow_rm_mstr = random.randint(0,15),
                                   flow_rm_slv = random.randint(0,15))
        set_async_verify(self, msg)

        msg = create_set_async()
        set_async_verify(self, msg)

#zhaoxiuchu  20121220 --2
class AsyncPacketInNoMatch(basic.SimpleDataPlane):
    """
    Test packet in according to async function
 
    Send a packet to each dataplane port and verify that a packet
    in message is received from the controller for each
    """
    def runTest(self):
        #async_logger.info("Running Async_NoPacketIn")

        #verifying without set_async_request, switch will packet in
        #step 1-1:clear all flow entries for unmatching
        of_ports = testutils.clear_switch(self, async_port_map.keys(), async_logger)

        #step 2-1:controller sends set_async_request msg
        async_logger.info("Sending set_async_request")
        mask = 1 << ofp.OFPR_NO_MATCH
        request_set = create_set_async(pkt_in_mstr = mask)
        #print(request_set.show())
        set_async_verify(self, request_set)

        #result 2-1: contrller sends msg successfully
        
        #no match default deal:drop; add flow entry to packet_in
        #step 3-1: install default mismatch flow entry ,action=packetin;
        testutils.set_table_config(self, config = ofp.OFPTC_TABLE_MISS_CONTROLLER)

        #send data to port
        for of_port in of_ports:
            async_logger.info("PKT IN test, port " + str(of_port))
            pkt = testutils.simple_tcp_packet()
            self.dataplane.send(of_port, str(pkt))
            #@todo Check for unexpected messages?
            testutils.packetin_verify(self, pkt)
            #print(response)

        #"verifying with set_async_request, switch will packet in"
        #step 1-2:clear all flow entries for unmatching
        rc = testutils.clear_switch(self, async_port_map.keys(), async_logger)

        #step 2-2:controller sends set_async_request msg
        async_logger.info("Sending set_async_request")
        mask = 0xffffffff ^ (1 << ofp.OFPR_NO_MATCH)
        request_set = create_set_async(pkt_in_mstr = mask)
        set_async_verify(self, request_set)
        #print("2-2 request_set"+request_set.show())
        #result 2-2: contrller sends msg successfully
        
        #no match default deal:drop; add flow entry to packet_in
        #step 3-2: install default mismatch flow entry ,action=packetin;
        testutils.set_table_config(self, config = ofp.OFPTC_TABLE_MISS_CONTROLLER)

        #(response, _) = self.controller.poll(ofp.OFPT_PACKET_IN, 2)
        #send data to port
        for of_port in async_port_map.keys():
            async_logger.info("PKT IN test, port " + str(of_port))
            pkt = testutils.simple_tcp_packet()
            self.dataplane.send(of_port, str(pkt))
            #@todo Check for unexpected messages?
            (response, _) = self.controller.poll(ofp.OFPT_PACKET_IN, 2)
            #print(response)
            self.assertTrue(response is None, 'Packet in message received unexpected')

        msg = create_set_async()
        set_async_verify(self, msg)

#zhaoxiuchu 20121220 --3
class AsyncPacketInAction(basic.SimpleDataPlane):
    """
    Test: flow entry includes action(packetin)
          set_async_request to tell switch not to packet in 
          result: switch does't packet in
 
    Send a packet to each dataplane port and verify that a packet
    in message is received from the controller for each
    """
    def runTest(self):
        #async_logger.info("Running Action_NoPacketIn")
        
        #"verifying without set_async_request, switch will packet in"
        #step 1-1:clear all flow entries for unmatching
        rc = testutils.delete_all_flows(self.controller, async_logger)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        #step 2-1:controller sends set_async_request msg
        async_logger.info("Sending set_async_request")
        mask = 1 << ofp.OFPR_ACTION
        request_set = create_set_async(pkt_in_mstr = mask)
        testutils.ofmsg_send(self, request_set)

        #result 2-1: contrller sends msg successfully
        
        #step 3-1: install default match flow entry ,action=packetin;
        testutils.set_table_config(self)
        pkt = testutils.simple_icmp_packet()
        flow_add = testutils.flow_msg_create(self, pkt,
                            egr_port = ofp.OFPP_CONTROLLER, table_id = testutils.EX_ICMP_TABLE)
        testutils.flow_msg_install(self, flow_add)
        
        #send data to port
        for of_port in async_port_map.keys():
            async_logger.info("PKT IN test, port " + str(of_port))
            self.dataplane.send(of_port, str(pkt))
            #@todo Check for unexpected messages?
            (response, _) = self.controller.poll(ofp.OFPT_PACKET_IN, 2)
            self.assertTrue(response is not None, 
                            'Packet in message not received')
        (response, _) = self.controller.poll(ofp.OFPT_PACKET_IN, 2)

        #"verifying with set_async_request, switch will not packet in"
        #step 1-2:clear all flow entries for unmatching
        rc = testutils.delete_all_flows(self.controller, async_logger)
        self.assertEqual(rc, 0, "Failed to delete all flows")
        
        #step 2-2:controller sends set_async_request msg
        async_logger.info("Sending set_async_request")
        mask = 0xffffffff ^ (1 << ofp.OFPR_ACTION)
        request_set = create_set_async(pkt_in_mstr = mask)
        testutils.ofmsg_send(self, request_set)
        #result 2-2: contrller sends msg successfully
        
        #step 3-2: install default match flow entry ,action=packetin;
        testutils.set_table_config(self)
        pkt = testutils.simple_icmp_packet()
        flow_add = testutils.flow_msg_create(self, pkt,
                            egr_port = ofp.OFPP_CONTROLLER, table_id = testutils.EX_ICMP_TABLE)
        testutils.flow_msg_install(self, flow_add)

        (response, _) = self.controller.poll(ofp.OFPT_PACKET_IN, 2)
        #send data to port
        for of_port in async_port_map.keys():
            async_logger.info("PKT IN test, port " + str(of_port))
            self.dataplane.send(of_port, str(pkt))
            #@todo Check for unexpected messages?
            (response, _) = self.controller.poll(ofp.OFPT_PACKET_IN, 2)
            #print(response)
            self.assertTrue(response is None, 
                            'Packet in message received unexpected')
        msg = create_set_async()
        set_async_verify(self, msg)

#zhaoxiuchu 20121220 --4
class AsyncPacketInInvalidTTL(basic.SimpleDataPlane):
    """
    Test packet in according to async function
 
    Send a packet to each dataplane port and verify that a packet
    in message is received from the controller for each
    """
    def runTest(self):
        #async_logger.info("Running InvalidTTL_NoPacketIn")

        #"verifying without set_async_request, switch will packet in"
        #step 1-1:clear all flow entries for unmatching
        rc = testutils.delete_all_flows(self.controller, async_logger)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        #step 2-1:controller sends set_async_request msg
        async_logger.info("Sending set_async_request")
        mask = 1 << ofp.OFPR_INVALID_TTL
        request_set = create_set_async(pkt_in_mstr = mask)
        testutils.ofmsg_send(self, request_set)
        #result 2-1: contrller sends msg successfully

        #step 3-1: install default mismatch flow entry ,action=output;
        testutils.set_table_config(self)
        pkt = testutils.simple_tcp_packet(ip_ttl=0)
        flow_add = testutils.flow_msg_create(self, pkt,
                            egr_port = ofp.OFPP_CONTROLLER, table_id = testutils.WC_L3_TABLE)
        testutils.flow_msg_install(self, flow_add)
        
        #send data(invalid ttl) to port
        for of_port in async_port_map.keys():
            async_logger.info("PKT IN test, port " + str(of_port))
            self.dataplane.send(of_port, str(pkt))
            #@todo Check for unexpected messages?
            (response, _) = self.controller.poll(ofp.OFPT_PACKET_IN, 2)

            self.assertTrue(response is not None, 
                            'Can not receive packet in message')
            #dataplane receive nothing
            (port_rec, pkt_rec, _) = self.dataplane.poll(of_port,1)
            self.assertTrue(pkt_rec is None, "dataplane not receive packet")

        (response, _) = self.controller.poll(ofp.OFPT_PACKET_IN, 2)
        (response, _) = self.controller.poll(ofp.OFPT_PACKET_IN, 2)

        #"verifying with set_async_request, switch will not packet in"
        #step 1-2:clear all flow entries for unmatching
        rc = testutils.delete_all_flows(self.controller, async_logger)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        #step 2-2:controller sends set_async_request msg
        async_logger.info("Sending set_async_request")
        mask = 0xffffffff ^ (1 << ofp.OFPR_INVALID_TTL)
        request_set = create_set_async(pkt_in_mstr = mask)
        testutils.ofmsg_send(self, request_set)
        #result 2-2: contrller sends msg successfully

        #step 3-2: install default mismatch flow entry ,action=output;
        testutils.set_table_config(self)
        pkt = testutils.simple_tcp_packet(ip_ttl=0)
        flow_add = testutils.flow_msg_create(self, pkt,
                            egr_port = ofp.OFPP_CONTROLLER, table_id = testutils.WC_L3_TABLE)
        testutils.flow_msg_install(self, flow_add)

        #(response, _) = self.controller.poll(ofp.OFPT_PACKET_IN, 2)
        #send data(invalid ttl) to port
        for of_port in async_port_map.keys():
            async_logger.info("PKT IN test, port " + str(of_port))
            self.dataplane.send(of_port, str(pkt))
            #@todo Check for unexpected messages?
            (response, _) = self.controller.poll(ofp.OFPT_PACKET_IN, 2)

            self.assertTrue(response is None, 
                            'Packet in message received unexpected')
            #dataplane receive nothing
            (port_rec, pkt_rec, _) = self.dataplane.poll(of_port,1)
            self.assertTrue(pkt_rec is None, "dataplane rec packet")
        msg = create_set_async()
        set_async_verify(self, msg)

#zhaoxiuchu 20121220 --5
class AsyncPortStatusModify(basic.SimpleProtocol):
    """
    Modify a bit in port config, there is no ofp_port_status msg, at last verify changed

    Set async, when port_status changes, ofp_port_status msg will not be sent to controller
    Get the switch configuration, modify the port configuration
    and write it back; verify controller not receive ofp_port_status,
    get the config again and verify changed.
    Then set it back to the way it was.
    """

    def runTest(self):
        #async_logger.info("Running " + str(self))
        #step 0:clear switch
        of_ports = testutils.clear_switch(self, async_port_map.keys(), async_logger)
        
        (response, _) = self.controller.poll(ofp.OFPT_PORT_STATUS, 2)
        (response, _) = self.controller.poll(ofp.OFPT_PORT_STATUS, 2)
        (response, _) = self.controller.poll(ofp.OFPT_PORT_STATUS, 2)
        #step 1:controller sends set_async_request msg
        async_logger.info("Sending set_async_request")
        mask = 0xffffffff ^ (1 << ofp.OFPPR_MODIFY)
        request_set = create_set_async(port_st_mstr = mask)
        testutils.ofmsg_send(self, request_set)
        #result 1: contrller sends msg successfully
    
        #step 2: set the first port's config to the other way
        async_logger.info("testcase executed on port: " + str(of_ports[0]))

        async_logger.debug("No flood bit port " + str(of_ports[0]) + " is now " + 
                           str(ofp.OFPPC_NO_PACKET_IN))                    
        rv = testutils.port_config_set(self.controller, of_ports[0],
                             ofp.OFPPC_NO_PACKET_IN, ofp.OFPPC_NO_PACKET_IN,
                             async_logger)
        #result 2:set the first port's config to the other way successfully
        self.assertTrue(rv != -1, "Error sending port mod")
        testutils.do_barrier(self.controller)

        #step 3: after the port's attribute changed, PORT_STATUS msg sended to controller
        (response, _) = self.controller.poll(ofp.OFPT_PORT_STATUS, 2)
        #result 3: no packetin msg sended to controller
        self.assertTrue(response is None, 'PORT_STATUS message received unexpected')

        #step 4: Verify change took place with same feature request
        _,config,_ = testutils.port_config_get(self.controller, of_ports[0], async_logger)

        async_logger.debug("No packet_in bit port " + str(of_ports[0]) + " is now " + 
                           str(config & ofp.OFPPC_NO_PACKET_IN))
        self.assertTrue(config is not None, "Did not get port config")
        self.assertTrue(config & ofp.OFPPC_NO_PACKET_IN != 0, "Bit change did not take")

        #step 5: Set it back
        mask = 1 << ofp.OFPPR_MODIFY
        request_set = create_set_async(port_st_mstr = mask)
        testutils.ofmsg_send(self, request_set)

        rv = testutils.port_config_set(self.controller, of_ports[0], 0,
                                        ofp.OFPPC_NO_PACKET_IN, async_logger)
        self.assertTrue(rv != -1, "Error sending port mod")

        (response, _) = self.controller.poll(ofp.OFPT_PORT_STATUS, 2)
        #result 3: no packetin msg sended to controller
        self.assertTrue(response is not None, 'PORT_STATUS message not received')

        testutils.clear_switch(self, async_port_map, async_logger)
        msg = create_set_async()
        set_async_verify(self, msg)
       
#zhaoxiuchu 20121220 --6 
class AsyncFlowRemIdleTimeOut(basic.SimpleDataPlane):
    """
    flow entry idle timeout but switch doesn't send send ofp_flow_removed msg
    because of set_async_request.

    set_async flow_removed_mask=OFPRR_IDLE_TIMEOUT
    Generate a packet
    Generate and install a matching flow with idle timeout = 1 sec
    Verify the flow expiration message is received
    """
    def runTest(self):
        of_ports = async_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")

        #"verifying without set_async_request, switch will send flow removed"
        #step 1-1:controller sends set_async_request msg
        async_logger.info("Sending set_async_request")
        mask = 1 << ofp.OFPRR_IDLE_TIMEOUT
        request_set = create_set_async(flow_rm_mstr = mask)
        testutils.ofmsg_send(self, request_set)
        #result 1-1: contrller sends msg successfully
        
        #step 2-1:clear all flow entry
        testutils.delete_all_flows(self.controller, async_logger)
        response,_ = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 2)
        while response != None:
            response,_ = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 1)

        #step 3-1:insert a flow entry: idle_timeout=1
        pkt = testutils.simple_tcp_packet()
        ing_port = of_ports[0]
        egr_port  = of_ports[1]
        async_logger.info("Ingress " + str(ing_port) + " to egress " + str(egr_port))

        request = testutils.flow_msg_create(self, pkt,
                            ing_port=ing_port, egr_port=egr_port, check_expire=True)
        request.cookie = random.randint(0,0xffffffffffffffff)
        request.idle_timeout = 1
        testutils.flow_msg_install(self, request)

        #step 4-1: wait for 2sec, make sure no ofp_flow_removed msg
        (response, _) = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 2)

        self.assertTrue(response is not None,
                                        'Not receive flow removed message')
        self.assertTrue(response.reason  == ofp.OFPRR_IDLE_TIMEOUT,
                                        'Not OFPRR_IDLE_TIMEOUT reason')
        self.assertTrue(response.cookie  == request.cookie,
                                        'Cookie is not equal')
        #self.assertTrue(response.match_fields  == request.match_fields,
        #                                'Match_fields is not equal')
        #step 5-1: verify there is no flow entry
        async_logger.info("Sending flow request")
        response = testutils.flow_stats_get(self, request.match_fields, request.table_id)
        async_logger.debug(response.show())

        self.assertEqual(len(response.stats),0, "len of stats is:"+str(len(response.stats)))

        #"verifying with set_async_request, switch will not send flow removed"
        #step 1-2:controller sends set_async_request msg
        async_logger.info("Sending set_async_request")
        mask = 0xffffffff ^ (1 << ofp.OFPRR_IDLE_TIMEOUT)
        request_set = create_set_async(flow_rm_mstr = mask)
        testutils.ofmsg_send(self, request_set)
        #result 1-2: contrller sends msg successfully
        
        #step 2-2:clear all flow entry
        testutils.delete_all_flows(self.controller, async_logger)
        response,_ = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 2)
        while response != None:
            response,_ = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 1)
        #step 3-2:insert a flow entry: idle_timeout=1
        async_logger.info("Ingress " + str(ing_port) + " to egress " + str(egr_port))
        testutils.flow_msg_install(self, request)

        #step 4-2: wait for 2sec, make sure no ofp_flow_removed msg
        (response, _) = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 2)

        self.assertTrue(response is None, 
                        'Receive flow removed message ')
                        
        #step 5-2: verify there is no flow entry
        async_logger.info("Sending flow request")
        response = testutils.flow_stats_get(self)
        async_logger.debug(response.show())

        self.assertEqual(len(response.stats),0, "len of stats is:"+str(len(response.stats)))
        msg = create_set_async()
        set_async_verify(self, msg)

#zhaoxiuchu 20121220 --7 
class AsyncFlowRemHardTimeOut(basic.SimpleDataPlane):
    """
    flow entry idle timeout but switch doesn't send send ofp_flow_removed msg because of set_async_request.

    set_async_request flow_removed_mask=OFPRR_IDLE_TIMEOUT
    Generate a packet
    Generate and install a matching flow with idle timeout = 1 sec
    Verify the flow expiration message is received
    """
    def runTest(self):
        of_ports = async_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")

        #"verifying without set_async_request, switch will send flow removed"
        #step 1-1:controller sends set_async_request msg
        async_logger.info("Sending set_async_request")
        mask = 1 << ofp.OFPRR_HARD_TIMEOUT
        request_set = create_set_async(flow_rm_mstr = mask)
        testutils.ofmsg_send(self, request_set)
        #result 1-1: contrller sends msg successfully
        
        #step 2-1:clear all flow entry
        testutils.delete_all_flows(self.controller, async_logger)
        response,_ = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 2)
        while response != None:
            response,_ = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 1)

        #step 3-1:insert a flow entry: idle_timeout=1
        pkt = testutils.simple_tcp_packet()
        ing_port = of_ports[0]
        egr_port  = of_ports[1]
        async_logger.info("Ingress " + str(ing_port) + " to egress " + str(egr_port))

        request = testutils.flow_msg_create(self, pkt, ing_port=ing_port,
                            egr_port=egr_port, table_id = testutils.WC_ALL_TABLE, check_expire=True)
        request.cookie = random.randint(0,0xffffffffffffffff)
        testutils.flow_msg_install(self, request)

        #step 4-1: wait for 2sec, make sure no ofp_flow_removed msg
        (response, _) = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 5)

        self.assertTrue(response is not None,
                                        'Not receive flow removed message')
        self.assertTrue(response.reason  == ofp.OFPRR_HARD_TIMEOUT,
                                        'Not OFPRR_HARD_TIMEOUT reason')
        self.assertTrue(response.cookie  == request.cookie,
                                        'Cookie is not equal')
        #self.assertTrue(response.match_fields  == request.match_fields,
        #                                'Match_fields is not equal')
        #step 5-1: verify there is no flow entry
        async_logger.info("Sending flow request")
        response = testutils.flow_stats_get(self, request.match_fields, request.table_id)
        async_logger.debug(response.show())

        self.assertEqual(len(response.stats),0, "len of stats is:"+str(len(response.stats)))

        #"verifying with set_async_request, switch will not send flow removed"
        #step 1-2:controller sends set_async_request msg
        async_logger.info("Sending set_async_request")
        mask = 0xffffffff ^ (1 << ofp.OFPRR_HARD_TIMEOUT)
        request_set = create_set_async(flow_rm_mstr = mask)
        testutils.ofmsg_send(self, request_set)
        #result 1-2: contrller sends msg successfully
        
        #step 2-2:clear all flow entry
        testutils.delete_all_flows(self.controller, async_logger)
        response,_ = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 2)
        while response != None:
            response,_ = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 1)
        #step 3-2:insert a flow entry: idle_timeout=1
        async_logger.info("Ingress " + str(ing_port) + " to egress " + str(egr_port))
        testutils.flow_msg_install(self, request)

        #step 4-2: wait for 2sec, make sure no ofp_flow_removed msg
        (response, _) = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 5)

        self.assertTrue(response is None, 
                        'Receive flow removed message ')
                        
        #step 5-2: verify there is no flow entry
        async_logger.info("Sending flow request")
        response = testutils.flow_stats_get(self)
        async_logger.debug(response.show())

        self.assertEqual(len(response.stats),0, "len of stats is:"+str(len(response.stats)))
        msg = create_set_async()
        set_async_verify(self, msg)

#zhaoxiuchu 20121220 -8
class AsyncFlowRemDelete(basic.SimpleProtocol):   
    """
    exact entry delete test;
    """
    def runTest(self):
        #"verifying with set_async_request, switch will not send flow removed"
        
        #step 1-1:controller sends set_async_request msg
        async_logger.info("Sending set_async_request")
        of_ports = async_port_map.keys()
        of_ports.sort()
        ing_port = of_ports[0]
        egr_port = of_ports[1]
        mask = 1 << ofp.OFPRR_DELETE
        request_set = create_set_async(flow_rm_mstr = mask)
        testutils.ofmsg_send(self, request_set)
        #result 1-1: contrller sends msg successfully
        
        #"step 2-1:clear all flow entry"
        testutils.delete_all_flows(self.controller, async_logger)
        response,_ = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 2)
        while response != None:
            response,_ = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 1)

        pkt = testutils.simple_tcp_packet(
                            vlan_tags=[{'type': 0x8100, 'vid': 5, 'pcp': 1}])
        request = testutils.flow_msg_create(self, pkt, ing_port=ing_port, egr_port=egr_port,
                            table_id = testutils.EX_VLAN_TABLE, check_expire=True)
        request.cookie = random.randint(0,0xffffffffffffffff)
        testutils.flow_msg_install(self, request)

        "delete it"
        request.command = ofp.OFPFC_DELETE
        testutils.flow_msg_install(self, request)

        #"receive flow removed msg"
        (response, _) = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 2)        
        self.assertTrue(response is not None,  'Not receive flow removed message ')
        self.assertTrue(response.reason  == ofp.OFPRR_DELETE,
                                        'Not OFPRR_DELETE reason')
        self.assertTrue(response.cookie  == request.cookie,
                                        'Cookie is not equal')
        #self.assertTrue(response.match_fields  == request.match_fields,
        #                                'Match_fields is not equal')

        #'read it back , returns blank;'
        response = testutils.flow_stats_get(self, request.match_fields, request.table_id)
        self.assertEqual(len(response.stats),0, "len of stats is:"+str(len(response.stats)))
        #print(response.show())
 
        #"verifying with set_async_request, switch will not send flow removed"
        "step 1-2:controller sends set_async_request msg"
        async_logger.info("Sending set_async_request")
        mask = 0xffffffff ^ (1 << ofp.OFPRR_DELETE)
        request_set = create_set_async(flow_rm_mstr = mask)
        testutils.ofmsg_send(self, request_set)
        "result 1-2: contrller sends msg successfully"
        
        "step 2-2:clear all flow entry"
        testutils.delete_all_flows(self.controller, async_logger)
        response,_ = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 2)
        while response != None:
            response,_ = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 1) 
        #table_id = 3
        "add a flow entry"
        request.command = ofp.OFPFC_ADD
        testutils.flow_msg_install(self, request)

        "delete it"
        request.command = ofp.OFPFC_DELETE
        testutils.flow_msg_install(self, request)

        "receive no flow removed msg"
        (response, _) = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 2)        
        self.assertTrue(response is None,  'Receive flow removed message ')
        'read it back , returns blank;'
        response = testutils.flow_stats_get(self, request.match_fields, request.table_id)
        self.assertEqual(len(response.stats),0, "len of stats is:"+str(len(response.stats)))
        #print(response.show())
        msg = create_set_async()
        set_async_verify(self, msg)

#zhaoxiuchu 20121220 add for async start
class AsyncFlowRemGroupDel(basic.SimpleProtocol):
    """
      A deletion for existing group should remove the group
    """

    def runTest(self):
        #self.clean_switch()
        #print("AsyncGroupDelNoFlowRemoved")
        #"verifying without set_async, switch will send flow removed"
        #step 1-1:controller sends set_async msg
        async_logger.info("Sending set_async")
        mask = 1 << ofp.OFPRR_GROUP_DELETE
        request_set = create_set_async(flow_rm_mstr = mask)
        testutils.ofmsg_send(self, request_set)
        #result 1-1: contrller sends msg successfully
        
        "step 2-1:clear all flow entry"
        testutils.delete_all_flows(self.controller, async_logger)
        response,_ = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 2)
        while response != None:
            response,_ = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 1)

        "step 3-1:add goup entry"
        group_add_msg = \
        groups.create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 10, buckets = [
            groups.create_bucket(0, 0, 0, [
                groups.create_action(action= ofp.OFPAT_OUTPUT, port= 1)
            ])
        ])
        testutils.ofmsg_send(self, group_add_msg)

        "step 4-1: add an flow entry ,install default mismatch flow entry;"
        pkt = testutils.simple_tcp_packet()
        act = groups.create_action(action= ofp.OFPAT_GROUP, group_id = 10)

        request = testutils.flow_msg_create(self, pkt, action_list = [act],
                            table_id = testutils.WC_L3_TABLE, check_expire=True)
        request.cookie = random.randint(0,0xffffffffffffffff)
        testutils.flow_msg_install(self, request)  
        
        "step 5-1: delete goup entry"
        group_del_msg = \
        groups.create_group_mod_msg(ofp.OFPGC_DELETE, ofp.OFPGT_ALL, group_id = 10, buckets = [
        ])
        testutils.ofmsg_send(self, group_del_msg)

        "step 5-1:receive flow removed msg"
        (response, _) = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 2)        
        self.assertTrue(response is not None,  'Receive flow removed message ')
        self.assertTrue(response.reason  == ofp.OFPRR_GROUP_DELETE,
                                        'Not OFPRR_DELETE reason')
        self.assertTrue(response.cookie  == request.cookie,
                                        'Cookie is not equal')
        #self.assertTrue(response.match_fields  == request.match_fields,
        #                                'Match_fields is not equal')
        
        #"verifying with set_async, switch will not send flow removed"        
        "step 1-2:controller sends set_async msg"
        async_logger.info("Sending set_async")
        mask = 0xffffffff ^ (1 << ofp.OFPRR_GROUP_DELETE)
        request_set = create_set_async(flow_rm_mstr = mask)
        testutils.ofmsg_send(self, request_set)
        "result 1-2: contrller sends msg successfully"

        
        "step 2-2:clear all flow entry"
        testutils.delete_all_flows(self.controller, async_logger)
        response,_ = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 2)
        while response != None:
            response,_ = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 1)

        "step 3-2:add goup entry"
        testutils.ofmsg_send(self, group_add_msg)

        "step 4-2: add an flow entry ,install default mismatch flow entry;"
        testutils.flow_msg_install(self, request)        
        
        "step 5-2: delete goup entry"
        testutils.ofmsg_send(self, group_del_msg)

        "step 6-2: receive no flow removed msg"
        (response, _) = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 2)        
        self.assertTrue(response is None,  'Receive flow removed message ')

        msg = create_set_async()
        set_async_verify(self, msg)

#zhaoxiuchu 20121220 add for async end

if __name__ == "__main__":
    print "Please run through oft script:  ./oft --test_spec=async"

