"""
Flow stats test case.
Similar to Flow stats test case in the perl test harness.

"""

import logging

#import unittest
import random

#import oftest.controller as controller
import oftest.cstruct as ofp
import oftest.message as message
#import oftest.dataplane as dataplane
import oftest.action as action
import oftest.parse as parse
import basic
import oftest.instruction as instruction
import oftest.match as match

import testutils
#from time import sleep

#@var port_map Local copy of the configuration map from OF port
# numbers to OS interfaces
pa_port_map = None
#@var pa_logger Local logger object
pa_logger = None
#@var pa_config Local copy of global configuration data
pa_config = None

def test_set_init(config):
    """
    Set up function for packet action test classes

    @param config The configuration dictionary; see oft
    """

    global pa_port_map
    global pa_logger
    global pa_config

    pa_logger = logging.getLogger("pkt_act")
    pa_logger.info("Initializing test set")
    pa_port_map = config["port_map"]
    pa_config = config

class FlowStats(basic.SimpleDataPlane):
    """
    Verify flow stats are properly retrieved.

    1) Delete all flows
    2) Insert a flow
    3) Generate a packet
    4) Send a flow_stats; verify the response has 1 flow with right counters
    """
    def runTest(self):
        global pa_port_map
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")
        ingress_port = of_ports[0];
        egress_port = of_ports[1];

        rc = testutils.delete_all_flows(self.controller, pa_logger)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        #controller send flow_mod to switch
        pkt = testutils.simple_tcp_packet()
        flow_mod_add = testutils.flow_msg_create(self, pkt, ing_port=ingress_port, egr_port=egress_port, table_id=testutils.EX_ACL_TABLE)
        testutils.flow_msg_install(self, flow_mod_add)

        #user send pkt to switch, switch transfer to eng_port
        pa_logger.info("Sending packet to dp port " +
                       str(ingress_port))
        self.dataplane.send(ingress_port, str(pkt))
        
        (rcv_port, rcv_pkt, _) = self.dataplane.poll(egress_port, timeout=2)
        self.assertTrue(rcv_pkt is not None, "Did not receive packet")
        pa_logger.debug("Packet len " + str(len(pkt)) + " in on " +
                        str(rcv_port))
        self.assertEqual(rcv_port, egress_port, "Unexpected receive port")
        self.assertEqual(str(pkt), str(rcv_pkt),
                         'Response packet does not match send packet')

        #check the  stats msg
        stat_req = message.flow_stats_request()
        stat_req.match_fields = flow_mod_add.match_fields
        stat_req.table_id = 0xff
        stat_req.out_port = ofp.OFPP_ANY;
        stat_req.out_group = ofp.OFPG_ANY;
        
        pa_logger.info("Sending stats request")
        testutils.ofmsg_send(self,  stat_req)

        (response, _) = self.controller.poll(ofp.OFPT_MULTIPART_REPLY, 2)
        self.assertTrue(response, "No Flow_stats reply")
        #print "YYY: Stats reply is \n%s" % (response.show())
        self.assertEqual(len(response.stats), 1, "Did not receive flow stats reply")
        self.assertEqual(response.stats[0].packet_count,1)
        self.assertEqual(response.stats[0].byte_count,len(rcv_pkt))
        
class AggregatePacketCount(basic.SimpleDataPlane):
    """
    A flow mod with flag OFPFF_NO_PKT_COUNTS and OFPFF_NO_BYT_COUNTS
    A packet sent to the group should increase byte/packet counters of group
    """

    def runTest(self):
        #testutils.clear_switch(self,pa_port_map,pa_logger)
        testutils.delete_all_flows(self.controller, pa_logger)
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")

        pkt  = testutils.simple_tcp_packet()
        #match_ls = packet_to_exact_flow_match(pkt = pkt, table_id = 0, in_port = of_ports[0])
        match_ls = parse.packet_to_flow_match(pkt)

        request = message.flow_mod()
        request.match_fields = match_ls
        request.flags = 0x18#set flags OFPFF_NO_PKT_COUNTS and OFPFF_NO_BYT_COUNTS
        
        action_list = []        
        act = action.action_output()
        act.port = of_ports[1]
        action_list.append(act)
        
        inst = None
        instruction_list = []
        
        if len(instruction_list) == 0: 
              inst = instruction.instruction_apply_actions()
              instruction_list.append(inst)
        
        for act in action_list:
              rv = inst.actions.add(act)
              self.assertTrue(rv, "Could not add action" + act.show())

        for i in instruction_list: 
              rv = request.instructions.add(i)
              self.assertTrue(rv, "Could not add instruction " + i.show())

        #testutils.message_send(self, request)
        rv0 = self.controller.message_send(request)
        self.assertTrue( rv0 != -1, "Error sending flow mod")
        testutils.do_barrier(self.controller)

        #self.send_data(pkt, of_ports[0])
        self.dataplane.send(of_ports[0],str(pkt))

        aggregate_stats_req = message.aggregate_stats_request()
        aggregate_stats_req.match_fields = match_ls
        
        rv = self.controller.message_send(aggregate_stats_req)
        self.assertTrue( rv != -1, "Error sending flow stat req")
        #testutils.message_send(self, aggregate_stats_req)

        (response, _) = self.controller.poll(ofp.OFPT_MULTIPART_REPLY, 2)
        #print(response.show())
        self.assertTrue(response is not None, "No aggregate_stats reply")
        self.assertEqual(len(response.stats), 1, "Did not receive aggregate stats reply")
        self.assertEqual(response.stats[0].packet_count,0)#1)
        self.assertEqual(response.stats[0].byte_count,0)#len(packet_in))
