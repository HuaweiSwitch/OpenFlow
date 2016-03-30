#wildcard  test case;

"""
exact test case;
"""

import sys
import logging

import unittest

import oftest.controller as controller
import oftest.cstruct as ofp
import oftest.message as message
import oftest.dataplane as dataplane
import oftest.action as action
import oftest.instruction as instruction
import oftest.parse as parse
import oftest.match as match
from oftest.match_list import match_list

import testutils

import basic

try:
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import *
    load_contrib("mpls")
    #TODO This should really be in scapy!
    bind_layers(MPLS, MPLS, s=0)
except:
    sys.exit("Need to install scapy for packet parsing")

#@var sdn_port_map Local copy of the configuration map from OF port
# numbers to OS interfaces
exact_port_map = None
#@var sdn_logger Local logger object
exact_logger = None
#@var sdn_config Local copy of global configuration data
exact_config = None


test_prio = {}

def test_set_init(config):
    """
    Set up function for basic test classes
    @param config The configuration dictionary; see oft
    """
    global exact_port_map
    global exact_logger
    global exact_config

    exact_logger = logging.getLogger("exact test case")
    exact_logger.info("Initializing test set")
    exact_port_map = config["port_map"]
    exact_config = config



class ExactEntryAdd(basic.SimpleProtocol):
    """
    exact entry add test;
    """
    def runTest(self):
        table_id = testutils.EX_L2_TABLE
        of_ports = exact_port_map.keys()
        egr_port = of_ports[len(of_ports)-1]

        pkt = testutils.simple_tcp_packet(dl_src='00:22:44:62:9b:1c', dl_dst='00:13:07:5f:61:ab')
        pkt_metadata = {'metadata_val':0xaa22334455667788, 
                        'metadata_msk':0xFFFFFFFFFFFFFFFF}
        request = testutils.flow_msg_create(self, pkt, pkt_metadata, egr_port = egr_port, table_id = table_id)
        request.hard_timeout = 8
        request.idle_timeout = 8

        testutils.flow_msg_install(self, request)
        #"get flow stats"
        stat_req = message.flow_stats_request()
        stat_req.buffer_id = 0xffffffff
        stat_req.table_id = table_id
        stat_req.out_port = ofp.OFPP_ANY
        stat_req.out_group = ofp.OFPG_ANY
        stat_req.match_fields = request.match_fields
        response, _ = self.controller.transact(stat_req, timeout=2)
        self.assertTrue(isinstance(response,message.flow_stats_reply),"Not a flow_stats_reply")
        self.assertEqual(len(response.stats),1, "len of stats is:"+str(len(response.stats)))


class ExactEntryMod(basic.SimpleProtocol):
    """
    exact entry mod test;
    """
    def runTest(self):
        table_id = testutils.EX_L2_TABLE
        of_ports = exact_port_map.keys()
        egr_port1 = of_ports[len(of_ports)-1]
        egr_port2 = of_ports[0]

        pkt = testutils.simple_tcp_packet(dl_src='99:33:11:11:11:55', dl_dst='33:33:11:11:77:66')
        pkt_metadata = {'metadata_val':0x99999999, 
                        'metadata_msk':0xFFFFFFFFFFFFFFFF}
        request = testutils.flow_msg_create(self, pkt, pkt_metadata, egr_port = egr_port1, table_id = table_id)
        testutils.flow_msg_install(self, request)

        #"mod it ,add outport 1"
        request_mod = testutils.flow_msg_create(self, pkt, match_fields = request.match_fields, egr_port = egr_port2, table_id = table_id)
        request_mod.command = ofp.OFPFC_MODIFY
        testutils.ofmsg_send(self, request_mod)
        #print(flow_mod.show())

        #"read it back;"
        stat_req = message.flow_stats_request()
        stat_req.buffer_id = 0xffffffff
        stat_req.table_id = table_id
        stat_req.out_port = ofp.OFPP_ANY
        stat_req.out_group = ofp.OFPG_ANY
        stat_req.match_fields = request.match_fields
        response, _ = self.controller.transact(stat_req, timeout=2)
        #print(response.show())
        self.assertTrue(isinstance(response,message.flow_stats_reply),"Not a flow_stats_reply")
        self.assertEqual(len(response.stats),1, "len of stats is:"+str(len(response.stats)))
        self.assertEqual(response.stats[0].instructions.items[0].actions.items[0].port,
                         request_mod.instructions.items[0].actions.items[0].port,
                         "action error:"+str(response.stats[0].instructions.items[0].actions.items[0].port))


class ExactEntryDel(basic.SimpleProtocol):
    """
    exact entry delete test;
    """
    def runTest(self):
        table_id = testutils.EX_L2_TABLE
        of_ports = exact_port_map.keys()
        egr_port = of_ports[0]

        pkt = testutils.simple_tcp_packet(dl_src='22:22:22:22:22:22', dl_dst='22:22:22:22:22:22')
        pkt_metadata = {'metadata_val':0x1122334455667788, 
                        'metadata_msk':0xFFFFFFFFFFFFFFFF}
        request = testutils.flow_msg_create(self, pkt, pkt_metadata, egr_port = egr_port, table_id = table_id)
        testutils.flow_msg_install(self, request)

        #"delete it"
        request_del = testutils.flow_msg_create(self, pkt, match_fields = request.match_fields, egr_port = egr_port, table_id = table_id)
        request_del.command = ofp.OFPFC_DELETE
        testutils.ofmsg_send(self, request_del)

        #'read it back , returns blank;'
        stat_req = message.flow_stats_request()
        stat_req.buffer_id = 0xffffffff
        stat_req.table_id = table_id
        stat_req.out_port = ofp.OFPP_ANY
        stat_req.out_group = ofp.OFPG_ANY
        stat_req.match_fields = request.match_fields
        response, _ = self.controller.transact(stat_req, timeout=2)
        self.assertTrue(isinstance(response,message.flow_stats_reply),"Not a flow_stats_reply")
        self.assertEqual(len(response.stats),0, "len of stats is:"+str(len(response.stats)))
        #print(response.show())


class ExactFlowEntryHardExpire(basic.SimpleProtocol):
    """
    exact flow entries expires test case;
    """
    def runTest(self):
        of_ports = testutils.clear_switch(self, exact_port_map.keys(), exact_logger)#zhaoxiuchu
        table_id = testutils.EX_L2_TABLE
        of_ports = exact_port_map.keys()
        egr_port = of_ports[1]

        pkt = testutils.simple_tcp_packet(dl_src='08:02:03:04:88:99', dl_dst='22:22:22:22:22:22')
        pkt_metadata = {'metadata_val':0xad22332e6f667588, 
                        'metadata_msk':0xFFFFFFFFFFFFFFFF}
        request = testutils.flow_msg_create(self, pkt, pkt_metadata, egr_port = egr_port, table_id = table_id)
        request.hard_timeout = 1
        request.flags |= ofp.OFPFF_SEND_FLOW_REM
        testutils.flow_msg_install(self, request)
        #print(request.show())

        (response, _) = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 3)

        self.assertTrue(response is not None,'Did not receive flow removed message ')
        self.assertEqual(request.cookie, response.cookie,'Cookies do not match')
        self.assertEqual(ofp.OFPRR_HARD_TIMEOUT, response.reason, 'Flow table entry removal reason is not idle_timeout')


class ExactFlowEntryIdleExpire(basic.SimpleProtocol):
    """
    exact flow entries expires test case;
    """
    def runTest(self):
        table_id = testutils.EX_L2_TABLE
        of_ports = exact_port_map.keys()
        egr_port = of_ports[1]

        pkt = testutils.simple_tcp_packet(dl_src='08:02:ff:34:88:99', dl_dst='22:22:ed:22:5f:1a')
        request = testutils.flow_msg_create(self, pkt, egr_port = egr_port, table_id = table_id)
        for obj in request.match_fields.tlvs:
            if obj.field == ofp.OFPXMT_OFB_METADATA:
                obj.value = 0x9922334455667788
        request.idle_timeout = 1
        request.flags |= ofp.OFPFF_SEND_FLOW_REM
        testutils.flow_msg_install(self, request)
        #print(request.show())

        (response, _) = self.controller.poll(ofp.OFPT_FLOW_REMOVED, 3)
        self.assertTrue(response is not None, 'Did not receive flow removed message ')
        self.assertEqual(request.cookie, response.cookie, 'Cookies do not match')
        self.assertEqual(ofp.OFPRR_IDLE_TIMEOUT, response.reason, 'Flow table entry removal reason is not idle_timeout')


class ExactEntryClearAll(basic.SimpleProtocol):
    """
    exact entry clear all test;
    """
    def runTest(self):
        testutils.delete_all_flows(self.controller, self.logger)


def exact_table_goto_table(parent = None, first_table = 0, second_table = 1, match_ls = None, actions = []):
    """
    exact table goto table
    """
    if parent == None or match_ls == None:
        print("parent == None or match_ls == None")
        return

    if first_table >= second_table :
        print( "first_table >= second_table")
        return

    request = message.flow_mod()
    request.table_id = first_table
    request.command = ofp.OFPFC_ADD

    request.match_fields = match_ls

    if(len(actions) != 0):
        inst = instruction.instruction_write_actions();
        inst.actions = actions
        request.instructions.add(inst)

    inst_goto = instruction.instruction_goto_table();
    inst_goto.table_id = second_table
    request.instructions.add(inst_goto)
    testutils.ofmsg_send(parent,request)

def exact_table_output(parent = None, table_id = None, match_ls = None, actions = [], egr_port = None):
    """
    exact table output
    """
    if parent == None or table_id == None or match_ls == None:
        print( "parent == None or table_id == None or match_ls == None:")
        return

    if egr_port is None:
        of_ports = exact_port_map.keys()
        egr_port = of_ports[len(of_ports)-1]
    request = message.flow_mod()
    request.table_id = table_id
    request.command = ofp.OFPFC_ADD
    request.match_fields = match_ls


    inst = instruction.instruction_write_actions();
    for item in actions:
        inst.actions.add(item)
    #print( inst.actions.show())
    #inst.actions.actions = actions

    act_out = action.action_output()
    act_out.port = egr_port
    inst.actions.add(act_out)
    request.instructions.add(inst)

    testutils.ofmsg_send(parent, request)

class ExactTableFlowStats(basic.SimpleDataPlane):
    """
    exact table flow stats
    """
    def runTest(self):
        #"clear swtich;"
        testutils.delete_all_flows(self.controller, self.logger)
        table_id = testutils.EX_ACL_TABLE
        of_ports = exact_port_map.keys()
        port_in = of_ports[0]
        egr_port = of_ports[1]
        vlan_tags=[{'type': 0x8100, 'vid': 3, 'pcp': 1}]
        mpls_tags=[{'type': 0x8847, 'label': 22, 'tc': 2, 'ttl': 48}]

        pkt = testutils.simple_tcp_packet(ip_src='192.168.0.99', dl_dst='00:06:07:08:09:aa', \
                                               vlan_tags = [], mpls_tags = [])

        match_ls = testutils.packet_to_exact_flow_match(pkt, None, testutils.EX_L2_TABLE, port_in)

        exact_table_output(self, table_id, match_ls, egr_port = egr_port)

        stat_req = message.flow_stats_request()
        stat_req.buffer_id = 0xffffffff
        stat_req.table_id = table_id
        stat_req.match_fields = match_ls
        stat_req.out_port = ofp.OFPP_ANY
        stat_req.out_group = ofp.OFPP_ANY
        
        response, _ = self.controller.transact(stat_req, timeout=2)
        #print(response.show())
        self.assertTrue(isinstance(response,message.flow_stats_reply),"Not a flow_stats_reply")
        self.assertEqual(len(response.stats),1, "len of stats is:"+str(len(response.stats)))

'''
class ExactTableReadFlow(basic.SimpleProtocol):
    """
    read simple flow;
    """
    def runTest
'''

class ExactTableMultiTableGoto(basic.SimpleDataPlane):
    """
    exact multi table goto test case;
    """
    def runTest(self):
        port_in = exact_port_map.keys()[0]
        egr_port = exact_port_map.keys()[1]
        #"clear swtich;"
        testutils.delete_all_flows(self.controller, self.logger)
        "make test packet;"
        pkt = testutils.simple_tcp_packet(dl_src='00:01:02:03:04:05', dl_dst='00:06:07:08:09:0a')

        match_ls = testutils.packet_to_exact_flow_match(pkt = pkt, table_id = testutils.EX_ACL_TABLE, ing_port = port_in)
        exact_table_goto_table(self, testutils.EX_ACL_TABLE, testutils.EX_L2_TABLE, match_ls)

        match_ls = testutils.packet_to_exact_flow_match(pkt = pkt, table_id = testutils.EX_L2_TABLE, ing_port = port_in)
        exact_table_output(self, testutils.EX_L2_TABLE, match_ls, egr_port = egr_port)

        testutils.do_barrier(self.controller)

        "send a packet from port_in "
        self.dataplane.send(port_in, str(pkt))
        "poll from the egr_port port"
        (port_rec, pkt_rec, _) = self.dataplane.poll(port_number=egr_port, timeout=1)
        #print( str(pkt_rec).encode('hex'))
        self.assertTrue(pkt_rec is not None,"rec none packets")
        self.assertEqual(str(pkt), str(pkt_rec), 'retruned pkt not equal to the original pkt')


class ExactTableMatch(basic.SimpleDataPlane):
    """
    exact match and output
    """
    def runTest(self):
        table_id = testutils.EX_ACL_TABLE
        port_in = exact_port_map.keys()[0]
        egr_port = exact_port_map.keys()[1]
        #"clear swtich;"
        testutils.delete_all_flows(self.controller, self.logger)
        # make packet
        pkt = testutils.simple_tcp_packet(ip_src='192.168.0.99')
        match_ls = testutils.packet_to_exact_flow_match(pkt = pkt, table_id = table_id, ing_port = port_in)

        exact_table_output(self, table_id, match_ls, egr_port = egr_port)

        testutils.do_barrier(self.controller)

        "get flow stats"
        stat_req = message.flow_stats_request()
        stat_req.buffer_id = 0xffffffff
        stat_req.table_id = table_id
        stat_req.match_fields = match_ls
        response, _ = self.controller.transact(stat_req, timeout=2)

        "send a packet from port_in "
        self.dataplane.send(port_in, str(pkt))
        "poll from the egr_port port"
        (port_rec, pkt_rec, _) = self.dataplane.poll(port_number=egr_port, timeout=1)
        self.assertTrue(pkt_rec is not None,"rec none packet")
        self.assertEqual(str(pkt), str(pkt_rec), 'retruned pkt not equal to the original pkt')


class ExactTableSetField(basic.SimpleDataPlane):
    """
    exact set field test case;
    """
    def runTest(self):
        table_id = testutils.EX_ACL_TABLE
        port_in = exact_port_map.keys()[0]
        egr_port = exact_port_map.keys()[1]
        #"clear swtich;"
        testutils.delete_all_flows(self.controller, self.logger)
        #make packet;
        pkt = testutils.simple_tcp_packet(dl_src='00:01:02:03:04:05', dl_dst='00:06:07:08:09:0a')
        exp_pkt = testutils.simple_tcp_packet(dl_src='00:01:02:03:04:05', dl_dst='aa:aa:aa:aa:aa:aa')
        # get match list
        match_ls = testutils.packet_to_exact_flow_match(pkt = pkt, table_id = table_id, ing_port = port_in)

        act = action.action_set_field()
        field = match.eth_dst(parse.parse_mac("aa:aa:aa:aa:aa:aa"))
        act.field.add(field)
        exact_table_output(self, table_id, match_ls, actions = [act], egr_port = egr_port)

        testutils.do_barrier(self.controller)

        "send a packet from port_in "
        self.dataplane.send(port_in, str(pkt))
        "poll from the egr_port port"
        (port_rec, pkt_rec, _) = self.dataplane.poll(port_number=egr_port, timeout=1)

        self.assertTrue(pkt is not None,"rec none packets")
        self.assertEqual(str(exp_pkt), str(pkt_rec), 'retruned pkt not equal to the original pkt')


class ExactTableGotoThrough(basic.SimpleDataPlane):
    """
    exact multi table match trough
    """
    def runTest(self):
        vlan_tags=[{'type': 0x8100, 'vid': 3, 'pcp': 1}]
        mpls_tags=[{'type': 0x8847, 'label': 22, 'tc': 2, 'ttl': 48}]
        ing_port = exact_port_map.keys()[0]
        egr_port = exact_port_map.keys()[1]
        #"clear swtich;"
        testutils.delete_all_flows(self.controller, self.logger)
        "make test packet;"
        pkt = testutils.simple_tcp_packet(vlan_tags = vlan_tags, mpls_tags = mpls_tags)

        match_ls = testutils.packet_to_exact_flow_match(pkt = pkt, table_id = testutils.EX_ACL_TABLE, ing_port = ing_port)
        exact_table_goto_table(self, testutils.EX_ACL_TABLE, testutils.EX_L2_TABLE, match_ls)

        match_ls = testutils.packet_to_exact_flow_match(pkt = pkt, table_id = testutils.EX_L2_TABLE, ing_port = ing_port)
        exact_table_goto_table(self, testutils.EX_L2_TABLE, testutils.EX_VLAN_TABLE, match_ls)

        match_ls = testutils.packet_to_exact_flow_match(pkt = pkt, table_id = testutils.EX_VLAN_TABLE, ing_port = ing_port)
        exact_table_goto_table(self, testutils.EX_VLAN_TABLE, testutils.EX_MPLS_TABLE, match_ls)

        match_ls = testutils.packet_to_exact_flow_match(pkt = pkt, table_id = testutils.EX_MPLS_TABLE, ing_port = ing_port)
        exact_table_goto_table(self, testutils.EX_MPLS_TABLE, testutils.EX_L3_TABLE, match_ls)

        match_ls = testutils.packet_to_exact_flow_match(pkt = pkt, table_id = testutils.EX_L3_TABLE, ing_port = ing_port)
        exact_table_output(self, testutils.EX_L3_TABLE, match_ls, egr_port = egr_port)

        testutils.do_barrier(self.controller)

        "send a packet from ing_port "
        self.dataplane.send(ing_port, str(pkt))
        "poll from the egr_port port"
        (port_rec, pkt_rec, _) = self.dataplane.poll(port_number=egr_port, timeout=1)
        self.assertTrue(pkt_rec is not None,"rec none packets")
        #print("++++++++++++++++++++++rcv_pkt++++++++++++++++++++++")
        #if pkt_rec is None:
        #   print(str(pkt_rec))
        #else:
        #   print(str(pkt_rec).encode('hex'))
        self.assertEqual(str(pkt), str(pkt_rec), 'retruned pkt not equal to the original pkt')


class ExactTableMissContinue(basic.SimpleDataPlane):
    """
    Exact table miss continue
    """
    def runTest(self):
        vlan_tags=[{'type': 0x8100, 'vid': 3, 'pcp': 1}]
        mpls_tags=[{'type': 0x8847, 'label': 22, 'tc': 2, 'ttl': 48}]
        ing_port = exact_port_map.keys()[0]
        egr_port = exact_port_map.keys()[1]
        #"clear swtich;"
        testutils.delete_all_flows(self.controller, self.logger)
        'make packet'
        pkt = testutils.simple_tcp_packet(dl_src='00:01:02:03:04:05', dl_dst='00:06:07:08:09:0a', \
                                            vlan_tags = vlan_tags, mpls_tags = mpls_tags)
        'table 0 goto table3'
        match_ls = testutils.packet_to_exact_flow_match(pkt = pkt, table_id = testutils.EX_ACL_TABLE, ing_port = ing_port)
        exact_table_goto_table(self, testutils.EX_ACL_TABLE, testutils.EX_L2_TABLE, match_ls)
        "set table 3 not match, continue"
        testutils.set_table_config(self, testutils.EX_L2_TABLE, ofp.OFPTC_TABLE_MISS_CONTINUE, True)
        'table 4 output'
        match_ls = testutils.packet_to_exact_flow_match(pkt = pkt, table_id = testutils.EX_VLAN_TABLE, ing_port = ing_port)
        exact_table_output(self, testutils.EX_VLAN_TABLE, match_ls, egr_port = egr_port)

        "send a packet from ing_port "
        self.dataplane.send(ing_port, str(pkt))
        'verify the rec data'
        testutils.receive_pkt_verify(self, egr_port, pkt)

        #'reset table3 miss to controller'
        #testutils.set_table_config(self, testutils.EX_L2_TABLE, ofp.OFPTC_TABLE_MISS_CONTROLLER, True)


class ExactTableMissDrop(basic.SimpleDataPlane):
    """
    Exact table miss drop
    """
    def runTest(self):
        vlan_tags=[{'type': 0x8100, 'vid': 3, 'pcp': 1}]
        mpls_tags=[{'type': 0x8847, 'label': 22, 'tc': 2, 'ttl': 48}]
        ing_port = exact_port_map.keys()[0]
        egr_port = exact_port_map.keys()[1]
        #"clear swtich;"
        testutils.delete_all_flows(self.controller, self.logger)
        'make packet'
        pkt = testutils.simple_tcp_packet(dl_src='00:01:02:03:04:05', dl_dst='00:06:07:08:09:0a', \
                                            vlan_tags = vlan_tags, mpls_tags = mpls_tags)
        'table 0 goto table3'
        match_ls = testutils.packet_to_exact_flow_match(pkt = pkt, table_id = testutils.EX_ACL_TABLE, ing_port = ing_port)
        exact_table_goto_table(self, testutils.EX_ACL_TABLE, testutils.EX_L2_TABLE, match_ls)
        "set table 3 not match, continue"
        testutils.set_table_config(self, testutils.EX_L2_TABLE, ofp.OFPTC_TABLE_MISS_DROP, True)
        'table 4 output'
        match_ls = testutils.packet_to_exact_flow_match(pkt, None, testutils.EX_VLAN_TABLE, ing_port)
        exact_table_output(self, testutils.EX_VLAN_TABLE, match_ls, egr_port = egr_port)

        "send a packet from ing_port "
        self.dataplane.send(ing_port, str(pkt))
        # checks no response from controller and dataplane
        (response, _) = self.controller.poll(ofp.OFPT_PACKET_IN, 2)
        # self.assertIsNone() is preferable for newer python
        self.assertFalse(response is not None, "PacketIn message is received")
        (_, rcv_pkt, _) = self.dataplane.poll(timeout=5)
        self.assertFalse(rcv_pkt is not None, "Packet on dataplane")

        #'reset table3 miss to controller'
        #testutils.set_table_config(self, testutils.EX_L2_TABLE, ofp.OFPTC_TABLE_MISS_CONTROLLER, True)


class ExactTableMissPacketIn(basic.SimpleDataPlane):
    """
    Exact table miss packet in
    """
    def runTest(self):
        of_ports = testutils.clear_switch(self, exact_port_map.keys(), exact_logger)#zhaoxiuchu
        vlan_tags=[{'type': 0x8100, 'vid': 3, 'pcp': 1}]
        mpls_tags=[{'type': 0x8847, 'label': 22, 'tc': 2, 'ttl': 48}]
        ing_port = exact_port_map.keys()[0]
        egr_port = exact_port_map.keys()[1]
        #"clear swtich;"
        #testutils.delete_all_flows(self.controller, self.logger)
        'make packet'
        pkt = testutils.simple_tcp_packet(dl_src='00:01:02:03:04:05', dl_dst='00:06:07:08:09:0a', \
                                            vlan_tags = vlan_tags, mpls_tags = mpls_tags)
        'table 0 goto table3'
        match_ls = testutils.packet_to_exact_flow_match(pkt = pkt, table_id = testutils.EX_ACL_TABLE, ing_port = ing_port)
        exact_table_goto_table(self, testutils.EX_ACL_TABLE, testutils.EX_L2_TABLE, match_ls)
        "set table 3 not match, continue"
        testutils.set_table_config(self, testutils.EX_L2_TABLE, ofp.OFPTC_TABLE_MISS_CONTROLLER, True)
        'table 4 output'
        match_ls = testutils.packet_to_exact_flow_match(pkt = pkt, table_id = testutils.EX_VLAN_TABLE, ing_port = ing_port)
        exact_table_output(self, testutils.EX_VLAN_TABLE, match_ls, egr_port = egr_port)

        "send a packet from ing_port "
        self.dataplane.send(ing_port, str(pkt))
         # checks no response from controller and dataplane
        (response, _) = self.controller.poll(ofp.OFPT_PACKET_IN, 2)
        # self.assertIsNone() is preferable for newer python
        self.assertTrue(response is not None, "PacketIn message is not received")
        (_, rcv_pkt, _) = self.dataplane.poll(timeout=5)
        self.assertFalse(rcv_pkt is not None, "Packet on dataplane")

        #'reset table3 miss to controller'
        #testutils.set_table_config(self, 3, ofp.OFPTC_TABLE_MISS_CONTROLLER, True)


class AllTableGotoThrough(basic.SimpleDataPlane):

    def runTest(self):
        vlan_tags=[{'type': 0x8100, 'vid': 1, 'pcp': 1}]
        #mpls_tags=[{'type': 0x8847, 'label': 22, 'tc': 2, 'ttl': 48}]

        pkt = testutils.simple_icmp_packet(
                                    dl_dst='00:01:02:03:04:05',
                                    dl_src='00:06:07:08:09:0a',
                                    vlan_tags=vlan_tags,
                                    mpls_tags=[],
                                    ip_src='192.168.0.55',
                                    ip_dst='192.168.3.254',
                                    ip_tos=5,
                                    ip_ttl=47,
                                    icmp_type=8,
                                    icmp_code=0,
                                    payload_len=100)

        of_ports = exact_port_map.keys()
        for dp_port1 in of_ports:
            ing_port = dp_port1
            for dp_port2 in of_ports:
                if dp_port2 != dp_port1:
                    egr_port = dp_port2

                    #match_ls = testutils.packet_to_exact_flow_match(pkt, None, testutils.EX_ACL_TABLE, ing_port)
                    #exact_table_goto_table(self, testutils.EX_ACL_TABLE, testutils.WC_ACL_TABLE, match_ls)

                    match_ls = testutils.packet_to_exact_flow_match(pkt, None, testutils.WC_ACL_TABLE, ing_port)
                    exact_table_goto_table(self, testutils.WC_ACL_TABLE, testutils.WC_SERV_TABLE, match_ls)

                    match_ls = testutils.packet_to_exact_flow_match(pkt, None, testutils.WC_SERV_TABLE, ing_port)
                    exact_table_goto_table(self, testutils.WC_SERV_TABLE, testutils.EX_L2_TABLE, match_ls)

                    match_ls = testutils.packet_to_exact_flow_match(pkt, None, testutils.EX_L2_TABLE, ing_port)
                    exact_table_goto_table(self, testutils.EX_L2_TABLE, testutils.EX_VLAN_TABLE, match_ls)

                    match_ls = testutils.packet_to_exact_flow_match(pkt, None, testutils.EX_VLAN_TABLE, ing_port)
                    exact_table_goto_table(self, testutils.EX_VLAN_TABLE, testutils.EX_MPLS_TABLE, match_ls)

                    match_ls = testutils.packet_to_exact_flow_match(pkt, None, testutils.EX_MPLS_TABLE, ing_port)
                    exact_table_goto_table(self, testutils.EX_MPLS_TABLE, testutils.EX_L3_TABLE, match_ls)

                    match_ls = testutils.packet_to_exact_flow_match(pkt, None, testutils.EX_L3_TABLE, ing_port)
                    exact_table_goto_table(self, testutils.EX_L3_TABLE, testutils.WC_L3_TABLE, match_ls)

                    match_ls = testutils.packet_to_exact_flow_match(pkt, None, testutils.WC_L3_TABLE, ing_port)
                    exact_table_goto_table(self, testutils.WC_L3_TABLE, testutils.EX_ICMP_TABLE, match_ls)

                    match_ls = testutils.packet_to_exact_flow_match(pkt, None, testutils.EX_ICMP_TABLE, ing_port)
                    exact_table_goto_table(self, testutils.EX_ICMP_TABLE, testutils.WC_ALL_TABLE, match_ls)

                    match_ls = testutils.packet_to_exact_flow_match(pkt, None, testutils.WC_ALL_TABLE, ing_port)
                    exact_table_output(self, testutils.WC_ALL_TABLE, match_ls, egr_port = egr_port)

                    self.dataplane.send(ing_port, str(pkt))
                    testutils.receive_pkt_verify(self, egr_port, pkt)


class ExactEntryPktCheck(basic.SimpleDataPlane):
    """
    exact entry PktCheck out test;
    """
    def runTest(self):
        of_ports = exact_port_map.keys()
        ing_port = of_ports[0]
        egr_port = of_ports[1]
        table_id = testutils.EX_ACL_TABLE

        "clear swtich;"
        testutils.delete_all_flows(self.controller, self.logger)
        "make test packet;"
        pkt = testutils.simple_tcp_packet()
        "construct flow entry"
        match_ls = testutils.packet_to_exact_flow_match(pkt, None, table_id, ing_port)
        flow_add = testutils.flow_msg_create(self, pkt, match_fields = match_ls, egr_port = egr_port, table_id = table_id)

        testutils.ofmsg_send(self, flow_add)

        "read flow back;"
        response = testutils.flow_stats_get(self, match_ls, table_id)
        self.assertTrue(len(response.stats) != 0, "stats len is 0")

        "send a packet from ing_port "
        self.dataplane.send(ing_port, str(pkt))
        "poll from the egr_port port"
        testutils.receive_pkt_verify(self, egr_port, pkt)

