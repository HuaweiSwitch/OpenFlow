'''
Created on Jan 27, 2011

@author: capveg
'''

import logging
import oftest.dataplane as dataplane
import basic
import testutils
from oftest import cstruct as ofp
import oftest.action as action
import oftest.instruction as instruction

import oftest.match as match
import oftest.message as message
from oftest.match_list import match_list

import ipaddr
import random

def test_set_init(config):
    """
    Set up function for flow_mods test classes

    @param config The configuration dictionary; see oft
    """

    global flow_mods_port_map
    global flow_mods_logger
    global flow_mods_config

    flow_mods_logger = logging.getLogger("flow_mods")
    flow_mods_logger.info("Initializing test set")
    flow_mods_port_map = config["port_map"]
    flow_mods_config = config

class FlowMod_ModifyStrict(basic.SimpleProtocol):
    """ Simple FlowMod Modify test
    delete all flows in the table
    insert an exact match flow_mod sending to port[1]
    then swap the output action from port[1] to port[2]
    then get flow_stats
    assert that the new actions are in place
    """
    def runTest(self):
        ing_port = flow_mods_port_map.keys()[0]
        out_port1 = flow_mods_port_map.keys()[1]
        out_port2 = flow_mods_port_map.keys()[2]
        pkt = testutils.simple_tcp_packet()
        testutils.delete_all_flows(self.controller, self.logger)
        fm_orig = testutils.flow_msg_create(self, pkt,
                                            ing_port=ing_port,
                                            egr_port=out_port1)
        fm_new = testutils.flow_msg_create(self, pkt,
                                            ing_port=ing_port,
                                            egr_port=out_port2)
        fm_new.command = ofp.OFPFC_MODIFY_STRICT
        testutils.ofmsg_send(self, fm_orig)
        testutils.ofmsg_send(self, fm_new)
        flow_stats = testutils.flow_stats_get(self)
        self.assertEqual(len(flow_stats.stats),1,
                         "Expected only one flow_mod")
        stat = flow_stats.stats[0]
        #self.assertEqual(stat.match_fields, fm_new.match_fields)
        self.assertEqual(stat.instructions, fm_new.instructions, "instructions not equal !")
        # @todo consider adding more tests here

class FlowMod_ModifyStrict2(basic.SimpleProtocol):
    """ Simple FlowMod Modify test 2
    1)delete all flows in the table
    2)insert an flow_mod(inport=ANY) sending to port[1]
    3)when in_port=ing_port[1],modify_strict; fail to then swap the output action from port[1] to port[2]
    4)then get flow_stats
    5)assert that the new actions are in place
    """
    def runTest(self):
        ing_port = flow_mods_port_map.keys()[0]
        out_port1 = flow_mods_port_map.keys()[1]
        out_port2 = flow_mods_port_map.keys()[2]
        pkt = testutils.simple_tcp_packet()
        testutils.delete_all_flows(self.controller, self.logger)
        fm_orig = testutils.flow_msg_create(self, pkt,
                                            ing_port=ofp.OFPP_ANY,
                                            egr_port=out_port1,
                                            table_id=2)
        fm_new = testutils.flow_msg_create(self, pkt,
                                            ing_port=ing_port,
                                            egr_port=out_port2,
                                            table_id=2)
        fm_new.command = ofp.OFPFC_MODIFY_STRICT
        testutils.ofmsg_send(self, fm_orig)

        testutils.ofmsg_send(self, fm_new)

        flow_stats = testutils.flow_stats_get(self)
        #print(flow_stats.show())
        self.assertEqual(len(flow_stats.stats),1,
                         "Expected only one flow_mod")
                         
        #fail to modify and instruction will remain the same
        stat = flow_stats.stats[0]
        self.assertEqual(stat.match, fm_orig.match)                  
        self.assertEqual(stat.instructions, fm_orig.instructions)  
        # @todo consider adding more tests here

class FlowModExactAddWildDel(basic.SimpleProtocol):
    """
        Add an entry to an exact flowtable, then del this entry
    """
    def runTest(self):
        ing_port = flow_mods_port_map.keys()[0]
        egr_port = flow_mods_port_map.keys()[1]
        table_id = testutils.EX_L3_TABLE
        flow_count = 10

        testutils.delete_all_flows_one_table(self.controller, self.logger, table_id)
        match_fields_ls = []
        ipv6_src_addr = 'fe80::2420:52ff:fe8f:5188'
        metadata_val = 0xaa22334455667788
        for i in range(flow_count):
            match_fields_ls.append(match_list())
            match_fields_ls[i].add(match.eth_type(testutils.IPV6_ETHERTYPE))
            match_fields_ls[i].add(match.ipv6_src(ipaddr.IPv6Address(ipv6_src_addr)))
            ipv6_dst_addr = 'fe80::2420:52ff:fe8f:' + str(5190+i)
            match_fields_ls[i].add(match.ipv6_dst(ipaddr.IPv6Address(ipv6_dst_addr)))
            match_fields_ls[i].add(match.metadata(metadata_val))

            request = testutils.flow_msg_create(self, None, ing_port=ing_port, 
                                    match_fields = match_fields_ls[i], egr_port = egr_port, table_id = table_id)
            testutils.flow_msg_install(self, request, False)

        match_fields = match_list()
        match_fields.add(match.eth_type(testutils.IPV6_ETHERTYPE))
        match_fields.add(match.ipv6_src(ipaddr.IPv6Address(ipv6_src_addr)))

        response = testutils.flow_stats_get(self, table_id = table_id)
        self.assertTrue(len(response.stats) == flow_count,
                    'Did not add all flows successfully! Get table entry num is %d'  %len(response.stats))

        request = testutils.flow_msg_create(self, None, None, ing_port, match_fields, table_id = table_id)
        request.command = ofp.OFPFC_DELETE
        testutils.flow_msg_install(self, request, False)

        response = testutils.flow_stats_get(self, table_id = table_id)
        
        self.assertTrue(len(response.stats) == 0,
                    'Switch did not del the flow entry! Current table entry num is %d' %len(response.stats))
class InstructionDuplicated (basic.SimpleProtocol):
    """ Switch must return error if instructions are duplicated
    """
    def runTest(self):
        ing_port = flow_mods_port_map.keys()[0]
        out_port1 = flow_mods_port_map.keys()[1]
        out_port2 = flow_mods_port_map.keys()[2]
        pkt = testutils.simple_tcp_packet()
        testutils.delete_all_flows(self.controller, self.logger)
        fm_orig = testutils.flow_msg_create(self, pkt,
                                            ing_port=ing_port,
                                            egr_port=out_port1)
        inst = None
        inst = instruction.instruction_write_actions()#instruct is the same, action is different
        act = action.action_output()
        act.port = out_port2
        rv = inst.actions.add(act)
        self.assertTrue(rv, "Could not add action" + act.show())
        fm_orig.instructions.add(inst)
        #print(fm_orig.show())
        testutils.ofmsg_send(self, fm_orig)
        (response, raw) = self.controller.poll(ofp.OFPT_ERROR, 5)
        self.assertTrue(response is not None, 'No error message received')
        self.assertEqual(ofp.OFPET_BAD_INSTRUCTION, response.type,
                       'Error message type mismatch: ' +
                       str(ofp.OFPET_BAD_INSTRUCTION,) + " != " +
                       str(response.type))
        self.assertEqual(ofp.OFPBIC_UNKNOWN_INST, response.code,
                       'Error message code mismatch: ' +
                       str(ofp.OFPBIC_UNKNOWN_INST) + " != " +
                       str(response.code))

        #error_verify(self, ofp.OFPET_BAD_INSTRUCTION, ofp.OFPBAC_BAD_ARGUMENT)        
class InconsistentMatch2(basic.SimpleProtocol):
    """Try to match both a IPV6 ethertpe and a IPV4 source, switch should
    return error
    """
    def runTest(self):
        ing_port = flow_mods_port_map.keys()[0]
        out_port1 = flow_mods_port_map.keys()[1]

        testutils.delete_all_flows(self.controller, self.logger)
        flow_add = message.flow_mod()
        flow_add.buffer_id = 0xffffffff;
        flow_add.header.xid = 123
        flow_add.table_id = 0
        flow_add.command = ofp.OFPFC_ADD
        flow_add.match_fields.add(match.eth_type(value = 0x86dd))
        flow_add.match_fields.add(match.ipv4_src(value = 3232235521))
        flow_add.match_fields.add(match.ipv4_dst(value = 3232235522))
        flow_add.match_fields.add(match.metadata(value = 0))
        "new a instruction"
        inst = instruction.instruction_write_actions()
        "new a output actions"
        act = action.action_output()
        act.port = out_port1
        inst.actions.add(act)
        flow_add.instructions.add(inst)
        #self.controller.message_send(flow_add)
        #print(flow_add.show())
	testutils.ofmsg_send(self, flow_add)

        (response, raw) = self.controller.poll(ofp.OFPT_ERROR, 2)
        self.assertTrue(response is not None, 'No error message received')
        self.assertEqual(ofp.OFPET_BAD_MATCH, response.type,
                       'Error message type mismatch: ' +
                       str(ofp.OFPET_BAD_MATCH) + " != " +
                       str(response.type))
        self.assertEqual(ofp.OFPBMC_BAD_PREREQ, response.code,
                       'Error message code mismatch: ' +
                       str(ofp.OFPBMC_BAD_PREREQ) + " != " +
                       str(response.code))

class FloodPlusIngress(basic.SimpleDataPlane):
    """ Switch must return error if instructions are duplicated
    """
    def runTest(self):
        ing_port = flow_mods_port_map.keys()[0]
        out_port1 = ofp.OFPP_FLOOD
        pkt = testutils.simple_tcp_packet()
        testutils.delete_all_flows(self.controller, self.logger)
        fm_orig = testutils.flow_msg_create(self, pkt,
                                            ing_port=ing_port,
                                            egr_port=out_port1)#flood
        inst = None
        inst = instruction.instruction_apply_actions()
        act = action.action_output()
        act.port = ofp.OFPP_IN_PORT #fwd to ingress
        rv = inst.actions.add(act)
        self.assertTrue(rv, "Could not add action" + act.show())
        fm_orig.instructions.add(inst)
        #print(fm_orig.show())
        testutils.ofmsg_send(self, fm_orig)
        (response, raw) = self.controller.poll(ofp.OFPT_ERROR, 2)
        self.assertTrue(response is None, 'Receive error message')
        #user sends packet
        self.dataplane.send(ing_port, str(pkt))
	testutils.do_barrier(self.controller)
        #verify pkt
        for of_ports in flow_mods_port_map.keys():
            testutils.receive_pkt_verify(self, of_ports, pkt)

class DirectTwoPorts(basic.SimpleDataPlane):
    """ Switch must return error if instructions are duplicated
    """
    def runTest(self):
        ing_port = flow_mods_port_map.keys()[0]
        out_port1 = flow_mods_port_map.keys()[1]
        out_port2 = flow_mods_port_map.keys()[2]
        pkt = testutils.simple_tcp_packet()
        testutils.delete_all_flows(self.controller, self.logger)
        fm_orig = testutils.flow_msg_create(self, pkt,
                                            ing_port=ing_port,
                                            egr_port=out_port1)
        inst = None
        inst = instruction.instruction_apply_actions()
        act = action.action_output()
        act.port = out_port2
        rv = inst.actions.add(act)
        self.assertTrue(rv, "Could not add action" + act.show())
        fm_orig.instructions.add(inst)
        #print(fm_orig.show())
        testutils.ofmsg_send(self, fm_orig)
        (response, raw) = self.controller.poll(ofp.OFPT_ERROR, 2)
        self.assertTrue(response is None, 'Receive error message')
        #user sends packet
        self.dataplane.send(ing_port, str(pkt))
        testutils.do_barrier(self.controller)
        #verify pkt
        testutils.receive_pkt_verify(self, flow_mods_port_map.keys()[1], pkt)
        testutils.receive_pkt_verify(self, flow_mods_port_map.keys()[2], pkt)

class AllPlusIngress(basic.SimpleDataPlane):
    """ Switch must return error if instructions are duplicated
    """
    def runTest(self):
        ing_port = flow_mods_port_map.keys()[0]
        out_port1 = ofp.OFPP_ALL
        pkt = testutils.simple_tcp_packet()
        testutils.delete_all_flows(self.controller, self.logger)
        fm_orig = testutils.flow_msg_create(self, pkt,
                                            ing_port=ing_port,
                                            egr_port=out_port1)#flood
        inst = None
        inst = instruction.instruction_apply_actions()
        act = action.action_output()
        act.port = ofp.OFPP_IN_PORT #fwd to ingress
        rv = inst.actions.add(act)
        self.assertTrue(rv, "Could not add action" + act.show())
        fm_orig.instructions.add(inst)
        #print(fm_orig.show())
        testutils.ofmsg_send(self, fm_orig)
        (response, raw) = self.controller.poll(ofp.OFPT_ERROR, 2)
        self.assertTrue(response is None, 'Receive error message')
        #user sends packet
        self.dataplane.send(ing_port, str(pkt))
        testutils.do_barrier(self.controller)
        #verify pkt
        for of_port in flow_mods_port_map.keys():
            testutils.receive_pkt_verify(self, of_port, pkt)

if __name__ == "__main__":
    print "Please run through oft script:  ./oft --test_spec=flow_mods"
