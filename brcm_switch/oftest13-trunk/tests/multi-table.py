'''
Created on Dec 14, 2010

@author: capveg
'''
import logging

import oftest.match as match
import oftest.cstruct as ofp
import oftest.message as message
import oftest.action as action
import oftest.parse as parse
import oftest.instruction as instruction
import basic

from oftest.match_list import match_list

import testutils

OFPMT_STANDARD_LENGTH = 128
MT_TEST_DL_TYPE = 0x800
test_prio = {}

def test_set_init(config):
    """
    Set up function for packet action test classes

    @param config The configuration dictionary; see oft
    """

    global pa_port_map
    global pa_logger
    global pa_config

    pa_logger = logging.getLogger("multi-table")
    pa_logger.info("Initializing test set")
    pa_port_map = config["port_map"]
    pa_config = config


class TwoTable(basic.SimpleDataPlane):
    """
    NOTE Zoltan: This test is not correct. It assumes that the action set of the packet will be executed
    when no match is found. However in that case the table config is executed, which will send the packet
    in a packet-in.

    Simple two table test

    Add two flow entries:
    Table 0 Match IP Src A; send to 1, goto 1
    Table 1 Match TCP port B; send to 2

    Then send in 2 packets:
    IP A, TCP C; expect out port 1
    IP A, TCP B; expect out port 2

    Lots of negative tests are not checked
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")

        # Clear flow table
        rv = testutils.initialize_table_config(self)
        self.assertEqual(rv, 0, "Failed to initialize table config")
        rv = testutils.delete_all_flows(self.controller, pa_logger)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        # Set up first match,fengqiang modify at 20130109
        testutils.write_goto_output(self, testutils.EX_ACL_TABLE, testutils.WC_ACL_TABLE, of_ports[0])

        # Set up fourth match,fengqiang modify at 20130109
        testutils.write_output(self, testutils.WC_ACL_TABLE, of_ports[1])    
        
        # Generate a packet matching both flow 1 and flow 2; rcv on port[1]
        pkt = testutils.simple_tcp_packet(ip_src = testutils.MT_TEST_IP)
        self.dataplane.send(of_ports[2], str(pkt))
        (rcv_port, rcv_pkt, _) = self.dataplane.poll(timeout=5)
        self.assertTrue(rcv_pkt is not None, "Did not receive packet")
        pa_logger.debug("Packet len " + str(len(rcv_pkt)) + " in on " +
                        str(rcv_port))
        self.assertEqual(rcv_port, of_ports[1], "Unexpected receive port")
        

class MultiTableWrite(basic.SimpleDataPlane):
    """
    multi table write test case;
    """
    def runTest(self):
        #testutils.skip_message_emit(self, 'skip!')
        #return
        #'instruction goto'
        inst_goto = instruction.instruction_goto_table()
        #'instruction table 0'
        inst = instruction.instruction_write_actions()
        #"action setfield"
        act = action.action_set_field()
        inst.actions.add(act)
        #"action output"
        act = action.action_output()
        act.port = 1
        inst.actions.add(act)
        #"table 0 instructions"
        request = message.flow_mod()
        request.table_id = 0
        request.instructions.add(inst)
        inst_goto.table_id = 1;
        request.instructions.add(inst_goto)

#fengqiang 00107390 create the testcase at 20130109
class MultiTableGoto(basic.SimpleDataPlane):
    """
    NOTE Zoltan: This test is not correct. It assumes that the action set of the packet will be executed
    when no match is found. However in that case the table config is executed, which will send the packet
    in a packet-in.

    Simple three table test for "goto"

    Lots of negative tests are not checked
    """
    def runTest(self):
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set up first match
        testutils.write_goto(self, testutils.WC_ACL_TABLE, testutils.WC_SERV_TABLE)

        # Set up second match
        testutils.write_goto(self, testutils.WC_SERV_TABLE, testutils.EX_L2_TABLE, of_ports[2])

        # Set up third match
        testutils.write_goto(self, testutils.EX_L2_TABLE, testutils.EX_L3_TABLE)
        
        # Set up fourth match
        testutils.write_output(self, testutils.EX_L3_TABLE, of_ports[1])

        # Generate a packet matching flow 1, 2, and 3; rcv on port[1]
        testutils.reply_check_dp(self, tcp_sport=1234,
                       ing_port = of_ports[2], egr_port = of_ports[1])
                       
#fengqiang 00107390 create the testcase at 20130109
class MultiTableGoto1(basic.SimpleDataPlane):
     def runTest(self):
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set up first match
        testutils.write_goto(self, testutils.WC_ACL_TABLE, testutils.EX_L2_TABLE)

        # Set up second match
        testutils.write_goto(self, testutils.WC_SERV_TABLE, testutils.EX_L2_TABLE, of_ports[2])

        # Set up third match
        testutils.write_goto(self, testutils.EX_L2_TABLE, testutils.EX_L3_TABLE)
        
        # Set up fourth match
        testutils.write_output(self, testutils.EX_L3_TABLE, of_ports[1])

        # Generate a packet matching flow 1, 2, and 3; rcv on port[1]
        testutils.reply_check_dp(self, tcp_sport=1234,
                       ing_port = of_ports[2], egr_port = of_ports[1])
#fengqiang 00107390 create the testcase at 20130109
class MultiTableGoto2(basic.SimpleDataPlane):
     def runTest(self):
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set up first match
        testutils.write_goto(self, testutils.WC_ACL_TABLE, testutils.EX_L3_TABLE)

        # Set up second match
        testutils.write_goto(self, testutils.WC_SERV_TABLE, testutils.EX_L2_TABLE, of_ports[2])

        # Set up third match
        testutils.write_goto(self, testutils.EX_L2_TABLE, testutils.EX_L3_TABLE)
        
        # Set up fourth match
        testutils.write_output(self, testutils.EX_L3_TABLE, of_ports[1])

        # Generate a packet matching flow 1, 2, and 3; rcv on port[1]
        testutils.reply_check_dp(self, tcp_sport=1234,
                       ing_port = of_ports[2], egr_port = of_ports[1])
                       
#fengqiang 00107390 create the testcase at 20130109
class MultiTableGotoAndSendport(basic.SimpleDataPlane):
    """
    Simple three table test for "goto and send to output port"

    Lots of negative tests are not checked
    """
    def runTest(self):
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set up first match
        testutils.write_goto(self, testutils.WC_ACL_TABLE, testutils.WC_SERV_TABLE)

        # Set up second match
        testutils.write_goto_output(self, testutils.WC_SERV_TABLE, testutils.EX_L2_TABLE, of_ports[0], of_ports[1])

        # Set up third match
        testutils.write_output(self, testutils.EX_L2_TABLE, of_ports[2])
        
        # Generate a packet and receive 3 responses
        pkt = testutils.simple_tcp_packet(ip_src = testutils.MT_TEST_IP)
        self.dataplane.send(of_ports[1], str(pkt))

        testutils.receive_pkt_verify(self, of_ports[2], pkt)

#fengqiang 00107390 create the testcase at 20130109
class MultiTableNoGoto(basic.SimpleDataPlane):
    """
    Simple four table test for "No-goto"

    Lots of negative tests are not checked
    """
    def runTest(self):
        """
        Add four flow entries:
        First Table; Match IP Src A; goto Second Table
        Second Table; Match IP Src A; send to 1, goto Third Table
        Third Table; Match IP Src A; do nothing // match but stop pipeline
        Fourth Table; Match IP Src A; send to 2  // not match, just a fake

        Then send in 2 packets:
        IP A, TCP C; expect out port 1
        IP A, TCP B; expect out port 1

        @param self object instance
        @param EX_ACL_TABLE first table
        @param WC_ACL_TABLE second table
        @param WC_SERV_TABLE third table
        @param EX_VLAN_TABLE fourth table
        """
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set up first match
        testutils.write_goto(self, testutils.EX_ACL_TABLE, testutils.WC_ACL_TABLE)

        # Set up second match
        testutils.write_goto_output(self, testutils.WC_ACL_TABLE, testutils.WC_SERV_TABLE, of_ports[0])

        # Set up third match
        testutils.write_output(self, testutils.WC_SERV_TABLE, of_ports[1], of_ports[2])

        # Set up fourth match
        testutils.write_output(self, testutils.EX_VLAN_TABLE, of_ports[1])

        # Generate a packet matching flow 1, 2, and 3; rcv on port[0]
        testutils.reply_check_dp(self, tcp_sport=1234,
                       ing_port = of_ports[2], egr_port = of_ports[1])

#fengqiang 00107390 create the testcase at 20130115
class MultiTablePolicyDecoupling(basic.SimpleDataPlane):
    """
    Simple two-table test for "policy decoupling"

    Lots of negative tests are not checked
    """
    def runTest(self):
        """
        Add flow entries:
        First Table; Match IP Src A; set ToS = tos1, goto Second Table
        First Table; Match IP Src B; set ToS = tos2, goto Second Table
        Second Table; Match IP Src A; send to 1
        Second Table; Match IP Src B; send to 1

        Then send packets:
        IP A;  expect port 1 with DSCP = dscp1
        IP B;  expect port 1 with DSCP = dscp2

        @param self object instance
        @param EX_ACL_TABLE first table
        @param WC_ACL_TABLE second table
        @param dscp1 DSCP value to be set for first flow
        @param dscp2 DSCP value to be set for second flow
        """
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set up flow match in table A: set ToS
        #t_act = action.action_set_nw_tos()
        #t_act.nw_tos = tos1
        dscp1 = 4
        dscp2 = 8
        t_act = action.action_set_field()
        t_act.field = match.ip_dscp(dscp1)
        testutils.write_goto_action(self, testutils.WC_ACL_TABLE, testutils.WC_ALL_TABLE, t_act,
                          ip_src='192.168.1.10')
        t_act.field = match.ip_dscp(dscp2)
        #t_act.field = match.ip_ecn(3)
        testutils.write_goto_action(self, testutils.WC_ACL_TABLE, testutils.WC_ALL_TABLE, t_act,
                          ip_src='192.168.1.30',clear_tag=False)

        # Set up flow matches in table B: routing
        testutils.write_output(self, testutils.WC_ALL_TABLE, of_ports[1], of_ports[2], ip_src="192.168.1.10")
        testutils.write_output(self, testutils.WC_ALL_TABLE, of_ports[1], of_ports[2], ip_src="192.168.1.30")

        # Generate packets and check them
        exp_pkt = testutils.simple_tcp_packet(ip_src='192.168.1.10',
                                              tcp_sport=1234, ip_dscp=dscp1)
        testutils.reply_check_dp(self, ip_src='192.168.1.10', tcp_sport=1234,
                 exp_pkt=exp_pkt, ing_port=of_ports[2], egr_port=of_ports[1])

        #exp_pkt = testutils.simple_tcp_packet(ip_src='192.168.1.30',
                                              #tcp_sport=10, ip_tos=tos2)
        #testutils.reply_check_dp(self, ip_src='192.168.1.30', tcp_sport=10,
                 #exp_pkt=exp_pkt, ing_port=of_ports[2], egr_port=of_ports[1])


#fengqiang 00107390 create the testcase at 20130109
class MultiTableClearAction(basic.SimpleDataPlane):
    """
    Simple four table test for "ClearAction"

    Lots of negative tests are not checked
    """
    def runTest(self):
        """
        Add four flow entries:
        First Table; Match IP Src A; goto Second Table
        Second Table; Match IP Src A; send to 1, goto Third Table
        Third Table; Match IP Src A; clear action, goto Fourth Table
        Fourth Table; Match IP Src A; send to 2

        Then send in 2 packets:
        IP A, TCP C; expect out port 1
        IP A, TCP B; expect out port 1

        @param self object instance
        @param EX_ACL_TABLE first table
        @param WC_ACL_TABLE second table
        @param WC_SERV_TABLE third table
        @param EX_L2_TABLE fourth table
        """
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set up first match
        #write_goto(self, testutils.EX_ACL_TABLE, testutils.WC_ACL_TABLE)
        act = action.action_set_field()
        field = match.eth_src(parse.parse_mac("aa:aa:aa:aa:aa:aa"))
        act.field.add(field)
        testutils.write_goto_action(self, testutils.WC_ACL_TABLE, testutils.WC_SERV_TABLE ,act = act)
        # Set up second match
        testutils.write_goto_output(self, testutils.WC_SERV_TABLE, testutils.EX_L3_TABLE, of_ports[0], of_ports[2])
        # Set up third match, "Clear Action"
        inst = instruction.instruction_clear_actions()
        testutils.write_goto(self, testutils.EX_L3_TABLE, testutils.WC_L3_TABLE, of_ports[2], add_inst=inst)
        # Set up fourth match
        testutils.write_output(self, testutils.WC_L3_TABLE, of_ports[1])
        #write_output(self, testutils.EX_L2_TABLE, 4)

        # Generate a packet matching flow 1, 2, and 3; rcv on port[1]
        testutils.reply_check_dp(self, tcp_sport=1234,
                       ing_port = of_ports[2], egr_port = of_ports[1])
        # Generate a packet matching flow 1, 2, and 3; rcv on port[1]
        #testutils.reply_check_dp(self, tcp_sport=10,
        #               ing_port = of_ports[2], egr_port = of_ports[1])


#fengqiang 00107390 create the testcase at 20130109
class MultiTableMetadata(basic.SimpleDataPlane):
    """
    Simple four table test for writing and matching "Metdata"

    Lots of negative tests are not checked
    """
    def runTest(self):
        """
        Add four flow entries:
        First Table; Match IP Src A; send to 1, goto Second Table
        Second Table; Match IP Src A; write metadata, goto Third Table
        Third Table; Match IP Src A and metadata; send to 2 // stop, do action
        Fourth Table; Match IP Src A; send to 1 // not match, just a trap

        Then send in 2 packets:
        IP A, TCP C; expect out port 2
        IP A, TCP B; expect out port 2

        @param self object instance
        @param EX_ACL_TABLE first table
        @param WC_ACL_TABLE second table
        @param WC_SERV_TABLE third table
        @param EX_VLAN_TABLE fourth table
        """
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set up first match
        testutils.write_goto_output(self, testutils.WC_ACL_TABLE, testutils.WC_SERV_TABLE, of_ports[0])

        # Set up second match
        inst = instruction.instruction_write_metadata()
        inst.metadata = 0xfedcba9876543210
        inst.metadata_mask = 0xffffffffffffffff
        testutils.write_goto(self, testutils.WC_SERV_TABLE, testutils.EX_L2_TABLE, of_ports[2], add_inst=inst)

        # Set up third match
        pkt_metadata = {'metadata_val':inst.metadata, 'metadata_msk':inst.metadata_mask}
        match_fields = testutils.packet_to_exact_flow_match(pkt_metadata = pkt_metadata,
                                                            table_id = testutils.EX_L2_TABLE)

        testutils.write_output(self, testutils.EX_L2_TABLE, of_ports[1], match_fields=match_fields)

        # Set up fourth match
        #write_output(self, testutils.EX_VLAN_TABLE, of_ports[0])

        # Generate a packet matching flow 1, 2, and 3; rcv on port[1]
        testutils.reply_check_dp(self, tcp_sport=1234,
                       ing_port = of_ports[2], egr_port = of_ports[1])


class MultiTableEmptyInstruction(basic.SimpleDataPlane):
    """
    Simple four table test for "Empty Instruction"

    Lots of negative tests are not checked
    """
    def runTest(self):
        """
        ** Currently, same scenario with "NoGoto" **

        Add four flow entries:
        First Table; Match IP Src A; goto Second Table
        Second Table; Match IP Src A; send to 1, goto Third Table
        Third Table; Match IP Src A; do nothing // match but stop pipeline
        Fourth Table; Match IP Src A; send to 2  // not match, just a fake

        Then send in 2 packets:
        IP A, TCP C; expect out port 1
        IP A, TCP B; expect out port 1
        """
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set up first match
        testutils.write_goto(self, testutils.WC_ACL_TABLE, testutils.WC_SERV_TABLE)

        # Set up second match
        testutils.write_goto_output(self, testutils.WC_SERV_TABLE, testutils.EX_L2_TABLE,
                                                                        of_ports[0], of_ports[2])

        # Set up third match, "Empty Instruction"
        pkt = testutils.simple_tcp_packet()
        request = testutils.flow_msg_create(self, pkt, ing_port = of_ports[2], table_id = testutils.EX_L2_TABLE)
        testutils.flow_msg_install(self, request)

        # Set up fourth match
        testutils.write_output(self, testutils.EX_VLAN_TABLE, of_ports[1])

        # Generate a packet matching flow 1, 2, and 3; rcv on port[0]
        testutils.reply_check_dp(self, tcp_sport=1234,
                       ing_port = of_ports[2], egr_port = of_ports[0])
        # Generate a packet matching flow 1, 2, and 3; rcv on port[0]
        #testutils.reply_check_dp(self, tcp_sport=80,
        #               ing_port = of_ports[2], egr_port = of_ports[0])

class MultiTableMiss(basic.SimpleDataPlane):
    """
    Simple four table test for all miss (not match)

    Lots of negative tests are not checked
    """
    def runTest(self):
        """
        Add five flow entries:
        First Table; Match IP Src A; send to 1
        Second Table; Match IP Src B; send to 1
        Third Table; Match IP Src C; send to 1
        Fourth Table; Match IP Src D; send to 1

        Then send in 2 packets:
        IP F, TCP C; expect packet_in
        IP G, TCP B; expect packet_in

        @param self object instance
        @param first_table first table
        @param second_table second table
        @param third_table third table
        @param fourth_table fourth table
        """
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set up matches
        #write_output(self, testutils.EX_ACL_TABLE, 1, ip_src="192.168.1.10")
        #write_output(self, testutils.EX_ACL_TABLE, of_ports[0], ip_src="128.128.128.10")
        testutils.set_table_config(self, config = ofp.OFPTC_TABLE_MISS_CONTROLLER)
        testutils.write_output(self, testutils.WC_ACL_TABLE, of_ports[0], ip_src="192.168.1.10")
        testutils.write_output(self, testutils.WC_SERV_TABLE, of_ports[0],
                                                ing_port=of_ports[1], ip_src="192.168.1.20")
        testutils.write_output(self, testutils.EX_L2_TABLE, of_ports[0], ip_src="192.168.1.30")
        testutils.write_output(self, testutils.EX_L3_TABLE, of_ports[0], ip_src="192.168.1.40")

        # Generate a packet not matching to any flow, then packet_in
        testutils.reply_check_ctrl(self, ip_src='192.168.1.70', tcp_sport=1234,
                         ing_port = of_ports[2])

#fengqiang 00107390 create the testcase at 20130109
class MultiTableConfigContinue(basic.SimpleDataPlane):
    """
    Simple table config test for "continue"

    Lots of negative tests are not checked
    """
    def runTest(self):
        """
        Set table config as "Continue" and add flow entry:
        First Table; Match IP Src A; send to 1 // not match then continue
        Second Table; Match IP Src B; send to 2 // do execution

        Then send in 2 packets:
        IP B; expect out port 2
        """
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set table config as "continue"
        testutils.set_table_config(self, testutils.WC_ACL_TABLE, ofp.OFPTC_TABLE_MISS_CONTINUE, True)

        # Set up flow entries
        #write_output(self, testutils.EX_ACL_TABLE, of_ports[0], ip_src="192.168.1.10")
        testutils.write_output(self, testutils.WC_ACL_TABLE, of_ports[0], ip_src="192.168.1.10")
        testutils.write_output(self, testutils.WC_SERV_TABLE, of_ports[1], of_ports[2],
                                                                        ip_src="192.168.1.70")
        testutils.do_barrier(self.controller)

        # Generate a packet not matching in the first table, but in the second
        testutils.reply_check_dp(self, ip_src='192.168.1.70', tcp_sport=1234,
                       ing_port = of_ports[2], egr_port = of_ports[1])

#fengqiang 00107390 create the testcase at 20130109
class MultiTableConfigController(basic.SimpleDataPlane):
    """
    Simple table config test for "controller"

    Lots of negative tests are not checked
    """
    def runTest(self):
        """
        Set the first table config as "Send to Controller" and the second
        table as "Drop", add flow entries:
        First Table; Match IP Src A; send to 1 // if not match, packet_in
        Second Table; Match IP Src B; send to 2 // if not match, drop

        Then send a packet:
        IP B; expect packet_in
        """
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set table config as "send to controller" and "drop"
        testutils.set_table_config(self, testutils.WC_ACL_TABLE, ofp.OFPTC_TABLE_MISS_CONTROLLER, True)
        testutils.set_table_config(self, testutils.WC_SERV_TABLE, ofp.OFPTC_TABLE_MISS_DROP, True)

        # Set up matches
        testutils.write_output(self, testutils.WC_ACL_TABLE, of_ports[0], ip_src="192.168.1.10")
        testutils.write_output(self, testutils.WC_SERV_TABLE, of_ports[1], of_ports[2],
                                                                        ip_src="192.168.1.70")

        # Generate a packet not matching to any flow entry in the first table
        testutils.reply_check_ctrl(self, ip_src='192.168.1.70', tcp_sport=1234,
                         ing_port = of_ports[2])

#fengqiang 00107390 create the testcase at 20130109
class MultiTableConfigDrop(basic.SimpleDataPlane):
    """
    Simple table config test for "drop"

    Lots of negative tests are not checked
    """
    def runTest(self):
        """
        Set the first table config as "Drop" and second table as "Controller"
        add flow entry:
        First Table; Match IP Src A; send to 1 // if not match, then drop
        Second Table; Match IP Src B; send to 2 // if not match, controller

        Then send in a packet:
        IP B; expect drop
        """
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set table config as "drop" and "send to controller"
        testutils.set_table_config(self, testutils.WC_ACL_TABLE, ofp.OFPTC_TABLE_MISS_DROP, True)
        testutils.set_table_config(self, testutils.WC_SERV_TABLE, ofp.OFPTC_TABLE_MISS_CONTROLLER, True)

        # Set up first match
        testutils.write_output(self, testutils.WC_ACL_TABLE, of_ports[0], ip_src="192.168.1.10")
        testutils.write_output(self, testutils.WC_SERV_TABLE, of_ports[1], of_ports[2], 
                                                                        ip_src="192.168.1.70")

        # Generate a packet not matching to any flow, then drop
        pkt = testutils.simple_tcp_packet(ip_src='192.168.1.70', tcp_sport=10)
        self.dataplane.send(of_ports[2], str(pkt))
        # checks no response from controller and dataplane
        (response, _) = self.controller.poll(ofp.OFPT_PACKET_IN, 2)
        # self.assertIsNone() is preferable for newer python
        self.assertFalse(response is not None, "PacketIn message is received")
        (_, rcv_pkt, _) = self.dataplane.poll(timeout=5)
        self.assertFalse(rcv_pkt is not None, "Packet on dataplane")


class TwoTableApplyActGenericSimple(basic.SimpleDataPlane):
    """
    Test if apply_action on one table is effective to the next table
    Table0: Modify one field and apply
    Table1: Match against modified pkt and send out to a port
    Expect packet with a modification
    """
    def __init__(self):
        basic.SimpleDataPlane.__init__(self)

        self.base_pkt_params = {}
        self.base_pkt_params['dl_dst'] = '00:DE:F0:12:34:56'
        #self.base_pkt_params['dl_src'] = '00:23:45:67:89:AB'
#TODO        
        #self.base_pkt_params['vlan_tags'] = [{'vid': 2, 'pcp': 0}]
        #self.base_pkt_params['ip_src'] = '192.168.0.1'
        #self.base_pkt_params['ip_dst'] = '192.168.0.2'
        ##self.base_pkt_params['ip_tos'] = 0
        #self.base_pkt_params['tcp_sport'] = 1234
        #self.base_pkt_params['tcp_dport'] = 80
        self.start_pkt_params = self.base_pkt_params.copy()
#TODO        
        #self.start_pkt_params['vlan_tags'] = []

        self.mod_pkt_params = {}
        self.mod_pkt_params['dl_dst'] = '00:21:0F:ED:CB:A9'
        self.mod_pkt_params['dl_src'] = '00:ED:CB:A9:87:65'
#TODO        
        #self.mod_pkt_params['vlan_tags'] = [{'vid': 3, 'pcp': 7}]
        self.mod_pkt_params['ip_src'] = '10.20.30.40'
        self.mod_pkt_params['ip_dst'] = '50.60.70.80'
        self.mod_pkt_params['ip_tos'] = 0xf0
        self.mod_pkt_params['tcp_sport'] = 4321
        self.mod_pkt_params['tcp_dport'] = 8765

    def runTest(self):
        #testutils.skip_message_emit(self, 'action type set tc not support')
        #return
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # For making the test simpler...
        ing_port = of_ports[0]
        egr_port = of_ports[1]
        check_expire_tbl0 = False
        check_expire_tbl1 = False

        # Build the ingress packet
        pkt = testutils.simple_tcp_packet(**self.base_pkt_params)
        #print(pkt.show())
        # Set action for the first table
        for item_tbl0 in self.start_pkt_params:
            tbl0_pkt_params = self.base_pkt_params.copy()
            tbl0_pkt_params[item_tbl0] = self.mod_pkt_params[item_tbl0]
            act = testutils.action_generate(self, item_tbl0, tbl0_pkt_params)
            action_list = [act]

            inst_1 = instruction.instruction_apply_actions()
            inst_2 = instruction.instruction_goto_table()
            inst_2.table_id = 1
            inst_list = [inst_1, inst_2]
            request0 = testutils.flow_msg_create(self, pkt,
                              ing_port=ing_port,
                              instruction_list=inst_list,
                              action_list=action_list,
                              check_expire=check_expire_tbl0,
                              table_id=0,
                              inst_app_flag=testutils.APPLY_ACTIONS_INSTRUCTION)

            exp_pkt = testutils.simple_tcp_packet(**tbl0_pkt_params)

            request1 = testutils.flow_msg_create(self, exp_pkt,
                              ing_port=ing_port,
                              check_expire=check_expire_tbl1,
                              table_id=1,
                              egr_port=egr_port,
                              inst_app_flag=testutils.APPLY_ACTIONS_INSTRUCTION)
            #print(request0.show())
            #print(request1.show())
            # Insert two flows
            self.logger.debug("Inserting flows: Modify-field: " + item_tbl0)
            testutils.flow_msg_install(self, request0)
            testutils.flow_msg_install(self, request1)

            # Send pkt
            self.logger.debug("Send packet: " + str(ing_port) +
                              " to " + str(egr_port))
            self.dataplane.send(ing_port, str(pkt))

            #@todo Not all HW supports both pkt and byte counters
            #@todo We shouldn't expect the order of coming response..
            if check_expire_tbl0:
                flow_removed_verify(self, request0, pkt_count=1,
                                    byte_count=len(pkt))
            if check_expire_tbl1:
                flow_removed_verify(self, request1, pkt_count=1,
                                    byte_count=len(exp_pkt))
            # Receive and verify pkt
            #testutils.receive_pkt_verify(self, egr_port, exp_pkt)


class TwoTableApplyActGeneric2Mod(TwoTableApplyActGenericSimple):
    """
    Test if apply_action on one table is effective to the next table
    Table0: Modify one field and apply
    Table1: Match against modified pkt, modify another field and send out
    Expect packet with two modifications
    """
    def runTest(self):
        #testutils.skip_message_emit(self, 'action type set tc not support')
        #return
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # For making the test simpler...
        ing_port = of_ports[0]
        egr_port = of_ports[1]
        check_expire_tbl0 = False
        check_expire_tbl1 = False

        # Build the ingress packet
        pkt = testutils.simple_tcp_packet(**self.base_pkt_params)

        # Set action for the first table
        for item_tbl0 in self.start_pkt_params:
            tbl0_pkt_params = self.base_pkt_params.copy()
            tbl0_pkt_params[item_tbl0] = self.mod_pkt_params[item_tbl0]
            act = testutils.action_generate(self, item_tbl0, tbl0_pkt_params)
            action_list = [act]

            inst_1 = instruction.instruction_apply_actions()
            inst_2 = instruction.instruction_goto_table()
            inst_2.table_id = 1
            inst_list = [inst_1, inst_2]
            request0 = testutils.flow_msg_create(self, pkt,
                              ing_port=ing_port,
                              instruction_list=inst_list,
                              action_list=action_list,
                              check_expire=check_expire_tbl0,
                              table_id=0)

            mod_pkt = testutils.simple_tcp_packet(**tbl0_pkt_params)

            for item_tbl1 in self.start_pkt_params:
                if item_tbl1 == item_tbl0:
                    continue
                tbl1_pkt_params = tbl0_pkt_params.copy()
                tbl1_pkt_params[item_tbl1] = self.mod_pkt_params[item_tbl1]
                act = testutils.action_generate(self, item_tbl1,
                                                tbl1_pkt_params)
                self.assertTrue(act is not None, "Action not available")
                action_list = [act]

                request1 = testutils.flow_msg_create(self, mod_pkt,
                              ing_port=ing_port,
                              action_list=action_list,
                              check_expire=check_expire_tbl1,
                              table_id=1,
                              egr_port=egr_port)

                exp_pkt = testutils.simple_tcp_packet(**tbl1_pkt_params)

                # Insert two flows
                self.logger.debug("Inserting flows: Modify-fields: TBL0= " +
                                  item_tbl0 + ", TBL1= " + item_tbl1)
                testutils.flow_msg_install(self, request0)

                testutils.flow_msg_install(self, request1)

                # Send pkt
                self.logger.debug("Send packet: " + str(ing_port) +
                                  " to " + str(egr_port))
                self.dataplane.send(ing_port, str(pkt))

                #@todo Not all HW supports both pkt and byte counters
                #@todo We shouldn't expect the order of coming response..
                if check_expire_tbl0:
                    flow_removed_verify(self, request0, pkt_count=1,
                                        byte_count=len(pkt))
                if check_expire_tbl1:
                    flow_removed_verify(self, request1, pkt_count=1,
                                        byte_count=len(exp_pkt))
                # Receive and verify pkt
                testutils.receive_pkt_verify(self, egr_port, exp_pkt)


class MultiTableMissContinue(basic.SimpleDataPlane):
    """
    MultiTableMissContinue
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        ing_port = of_ports[1]
        egr_port = of_ports[2]

        "clear swtich;"
        testutils.delete_all_flows(self.controller, self.logger)
        # Set table config as "continue"
        testutils.set_table_config(self, testutils.EX_ACL_TABLE, ofp.OFPTC_TABLE_MISS_CONTINUE, True)
        testutils.set_table_config(self, testutils.WC_ACL_TABLE, ofp.OFPTC_TABLE_MISS_CONTINUE, True)
        testutils.set_table_config(self, testutils.WC_SERV_TABLE, ofp.OFPTC_TABLE_MISS_CONTROLLER, True)
        testutils.set_table_config(self, testutils.EX_L2_TABLE, ofp.OFPTC_TABLE_MISS_CONTINUE, True)
        testutils.set_table_config(self, testutils.EX_VLAN_TABLE, ofp.OFPTC_TABLE_MISS_CONTINUE, True)
        testutils.set_table_config(self, testutils.EX_MPLS_TABLE, ofp.OFPTC_TABLE_MISS_CONTINUE, True)
        testutils.set_table_config(self, testutils.EX_L3_TABLE, ofp.OFPTC_TABLE_MISS_CONTROLLER, True)

        #"make test packet;"
        pkt = testutils.simple_icmp_packet()

        inst_write_metadata = instruction.instruction_write_metadata();
        inst_write_metadata.metadata = 0x20000000
        inst_write_metadata.metadata_mask = 0xf0000000

        testutils.write_goto(self, testutils.WC_SERV_TABLE, testutils.EX_L2_TABLE, ing_port, add_inst = inst_write_metadata)

        pkt_metadata = {'metadata_val':inst_write_metadata.metadata, 
                        'metadata_msk':inst_write_metadata.metadata_mask}
        match_fields = testutils.packet_to_exact_flow_match(pkt_metadata = pkt_metadata, table_id = testutils.EX_L3_TABLE)
        testutils.write_output(self, testutils.EX_L3_TABLE, egr_port, match_fields=match_fields)

        testutils.reply_check_dp(self, tcp_sport=1234, ing_port = ing_port, egr_port = egr_port)
        
        testutils.set_table_config(self, testutils.EX_L3_TABLE, ofp.OFPTC_TABLE_MISS_CONTROLLER)

class MultiTableWriteMetadata(basic.SimpleDataPlane):
    """
    MultiTableMissContinue
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        ing_port = of_ports[1]
        egr_port =ofp.OFPP_CONTROLLER

        "clear swtich;"
        testutils.delete_all_flows(self.controller, self.logger)
        # Set table config as "continue"
        testutils.set_table_config(self, testutils.WC_ACL_TABLE, ofp.OFPTC_TABLE_MISS_CONTINUE, True)
        testutils.set_table_config(self, testutils.WC_SERV_TABLE, ofp.OFPTC_TABLE_MISS_DROP, True)
        testutils.set_table_config(self, testutils.EX_L2_TABLE, ofp.OFPTC_TABLE_MISS_CONTROLLER, True)

        #"make test packet;"
        pkt = testutils.simple_icmp_packet()

        inst_write_metadata = instruction.instruction_write_metadata();
        inst_write_metadata.metadata = 0x20000000
        inst_write_metadata.metadata_mask = 0xf0000000

        testutils.write_goto(self, testutils.WC_SERV_TABLE, testutils.EX_L2_TABLE, ing_port, add_inst = inst_write_metadata)

        pkt_metadata = {'metadata_val':inst_write_metadata.metadata, 'metadata_msk':inst_write_metadata.metadata_mask}
        match_fields = testutils.packet_to_exact_flow_match(pkt_metadata = pkt_metadata, table_id = testutils.EX_L2_TABLE)
        testutils.write_output(self, testutils.EX_L2_TABLE, egr_port, match_fields=match_fields)
        
        self.dataplane.send(ing_port, str(pkt))
        (response, _) = self.controller.poll(ofp.OFPT_PACKET_IN, 2)
        self.assertTrue(response is not None, 'Packet in message not received on port ' + str(egr_port))
        if str(pkt) != response.data:
               pa_logger.debug("pkt  len " + str(len(str(pkt))) +": " + str(pkt))
               pa_logger.debug("resp len " + str(len(str(response.data))) + ": " + str(response.data))
