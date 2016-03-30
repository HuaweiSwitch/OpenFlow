# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Pan Zhang
"""
Test suite 150 verifies the correct implementation of error messages associated with flow modification messages.
Basic conformance
To satisfy the basic requirements an OpenFlow enabled device must pass all test cases in this test suite.

"""

import logging

from oftest import config
import oftest.base_tests as base_tests
import oftest.parse as parse
import ofp
import oftest.packet as scapy
from loxi.pp import pp

from oftest.testutils import *
from oftest.oflog import *
from time import sleep

import BII_testgroup80
# import BII_testgroup430


class Testcase_150_10_Invalid_table(base_tests.SimpleDataPlane):
    """
    TODO: May add a method to select the invalid table id automatically
    Purpose
    Verify how "FLOW_MOD" with invalid TABLE-ID is handled. 

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow with matching on named field. Send OFPFC_DELETE flow_mod message for this flow with invalid table-id. Verify switch sends the ofp_error_msg with OFPET_FLOW_MOD_FAILED type and OFPFMFC_BAD_TABLE_ID code.  Verify that the flow remains installed.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.10 Invalid table")

        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(out_port)]
        match = ofp.match([
            ofp.oxm.eth_type(0x0800)
        ])
        #logging.info("Running actions test for %s", pp(actions))
        request = ofp.message.features_request()
        (reply, pkt)= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive Features Reply Message")
        tables_no = reply.n_tables 

        delete_all_flows(self.controller)
        pkt = simple_tcp_packet()

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

        request = ofp.message.flow_delete(
                table_id=tables_no+1, #invalid table id
                #match=packet_to_flow_match(self, pkt),
                match = match,
                out_port = ofp.OFPP_ANY,
                out_group = ofp.OFPG_ANY,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 1000)
        self.controller.message_send(request)
        logging.info("deleting the previous flow")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "Switch did not generated an error message")
        self.assertEqual(reply.err_type, ofp.OFPET_FLOW_MOD_FAILED,
                         ("Error type %d was received, but we expected "
                          "OFPET_FLOW_MOD_FAILED.") % reply.err_type)
        self.assertEqual(reply.code, ofp.OFPFMFC_BAD_TABLE_ID,
                         ("Flow mod failed code %d was received, but we "
                          "expected OFPFMFC_BAD_TABLE_ID.") % reply.code)
       
class Testcase_150_20_TableID_OFPTT_ALL(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify how "FLOW_MOD" with "OFPTT_ALL" in add or modify request is handled.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow with table-id OFPTT_ALL. Verify switch sends the ofp_error_msg with OFPET_flow_MOD_FAILED type and OFPFMFC_BAD_TABLE_ID code. Verify that the flow got not added to the flow tables. Add at least one flow to the flow table, and send a matching modify command with table-id OFPTT_ALL changing the action. Verify switch sends the ofp_error_msg with OFPET_flow_MOD_FAILED type and OFPFMFC_BAD_TABLE_ID code. Verify that the flow did not get modified. 

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.20 Modify with table-id OFPT_ALL")

        in_port, out_port, out_portY = openflow_ports(3)

        actions = [ofp.action.output(out_port)]
        match = ofp.match([
            ofp.oxm.eth_type(0x0800)
        ])
        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=ofp.OFPTT_ALL,
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d with table id = OFPTT_ALL", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "Switch did not generated an error message")
        self.assertEqual(reply.err_type, ofp.OFPET_FLOW_MOD_FAILED,
                         ("Error type %d was received, but we expected "
                          "OFPET_FLOW_MOD_FAILED.") % reply.err_type)
        self.assertEqual(reply.code, ofp.OFPFMFC_BAD_TABLE_ID,
                         ("Flow mod failed code %d was received, but we "
                          "expected OFPFMFC_BAD_TABLE_ID.") % reply.code)

        table_stats = get_stats(self, ofp.message.table_stats_request())
        self.assertEqual(table_stats[0].active_count, 0, "active flow count is not 0")

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

        request = ofp.message.flow_mod(
                table_id=ofp.OFPTT_ALL, #invalid table id
                #match=packet_to_flow_match(self, pkt),
                match = match,
                out_port = ofp.OFPP_ANY,
                out_group = ofp.OFPG_ANY,
                instructions=[
                    ofp.instruction.apply_actions([ofp.action.output(out_portY)])],
                buffer_id=ofp.OFP_NO_BUFFER, priority = 1000)
        self.controller.message_send(request)
        logging.info("modifying the previous flow with table_id OFPTT_ALL and output port %r", out_portY)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "Switch did not generated an error message")
        self.assertEqual(reply.err_type, ofp.OFPET_FLOW_MOD_FAILED,
                         ("Error type %d was received, but we expected "
                          "OFPET_FLOW_MOD_FAILED.") % reply.err_type)
        self.assertEqual(reply.code, ofp.OFPFMFC_BAD_TABLE_ID,
                         ("Flow mod failed code %d was received, but we "
                          "expected OFPFMFC_BAD_TABLE_ID.") % reply.code)

        self.dataplane.send(in_port, str(pkt))
        verify_packet(self, str(pkt),out_port)

class Testcase_150_30_Table_full(base_tests.SimpleDataPlane):
    """ 

    TODO: May suggest to the spec develop team about the real situation
    Purpose
    Verify how "OFPFC_ADD" is handled if table has no space.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, keep sending OFPFC_ADD flow_mod messages until no further flow can be added due to lack of space. Now, send  another OFPFC_ADD request, verify the switch sends ofp_error_msg with OFPET_flow_MOD_FAILED type and OFPFMFC_TABLE_FULL code.  Verify that the flow got not added to the flow tables.

    """
    
    def tearDown(self):
        delete_all_flows(self.controller)
        do_barrier(self.controller, timeout=15)
        base_tests.SimpleProtocol.tearDown(self)
        
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.30 Table full")
        delete_all_flows(self.controller)
        
        in_port, out_port = openflow_ports(2)
        flow_count = 0
        max_flow_num = test_param_get("maxflow", 2000)
        if max_flow_num > 2000:
            logging.info("This testcase is not applicable")
        else:
            actions = [ofp.action.output(out_port)]
            instructions = [ofp.instruction.apply_actions(actions)]
            priority = 1
            buffer_id = ofp.OFP_NO_BUFFER
            table_id = test_param_get("table", 0)
            
            for i in range(1, 10):
                for j in range(1, 10):
                    for k in range(1, 20):
                        match = ofp.match([ofp.oxm.eth_src(parse.parse_mac("00:01:02:" +str(k) + ":" +str(j)+ ":" + str(i)))])
                        req = ofp.message.flow_add(table_id=table_id,
                                               match= match,
                                               buffer_id=ofp.OFP_NO_BUFFER,
                                               instructions=instructions,
                                               priority=priority)
                        self.controller.message_send(req)
                        flow_count += 1
                        logging.info("Install flow %d", flow_count)
                        sleep(0.1)
                        
                        if flow_count % 20 == 0:
                            logging.info("Checking for table_full error")
                            err,_ = self.controller.poll(ofp.OFPT_ERROR, 1 )
                            if err is not None:
                                logging.info("Received error message from DUT")
                                self.assertEqual(err.err_type, ofp.const.OFPET_FLOW_MOD_FAILED,
                                                 "Error type was not OFPET_FLOW_MOD_FAILED")
                                self.assertEqual(err.code, ofp.const.OFPFMFC_TABLE_FULL,
                                                 "Error code was not OFPFMFC_TABLE_FULL")
                                logging.info("Received error message with correct type and code")
                                return
                            elif flow_count >= (max_flow_num + 100):
                                self.assertEqual(1,0,"Switch failed to generate an error")
                                return
                                
            self.assertEqual(1,0,"Switch failed to generate an error")


class Testcase_150_40_unknown_instruction(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify how unknown instructions in "FLOW_MOD" are handled.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, send OFPFC_ADD flow_mod message with unknown instruction. Verify switch sends ofp_error_msg with OFPET_BAD_INSTRUCTION type and OFPBIC_UNKNOWN_INST code.  Verify that the flow got not added to the flow tables.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.40 unknown instruction")

        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(out_port)]
        match = ofp.match([
            ofp.oxm.eth_type(0x0800)
        ])
        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))
        invalid_instruction = ofp.instruction.apply_actions(actions)
        invalid_instruction.type = 0xf000
        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[
                    invalid_instruction],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d with table id = OFPTT_ALL", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "Switch did not generated an error message")
        self.assertEqual(reply.err_type, ofp.OFPET_BAD_INSTRUCTION,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_INSTRUCTION.") % reply.err_type)
        self.assertEqual(reply.code, ofp.OFPBIC_UNKNOWN_INST,
                         ("Flow mod failed code %d was received, but we "
                          "expected OFPBIC_UNKNOWN_INST.") % reply.code)

class Testcase_150_50_unsupported_instruction(base_tests.SimpleDataPlane):
    """

    TODO: Verify the correctness of the testcase by using another DUT
    Purpose
    Verify how unsupported instructions in "FLOW_MOD" are handled

    Methodology
    Configure and connect DUT to controller. Refer to switch documentation for switch capabilities for supported instructions. After control channel establishment, send OFPFC_ADD flow_mod message with unsupported instruction. Verify switch sends ofp_error_msg with OFPET_BAD_INSTRUCTION type and OFPBIC_UNSUP_INST code.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.50 unsupported instruction")
        logging.info("If a device supports all instructions types defined in chapter 5.9 of the OpenFlow v1.3 Specification test case 150.50 cannot be tested, and the recorded test result shall be not applicable or pass.")

        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(out_port)]

        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))
        delete_all_flows(self.controller)

        table_stats = get_stats(self, ofp.message.table_stats_request())
        self.assertIsNotNone(table_stats, "Did not receive table stats reply message.")
        max_table_id = table_stats[-1].table_id
        #print max_table_id

        unsupported_instruction = ofp.instruction.goto_table(max_table_id)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=max_table_id,
                match=packet_to_flow_match(self, pkt),
                instructions=[
                    unsupported_instruction],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow to forward packet to port %d with table id = OFPTT_ALL", out_port)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "Switch did not generated an error message")
        self.assertEqual(reply.err_type, ofp.OFPET_BAD_INSTRUCTION,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_INSTRUCTION.") % reply.err_type)
        self.assertEqual(reply.code, ofp.OFPBIC_UNSUP_INST,
                         ("Flow mod failed code %d was received, but we "
                          "expected OFPBIC_UNSUP_INST.") % reply.code)


class Testcase_150_60_Goto_invalidtable(base_tests.SimpleDataPlane):
    """

    Purpose
    Verify how invalid table is handled in Goto-Table and next-table-id

    Methodology
    Configure and connect DUT to controller. After control channel establishment, send OFPFC_ADD flow_mod message with actions as Goto-Table with invalid value. Verify switch sends ofp_error_msg with OFPET_BAD_INSTRUCTION type and OFPBIC_BAD_TABLE_ID code.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.60 Goto invalid table")
        
        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(out_port)]

        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))
        delete_all_flows(self.controller)

        table_stats = get_stats(self, ofp.message.table_stats_request())
        self.assertIsNotNone(table_stats, "Did not receive table stats reply message.")

        max_table_id = table_stats[-1].table_id
        if max_table_id < ofp.OFPTT_MAX:
            table_id = max_table_id + 1
            invalidtable_instruction = ofp.instruction.goto_table(table_id)

            logging.info("Inserting flow")
            request = ofp.message.flow_add(
                    table_id=test_param_get("table", 0),
                    match=packet_to_flow_match(self, pkt),
                    instructions=[
                        invalidtable_instruction],
                    buffer_id=ofp.OFP_NO_BUFFER,
                    priority=1000)
            self.controller.message_send(request)
            logging.info("Inserting a flow to forward packet to port %d with table id = OFPTT_ALL", out_port)
            reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
            self.assertIsNotNone(reply, "Switch did not generated an error message")
            self.assertEqual(reply.err_type, ofp.OFPET_BAD_INSTRUCTION,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_INSTRUCTION.") % reply.err_type)
            self.assertEqual(reply.code, ofp.OFPBIC_BAD_TABLE_ID,
                         ("Flow mod failed code %d was received, but we "
                          "expected OFPBIC_BAD_TABLE_ID.") % reply.code)
        else:
            logging.info("This testcase is not applicable.")


class Testcase_150_70_unsupported_meta_data(base_tests.SimpleDataPlane):
    """
    TODO: Find a way to find unsupported meta_data and meta_data_mask
    Purpose
    Verify how unsupported metadata value or mask values are handled in Write-Metadata

    Methodology
    Configure and connect DUT to controller. After control channel establishment, send OFPFC_ADD flow_mod message with a write-metadata instruction with unsupported write-metadata or metadata mask. If the device does not support the write-metadata instruction verify the switch sends an OFPET_BAD_INSTRUCTION error with an OFPBIC_UNSUP_INST code. Otherwise verify the switch sends ofp_error_msg with OFPET_BAD_INSTRUCTION type and OFPBIC_UNSUP_METADATA or OFPBIC_UNSUP_METADATA_MASK code.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.70 unsupported meta data")
        
        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(out_port)]

        pkt = simple_tcp_packet()

        #logging.info("Running actions test for %s", pp(actions))
        delete_all_flows(self.controller)

        #table_stats = get_stats(self, ofp.message.table_stats_request())
        #self.assertIsNotNone(table_stats, "Did not receive table stats reply message.")
        instruction = ofp.instruction.write_metadata()

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                instructions=[
                        instruction],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow with instruction write_metadata")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        if reply is not None:
        #self.assertIsNone(reply, "Switch generated an error message")
            self.assertEqual(reply.err_type, ofp.OFPET_BAD_INSTRUCTION,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_INSTRUCTION.") % reply.err_type)
            self.assertEqual(reply.code, ofp.OFPBIC_UNSUP_INST,
                         ("Flow mod failed code %d was received, but we "
                          "expected OFPBIC_UNSUP_INST.") % reply.code)
        else:
            table_stats = get_stats(self, ofp.message.table_stats_request())
            self.assertIsNotNone(table_stats, "Did not receive table stats reply message.")
            """
            if  table_stats[0].metadata_write == 0xffffffffffffffff:
                logging.info("This testcase is not applicable")
            else:
                mdata = 0xaaaaaaaaaaaaaaaa
                mmask = writable_bits
                instruction = ofp.instruction.write_metadata(metadata=mdata,
                                                     metadata_mask=mmask)
                request = ofp.message.flow_add(
                                                table_id=test_param_get("table", 0),
                                                match=packet_to_flow_match(self, pkt),
                                                instructions=[
                                                    instruction],
                                                buffer_id=ofp.OFP_NO_BUFFER,
                                                priority=1000)
                self.controller.message_send(request)
                logging.info("Inserting a flow with instruction write_metadata")
                reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
                #self.assertIsNone(reply, "Switch generated an error message")
                self.assertEqual(reply.err_type, ofp.OFPET_BAD_INSTRUCTION,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_INSTRUCTION.") % reply.err_type)
                self.assertEqual(reply.code, ofp.OFPBIC_UNSUP_METADATA,
                         ("Flow mod failed code %d was received, but we "
                          "expected OFPBIC_UNSUP_METADATA.") % reply.code)
            """


class Testcase_150_80_Bad_match_field(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify how OXM_TVL with unsupported value in FLOW_MOD is handled. 

    Methodology
    Configure and connect DUT to controller. After control channel establishment, define an oxm TLV header including the basic openflow match class, an undefined oxm_field value (x: x > 39), the oxm_mask bit unset, a match value length of 1 byte, and a data payload of size 1. Create and install an ofp_flow_mod matching on the previously defined OXM type with an output action to controller. Verify an error is returned with error type OFPET_BAD_MATCH and error code OFPBMC_BAD_FIELD.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.80 Bad match field")

        in_port, out_port = openflow_ports(2)

        #actions = [ofp.action.output(out_port)]

        oxm_class = 0x8000 # Basic OpenFlow match class.
        oxm_field = 40 #bad oxm_field_value
        oxm_mask = 0
        oxm_len = 4
        bad_oxm_header = ofp.oxm.oxm(type_len=((oxm_class << 16) |
                                         (oxm_field << 9) |
                                         (oxm_mask << 8) |
                                         (oxm_len)))

        delete_all_flows(self.controller)

    
        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=ofp.match([bad_oxm_header]),
                instructions=[
                        ofp.instruction.apply_actions(actions = [ofp.action.output(out_port)])],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow with bad match field")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch did not generate an OFPT_ERROR.")
        self.assertEqual(reply.err_type, ofp.OFPET_BAD_MATCH,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_MATCH.") % reply.err_type)
        self.assertEqual(reply.code, ofp.OFPBMC_BAD_FIELD,
                         ("Bad instruction code %d was received, but we "
                          "expected OFPFBMC_BAD_FIELD.") % reply.code)
      


class Testcase_150_85_Bad_match_class(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify how OXM_TVL with unsupported class in FLOW_MOD is handled. 

    Methodology
    Configure and connect DUT to controller. After control channel establishment, define an oxm TLV header, set the openflow match class to an undefined value, the oxm_field to a defined value, the oxm_mask bit unset, a match value length of 1 byte, and a data payload of size 1. Create and install an ofp_flow_mod matching on the previously defined OXM type with an output action to controller. Verify an error is returned with error type OFPET_BAD_MATCH and error code OFPBMC_BAD_FIELD.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.85 Bad match class")

        in_port, out_port = openflow_ports(2)

        #actions = [ofp.action.output(out_port)]

        oxm_class = 0x8001 # Bad match class
        oxm_field = 0 # Defined oxm_field value
        oxm_mask = 0
        oxm_len = 4
        bad_oxm_header = ofp.oxm.oxm(type_len=((oxm_class << 16) |
                                         (oxm_field << 9) |
                                         (oxm_mask << 8) |
                                         (oxm_len)))
        
        delete_all_flows(self.controller)

    
        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=ofp.match([bad_oxm_header]),
                instructions=[
                        ofp.instruction.apply_actions(actions = [ofp.action.output(out_port)])],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow with bad match class")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch did not generate an OFPT_ERROR.")
        self.assertEqual(reply.err_type, ofp.OFPET_BAD_MATCH,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_MATCH.") % reply.err_type)
        self.assertEqual(reply.code, ofp.OFPBMC_BAD_FIELD,
                         ("Bad instruction code %d was received, but we "
                          "expected OFPFBMC_BAD_FIELD.") % reply.code)

"""class Testcase_150_90_Duplicate_field(BII_testgroup80.Testcase_80_200_Multiple_instances_same_OXM_TYPE):
    
    Purpose
    Verify how OFP_FLOW_MOD handles multiple OXM_FIELD.

    Methodology
    80, 200

    """


"""class Testcase_150_100_Bad_Prerequisite(BII_testgroup80.Testcase_80_180_Missing_Prerequisite):
   Purpose
    Verify how OFP_FLOW_MOD handles a field without its prerequisites specified. 

    Methodology
    80, 180



    """



class Testcase_150_110_Bad_network_mask(base_tests.SimpleDataPlane):
    """
    TODO: Verify the correctness of the testcase by using another DUT
    Purpose
    Verify how OFP_FLOW_MOD handles an arbitrary not supported mask in Layer 2 OR 3.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, create and install an ofp_flow_mod matching on a masked eth_src address with a mask value of "00:00:00:ff:ff:ff". Verify an error is returned with error type OFPET_BAD_MATCH and error code OFPBMC_BAD_DL_ADDR_MASK. Create and install a second ofp_flow_mod matching on a masked ipv4_src address with a mask value of "0.0.255.255f". Verify an error is returned with error type OFPET_BAD_MATCH and error code OFPBMC_BAD_NW_ADDR_MASK.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.110 Bad network mask")

        in_port, out_port = openflow_ports(2)

        #actions = [ofp.action.output(out_port)]
        delete_all_flows(self.controller)
        pkt = simple_tcp_packet()
        #match=packet_to_flow_match(self, pkt)
        
        bad_network_mask_match = ofp.match([ofp.oxm.eth_src_masked([0,1,2,3,4,5],[0,0,0,0xff,0xff,0xff])])
        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = bad_network_mask_match,
                instructions=[ofp.instruction.apply_actions(actions = [ofp.action.output(out_port)])],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow with bad eth_src mask")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch did not generate an OFPT_ERROR.")
        self.assertEqual(reply.err_type, ofp.OFPET_BAD_MATCH,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_MATCH.") % reply.err_type)
        self.assertEqual(reply.code, ofp.OFPBMC_BAD_DL_ADDR_MASK,
                         ("Bad instruction code %d was received, but we "
                          "expected OFPBMC_BAD_DL_ADDR_MASK.") % reply.code)
        
        bad_network_mask_match = ofp.match([ofp.oxm.eth_type(0x0800),ofp.oxm.ipv4_src_masked(0xc0a80101,0x0000ffff)]) #192.168.1.1 mask 0.0.255.255
        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = bad_network_mask_match,
                instructions=[ofp.instruction.apply_actions(actions = [ofp.action.output(out_port)])],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow with bad eth_src mask")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch did not generate an OFPT_ERROR.")
        self.assertEqual(reply.err_type, ofp.OFPET_BAD_MATCH,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_MATCH.") % reply.err_type)
        self.assertEqual(reply.code, ofp.OFPBMC_BAD_NW_ADDR_MASK,
                         ("Bad instruction code %d was received, but we "
                          "expected OFPBMC_BAD_NW_ADDR_MASK.") % reply.code)

class Testcase_150_120_NDDL_mask_wrong(base_tests.SimpleDataPlane):
    """
    TODO: Verify the correctness of the testcase by using another DUT
    Purpose
    Verify how OFP_FLOW_MOD handles an arbitrary not supported mask in Layer 2 AND 3.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, create and install an ofp_flow_mod matching on a masked eth_src address with a mask value of "00:00:00:ff:ff:ff", and matching on a masked ipv4_src address with a mask value of "0.0.255.255f". Verify an error is returned with error type OFPET_BAD_MATCH and error code OFPBMC_BAD_DL_ADDR_MASK.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.120 ND DL mask wrong")

        in_port, out_port = openflow_ports(2)

        #actions = [ofp.action.output(out_port)]
        delete_all_flows(self.controller)
        pkt = simple_tcp_packet()
        #match=packet_to_flow_match(self, pkt)
        
        bad_network_mask_match = ofp.match([ofp.oxm.eth_type(0x0800),ofp.oxm.eth_src_masked([0,1,2,3,4,5],[0,0,0,0xff,0xff,0xff]),ofp.oxm.ipv4_src_masked(0xc0a80101,0x0000ffff)])
        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = bad_network_mask_match,
                instructions=[ofp.instruction.apply_actions(actions = [ofp.action.output(out_port)])],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow with ND DL mask wrong")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch did not generate an OFPT_ERROR.")
        self.assertEqual(reply.err_type, ofp.OFPET_BAD_MATCH,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_MATCH.") % reply.err_type)
        self.assertEqual(reply.code, ofp.OFPBMC_BAD_DL_ADDR_MASK,
                         ("Bad instruction code %d was received, but we "
                          "expected OFPBMC_BAD_DL_ADDR_MASK.") % reply.code)
        
class Testcase_150_130_unsupported_mask(base_tests.SimpleDataPlane):
    """
    TODO: Verify the correctness of the testcase by using another DUT
    Purpose
    Purpose
    Verify how OFP_FLOW_MOD handles an arbitrary mask for the fields that don't support it. 

    Methodology
    Configure and connect DUT to controller. After control channel establishment, create and install an ofp_flow_mod matching on a masked match type that is not supported. Verify an error is returned with error type OFPET_BAD_MATCH and error code OFPBMC_BAD_MASK.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.130 unsupported mask")

        in_port, out_port = openflow_ports(2)

        #actions = [ofp.action.output(out_port)]
        delete_all_flows(self.controller)
        pkt = simple_tcp_packet()
        #match=packet_to_flow_match(self, pkt)
        
        bad_network_mask_match = ofp.match([ofp.oxm.eth_type_masked(0x0800,0xff00)])
        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = bad_network_mask_match,
                instructions=[ofp.instruction.apply_actions(actions = [ofp.action.output(out_port, max_len=128)])],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow with unsupported mask")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch did not generate an OFPT_ERROR.")
        self.assertEqual(reply.err_type, ofp.OFPET_BAD_MATCH,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_MATCH.") % reply.err_type)
        self.assertEqual(reply.code, ofp.OFPBMC_BAD_MASK,
                         ("Bad instruction code %d was received, but we "
                          "expected OFPBMC_BAD_MASK.") % reply.code)

class Testcase_150_140_illegal_value(base_tests.SimpleDataPlane):
    """

    Purpose
    Verify how OFP_FLOW_MOD handles an arbitrary mask for the fields that don't support it. 

    Methodology
    Configure and connect DUT to controller. After control channel establishment, create and install an ofp_flow_mod matching on a masked match type that is not supported. Verify an error is returned with error type OFPET_BAD_MATCH and error code OFPBMC_BAD_MASK.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.140 illegal value")

        in_port, out_port = openflow_ports(2)

        #actions = [ofp.action.output(out_port)]
        delete_all_flows(self.controller)
        pkt = simple_tcp_packet()
        #match=packet_to_flow_match(self, pkt)
        
        """bad_network_mask_match = ofp.match([ofp.oxm.vlan_vid(0)])
        logging.info("Inserting flow 1")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = bad_network_mask_match,
                instructions=[ofp.instruction.apply_actions(actions = [ofp.action.output(out_port)])],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow with illegal value")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch did not generate an OFPT_ERROR.")
        self.assertEqual(reply.err_type, ofp.OFPET_BAD_MATCH,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_MATCH.") % reply.err_type)
        self.assertEqual(reply.code, ofp.OFPBMC_BAD_VALUE,
                         ("Bad instruction code %d was received, but we "
                          "expected OFPBMC_BAD_VALUE.") % reply.code)"""
                          
        bad_network_mask_match = ofp.match([ofp.oxm.vlan_vid(4095)])
        logging.info("Inserting flow 2")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = bad_network_mask_match,
                instructions=[ofp.instruction.apply_actions(actions = [ofp.action.output(out_port)])],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow with illegal value")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch did not generate an OFPT_ERROR.")
        self.assertEqual(reply.err_type, ofp.OFPET_BAD_MATCH,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_MATCH.") % reply.err_type)
        self.assertEqual(reply.code, ofp.OFPBMC_BAD_VALUE,
                         ("Bad instruction code %d was received, but we "
                          "expected OFPBMC_BAD_VALUE.") % reply.code)

class Testcase_150_145_Bad_action(base_tests.SimpleDataPlane):
    """

    Purpose
    Verify how OFP_FLOW_MOD handles an arbitrary mask for the fields that don't support it. 

    Methodology
    Configure and connect DUT to controller. After control channel establishment, create and install an ofp_flow_mod matching on a masked match type that is not supported. Verify an error is returned with error type OFPET_BAD_MATCH and error code OFPBMC_BAD_MASK.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.145 bad action")

        in_port, out_port = openflow_ports(2)

        #actions = [ofp.action.output(out_port)]
        delete_all_flows(self.controller)
        pkt = simple_tcp_packet()
        action = ofp.action.output(port = out_port)
        action.type = 30 #bad action
        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                #match = bad_network_mask_match,
                instructions=[ofp.instruction.apply_actions([action])],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow with bad action")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch did not generate an OFPT_ERROR.")
        self.assertEqual(reply.err_type, ofp.OFPET_BAD_ACTION,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_ACTION.") % reply.err_type)
        self.assertEqual(reply.code, ofp.OFPBAC_BAD_TYPE,
                         ("Bad instruction code %d was received, but we "
                          "expected OFPBAC_BAD_TYPE.") % reply.code)

class Testcase_150_150_Never_valid_port(base_tests.SimpleDataPlane):
    """

    Purpose
    Verify how OFP_FLOW_MOD handles an arbitrary mask for the fields that don't support it. 

    Methodology
    Configure and connect DUT to controller. After control channel establishment, create and install an ofp_flow_mod matching on a masked match type that is not supported. Verify an error is returned with error type OFPET_BAD_MATCH and error code OFPBMC_BAD_MASK.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.150 Never valid port")

        in_port, out_port = openflow_ports(2)

        #actions = [ofp.action.output(out_port)]
        delete_all_flows(self.controller)
        pkt = simple_tcp_packet()
        action = ofp.action.output(port = ofp.OFPP_ANY)
        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                #match = bad_network_mask_match,
                instructions=[ofp.instruction.apply_actions([action])],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow with invalid port")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch did not generate an OFPT_ERROR.")
        self.assertEqual(reply.err_type, ofp.OFPET_BAD_ACTION,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_ACTION.") % reply.err_type)
        self.assertEqual(reply.code, ofp.OFPBAC_BAD_OUT_PORT,
                         ("Bad instruction code %d was received, but we "
                          "expected OFPBAC_BAD_OUT_PORT.") % reply.code)

class Testcase_150_160_Currently_valid_port(base_tests.SimpleDataPlane):
    """

    Purpose
    Verify how OFP_FLOW_MOD handles an arbitrary mask for the fields that don't support it. 

    Methodology
    Configure and connect DUT to controller. After control channel establishment, create and install an ofp_flow_mod matching on a masked match type that is not supported. Verify an error is returned with error type OFPET_BAD_MATCH and error code OFPBMC_BAD_MASK.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.160 Currently invalid port")

        in_port, out_port = openflow_ports(2)

        #actions = [ofp.action.output(out_port)]
        delete_all_flows(self.controller)
        pkt = simple_tcp_packet()
        action = ofp.action.output(port = 800) # a port is currently invalid 
        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                #match = bad_network_mask_match,
                instructions=[ofp.instruction.apply_actions([action])],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow with invalid port")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        #self.assertIsNotNone(reply, "The switch did not generate an OFPT_ERROR.")
        if reply is not None:
            self.assertEqual(reply.err_type, ofp.OFPET_BAD_ACTION,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_ACTION.") % reply.err_type)
            self.assertEqual(reply.code, ofp.OFPBAC_BAD_OUT_PORT,
                         ("Bad instruction code %d was received, but we "
                          "expected OFPBAC_BAD_OUT_PORT.") % reply.code)
        else:
            table_stats = get_stats(self, ofp.message.table_stats_request())
            self.assertIsNotNone(table_stats, "Did not receive table stats reply message")
            self.assertEqual(table_stats[0].active_count, 1, "active flow count is not 1")
            self.dataplane.send(in_port, str(pkt))
            verify_no_packet(self, str(pkt),openflow_ports(4))

class Testcase_150_170_undefined_group(base_tests.SimpleDataPlane):
    """

    Purpose
    Verify how OFP_FLOW_MOD handles non existent group. 

    Methodology
    Configure and connect DUT to controller. After control channel establishment, verify DUT supports groups if so, add a flow matching on a named field (under the given Pre-requisites for the match) with a group action to group_id OFPG_ALL. Verify an error is returned, and that the received error type is OFPET_BAD_ACTION and error code is OFPBAC_BAD_OUT_GROUP

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.170 undefined group")

        in_port, out_port = openflow_ports(2)

        #actions = [ofp.action.output(out_port)]
        delete_all_flows(self.controller)
        
        request = ofp.message.group_features_stats_request()
        reply, _= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive group features reply")
        if reply.type == ofp.const.OFPT_ERROR:
            self.assertEqual(reply.err_type, ofp.const.OFPET_BAD_REQUEST, "Error type is not OFPET_BAD_REQUEST")
            self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_STAT, "Error code is not OFPBRC_BAD_STAT")
            logging.info("DUT does not support group features and returned error msg as expected")
        else:
            self.assertEqual(reply.stats_type,ofp.const.OFPST_GROUP_FEATURES,"Received msg is not group features")
            #self.assertTrue(reply.capabilities!=0,"Group is not supported by DUT")
            
        pkt = simple_tcp_packet()
        action = ofp.action.group(group_id = ofp.OFPG_ALL) 
        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                #match = bad_network_mask_match,
                instructions=[ofp.instruction.apply_actions([action])],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow with invalid port")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch did not generate an OFPT_ERROR.")
        self.assertEqual(reply.err_type, ofp.OFPET_BAD_ACTION,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_ACTION.") % reply.err_type)
        self.assertEqual(reply.code, ofp.OFPBAC_BAD_OUT_GROUP,
                         ("Bad instruction code %d was received, but we "
                          "expected OFPBAC_BAD_OUT_GROUP.") % reply.code)


class Testcase_150_175_undefined_meter(base_tests.SimpleDataPlane):
    """
    TODO: Can not add a flow references to a specific meter table. (controller doesn't send message) Need to fix the bug
    Purpose
    Verify how OFP_FLOW_MOD handles non existent group. 

    Methodology
    Configure and connect DUT to controller. After control channel establishment, verify DUT supports groups if so, add a flow matching on a named field (under the given Pre-requisites for the match) with a group action to group_id OFPG_ALL. Verify an error is returned, and that the received error type is OFPET_BAD_ACTION and error code is OFPBAC_BAD_OUT_GROUP

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.175 undefined meter")

        in_port, out_port = openflow_ports(2)

        delete_all_flows(self.controller)
               
        request = ofp.message.meter_features_stats_request()
        reply, _= self.controller.transact(request)
        self.assertIsNotNone(reply, "Did not receive meter features reply")
        if reply.type == ofp.const.OFPT_ERROR:
            self.assertEqual(reply.err_type, ofp.const.OFPET_BAD_REQUEST, "Error type is not OFPET_BAD_REQUEST")
            self.assertEqual(reply.code, ofp.const.OFPBRC_BAD_STAT, "Error code is not OFPBRC_BAD_STAT")
            logging.info("DUT does not support meter features and returned error msg as expected")

        else:
            self.assertEqual(reply.stats_type,ofp.const.OFPST_METER_FEATURES,"Received msg is not meter features")
            self.assertIsNotNone(reply.features,"meter is not supported by DUT")
            
            pkt = simple_tcp_packet()
            #action = ofp.action.meter(meter_id = 1) 
            logging.info("Inserting flow")
            request = ofp.message.flow_add(
                    table_id=test_param_get("table", 0),
                    match=packet_to_flow_match(self, pkt),
                    #match = bad_network_mask_match,
                    instructions=[ofp.instruction.meter(meter_id = reply.features.max_meter + 1)],
                    buffer_id=ofp.OFP_NO_BUFFER,
                    priority=1000)
            self.controller.message_send(request)
            reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
            self.assertIsNotNone(reply, "The switch did not generate an OFPT_ERROR.")
            self.assertEqual(reply.err_type, ofp.OFPET_METER_MOD_FAILED,
                             ("Error type %d was received, but we expected "
                              "OFPET_METER_MOD_FAILED.") % reply.err_type)
            self.assertEqual(reply.code, ofp.OFPMMFC_UNKNOWN_METER,
                             ("Bad instruction code %d was received, but we "
                              "expected OFPMMFC_UNKNOWN_METER.") % reply.code)

class Testcase_150_180_bad_action(base_tests.SimpleDataPlane):
    """

    Purpose
    Verify how OFP_FLOW_MOD handles an invalid set-field


    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a VLan. Send a flow mod with a value (x: x> 4095) , or a DSCP vlaue using more than 6 bits. Verify an error is returned, and that the received error type is OFPET_BAD_ACTION type and OFPBAC_BAD_SET_ARGUMENT code.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.180 bad action")

        in_port, out_port = openflow_ports(2)

        #actions = [ofp.action.output(out_port)]
        delete_all_flows(self.controller)
        pkt = simple_tcp_packet()
        #match=packet_to_flow_match(self, pkt)
        
        match = ofp.match([ofp.oxm.vlan_vid(ofp.OFPVID_PRESENT|2)])
        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                match = match,
                instructions=[ofp.instruction.apply_actions(actions = [ofp.action.set_field(ofp.oxm.vlan_vid(4096)),ofp.action.output(out_port)])],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow matching on vlan_vid 2")
        #logging.info("Inserting a flow with illegal value")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch did not generate an OFPT_ERROR.")
        self.assertEqual(reply.err_type, ofp.OFPET_BAD_ACTION,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_ACTION.") % reply.err_type)
        self.assertEqual(reply.code, ofp.OFPBAC_BAD_SET_ARGUMENT,
                         ("Bad instruction code %d was received, but we "
                          "expected OFPBAC_BAD_SET_ARGUMENT.") % reply.code)

class Testcase_150_190_bad_argument(base_tests.SimpleDataPlane):
    """

    Purpose
    Verify how OFP_FLOW_MOD handles an invalid value

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the given Pre-requisites for the match) with a push_vlan action with an invalid ethertype. Verify an error is returned, and that the received error type is OFPET_BAD_ACTION and error code is OFPBAC_BAD_ARGUMENT.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.190 bad argument")

        in_port, out_port = openflow_ports(2)

        #actions = [ofp.action.output(out_port)]
        delete_all_flows(self.controller)
        pkt = simple_tcp_packet()
        #match=packet_to_flow_match(self, pkt)
        
        #match = ofp.match([ofp.oxm.vlan_vid(1)])
        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                #match = match,
                instructions=[ofp.instruction.apply_actions(actions = [ofp.action.push_vlan(ethertype = 0x0801)])],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow with invalid ethertype value")
        #logging.info("Inserting a flow with illegal value")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch did not generate an OFPT_ERROR.")
        self.assertEqual(reply.err_type, ofp.OFPET_BAD_ACTION,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_ACTION.") % reply.err_type)
        self.assertEqual(reply.code, ofp.OFPBAC_BAD_ARGUMENT,
                         ("Bad instruction code %d was received, but we "
                          "expected OFPBAC_BAD_SET_ARGUMENT.") % reply.code)

"""class Testcase_150_220_bad_action(base_tests.SimpleDataPlane):
    
    Purpose
    Verify how OFP_FLOW_MOD handles a field not supported in the table

    Methodology
    430.50

    
    @wireshark_capture
    def runTest(self):
        logging.info("Running 10.80 - Version negotiation failure test")
        timeout = 5
        nego_version = 0
        logging.info("Received Hello msg with correct version")
        request = ofp.message.hello()
        request.version=nego_version
        self.controller.message_send(request)
        logging.info("Sending Hello msg with version 0")
        (rv, pkt) = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=timeout)
        self.assertIsNotNone(rv, 'Did not receive Error msg')
        self.assertEqual(rv.err_type,ofp.const.OFPET_HELLO_FAILED, " Error type is not correct. Expect error type: OFPET_HELLO_FAILED")
        logging.info("Received OFPET_HELLO_FAILED")
        self.assertEqual(rv.code, ofp.const.OFPHFC_INCOMPATIBLE, "Error Code is not correct. Expect error code: OFPHFC_INCOMPATIBLE")
        logging.info("Received Error code is OFPHFC_INCOMPATIBLE")


class Testcase_150_230_bad_action(base_tests.SimpleDataPlane):
    
    Purpose
    Verify how OFP_FLOW_MOD handles duplicate actions 

    Methodology
    430.320

    
    def runTest(self):
        logging.info("Running test case Bad Action Too Many")
        delete_all_flows(self.controller)
        port_a, port_b, = openflow_ports(2)

        #Create flow_mod message with lot of actions
        table_id = test_param_get("table", 0)
        priority = 1
        match = ofp.match([
                ofp.oxm.eth_type(0x0800)
                ])
        act1 = ofp.action.set_field(ofp.oxm.ipv4_src(167772361))
        act2 = ofp.action.output(port=port_b,max_len=128)
        actions = [act1, act2]
        # add a lot of actions
        no = 167772167
        for i in range(167772162, no):
            act1 = ofp.action.set_field(ofp.oxm.ipv4_src(i))
            act2 = ofp.action.output(port=port_b,max_len=128)
            actions.append(act1)
            actions.append(act2)
        instructions = [ofp.instruction.apply_actions(actions=actions)]
        flow_mod_msg = ofp.message.flow_add(table_id=table_id,
                                       match=match,
                                       buffer_id=ofp.OFP_NO_BUFFER,
                                       instructions=instructions,
                                       priority=priority) 
        logging.info("Sending flow_mod message...")
        rv = self.controller.message_send(flow_mod_msg)
        self.assertTrue(rv != -1, "Error installing flow mod")
        self.assertEqual(do_barrier(self.controller), 0, "Barrier failed")

        logging.info("Waiting for OFPT_ERROR message...")
        (response, pkt) = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=5)
        self.assertTrue(response is not None,
                               'Switch did not replay with error messge')
        self.assertTrue(response.type==ofp.OFPET_BAD_ACTION,
                               'Error type is not OFPET_BAD_ACTION got {0}' .format(response.type))
        self.assertTrue(response.code==ofp.OFPBAC_TOO_MANY,
                               'Error code is not OFPBAC_TOO_MANY')


class Testcase_150_250_unsupported_action_order(base_tests.SimpleDataPlane):
    
    TODO: Verify the correctness of this testcase by using another DUT
    Purpose
    Verify how OFP_FLOW_MOD handles action list that can't be supported in the specified sequence.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on a named field (under the given Pre-requisites for the match) with two actions. The first action should be an output action to a data plane test port. The second action should be a set_field IPv4 source action. After installation verify an error is returned with error type OFPET_BAD_ACTION and error code OFPBAC_UNSUPPORTED_ORDER.

    
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.250 unsupported action order")

        in_port, out_port = openflow_ports(2)

        #actions = [ofp.action.output(out_port)]
        delete_all_flows(self.controller)
        pkt = simple_tcp_packet()
        #match=packet_to_flow_match(self, pkt)
        
        #match = ofp.match([ofp.oxm.vlan_vid(1)])
        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                #match = match,
                instructions=[ofp.instruction.apply_actions(actions = [ofp.action.output(out_port),ofp.action.set_field(ofp.oxm.ipv4_src(0xc0a80101))])],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a flow with two unsupported sequence actions")
        #logging.info("Inserting a flow with illegal value")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch did not generate an OFPT_ERROR.")
        self.assertEqual(reply.err_type, ofp.OFPET_BAD_ACTION,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_ACTION.") % reply.err_type)
        self.assertEqual(reply.code, ofp.OFPBAC_UNSUPPORTED_ORDER,
                         ("Bad instruction code %d was received, but we "
                          "expected OFPBAC_UNSUPPORTED_ORDER.") % reply.code)
"""

class Testcase_150_260_bad_instruction(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify how OFP_FLOW_MOD handles Clear action with some actions

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a table miss entry with a clear actions instruction with an output action. Verify an error of type OFPET_BAD_ISTRUCTION is generated by the device with an error code of OFPBIC_BAD_LEN.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 150.260 bad instruction")

        in_port, out_port = openflow_ports(2)

        #actions = [ofp.action.output(out_port)]
        delete_all_flows(self.controller)
        pkt = simple_tcp_packet()
        #match=packet_to_flow_match(self, pkt)
        
        #match = ofp.match([ofp.oxm.vlan_vid(1)])
        instruction = ofp.instruction.apply_actions(actions= [ofp.action.output(out_port)])
        instruction.type = 5 # clear-action instruction
        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                #match=packet_to_flow_match(self, pkt),
                #match = match,
                instructions = [instruction],
                #instructions=[ofp.instruction.clear_actions(actions = [ofp.action.output(out_port)])],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=0)
        self.controller.message_send(request)
        logging.info("Inserting a table-miss flow matching with clear-actions instruction and output action")
        #logging.info("Inserting a flow with illegal value")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNotNone(reply, "The switch did not generate an OFPT_ERROR.")
        self.assertEqual(reply.err_type, ofp.OFPET_BAD_INSTRUCTION,
                         ("Error type %d was received, but we expected "
                          "OFPET_BAD_INSTRUCTION.") % reply.err_type)
        self.assertEqual(reply.code, ofp.OFPBIC_BAD_LEN,
                         ("Bad instruction code %d was received, but we "
                          "expected OFPBIC_BAD_LEN.") % reply.code)