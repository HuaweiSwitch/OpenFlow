# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Pan Zhang

"""

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
from loxi.of13.oxm import *

import BII_testgroup100
import BII_testgroup200
import BII_testgroup50
import BII_testgroup230
import BII_testgroup250
"""
class Testcase_410_10_packet_in_structure(BII_testgroup100.Testcase_100_70_Controller):
    """"""
    Purpose
    Verify that a packet matching a flow with an associated output:controller action generates a packet_in to the controller

    Methodology
    100.70

    """"""



class Testcase_410_20_packet_in_data(BII_testgroup200.Testcase_200_110_basic_OFPT_PACKET_OUT):
    """"""
    Purpose
    Verify packets sent via packet_out are received.

    Methodology
    200.110


    """"""


class Testcase_410_30_packet_in_max_length(BII_testgroup230.Testcase_230_50_ActionHeaderMaxLenMax):
    """"""
    Purpose
    Verify packets "send to controller" action that are smaller than OFPCML_MAX = 0xffe5 are sent in their entirety.

    Methodology
    230.50

    """"""


class Testcase_410_40_packet_in_miss_send_length(BII_testgroup250.Testcase_250_140_SwitchConfigMissSendLen):
    """"""
    Purpose
    Verify size of data in OFP_PACKET_IN message specified by MISS_SEND_LEN when action output is not OFFP_CONTROLLER.

    Methodology
    250.140

    """



class Testcase_410_50_default_miss_send_length(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify the default miss_send_len is 128 bytes.

    Methodology
    If possible configure the DUT's default table-miss behavior to trigger an ofp_packet_in message. If this configuration is not possible this test is not applicable.

    Connect DUT to controller. After control channel establishment  send an OFPT_GET_CONFIG_REQUEST message. Verify the switch responds with an OFPT_GET_CONFIG_REPLY message. Verify the returned miss_send_len value is 128.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 410.50 packet out in port")
        in_port, out_port = openflow_ports(2)
        request = ofp.message.get_config_request()
        self.controller.message_send(request)
        reply, _ = self.controller.poll(exp_msg = ofp.OFPT_GET_CONFIG_REPLY, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive get config reply message.")
        self.assertEqual(reply.miss_send_len,128,"The miss send length is not 128")
"""
class Testcase_410_60_action_output_controller_max_length_no_buffer(BII_testgroup230.Testcase_230_60_ActionHeaderMaxLenNoBuffer):
    
    Purpose
    Verify packets "send to controller" action with MAX_LEN of OFPCML_NO_BUFFER set to 0xffff are sent in their entirety

    Methodology
    230.60


    """


"""
class Testcase_410_70_packet_in_buffer_documentation(base_tests.SimpleDataPlane):
    
    Purpose
    Verify devices expose available buffering to its users.

    Methodology
    Vendor must provide this documentation to complete the basic conformance test suite. If the proper documentation is not provided this test case result shall be "fail."

    
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 410.70 action output controller max length no buffer")
        logging.info("Vendor must provide this documentation to complete the basic conformance test suite. If the proper documentation is not provided this test case result shall be fail")

"""




class Testcase_410_90_packet_in_buffer_timeout(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify buffers are protected until they have been used or have timed out.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), action is output to port CONTROLLER with max_len set to 0. Send a matching packet on the data plane. Note the timeout value (t-timeout) and max number of packets buffered (n-max) from the documentation. Send one dataplane packet, and note the buffer_id. Wait 2 seconds, send n-max packets on the dataplane. Verify you get n-1 valid buffer_ids and one packet_in with buffer-id -1 and full packet in payload. Wait (t-timeout)-1s from the first packet, send another dataplane packet, verify it is not buffered. Wait two more seconds, send 2 dataplane packets. Verify one is buffered, with the buffer-id from the very first packet_in, the other one is not buffered.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 410.90 packet in buffer timeout")
        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(ofp.OFPP_CONTROLLER, max_len = 0)]

        t_timeout = 10 
        n_max = 128  # values get from device document

        pkt = simple_tcp_packet()

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                #match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a table miss flow to forward packet to controller")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)

        self.dataplane.send(in_port, str(pkt))
        reply, _ = self.controller.poll(exp_msg = ofp.const.OFPT_PACKET_IN, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive packet in message")
        first_buffer_id = reply.buffer_id
        sleep(2)
        for i in range(n_max):
            self.dataplane.send(in_port, str(pkt))
            reply, _ = self.controller.poll(exp_msg = ofp.const.OFPT_PACKET_IN, timeout = 3)
            self.assertIsNotNone(reply, "Did not receive packet in message")
            if i < (n_max - 1):
                self.assertTrue(reply.buffer_id != ofp.OFP_NO_BUFFER, "Received packet in message with no buffer id")
            else:
                self.assertEqual(reply.buffer_id, ofp.OFP_NO_BUFFER, "Received packet in message without no buffer id")

        sleep(t_timeout - 1)
        self.dataplane.send(in_port, str(pkt))
        reply, _ = self.controller.poll(exp_msg = ofp.const.OFPT_PACKET_IN, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive packet in message")
        self.assertEqual(reply.buffer_id, ofp.OFP_NO_BUFFER, "Received packet in message without no buffer id")

        sleep(2)
        self.dataplane.send(in_port, str(pkt))
        reply, _ = self.controller.poll(exp_msg = ofp.const.OFPT_PACKET_IN, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive packet in message")
        self.assertEqual(reply.buffer_id, first_buffer_id, "bufer id is not equal to the first packet's buffer id")

"""     
class Testcase_410_80_packet_in_buffer_full(Testcase_410_90_packet_in_buffer_timeout):
    
    Purpose
    Verify a device can handle buffered packets that are never dequeued by the controller.

    Methodology
    410,90

    """
        
"""
class Testcase_410_130_packet_in_reason_no_match(BII_testgroup50.Testcase_50_30_TableMissPacketInReason):
    
    Purpose
    Verify ofp_packet_in reason is correctly reported.

    Methodology
    50.30

    """




class Testcase_410_140_packet_in_reason_action(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify ofp_packet_in reason is correctly reported.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), action is output to port CONTROLLER. Send a matching packet on the data plane. Verify a packet_in message encapsulates the matching packet is triggered. Verify the reason is OFPR_ACTION.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 410.140 packet in reason action")
        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(ofp.OFPP_CONTROLLER, max_len = 128)]

        pkt = simple_tcp_packet()

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                #match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a table miss flow to forward packet to controller")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)

        self.dataplane.send(in_port, str(pkt))
        reply, _ = self.controller.poll(exp_msg = ofp.const.OFPT_PACKET_IN, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive packet in message")
        self.assertEqual(reply.reason, ofp.OFPR_ACTION, "The reason is not OFPR_ACTION")


class Testcase_410_200_packet_in_cookie(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify that the cookie field of an ofp_packet_in message matches that of the ofp_flow_mod that triggered the ofp_packet_in.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), with an action output to port CONTROLLER. Note the cookie_id in the ofp_flow_mod. Send a matching packet on the data plane. Verify a packet_in message that encapsulates the matching packet is triggered. Verify the cookie field matches the cookie field of the ofp_flow_mod.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 410.200 packet in cookie")
        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(ofp.OFPP_CONTROLLER, max_len = 128)]

        pkt = simple_tcp_packet()

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                #match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,cookie = 1001, 
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a table miss flow to forward packet to controller")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)

        self.dataplane.send(in_port, str(pkt))
        reply, _ = self.controller.poll(exp_msg = ofp.const.OFPT_PACKET_IN, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive packet in message")
        self.assertEqual(reply.cookie, 1001, "The cookie value is not matched")


class Testcase_410_220_packet_in_cookie_negative_one(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify that if a cookie cannot be associated with a flow, the cookie field is set to negative one.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), with an action output to OFPP_CONTROLLER using the write_actions instruction. Send a matching packet on the data plane. Verify a packet_in message that encapsulates the matching packet is triggered. Verify the cookie field is set to -1.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 410.220 packet in cookie nagative one")
        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(ofp.OFPP_CONTROLLER, max_len = 128)]

        pkt = simple_tcp_packet()

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                #match = match,
                instructions=[
                    ofp.instruction.write_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER,
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a table miss flow to forward packet to controller")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)

        self.dataplane.send(in_port, str(pkt))
        reply, _ = self.controller.poll(exp_msg = ofp.const.OFPT_PACKET_IN, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive packet in message")
        self.assertEqual(reply.cookie, 0xffffffffffffffff, "The cookie value is not matched")
"""
class Testcase_410_230_packet_in_cookie_field(Testcase_410_200_packet_in_cookie):
    
    Purpose
    Verify that the cookie field of an ofp_packet_in message matches that of the ofp_flow_mod that triggered the ofp_packet_in.

    Methodology
    410.200


    """




class Testcase_410_240_packet_in_match(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify that the match field of a packet_in message is not empty.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), with an action output to OFPP_CONTROLLER. Send a matching packet on the data plane. Verify a packet_in message that encapsulates the matching packet is triggered. Verify the match field is not empty.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 410.240 packet in match")
        in_port, out_port = openflow_ports(2)
        match = ofp.match([ofp.oxm.in_port(in_port)])
        actions = [ofp.action.output(ofp.OFPP_CONTROLLER, max_len = 128)]
        pkt = simple_tcp_packet()

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, 
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a table miss flow to forward packet to controller")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)

        self.dataplane.send(in_port, str(pkt))
        reply, _ = self.controller.poll(exp_msg = ofp.const.OFPT_PACKET_IN, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive packet in message")
        self.assertIsNotNone(reply.match, "Match is empty")


class Testcase_410_250_in_port_match(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify that the match field of an ofp_packet_in contains an in_port OXM.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field (under the given Pre-requisites for the match), with an action output to OFPP_CONTROLLER. Send a matching packet on the data plane. Verify a packet_in message that encapsulates the matching packet is triggered. Verify the match field contains an OFPXMT_OFB_IN_PORT.

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 410.240 packet in match")
        in_port, out_port = openflow_ports(2)

        actions = [ofp.action.output(ofp.OFPP_CONTROLLER, max_len = 128)]

        pkt = simple_tcp_packet()

        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match=packet_to_flow_match(self, pkt),
                #match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, 
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a table miss flow to forward packet to controller")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)

        self.dataplane.send(in_port, str(pkt))
        reply, _ = self.controller.poll(exp_msg = ofp.const.OFPT_PACKET_IN, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive packet in message")
        self.assertEqual(reply.match.oxm_list[0].value, in_port,"The in port is not match")
        
        
        
class Testcase_410_260_physical_port_match(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify that the in_phy_port OXM is included in the match field of ofp_packet_in messages in the correct instances.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field 
    (under the given Pre-requisites for the match), with an action output to OFPP_CONTROLLER. Send a matching packet on a 
    data plane logical port. Verify a packet_in message that encapsulates the matching packet is triggered. Verify the 
    match field contains an OFPXMT_OFB_IN_PHY_PORT. If no logical ports are supported, verify the OXFMT_OFB_IN_PHY_PORT 
    is not included.


    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 410.260 - Physical port match")
        port, = openflow_ports(1)
        table_id=test_param_get("table", 0)
        test_port=test_param_get("logical_port", port)

        match = ofp.match([ofp.oxm.in_port(test_port)])
        actions = [ofp.action.output(ofp.OFPP_CONTROLLER, max_len = 128)]
        pkt = simple_tcp_packet()
        
        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, 
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a table miss flow to forward packet to controller")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)

        self.dataplane.send(test_port, str(pkt))
        reply, _ = self.controller.poll(exp_msg = ofp.const.OFPT_PACKET_IN, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive packet in message")
        logging.info("Received packet_in message.")
        self.assertIsNotNone(reply.match.oxm_list, "oxm list was empty")
        
        for oxm_id in reply.match.oxm_list:
            if oxm_id.type_len == in_phy_port.type_len:
                self.assertEqual(oxm_id.value, test_port, "in physical port value was not correct")
            elif oxm_id.type_len == in_port.type_len:
                self.assertEqual(oxm_id.value, port, "in port value was not correct")
                logging.info("DUT did not configure physical in port")

                
                
                
class Testcase_410_280_tunnel_id_match(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify that the tunnel_id OXM is included in the match field of ofp_packet_in messages in the correct instances.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field 
    (under the given Pre-requisites for the match), with an action output to OFPP_CONTROLLER. Send a matching packet on 
    a data plane tunnel interface. Verify a packet_in message that encapsulates the matching packet is triggered. Verify 
    the match field contains an OFPXMT_OFB_TUNNEL_ID. If no tunnel interface is supported, verify the OXFXMT_OFB_TUNNEL_ID 
    is not included.


    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 410.280 - Tunnel id match")
        port, = openflow_ports(1)
        table_id=test_param_get("table", 0)
        test_port=test_param_get("tunnel_id", port)

        match = ofp.match([ofp.oxm.in_port(test_port)])
        actions = [ofp.action.output(ofp.OFPP_CONTROLLER, max_len = 128)]
        pkt = simple_tcp_packet()
        
        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, 
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a table miss flow to forward packet to controller")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)

        self.dataplane.send(test_port, str(pkt))
        reply, _ = self.controller.poll(exp_msg = ofp.const.OFPT_PACKET_IN, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive packet in message")
        logging.info("Received packet_in message.")
        self.assertIsNotNone(reply.match.oxm_list, "oxm list was empty")
        
        for oxm_id in reply.match.oxm_list:
            if oxm_id.type_len == tunnel_id.type_len:
                self.assertEqual(oxm_id.value, test_port, "tunnel id value was not correct")
            elif oxm_id.type_len == in_port.type_len:
                self.assertEqual(oxm_id.value, port, "in port value was not correct")
                logging.info("DUT did not configure tunnel id")


                
# class Testcase_410_290_standard_match(base_tests.SimpleDataPlane):
    # """
    # Purpose
    # Verify that all standard OXM types included in an ofp_packet_in message's match field are non zero.

    # Methodology
    # Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named field 
    # (under the given Pre-requisites for the match), with an action output to OFPP_CONTROLLER. Send a matching packet on 
    # the data plane. Verify a packet_in message that encapsulates the matching packet is triggered. Verify that any pipeline 
    # fields that are included is non-zero.


    # """
    # @wireshark_capture
    # def runTest(self):
        # logging.info("Running testcase 410.290 - Standard match")
        # in_port, = openflow_ports(1)
        # table_id=test_param_get("table", 0)

        # match = ofp.match([ofp.oxm.in_port(in_port)])
        # actions = [ofp.action.output(ofp.OFPP_CONTROLLER, max_len = 128)]
        # pkt = simple_tcp_packet()
        
        # delete_all_flows(self.controller)

        # logging.info("Inserting flow")
        # request = ofp.message.flow_add(
                # table_id=test_param_get("table", 0),
                # match = match,
                # instructions=[
                    # ofp.instruction.apply_actions(actions)],
                # buffer_id=ofp.OFP_NO_BUFFER, 
                # priority=1000)
        # self.controller.message_send(request)
        # logging.info("Inserting a table miss flow to forward packet to controller")
        # reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        # self.assertIsNone(reply, "Switch generated an error when inserting flow")

        # do_barrier(self.controller)

        # self.dataplane.send(in_port, str(pkt))
        # reply, _ = self.controller.poll(exp_msg = ofp.const.OFPT_PACKET_IN, timeout = 3)
        # self.assertIsNotNone(reply, "Did not receive packet in message")
        # logging.info("Received packet_in message.")
        # self.assertIsNotNone(reply.match.oxm_list, "oxm list was empty")
        
        # for oxm_id in reply.match.oxm_list:
            # self.assertIsNotNone(oxm_id.type_len, "OXM type was zero")


            
class Testcase_410_310_physical_port_match_omissions(base_tests.SimpleDataPlane):
    """
    Purpose
    Verify that ofp_packet_in messages generated due to traffic on physical ports report the correct in_port.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the 
    named field (under the given Pre-requisites for the match), with an action output to port CONTROLLER. Send
    a matching packet on a physical (non-logical) data plane port. Verify a packet_in message that encapsulates 
    the matching packet is triggered. Verify that OFPXMT_OFB_IN_PHY_PORT is omitted, and that OFPXMT_OFB_IN_PORT 
    is equal to the correct data plane port number. 

    """
    @wireshark_capture
    def runTest(self):
        logging.info("Running testcase 410.310 - Physical port match omissions")
        port, = openflow_ports(1)
        table_id=test_param_get("table", 0)
        test_port=test_param_get("logical_port", port)

        match = ofp.match([ofp.oxm.in_port(test_port)])
        actions = [ofp.action.output(ofp.OFPP_CONTROLLER, max_len = 128)]
        pkt = simple_tcp_packet()
        
        delete_all_flows(self.controller)

        logging.info("Inserting flow")
        request = ofp.message.flow_add(
                table_id=test_param_get("table", 0),
                match = match,
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER, 
                priority=1000)
        self.controller.message_send(request)
        logging.info("Inserting a table miss flow to forward packet to controller")
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "Switch generated an error when inserting flow")
        #logging.info("Switch generated an error")

        do_barrier(self.controller)

        self.dataplane.send(test_port, str(pkt))
        reply, _ = self.controller.poll(exp_msg = ofp.const.OFPT_PACKET_IN, timeout = 3)
        self.assertIsNotNone(reply, "Did not receive packet in message")
        logging.info("Received packet_in message.")
        self.assertIsNotNone(reply.match.oxm_list, "oxm list was empty")
        reported = []
        
        for oxm_id in reply.match.oxm_list:
            if oxm_id.type_len == in_phy_port.type_len:
                self.assertEqual(oxm_id.value, test_port, "in physical port value was not correct")
                reported.append(oxm_id.value)
            elif oxm_id.type_len == in_port.type_len:
                self.assertEqual(oxm_id.value, port, "in port value was not correct")
                logging.info("DUT did not configure physical in port")
                reported.append(oxm_id.value)
                
        self.assertTrue(len(reported)==1, "Physical port match was not omitted")
        
        
        
        
class Testcase_410_320_logical_port_match(Testcase_410_260_physical_port_match):
    """
    Tested in 410.260
    
    Purpose
    Verify that ofp_packet_in messages generated due to traffic on logical ports report the correct in_port.

    Methodology
    Configure and connect DUT to controller. After control channel establishment, add a flow matching on the named 
    field (under the given Pre-requisites for the match), with an action output to port CONTROLLER. Send a matching 
    packet on a logical port included in the data plane. Verify a packet_in message that encapsulates the matching 
    packet is triggered. Verify that OFPXMT_OFB_IN_PHY_PORT corresponds to the correct physical port, and that 
    OFPXMT_OFB_IN_PORT is equal to the correct logical data plane port number. 

    """