# Copyright (c) 2014 InCNTRE
#from conformance.incntreutils import *
from oftest import config
from oftest.parse import parse_ip, parse_ipv6, parse_mac
from oftest.mpls import *
from oftest.testutils import *
from time import sleep

import copy
import logging
import ofp
import oftest.base_tests as base_tests
import oftest.controller as controller
import oftest.dataplane as dataplane
import oftest.illegal_message as illegal_message
import oftest.parse as parse
import sys
import json
import os
from loxi.of13.oxm import *





def tables_supporting_action(testcase, action, property_type):
    """Returns a list of all tables supporting the requested action.

    For the given property_type, return a list of tables supporting
    action. Valid property_types include OFPTFPT_WRITE_ACTIONS* and
    OFPTFPT_APPLY_ACTIONS*.
    """
    # Valid property types for actions are 4, 5, 6, 7.
    valid_property_types = [ofp.const.OFPTFPT_WRITE_ACTIONS,
                            ofp.const.OFPTFPT_WRITE_ACTIONS_MISS,
                            ofp.const.OFPTFPT_APPLY_ACTIONS,
                            ofp.const.OFPTFPT_APPLY_ACTIONS_MISS]
    testcase.assertIn(property_type, valid_property_types,
                      ("Cannot check for action support, in non-action "
                       "table_feature_property."))

    corresponding_property = -1
    if (property_type % 2) != 0:
        corresponding_property = property_type - 1
    
    def supports_action(table):
        # When a property of the table-miss flow entry is the same as the
        # corresponding property for regular flow entries, this table-miss
        # property can be omited from the property list.

        corresponding_actions = []
        property_actions = []
        for prop in table.properties:
            if prop.type == corresponding_property:
                corresponding_actions = [act.type for act in prop.action_ids]
            if prop.type == property_type:
                property_actions = [act.type for act in prop.action_ids]

        if property_actions == []:
            if action in corresponding_actions:
                return table.table_id
            return -1

        if action in property_actions:
            return table.table_id
        return -1

    req = ofp.message.table_features_stats_request()
    res = get_stats(testcase, req)
    testcase.assertTrue(res, "Received no response to table_features_request.")
        
    return filter((lambda x: x > -1), map(supports_action, res))

        

def test_output(testcase, table_id, ports, property_type):
    """ Verify OFPAT_OUTPUT works as expected.
    @returns False if table_id doesn't support property_type
    """
    msg = "Checking if table {0} supports OFPAT_OUTPUT."
    logging.info(msg.format(table_id))

    # Check if table_id supports OFPAT_OUTPUT.
    supporting_tables = tables_supporting_action(testcase,
                                                 ofp.const.OFPAT_OUTPUT,
                                                 property_type)
    logging.info("Tables {0} support the OFPAT_OUTPUT.".format(supporting_tables))
    if table_id not in supporting_tables:
        logging.info("Table does not support OFPAT_OUTPUT type. Skipping check.")
        return False

    # If a property is not a *_MISS property set the priority to one.
    priority = 0
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        priority = 1
    if property_type == ofp.const.OFPTFPT_APPLY_ACTIONS:
        priority = 1

    actions = [ofp.action.output(port=ofp.OFPP_CONTROLLER, max_len=128)]
    instructions = []
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    elif property_type == ofp.const.OFPTFPT_WRITE_ACTIONS_MISS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    else:
        instructions.append(ofp.instruction.apply_actions(actions=actions))

    req = ofp.message.flow_add(table_id=table_id, instructions=instructions,
                               buffer_id=ofp.const.OFP_NO_BUFFER, priority=priority)
    testcase.controller.message_send(req)
    err, _ = testcase.controller.poll(exp_msg=ofp.const.OFPT_ERROR)
    testcase.assertIsNone(err, "Unexpected ofp_error_msg received: %s." % err)
    logging.info("Installed ofp_flow_mod table entry.")
    
    pkt = str(simple_tcp_packet())
    logging.info("Sending a packet to match on port %s.", ports[0])
    testcase.dataplane.send(ports[0], pkt)

    res, _ = testcase.controller.poll(exp_msg=ofp.const.OFPT_PACKET_IN)
    testcase.assertIsNotNone(res, "Did not receive expected ofp_packet_in.")
    return True


def test_copy_ttl_out(testcase, table_id, ports, property_type):
    """ Verify TTL can be copied outwards from IP to MPLS labled frames.
    Test case 110.220
    Configure and connect DUT to controller. After control channel 
    establishment, add a flow matching on the named field (under the 
    given Pre-requisites for the match), action push MPLS header. Send a
    matching packet with MPLS TTL field on the dataplane.Verify the 
    inner MPLS TTL field is copied to newly pushed MPLS TTL field.
    """
    msg = "Checking if table {0} supports OFPAT_COPY_TTL_OUT."
    logging.info(msg.format(table_id))

    # Check if table_id supports OFPAT_COPY_TTL_OUT.
    supporting_tables = tables_supporting_action(testcase,
                                                 ofp.const.OFPAT_COPY_TTL_OUT,
                                                 property_type)
    logging.info("Tables {0} support the OFPAT_COPT_TTL_OUT.".format(supporting_tables))
    if table_id not in supporting_tables:
        logging.info("Table does not support OFPAT_COPT_TTL_OUT type. Skipping check.")
        return False

    # If a property is not a *_MISS property set the priority to one.
    priority = 0
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        priority = 1
    if property_type == ofp.const.OFPTFPT_APPLY_ACTIONS:
        priority = 1

    # Valid MPLS ethertypes are 0x8847 (unicast) and 0x8848 (multicast).
    mpls_label = 23
    packet_ttl = 46
    actions = [
        ofp.action.push_mpls(ethertype=0x8847),
        ofp.action.set_field(ofp.oxm.mpls_label(mpls_label)),
        ofp.action.copy_ttl_out(),
        ofp.action.output(port=ports[1], max_len=128)
        ]
    instructions = []
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    elif property_type == ofp.const.OFPTFPT_WRITE_ACTIONS_MISS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    else:
        instructions.append(ofp.instruction.apply_actions(actions=actions))

    req = ofp.message.flow_add(table_id=table_id, instructions=instructions,
                               buffer_id=ofp.const.OFP_NO_BUFFER, priority=priority)
    testcase.controller.message_send(req)
    err, _ = testcase.controller.poll(exp_msg=ofp.const.OFPT_ERROR)
    testcase.assertIsNone(err, "Unexpected ofp_error_msg received: %s." % err)
    logging.info("Installed ofp_flow_mod table entry.")

    # Generate a packet with an IPv4 bos label.
    labels = [MPLS(label=0, ttl=30, s=1)]
    packet = simple_mpls_packet(ip_ttl=packet_ttl, mpls_labels=labels)
    testcase.dataplane.send(ports[0], str(packet))

    # After copy_ttl_out action we expect the ttl on the outer most
    # label should equal the ttl of the ip_ttl if DEC_MPLS_DDL is not
    # included.
    labels = [MPLS(label=0, ttl=30, s=1), MPLS(label=mpls_label, ttl=packet_ttl)]
    packet = simple_mpls_packet(ip_ttl=packet_ttl, mpls_labels=labels)    
    verify_packet(testcase, str(packet), ports[1])
    return True


def test_copy_ttl_in(testcase, table_id, ports, property_type):
    """ Verify TTL can be copied inwards from MPLS labled frames to IP frames.
    Test case 130.120
    """
    msg = "Checking if table {0} supports OFPAT_COPY_TTL_IN."
    logging.info(msg.format(table_id))

    # Check if table_id supports OFPAT_COPY_TTL_IN.
    supporting_tables = tables_supporting_action(testcase,
                                                 ofp.const.OFPAT_COPY_TTL_IN,
                                                 property_type)
    logging.info("Tables {0} support the OFPAT_COPT_TTL_IN.".format(supporting_tables))
    if table_id not in supporting_tables:
        logging.info("Table does not support OFPAT_COPT_TTL_IN type. Skipping check.")
        return False

    # If a property is not a *_MISS property set the priority to one.
    priority = 0
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        priority = 1
    if property_type == ofp.const.OFPTFPT_APPLY_ACTIONS:
        priority = 1

    # Push a MPLS label, set the label, and then copy the TTL outwards.
    # Valid MPLS ethertypes are 0x8847 (unicast) and 0x8848 (multicast).
    mpls_label = 23
    mpls_ttl = 25
    actions = [
        ofp.action.copy_ttl_in(),
        ofp.action.output(port=ports[1], max_len=128)
        ]
    instructions = []
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    elif property_type == ofp.const.OFPTFPT_WRITE_ACTIONS_MISS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    else:
        instructions.append(ofp.instruction.apply_actions(actions=actions))

    req = ofp.message.flow_add(table_id=table_id, instructions=instructions,
                               buffer_id=ofp.const.OFP_NO_BUFFER, priority=priority)
    testcase.controller.message_send(req)
    err, _ = testcase.controller.poll(exp_msg=ofp.const.OFPT_ERROR)
    testcase.assertIsNone(err, "Unexpected ofp_error_msg received: %s." % err)
    logging.info("Installed ofp_flow_mod table entry.")

    # Generate a packet with an IPv4 bos label.
    labels = [MPLS(label=0, ttl=mpls_ttl, s=1)]
    packet = simple_mpls_packet(ip_ttl=50, mpls_labels=labels)
    testcase.dataplane.send(ports[0], str(packet))

    # After copy_ttl_in action we expect the ttl on the outer most
    # label should equal the ttl of the ip_ttl.
    labels = [MPLS(label=0, ttl=mpls_ttl, s=1)]
    packet = simple_mpls_packet(ip_ttl=mpls_ttl, mpls_labels=labels)    
    verify_packet(testcase, str(packet), ports[1])
    return True


def test_set_mpls_ttl(testcase, table_id, ports, property_type):
    """ Verify TTL can be set on the top of stack MPLS label.
    Test case 230.90
    """
    msg = "Checking if table {0} supports OFPAT_SET_MPLS_TTL."
    logging.info(msg.format(table_id))

    # Check if table_id supports OFPAT_SET_MPLS_TTL.
    supporting_tables = tables_supporting_action(testcase,
                                                 ofp.const.OFPAT_SET_MPLS_TTL,
                                                 property_type)
    logging.info("Tables {0} support the OFPAT_SET_MPLS_TTL.".format(supporting_tables))
    if table_id not in supporting_tables:
        logging.info("Table does not support OFPAT_SET_MPLS_TTL type. Skipping check.")
        return False

    # If a property is not a *_MISS property set the priority to one.
    priority = 0
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        priority = 1
    if property_type == ofp.const.OFPTFPT_APPLY_ACTIONS:
        priority = 1

    mpls_ttl = 125
    actions = [
        ofp.action.set_mpls_ttl(mpls_ttl=mpls_ttl),
        ofp.action.output(port=ports[1], max_len=128)
        ]
    instructions = []
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    elif property_type == ofp.const.OFPTFPT_WRITE_ACTIONS_MISS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    else:
        instructions.append(ofp.instruction.apply_actions(actions=actions))

    req = ofp.message.flow_add(table_id=table_id, instructions=instructions,
                               buffer_id=ofp.const.OFP_NO_BUFFER, priority=priority)
    testcase.controller.message_send(req)
    err, _ = testcase.controller.poll(exp_msg=ofp.const.OFPT_ERROR)
    testcase.assertIsNone(err, "Unexpected ofp_error_msg received: %s." % err)
    logging.info("Installed ofp_flow_mod table entry.")

    # Generate a packet with an IPv4 bos label.
    labels = [MPLS(label=0, ttl=25, s=1)]
    packet = simple_mpls_packet(mpls_labels=labels)
    testcase.dataplane.send(ports[0], str(packet))

    # After copy_ttl_in action we expect the ttl on the outer most
    # label should equal the ttl of the ip_ttl.
    labels = [MPLS(label=0, ttl=mpls_ttl, s=1)]
    packet = simple_mpls_packet(mpls_labels=labels)    
    verify_packet(testcase, str(packet), ports[1])
    return True


def test_dec_mpls_ttl(testcase, table_id, ports, property_type):
    """ Verify TTL on the top of stack MPLS label can be decremented.
    Test case 230.100
    """
    msg = "Checking if table {0} supports OFPAT_DEC_MPLS_TTL."
    logging.info(msg.format(table_id))

    # Check if table_id supports OFPAT_DEC_MPLS_TTL.
    supporting_tables = tables_supporting_action(testcase,
                                                 ofp.const.OFPAT_DEC_MPLS_TTL,
                                                 property_type)
    logging.info("Tables {0} support the OFPAT_DEC_MPLS_TTL.".format(supporting_tables))
    if table_id not in supporting_tables:
        logging.info("Table does not support OFPAT_DEC_MPLS_TTL type. Skipping check.")
        return False

    # If a property is not a *_MISS property set the priority to one.
    priority = 0
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        priority = 1
    if property_type == ofp.const.OFPTFPT_APPLY_ACTIONS:
        priority = 1

    # Valid MPLS ethertypes are 0x8847 (unicast) and 0x8848 (multicast).
    mpls_ttl = 125
    actions = [
        ofp.action.dec_mpls_ttl(),
        ofp.action.output(port=ports[1], max_len=128)
        ]
    instructions = []
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    elif property_type == ofp.const.OFPTFPT_WRITE_ACTIONS_MISS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    else:
        instructions.append(ofp.instruction.apply_actions(actions=actions))

    req = ofp.message.flow_add(table_id=table_id, instructions=instructions,
                               buffer_id=ofp.const.OFP_NO_BUFFER, priority=priority)
    testcase.controller.message_send(req)
    err, _ = testcase.controller.poll(exp_msg=ofp.const.OFPT_ERROR)
    testcase.assertIsNone(err, "Unexpected ofp_error_msg received: %s." % err)
    logging.info("Installed ofp_flow_mod table entry.")

    # Generate a packet with an IPv4 bos label.
    labels = [MPLS(label=0, ttl=mpls_ttl, s=1)]
    packet = simple_mpls_packet(mpls_labels=labels)
    testcase.dataplane.send(ports[0], str(packet))

    # MPLS label should be the packet's label minus one.
    labels = [MPLS(label=0, ttl=mpls_ttl-1, s=1)]
    packet = simple_mpls_packet(mpls_labels=labels)    
    verify_packet(testcase, str(packet), ports[1])
    return True


def test_push_vlan(testcase, table_id, ports, property_type):
    """ Verify that VLAN tags can be pushed onto the packet.
    """
    msg = "Checking if table {0} supports OFPAT_PUSH_VLAN."
    logging.info(msg.format(table_id))

    # Check if table_id supports OFPAT_PUSH_VLAN.
    supporting_tables = tables_supporting_action(testcase,
                                                 ofp.const.OFPAT_PUSH_VLAN,
                                                 property_type)
    logging.info("Tables {0} support the OFPAT_PUSH_VLAN.".format(supporting_tables))
    if table_id not in supporting_tables:
        logging.info("Table does not support OFPAT_PUSH_VLAN type. Skipping check.")
        return False

    # If a property is not a *_MISS property set the priority to one.
    priority = 0
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        priority = 1
    if property_type == ofp.const.OFPTFPT_APPLY_ACTIONS:
        priority = 1

    actions = [
        ofp.action.push_vlan(ethertype=0x8100),
        ofp.action.output(port=ports[1], max_len=128)
        ]
    instructions = []
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    elif property_type == ofp.const.OFPTFPT_WRITE_ACTIONS_MISS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    else:
        instructions.append(ofp.instruction.apply_actions(actions=actions))

    req = ofp.message.flow_add(table_id=table_id, instructions=instructions,
                               buffer_id=ofp.const.OFP_NO_BUFFER, priority=priority)
    testcase.controller.message_send(req)
    err, _ = testcase.controller.poll(exp_msg=ofp.const.OFPT_ERROR)
    testcase.assertIsNone(err, "Unexpected ofp_error_msg received: %s." % err)
    logging.info("Installed ofp_flow_mod table entry.")

    packet = simple_tcp_packet()
    expected_packet = simple_tcp_packet(dl_vlan_enable=True)

    testcase.dataplane.send(ports[0], str(packet))
    verify_packet(testcase, str(expected_packet), ports[1])
    return True


def test_pop_vlan(testcase, table_id, ports, property_type):
    """ Verify that VLAN tags can be popped from the packet.
    """
    msg = "Checking if table {0} supports OFPAT_POP_VLAN."
    logging.info(msg.format(table_id))

    # Check if table_id supports OFPAT_POP_VLAN.
    supporting_tables = tables_supporting_action(testcase,
                                                 ofp.const.OFPAT_POP_VLAN,
                                                 property_type)
    logging.info("Tables {0} support the OFPAT_POP_VLAN.".format(supporting_tables))
    if table_id not in supporting_tables:
        logging.info("Table does not support OFPAT_POP_VLAN type. Skipping check.")
        return False

    # If a property is not a *_MISS property set the priority to one.
    priority = 0
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        priority = 1
    if property_type == ofp.const.OFPTFPT_APPLY_ACTIONS:
        priority = 1
    actions = [
        ofp.action.pop_vlan(),
        ofp.action.output(port=ports[1], max_len=128)
        ]
    instructions = []
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    elif property_type == ofp.const.OFPTFPT_WRITE_ACTIONS_MISS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    else:
        instructions.append(ofp.instruction.apply_actions(actions=actions))

    req = ofp.message.flow_add(table_id=table_id, match = ofp.match([ofp.oxm.vlan_vid(value=0x1002)]),instructions=instructions,
                               buffer_id=ofp.const.OFP_NO_BUFFER, priority=priority)
    testcase.controller.message_send(req)
    err, _ = testcase.controller.poll(exp_msg=ofp.const.OFPT_ERROR)
    testcase.assertIsNone(err, "Unexpected ofp_error_msg received: %s." % err)
    logging.info("Installed ofp_flow_mod table entry.")

    packet = simple_tcp_packet(dl_vlan_enable=True, vlan_vid=2)
    expected_packet = simple_tcp_packet(pktlen=96)
    testcase.dataplane.send(ports[0], str(packet))
    verify_packet(testcase, str(expected_packet), ports[1])
    return True


def test_push_mpls(testcase, table_id, ports, property_type):
    """ Verify that MPLS tags can be pushed onto the packet.
    """
    msg = "Checking if table {0} supports OFPAT_PUSH_MPLS."
    logging.info(msg.format(table_id))

    # Check if table_id supports OFPAT_PUSH_MPLS.
    supporting_tables = tables_supporting_action(testcase,
                                                 ofp.const.OFPAT_PUSH_MPLS,
                                                 property_type)
    logging.info("Tables {0} support the OFPAT_PUSH_MPLS.".format(supporting_tables))
    if table_id not in supporting_tables:
        logging.info("Table does not support OFPAT_PUSH_MPLS type. Skipping check.")
        return False

    # If a property is not a *_MISS property set the priority to one.
    priority = 0
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        priority = 1
    if property_type == ofp.const.OFPTFPT_APPLY_ACTIONS:
        priority = 1

    actions = [
        ofp.action.push_mpls(ethertype=0x8847),
        ofp.action.output(port=ports[1], max_len=128)
        ]
    instructions = []
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    elif property_type == ofp.const.OFPTFPT_WRITE_ACTIONS_MISS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    else:
        instructions.append(ofp.instruction.apply_actions(actions=actions))

    req = ofp.message.flow_add(table_id=table_id, instructions=instructions,
                               buffer_id=ofp.const.OFP_NO_BUFFER, priority=priority)
    testcase.controller.message_send(req)
    err, _ = testcase.controller.poll(exp_msg=ofp.const.OFPT_ERROR)
    testcase.assertIsNone(err, "Unexpected ofp_error_msg received: %s." % err)
    logging.info("Installed ofp_flow_mod table entry.")

    # Field values of all fields specified in Table 8 should be copied
    # from existing outer headers to new outer headers when executing a
    # push action.
    ttl = 25
    packet = simple_tcp_packet(ip_ttl=ttl)
    lables = [MPLS(label=0, ttl=ttl, s=1)]
    expected_packet = simple_mpls_packet(mpls_labels=labels)

    testcase.dataplane.send(ports[0], str(packet))
    verify_packet(testcase, str(expected_packet), ports[1])
    return True


def test_pop_mpls(testcase, table_id, ports, property_type):
    """ Verify that MPLS tags can be popped from the packet.
    """
    msg = "Checking if table {0} supports OFPAT_POP_MPLS."
    logging.info(msg.format(table_id))

    # Check if table_id supports OFPAT_POP_MPLS.
    supporting_tables = tables_supporting_action(testcase,
                                                 ofp.const.OFPAT_POP_MPLS,
                                                 property_type)
    logging.info("Tables {0} support the OFPAT_POP_MPLS.".format(supporting_tables))
    if table_id not in supporting_tables:
        logging.info("Table does not support OFPAT_POP_MPLS type. Skipping check.")
        return False

    # If a property is not a *_MISS property set the priority to one.
    priority = 0
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        priority = 1
    if property_type == ofp.const.OFPTFPT_APPLY_ACTIONS:
        priority = 1

    actions = [
        ofp.action.pop_mpls(),
        ofp.action.output(port=ports[1], max_len=128)
        ]
    instructions = []
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    elif property_type == ofp.const.OFPTFPT_WRITE_ACTIONS_MISS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    else:
        instructions.append(ofp.instruction.apply_actions(actions=actions))

    req = ofp.message.flow_add(table_id=table_id, instructions=instructions,
                               buffer_id=ofp.const.OFP_NO_BUFFER, priority=priority)
    testcase.controller.message_send(req)
    err, _ = testcase.controller.poll(exp_msg=ofp.const.OFPT_ERROR)
    testcase.assertIsNone(err, "Unexpected ofp_error_msg received: %s." % err)
    logging.info("Installed ofp_flow_mod table entry.")

    ttl = 25
    lables = [MPLS(label=0, ttl=ttl, s=1)]
    packet = simple_mpls_packet(mpls_labels=labels)
    expected_packet = simple_tcp_packet()

    testcase.dataplane.send(ports[0], str(packet))
    verify_packet(testcase, str(expected_packet), ports[1])
    return True


def test_set_queue(testcase, table_id, ports, property_type):
    """ Verify that packets can be placed in the correct queue.
    """
    msg = "Checking if table {0} supports OFPAT_SET_QUEUE."
    logging.info(msg.format(table_id))

    # Check if table_id supports OFPAT_SET_QUEUE.
    supporting_tables = tables_supporting_action(testcase,
                                                 ofp.const.OFPAT_SET_QUEUE,
                                                 property_type)
    logging.info("Tables {0} support the OFPAT_SET_QUEUE.".format(supporting_tables))
    if table_id not in supporting_tables:
        logging.info("Table does not support OFPAT_SET_QUEUE type. Skipping check.")
        return False

    # If a property is not a *_MISS property set the priority to one.
    priority = 0
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        priority = 1
    if property_type == ofp.const.OFPTFPT_APPLY_ACTIONS:
        priority = 1

    req = ofp.message.queue_stats_request(port_no=ports[1])
    res = get_stats(testcase, req)
    if len(res) < 1:
        logging.warn("DUT claims to support queues, but none appear configured.")
        return True
    queue_id = res[0].queue_id
    tx_packets = res[0].tx_packets

    actions = [
        ofp.action.set_queue(queue_id),
        ofp.action.output(port=ports[1], max_len=128)
        ]
    instructions = []
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    elif property_type == ofp.const.OFPTFPT_WRITE_ACTIONS_MISS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    else:
        instructions.append(ofp.instruction.apply_actions(actions=actions))

    req = ofp.message.flow_add(table_id=table_id, instructions=instructions,
                               buffer_id=ofp.const.OFP_NO_BUFFER, priority=priority)
    testcase.controller.message_send(req)
    err, _ = testcase.controller.poll(exp_msg=ofp.const.OFPT_ERROR)
    testcase.assertIsNone(err, "Unexpected ofp_error_msg received: %s." % err)
    logging.info("Installed ofp_flow_mod table entry.")

    packet = simple_tcp_packet()
    testcase.dataplane.send(ports[0], str(packet))
    verify_packet(testcase, str(packet), ports[1])

    req = ofp.message.queue_stats_request(port_no=ports[1])
    res = get_stats(testcase, req)
    testcase.assertEqual(res[0].tx_packets, tx_packets + 1,
                         "Received wrong tx_count, could not verify queue.")
    return True


def test_group(testcase, table_id, ports, property_type):
    """ Verify that packets can be placed in the correct queue.
    """
    msg = "Checking if table {0} supports OFPAT_SET_QUEUE."
    logging.info(msg.format(table_id))

    # Check if table_id supports OFPAT_SET_QUEUE.
    supporting_tables = tables_supporting_action(testcase,
                                                 ofp.const.OFPAT_SET_QUEUE,
                                                 property_type)
    logging.info("Tables {0} support the OFPAT_SET_QUEUE.".format(supporting_tables))
    if table_id not in supporting_tables:
        logging.info("Table does not support OFPAT_SET_QUEUE type. Skipping check.")
        return False

    # If a property is not a *_MISS property set the priority to one.
    priority = 0
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        priority = 1
    if property_type == ofp.const.OFPTFPT_APPLY_ACTIONS:
        priority = 1
    group_id = 1

    req = ofp.message.group_add(
        group_type=ofp.OFPGT_ALL,
        group_id=group_id,
        buckets=[
            ofp.bucket(actions=[ofp.action.output(ports[1])])
            ])
    testcase.controller.message_send(req)
    err, _ = testcase.controller.poll(exp_msg=ofp.const.OFPT_ERROR)
    testcase.assertIsNone(err, "Unexpected ofp_error_msg received: %s." % err)

    actions = [ofp.action.group(group_id=group_id)]
    instructions = []
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    elif property_type == ofp.const.OFPTFPT_WRITE_ACTIONS_MISS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    else:
        instructions.append(ofp.instruction.apply_actions(actions=actions))

    req = ofp.message.flow_add(table_id=table_id, instructions=instructions,
                               buffer_id=ofp.const.OFP_NO_BUFFER, priority=priority)
    testcase.controller.message_send(req)
    err, _ = testcase.controller.poll(exp_msg=ofp.const.OFPT_ERROR)
    testcase.assertIsNone(err, "Unexpected ofp_error_msg received: %s." % err)

    packet = simple_tcp_packet()
    testcase.dataplane.send(ports[0], str(packet))
    verify_packet(testcase, str(packet), ports[1])
    return True


def test_set_nw_ttl(testcase, table_id, ports, property_type):
    msg = "Checking if table {0} supports OFPAT_SET_NW_TTL."
    logging.info(msg.format(table_id))

    # Check if table_id supports OFPAT_SET_NW_TTL.
    supporting_tables = tables_supporting_action(testcase,
                                                 ofp.const.OFPAT_SET_NW_TTL,
                                                 property_type)
    logging.info("Tables {0} support the OFPAT_SET_NW_TTL.".format(supporting_tables))
    if table_id not in supporting_tables:
        logging.info("Table does not support OFPAT_SET_NW_TTL type. Skipping check.")
        return False

    # If a property is not a *_MISS property set the priority to one.
    priority = 0
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        priority = 1
    if property_type == ofp.const.OFPTFPT_APPLY_ACTIONS:
        priority = 1
    ttl = 25
    exp_ttl = 50

    actions = [
        ofp.action.set_nw_ttl(exp_ttl),
        ofp.action.output(port=ports[1], max_len=128)
        ]
    instructions = []
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    elif property_type == ofp.const.OFPTFPT_WRITE_ACTIONS_MISS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    else:
        instructions.append(ofp.instruction.apply_actions(actions=actions))

    req = ofp.message.flow_add(table_id=table_id, instructions=instructions,
                               buffer_id=ofp.const.OFP_NO_BUFFER, priority=priority)
    testcase.controller.message_send(req)
    err, _ = testcase.controller.poll(exp_msg=ofp.const.OFPT_ERROR)
    testcase.assertIsNone(err, "Unexpected ofp_error_msg received: %s." % err)
    logging.info("Installed ofp_flow_mod table entry.")

    packet = simple_tcp_packet(ip_ttl=ttl)
    expected_packet = simple_tcp_packet(ip_ttl=exp_ttl)
    testcase.dataplane.send(ports[0], str(packet))
    verify_packet(testcase, str(expected_packet), ports[1])
    return True


def test_dec_nw_ttl(testcase, table_id, ports, property_type):
    msg = "Checking if table {0} supports OFPAT_DEC_NW_TTL."
    logging.info(msg.format(table_id))

    # Check if table_id supports OFPAT_DEC_NW_TTL.
    supporting_tables = tables_supporting_action(testcase,
                                                 ofp.const.OFPAT_DEC_NW_TTL,
                                                 property_type)
    logging.info("Tables {0} support the OFPAT_DEC_NW_TTL.".format(supporting_tables))
    if table_id not in supporting_tables:
        logging.info("Table does not support OFPAT_DEC_NW_TTL type. Skipping check.")
        return False

    # If a property is not a *_MISS property set the priority to one.
    priority = 0
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        priority = 1
    if property_type == ofp.const.OFPTFPT_APPLY_ACTIONS:
        priority = 1
    ttl = 25
    exp_ttl = 24

    actions = [
        ofp.action.dec_nw_ttl(),
        ofp.action.output(port=ports[1], max_len=128)
        ]
    instructions = []
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    elif property_type == ofp.const.OFPTFPT_WRITE_ACTIONS_MISS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    else:
        instructions.append(ofp.instruction.apply_actions(actions=actions))

    req = ofp.message.flow_add(table_id=table_id, instructions=instructions,
                               buffer_id=ofp.const.OFP_NO_BUFFER, priority=priority)
    testcase.controller.message_send(req)
    err, _ = testcase.controller.poll(exp_msg=ofp.const.OFPT_ERROR)
    testcase.assertIsNone(err, "Unexpected ofp_error_msg received: %s." % err)
    logging.info("Installed ofp_flow_mod table entry.")

    packet = simple_tcp_packet(ip_ttl=ttl)
    expected_packet = simple_tcp_packet(ip_ttl=exp_ttl)
    testcase.dataplane.send(ports[0], str(packet))
    verify_packet(testcase, str(expected_packet), ports[1])
    return True

    
    
def get_oxm_ids(test,table_id,prop_type):
    
    """
    Returns the list of all oxm_ids returned by the DUT
    of the particular prop_type
    @param test instance of base_testa
    @param table_id table_id to get the oxm_ids from
    @prop_type One of the valid prop_types of OFPTFPT_*
    """
    oids = []
    valid_prop = [ofp.const.OFPTFPT_WILDCARDS,
                  ofp.const.OFPTFPT_MATCH,
                  ofp.const.OFPTFPT_WRITE_SETFIELD,
                  ofp.const.OFPTFPT_WRITE_SETFIELD_MISS,
                  ofp.const.OFPTFPT_APPLY_SETFIELD,
                  ofp.const.OFPTFPT_APPLY_SETFIELD_MISS]
    test.assertIn(prop_type,valid_prop, "%s is not valid prop_type for oxm_ids"%prop_type)
    req = ofp.message.table_features_stats_request()
    res = get_stats(test, req)
    test.assertIsNotNone(res, "Could not retreive table statistics.")
    logging.info("Table features were successfully received.")
    for features in res:
        if features.table_id == table_id:
           for prop in features.properties:
               if prop.type == prop_type:
                   for ids in prop.oxm_ids:
                       try:
                           oids.append(oxm.subtypes[ids.value].__name__)
                       except KeyError:
                           logging.warn("Invalid oxm_id reported %d"%ids.value)
                           continue
                   return oids
               else:
                   continue

    return oids
    

def test_set_field(testcase, table_id, ports, property_type):
    msg = "Checking if table {0} supports OFPAT_SET_FIELD."
    logging.info(msg.format(table_id))

    # Check if table_id supports OFPAT_SET_FIELD.
    supporting_tables = tables_supporting_action(testcase,
                                                 ofp.const.OFPAT_SET_FIELD,
                                                 property_type)
    logging.info("Tables {0} support the OFPAT_OFPAT_SET_FIELD.".format(supporting_tables))
    if table_id not in supporting_tables:
        logging.info("Table does not support OFPAT_OFPAT_SET_FIELD type. Skipping check.")
        return False

    # If a property is not a *_MISS property set the priority to one.
    priority = 0
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        priority = 1
    if property_type == ofp.const.OFPTFPT_APPLY_ACTIONS:
        priority = 1

    if property_type==ofp.const.OFPTFPT_WRITE_ACTIONS_MISS:
	property_type=ofp.const.OFPTFPT_WRITE_SETFIELD_MISS
    elif property_type==ofp.const.OFPTFPT_WRITE_ACTIONS:
	property_type=ofp.const.OFPTFPT_WRITE_SETFIELD
    elif property_type==ofp.const.OFPTFPT_APPLY_ACTIONS:
	property_type=ofp.const.OFPTFPT_APPLY_SETFIELD
    elif property_type==ofp.const.OFPTFPT_APPLY_ACTIONS_MISS:
	property_type=ofp.const.OFPTFPT_APPLY_SETFIELD_MISS
    oxm_ids = get_oxm_ids(testcase, table_id, property_type)
    if oxm_ids is []:
        logging.warn("DUT supports set-field action, but no oxm types.")
        return False

    # Generate an expected_packet and associated oxm tlv
    packet = simple_tcp_packet()
    expected_packet = None
    oxm_under_test = None

    ipv4 = "127.127.127.127"
    mac = "aa:bb:cc:dd:ee:ff"
    oxm_packets = [
        (ofp.oxm.ipv4_src(value=parse_ip(ipv4)), simple_tcp_packet(ip_src=ipv4)),
        (ofp.oxm.ipv4_dst(value=parse_ip(ipv4)), simple_tcp_packet(ip_dst=ipv4)),
        (ofp.oxm.eth_src(value=parse_mac(mac)), simple_tcp_packet(eth_src=mac)),
        (ofp.oxm.eth_dst(value=parse_mac(mac)), simple_tcp_packet(eth_src=mac))
        ]
    for oxm_pkt in oxm_packets:
        if oxm_pkt[0].type_len in oxm_ids:
            oxm_under_test, expected_packet = oxm_pkt
    if oxm_under_test is None:
        logging.warn("DUT doesn't support common oxm set-field types.")
        return False

    actions = [
        ofp.action.set_field(field=oxm_under_test),
        ofp.action.output(port=ports[1], max_len=128)
        ]
    instructions = []
    if property_type == ofp.const.OFPTFPT_WRITE_ACTIONS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    elif property_type == ofp.const.OFPTFPT_WRITE_ACTIONS_MISS:
        instructions.append(ofp.instruction.write_actions(actions=actions))
    else:
        instructions.append(ofp.instruction.apply_actions(actions=actions))

    req = ofp.message.flow_add(table_id=table_id, instructions=instructions,
                               buffer_id=ofp.const.OFP_NO_BUFFER, priority=priority)
    testcase.controller.message_send(req)
    err, _ = testcase.controller.poll(exp_msg=ofp.const.OFPT_ERROR)
    testcase.assertIsNone(err, "Unexpected ofp_error_msg received: %s." % err)
    logging.info("Installed ofp_flow_mod table entry.")

    packet = simple_tcp_packet()
    testcase.dataplane.send(ports[0], str(packet))
    verify_packet(testcase, str(expected_packet), ports[1])    
    return True


def test_push_pbb(testcase, table_id, ports, property_type):
    return True

def test_pop_pbb(testcase, table_id, ports, property_type):
    return True
