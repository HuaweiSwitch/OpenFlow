"""
Group table test cases.
"""
#import time
#import signal
#import sys
import logging

import oftest.match as oxm_field
import oftest.cstruct as ofp
import oftest.controller as controller
import oftest.dataplane as dataplane
import oftest.message as message
import oftest.action as action
import oftest.instruction as instruction
import oftest.bucket as bucket
import oftest.parse as parse
import oftest.match as match
import unittest
import basic

import testutils


group_port_map = None
group_logger = None
group_config = None

test_prio = {}

def test_set_init(config):
    """
    Set up function for basic test classes

    @param config The configuration dictionary; see oft
    """

    global group_port_map
    global group_logger
    global group_config

    group_logger = logging.getLogger("group")
    group_logger.info("Initializing test set")
    group_port_map = config["port_map"]
    group_config = config



def create_group_desc_stats_req():
    # XXX Zoltan: hack, remove if message module is fixed
    m = message.group_desc_stats_request()

    return m



def create_group_stats_req(group_id = 0):
    m = message.group_stats_request()
    m.group_id = group_id

    return m



def create_group_mod_msg(command = ofp.OFPGC_ADD, type = ofp.OFPGT_ALL,
               group_id = 0, buckets = []):
    m = message.group_mod()
    m.command = command
    m.type = type
    m.group_id = group_id
    for b in buckets:
        m.buckets.add(b)

    return m



# XXX Zoltan: watch_port/_group off ?
def create_bucket(weight = 0, watch_port = 0, watch_group = 0, actions=[]):
    b = bucket.bucket()
    b.weight = weight
    b.watch_port = watch_port
    b.watch_group = watch_group
    for a in actions:
        b.actions.add(a)

    return b



def create_action(**kwargs):
    a = kwargs.get('action')
    if a == ofp.OFPAT_OUTPUT:
        act = action.action_output()
        act.port = kwargs.get('port', group_port_map.keys()[0])
        return act
    if a == ofp.OFPAT_GROUP:
        act = action.action_group()
        act.group_id = kwargs.get('group_id', 0)
        return act
    if a == ofp.OFPAT_SET_FIELD:
        port = kwargs.get('tcp_sport', 0)
        field_2b_set = oxm_field.tcp_src(port)
        act = action.action_set_field()
        act.field = field_2b_set
        return act;



def create_flow_msg(packet = None, in_port = None, match = None, apply_action_list = []):

    apply_inst = instruction.instruction_apply_actions()

    if apply_action_list is not None:
        for act in apply_action_list:
            apply_inst.actions.add(act)

    request = message.flow_mod()
    request.match.type = ofp.OFPMT_OXM

    if match is None:
        match = parse.packet_to_flow_match(packet)

    request.match_fields = match

    if in_port != None:
        match_port = oxm_field.in_port(in_port)
        request.match_fields.tlvs.append(match_port)
    request.buffer_id = 0xffffffff
    request.priority = 1000

    request.instructions.add(apply_inst)

    return request



class GroupTest(basic.SimpleDataPlane):

    def clean_switch(self):
        testutils.clear_switch(self,group_port_map,group_logger)

    def send_ctrl_exp_noerror(self, msg, log = ''):
        group_logger.info('Sending message ' + log)
        testutils.ofmsg_send(self, msg)

        group_logger.info('Waiting for error messages...')
        (response, raw) = self.controller.poll(ofp.OFPT_ERROR, 1)

        self.assertTrue(response is None, 'Unexpected error message received')

        testutils.do_barrier(self.controller);



    def send_ctrl_exp_error(self, msg, log = '', type = 0, code = 0):
        group_logger.info('Sending message ' + log)
        testutils.ofmsg_send(self, msg)

        group_logger.info('Waiting for error messages...')
        (response, raw) = self.controller.poll(ofp.OFPT_ERROR, 1)

        self.assertTrue(response is not None,
                        'Did not receive an error message')

        self.assertEqual(response.header.type, ofp.OFPT_ERROR,
                         'Did not receive an error message')

        if type != 0:
            self.assertEqual(response.type, type,
                             'Did not receive a ' + str(type) + ' type error message')

        if code != 0:
            self.assertEqual(response.code, code,
                             'Did not receive a ' + str(code) + ' code error message')

        testutils.do_barrier(self.controller);



    def send_ctrl_exp_reply(self, msg, header_type = ofp.OFPT_ERROR, body_type = None, log = ''):
        group_logger.info('Sending message ' + log)
        testutils.ofmsg_send(self, msg)

        group_logger.info('Waiting for error messages...')
        (response, raw) = self.controller.poll(header_type, 1)

        if body_type is not None:
            while response is not None:
                if response.type == body_type:
                    break
                (response, raw) = self.controller.poll(header_type, 1)

        self.assertTrue(response is not None, 'Did not receive expected message')

        return response



    def send_data(self, packet, in_port):
        self.logger.debug("Send packet on port " + str(in_port))
        self.dataplane.send(in_port, str(packet))


    def recv_data(self, port, expected = None):
        pkt = testutils.receive_pkt_verify(self, port, expected)
        return pkt

"""
Management
"""

class GroupAdd(GroupTest):
    """
    A regular group should be added successfully (without errors)
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 0, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[0])
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg, 'group add')



class GroupAddInvalidAction(GroupTest):
    """
    If any action in the buckets is invalid, OFPET_BAD_ACTION/<code> should be returned
    """

    def runTest(self):
        self.clean_switch()

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 0, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action= ofp.OFPAT_OUTPUT, port= ofp.OFPP_ANY)
            ])
        ])

        self.send_ctrl_exp_error(group_add_msg, 'group add',
                                 ofp.OFPET_BAD_ACTION,
                                 ofp.OFPBAC_BAD_OUT_PORT)



class GroupAddExisting(GroupTest):
    """
    An addition with existing group id should result in OFPET_GROUP_MOD_FAILED/OFPGMFC_GROUP_EXISTS
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 0, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[0])
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg, 'group add 1')

        self.send_ctrl_exp_error(group_add_msg, 'group add 2',
                                 ofp.OFPET_GROUP_MOD_FAILED,
                                 ofp.OFPGMFC_GROUP_EXISTS)



class GroupAddInvalidID(GroupTest):
    """
    An addition with invalid group id (reserved) should result in OFPET_GROUP_MOD_FAILED/OFPGMFC_INVALID_GROUP
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = ofp.OFPG_ALL, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[0])
            ])
        ])

        self.send_ctrl_exp_error(group_add_msg, 'group add',
                                 ofp.OFPET_GROUP_MOD_FAILED,
                                 ofp.OFPGMFC_INVALID_GROUP)



class GroupMod(GroupTest):
    """
    A regular group modification should be successful (no errors)
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 0, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[1])
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg, 'group add')

        group_mod_msg = \
        create_group_mod_msg(ofp.OFPGC_MODIFY, ofp.OFPGT_ALL, group_id = 0, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[2])
            ])
        ])

        self.send_ctrl_exp_noerror(group_mod_msg, 'group mod')



class GroupModNonexisting(GroupTest):
    """
    A modification for non-existing group should result in OFPET_GROUP_MOD_FAILED/OFPGMFC_UNKNOWN_GROUP
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 0, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[0])
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg, 'group add')

        group_mod_msg = \
        create_group_mod_msg(ofp.OFPGC_MODIFY, ofp.OFPGT_ALL, group_id = 1, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[1])
            ])
        ])

        self.send_ctrl_exp_error(group_mod_msg, 'group mod',
                                 ofp.OFPET_GROUP_MOD_FAILED,
                                 ofp.OFPGMFC_UNKNOWN_GROUP)



class GroupModLoop(GroupTest):
    """
    A modification causing loop should result in OFPET_GROUP_MOD_FAILED/OFPGMFC_LOOP
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()

        group_add_msg1 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 0, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[0])
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg1, 'group add 1')

        group_add_msg2 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 1, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action= ofp.OFPAT_GROUP, group_id= 0)
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg2, 'group add 2')

        group_add_msg3 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 2, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action= ofp.OFPAT_GROUP, group_id= 0)
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg3, 'group add 3')


        group_mod_msg = \
        create_group_mod_msg(ofp.OFPGC_MODIFY, ofp.OFPGT_ALL, group_id = 0, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action= ofp.OFPAT_GROUP, group_id= 2)
            ])
        ])

        self.send_ctrl_exp_error(group_mod_msg, 'group mod',
                                 ofp.OFPET_GROUP_MOD_FAILED,
                                 ofp.OFPGMFC_LOOP)



class GroupModInvalidID(GroupTest):
    """
    A modification for reserved group should result in OFPET_BAD_ACTION/OFPGMFC_INVALID_GROUP
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()

        group_mod_msg = \
        create_group_mod_msg(ofp.OFPGC_MODIFY, ofp.OFPGT_ALL, group_id = ofp.OFPG_ALL, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[0])
            ])
        ])

        self.send_ctrl_exp_error(group_mod_msg, 'group mod',
                                 ofp.OFPET_GROUP_MOD_FAILED,
                                 ofp.OFPGMFC_INVALID_GROUP)



class GroupModEmpty(GroupTest):
    """
    A modification for existing group with no buckets should be accepted
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 0, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[0])
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg, 'group add')

        group_mod_msg = \
        create_group_mod_msg(ofp.OFPGC_MODIFY, ofp.OFPGT_ALL, group_id = 0, buckets = [
        ])

        self.send_ctrl_exp_noerror(group_mod_msg, 'group mod')



class GroupDelExisting(GroupTest):
    """
    A deletion for existing group should remove the group
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 10, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[0])
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg, 'group add')

        group_del_msg = \
        create_group_mod_msg(ofp.OFPGC_DELETE, ofp.OFPGT_ALL, group_id = 10, buckets = [
        ])

        self.send_ctrl_exp_noerror(group_del_msg, 'group del')

        self.send_ctrl_exp_noerror(group_add_msg, 'group add')


class GroupDelNonexisting(GroupTest):
    """
    A deletion for nonexisting group should result in no error
    """

    def runTest(self):
        self.clean_switch()

        group_del_msg = \
        create_group_mod_msg(ofp.OFPGC_DELETE, ofp.OFPGT_ALL, group_id = 20, buckets = [
        ])

        self.send_ctrl_exp_noerror(group_del_msg, 'group del')


class GroupDelAll(GroupTest):
    """
    #@todo: A deletion for OFGP_ALL should remove all groups
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()

        group_add_msg1 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 1, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[0])
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg1, 'group add 1')

        group_add_msg2 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 2, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[1])
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg2, 'group add 2')

        group_del_msg = \
        create_group_mod_msg(ofp.OFPGC_DELETE, group_id = ofp.OFPG_ALL)

        self.send_ctrl_exp_noerror(group_del_msg, 'group del')

        self.send_ctrl_exp_noerror(group_add_msg1, 'group add 1')
        self.send_ctrl_exp_noerror(group_add_msg2, 'group add 2')


"""
Management (specific)
"""

class GroupAddAllWeight(GroupTest):
    """
    An ALL group with weights for buckets should result in OFPET_GROUP_MOD_FAILED, OFPGMFC_INVALID_GROUP
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 0, buckets = [
            create_bucket(1, 0, 0, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[0])
            ]),
            create_bucket(2, 0, 0, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[1])
            ])
        ])

        self.send_ctrl_exp_error(group_add_msg, 'group add',
                                 ofp.OFPET_GROUP_MOD_FAILED,
                                 ofp.OFPGMFC_INVALID_GROUP)



class GroupAddIndirectWeight(GroupTest):
    """
    An INDIRECT group with weights for buckets should result in OFPET_GROUP_MOD_FAILED, OFPGMFC_INVALID_GROUP
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_INDIRECT, group_id = 0, buckets = [
            create_bucket(1, 0, 0, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[1])
            ])
        ])

        self.send_ctrl_exp_error(group_add_msg, 'group add',
                                 ofp.OFPET_GROUP_MOD_FAILED,
                                 ofp.OFPGMFC_INVALID_GROUP)

class GroupAddIndirectNoBucket(GroupTest):
    """
    An INDIRECT group without bucket should result in OFPET_GROUP_MOD_FAILED, OFPGMFC_INVALID_GROUP
    """

    def runTest(self):
        self.clean_switch()

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_INDIRECT, group_id = 0, buckets = [])

        self.send_ctrl_exp_error(group_add_msg, 'group add',
                                 ofp.OFPET_GROUP_MOD_FAILED,
                                 ofp.OFPGMFC_INVALID_GROUP)

class GroupAddIndirectBuckets(GroupTest):
    """
    An INDIRECT group with <>1 bucket should result in OFPET_GROUP_MOD_FAILED, OFPGMFC_INVALID_GROUP
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_INDIRECT, group_id = 0, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[0])
            ]),
            create_bucket(0, 0, 0, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[1])
            ])
        ])

        self.send_ctrl_exp_error(group_add_msg, 'group add',
                                 ofp.OFPET_GROUP_MOD_FAILED,
                                 ofp.OFPGMFC_INVALID_GROUP)



class GroupAddSelectNoWeight(GroupTest):
    """
    A SELECT group with ==0 weights should result in OFPET_GROUP_MOD_FAILED, OFPGMFC_INVALID_GROUP
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_SELECT, group_id = 0, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[0])
            ]),
            create_bucket(0, 0, 0, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[1])
            ])
        ])

        self.send_ctrl_exp_error(group_add_msg, 'group add',
                                 ofp.OFPET_GROUP_MOD_FAILED,
                                 ofp.OFPGMFC_INVALID_GROUP)

class GroupAddFFNoBucket(GroupTest):
    """
    A FF group without bucket should result in packet drop
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_FF, group_id = 0, buckets = [])

        self.send_ctrl_exp_noerror(group_add_msg, 'group add')

        pkt  = testutils.simple_tcp_packet()

        flow_add_msg = \
        testutils.flow_msg_create(self, pkt,ing_port = of_ports[0], action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 0)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg, 'flow add')

        self.send_data(pkt, of_ports[0])

        for of_port in of_ports:
            self.recv_data(of_port, None)


class GroupAddFFInvalidGroupId(GroupTest):
    """
    A fast failover group pointed to a invalid group_id should result in OFPET_GROUP_MOD_FAILED, OFPGMFC_INVALID_GROUP
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_FF, group_id = 0, buckets = [
            create_bucket(0, 2, ofp.OFPG_ANY, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[1])
            ]),
            create_bucket(0, ofp.OFPP_ANY, 1, [
                create_action(action= ofp.OFPAT_GROUP, group_id= 1)
            ])
        ])

        self.send_ctrl_exp_error(group_add_msg, 'group add',
                                 ofp.OFPET_BAD_ACTION,
                                 ofp.OFPBAC_BAD_OUT_GROUP)


class GroupAddFFWeight(GroupTest):
    """
    A fast failover group with weights for buckets should result in OFPET_GROUP_MOD_FAILED, OFPGMFC_INVALID_GROUP
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_FF, group_id = 0, buckets = [
            create_bucket(1, 2, ofp.OFPG_ANY, [
                create_action(action= ofp.OFPAT_OUTPUT, port= of_ports[1])
            ])
        ])

        self.send_ctrl_exp_error(group_add_msg, 'group add',
                                 ofp.OFPET_GROUP_MOD_FAILED,
                                 ofp.OFPGMFC_INVALID_GROUP)
class GroupModifyFF(GroupTest):
    """
    A fast failover group modify
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()
        ing_port = of_ports[1]
        new_egr_port = of_ports[2]
        org_egr_port = of_ports[0]

        group_add_msg_add = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_FF, group_id = 0, buckets = [
            create_bucket(0, org_egr_port, ofp.OFPG_ANY, [
                create_action(action= ofp.OFPAT_OUTPUT, port= org_egr_port)
            ])
        ])

        group_add_msg_modify = \
        create_group_mod_msg(ofp.OFPGC_MODIFY, ofp.OFPGT_FF, group_id = 0, buckets = [
            create_bucket(0, new_egr_port, ofp.OFPG_ANY, [
                create_action(action= ofp.OFPAT_OUTPUT, port= new_egr_port)
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg_add, 'group_add_msg_add')
        self.send_ctrl_exp_noerror(group_add_msg_modify, 'group_add_msg_modify')

        pkt  = testutils.simple_tcp_packet()

        flow_add_msg = \
        testutils.flow_msg_create(self, pkt, ing_port = ing_port,action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 0)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg, 'flow add')

        self.send_data(pkt, ing_port)

        self.recv_data(new_egr_port, pkt) #packet received in new_egr_port
        self.recv_data(org_egr_port, None) #No packet received in org_egr_port

class GroupDeleteFF(GroupTest):
    """
    A fast failover group delete
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()
        ing_port = of_ports[1]
        egr_port = of_ports[2]

        group_add_msg_add = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_FF, group_id = 0, buckets = [
            create_bucket(0, egr_port, ofp.OFPG_ANY, [
                create_action(action= ofp.OFPAT_OUTPUT, port= egr_port)
            ])
        ])

        group_add_msg_delete = \
        create_group_mod_msg(ofp.OFPGC_DELETE, ofp.OFPGT_FF, group_id = 0, buckets = [])

        self.send_ctrl_exp_noerror(group_add_msg_add, 'group_add_msg_add')
        self.send_ctrl_exp_noerror(group_add_msg_delete, 'group_add_msg_delete')

        pkt  = testutils.simple_tcp_packet()

        flow_add_msg = \
        testutils.flow_msg_create(self, pkt, ing_port = ing_port,action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 0)
        ])

        self.send_ctrl_exp_error(flow_add_msg, 'group mod',
                                 ofp.OFPET_BAD_ACTION, ofp.OFPBAC_BAD_OUT_GROUP)

"""
Action
"""

#@todo: A group action with invalid id should result in error
#@todo: A group action for nonexisting group should result in error


"""
Working
"""

class GroupProcEmpty(GroupTest):
    """
    A group with no buckets should not alter the action set of the packet
    """

    def runTest(self):

        self.clean_switch()
        of_ports = group_port_map.keys()
        ing_port = of_ports[1]
        egr_port = of_ports[2]

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 1, buckets = [
        ])

        self.send_ctrl_exp_noerror(group_add_msg, 'group add')

        packet_in  = testutils.simple_tcp_packet()

        flow_add_msg = \
        create_flow_msg(packet = packet_in, in_port = ing_port, apply_action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 1)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg, 'flow add')

        self.send_data(packet_in, ing_port)

        self.recv_data(egr_port, None)


class GroupProcSimple(GroupTest):
    """
    A group should apply its actions on packets
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()
        ing_port = of_ports[1]
        egr_port = of_ports[2]

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 1, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 2000),
                create_action(action = ofp.OFPAT_OUTPUT, port = egr_port)
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg, 'group add')

        packet_in  = testutils.simple_tcp_packet(tcp_sport=1000)
        packet_out = testutils.simple_tcp_packet(tcp_sport=2000)

        flow_add_msg = \
        testutils.flow_msg_create(self, packet_in, ing_port = ing_port, action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 1)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg, 'flow add')

        self.send_data(packet_in, ing_port)

        self.recv_data(egr_port, packet_out)



class GroupProcMod(GroupTest):
    """
    A modification for existing group should modify the group
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()
        ing_port = of_ports[1]
        egr_port = of_ports[2]

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 1, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 2000),
                create_action(action = ofp.OFPAT_OUTPUT, port = egr_port)
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg, 'group add')

        group_mod_msg = \
        create_group_mod_msg(ofp.OFPGC_MODIFY, ofp.OFPGT_ALL, group_id = 1, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 3000),
                create_action(action = ofp.OFPAT_OUTPUT, port = egr_port)
            ])
        ])

        self.send_ctrl_exp_noerror(group_mod_msg, 'group mod')


        packet_in  = testutils.simple_tcp_packet(tcp_sport=1000)
        packet_out = testutils.simple_tcp_packet(tcp_sport=3000)

        flow_add_msg = \
        testutils.flow_msg_create(self, packet_in, ing_port = ing_port, action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 1)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg, 'flow add')

        self.send_data(packet_in, ing_port)

        self.recv_data(egr_port, packet_out)



class GroupProcChain(GroupTest):
    """
    A group after a group should apply its actions on packets
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()
        ing_port = of_ports[1]
        egr_port = of_ports[2]

        group_add_msg2 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 2, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 2000),
                create_action(action = ofp.OFPAT_OUTPUT, port = egr_port)
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg2, 'group add')

        group_add_msg1 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 1, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action = ofp.OFPAT_GROUP, group_id = 2),
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg1, 'group add')

        packet_in  = testutils.simple_tcp_packet(tcp_sport=1000)
        packet_out = testutils.simple_tcp_packet(tcp_sport=2000)

        flow_add_msg = \
        testutils.flow_msg_create(self, packet_in, ing_port = ing_port, action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 1)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg, 'flow add')

        self.send_data(packet_in, ing_port)

        self.recv_data(egr_port, packet_out)



"""
Working (specific)
"""

class GroupProcAll(GroupTest):
    """
    An ALL group should use all of its buckets, modifying the resulting packet(s)
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()
        ing_port  = of_ports[0]
        egr_port1 = of_ports[1]
        egr_port2 = of_ports[2]
        egr_port3 = of_ports[0] #of_ports[3]

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 1, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 2000),
                create_action(action = ofp.OFPAT_OUTPUT, port = egr_port1)
            ]),
            create_bucket(0, 0, 0, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 3000),
                create_action(action = ofp.OFPAT_OUTPUT, port = egr_port2)
            ]),
            create_bucket(0, 0, 0, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 4000),
                create_action(action = ofp.OFPAT_OUTPUT, port = ofp.OFPP_IN_PORT)
            ])
        ])
        self.send_ctrl_exp_noerror(group_add_msg, 'group add')

        packet_in   = testutils.simple_tcp_packet(tcp_sport=1000)
        packet_out1 = testutils.simple_tcp_packet(tcp_sport=2000)
        packet_out2 = testutils.simple_tcp_packet(tcp_sport=3000)
        packet_out3 = testutils.simple_tcp_packet(tcp_sport=4000)

        flow_add_msg = \
        testutils.flow_msg_create(self, packet_in, ing_port = ing_port, action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 1)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg, 'flow add')

        self.send_data(packet_in, ing_port)

        self.recv_data(egr_port1, packet_out1)
        self.recv_data(egr_port2, packet_out2)
        self.recv_data(egr_port3, packet_out3)



class GroupProcAllChain(GroupTest):
    """
    An ALL group should use all of its buckets, modifying the resulting packet(s)
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()
        ing_port  = of_ports[0]
        egr_port1 = of_ports[1]
        egr_port2 = of_ports[2]
        egr_port3 = of_ports[len(of_ports) - 1]

        group_add_msg2 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 2, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 2000),
                create_action(action = ofp.OFPAT_OUTPUT, port = egr_port1)
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg2, 'group add 2')

        group_add_msg3 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 3, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 3000),
                create_action(action = ofp.OFPAT_OUTPUT, port = egr_port2)
            ]),
            create_bucket(0, 0, 0, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 4000),
                create_action(action = ofp.OFPAT_OUTPUT, port = egr_port3)
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg3, 'group add 3')

        group_add_msg1 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 1, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action = ofp.OFPAT_GROUP, group_id = 2),
            ]),
            create_bucket(0, 0, 0, [
                create_action(action = ofp.OFPAT_GROUP, group_id = 3),
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg1, 'group add 1')

        packet_in   = testutils.simple_tcp_packet(tcp_sport=1000)
        packet_out1 = testutils.simple_tcp_packet(tcp_sport=2000)
        packet_out2 = testutils.simple_tcp_packet(tcp_sport=3000)
        packet_out3 = testutils.simple_tcp_packet(tcp_sport=4000)

        flow_add_msg = \
        testutils.flow_msg_create(self,packet_in,ing_port = 1,action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 1)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg, 'flow add')

        self.send_data(packet_in, ing_port)

        self.recv_data(egr_port1, packet_out1)
        self.recv_data(egr_port2, packet_out2)
        self.recv_data(egr_port3, packet_out3)



class GroupProcIndirect(GroupTest):
    """
    An INDIRECT group should use its only bucket
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()
        ing_port = of_ports[1]
        egr_port = of_ports[2]

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_INDIRECT, group_id = 1, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 2000),
                create_action(action = ofp.OFPAT_OUTPUT, port = egr_port)
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg, 'group add')

        packet_in  = testutils.simple_tcp_packet(tcp_sport=1000)
        packet_out = testutils.simple_tcp_packet(tcp_sport=2000)

        flow_add_msg = \
        testutils.flow_msg_create(self, packet_in, ing_port = ing_port, action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 1)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg, 'flow add')

        self.send_data(packet_in, ing_port)

        self.recv_data(egr_port, packet_out)



class GroupProcSelect(GroupTest):
    """
    An ALL group should use all of its buckets, modifying the resulting packet(s)
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()
        ing_port  = of_ports[0]
        egr_port1 = of_ports[1]
        egr_port2 = of_ports[2]
        egr_port3 = of_ports[len(of_ports) - 1]

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_SELECT, group_id = 1, buckets = [
            create_bucket(1, 0, 0, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 2000),
                create_action(action = ofp.OFPAT_OUTPUT, port = egr_port1)
            ]),
            create_bucket(1, 0, 0, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 3000),
                create_action(action = ofp.OFPAT_OUTPUT, port = egr_port2)
            ]),
            create_bucket(1, 0, 0, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 4000),
                create_action(action = ofp.OFPAT_OUTPUT, port = egr_port3)
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg, 'group add')

        packet_in   = testutils.simple_tcp_packet(tcp_sport=1000)
        packet_out1 = testutils.simple_tcp_packet(tcp_sport=2000)
        packet_out2 = testutils.simple_tcp_packet(tcp_sport=3000)
        packet_out3 = testutils.simple_tcp_packet(tcp_sport=4000)

        flow_add_msg = \
        testutils.flow_msg_create(self, packet_in, ing_port = ing_port, action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 1)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg, 'flow add')

        self.send_data(packet_in, ing_port)
        self.send_data(packet_in, ing_port)
        self.send_data(packet_in, ing_port)

        self.recv_data(egr_port1, packet_out1)
        self.recv_data(egr_port2, packet_out2)
        self.recv_data(egr_port3, packet_out3)

        self.recv_data(egr_port1, None)
        self.recv_data(egr_port2, None)
        self.recv_data(egr_port3, None)


class GroupProcFFExecFirstBucket(GroupTest):
    """
    A FF group with >1 buckets should execute the first bucket with a live port/group
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()
        last = len(of_ports) - 1
        ing_port  = of_ports[0]
        egr_port1 = of_ports[1]
        egr_port2 = of_ports[2]
        egr_port3 = of_ports[last]

        group_add_msg1 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_FF, group_id = 0, buckets = [
            create_bucket(0, egr_port1, ofp.OFPG_ANY, [
                create_action(action= ofp.OFPAT_OUTPUT, port= egr_port1)
            ]),
            create_bucket(0, egr_port2, ofp.OFPG_ANY, [
                create_action(action= ofp.OFPAT_OUTPUT, port= egr_port2)
            ]),
            create_bucket(0, ofp.OFPP_ANY, 1, [
                create_action(action = ofp.OFPAT_GROUP,  group_id = 1)
            ])
        ])

        group_add_msg2 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_FF, group_id = 1, buckets = [
            create_bucket(0, egr_port3, ofp.OFPG_ANY, [
                create_action(action= ofp.OFPAT_OUTPUT, port= egr_port3)
            ])
        ])

        #added first because goup_id=0 will point to group_id=1
        self.send_ctrl_exp_noerror(group_add_msg2, 'group add 2')
        self.send_ctrl_exp_noerror(group_add_msg1, 'group add 1')

        pkt = testutils.simple_tcp_packet()

        flow_add_msg = \
        testutils.flow_msg_create(self, pkt, ing_port = ing_port, action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 0)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg, 'flow add')

        self.send_data(pkt, ing_port)

        self.recv_data(egr_port1, pkt)     #packet received in port 2
        self.recv_data(egr_port2, None) #No packet received in port 3
        self.recv_data(egr_port3, None) #No packet received in port 4


class GroupProcFFExecSecondBucket(GroupTest):
    """
    A FF group with >1 buckets should execute the first bucket with a live port/group
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()
        if len(of_ports) >= 4:
            last = len(of_ports) - 1
        else:
            last = 1

        ing_port  = of_ports[0]
        egr_port1 = of_ports[1]
        egr_port2 = of_ports[2]
        egr_port3 = of_ports[last]

        group_add_msg1 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_FF, group_id = 0, buckets = [
            create_bucket(0, egr_port1, ofp.OFPG_ANY, [
                create_action(action= ofp.OFPAT_OUTPUT, port= egr_port1)
            ]),
            create_bucket(0, egr_port2, ofp.OFPG_ANY, [
                create_action(action= ofp.OFPAT_OUTPUT, port= egr_port2)
            ]),
            create_bucket(0, ofp.OFPP_ANY, 1, [
                create_action(action = ofp.OFPAT_GROUP,  group_id = 1)
            ])
        ])

        group_add_msg2 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_FF, group_id = 1, buckets = [
            create_bucket(0, egr_port3, ofp.OFPG_ANY, [
                create_action(action= ofp.OFPAT_OUTPUT, port= egr_port3)
            ])
        ])

        #added first because goup_id=0 will point to group_id=1
        self.send_ctrl_exp_noerror(group_add_msg2, 'group add 2')
        self.send_ctrl_exp_noerror(group_add_msg1, 'group add 1')

        pkt  = testutils.simple_tcp_packet()

        flow_add_msg = \
        testutils.flow_msg_create(self, pkt, ing_port = ing_port, action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 0)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg, 'flow add')

        rv = testutils.port_config_set(self.controller, egr_port1,
                             ofp.OFPPC_PORT_DOWN, ofp.OFPPC_PORT_DOWN, self.logger)
        self.assertTrue(rv != -1, "Error sending port mod")

        self.send_data(pkt, ing_port)

        rv = testutils.port_config_set(self.controller, egr_port1,
                             0xffffffff ^ ofp.OFPPC_PORT_DOWN, ofp.OFPPC_PORT_DOWN, self.logger)
        self.assertTrue(rv != -1, "Error sending port mod")

        self.recv_data(egr_port2, pkt)     #packet received in port 3
        self.recv_data(egr_port1, None) #No packet received in port 2
        self.recv_data(egr_port3, None) #No packet received in port 4


class GroupProcFFChooseOneBucket(GroupTest):
    """
    A fast failover group should use its only one bucket with a live port/group
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()
        ing_port  = of_ports[0]
        egr_port1 = of_ports[1]
        egr_port2 = of_ports[2]

        group_add_msg1 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_FF, group_id = 0, buckets = [
            create_bucket(0, ofp.OFPP_ANY, ofp.OFPG_ANY, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 2000),
                create_action(action = ofp.OFPAT_OUTPUT, port = egr_port1)
            ]),
            create_bucket(0, ofp.OFPP_ANY, 1, [
                create_action(action = ofp.OFPAT_GROUP,  group_id = 1)
            ]),
            create_bucket(0, egr_port1, ofp.OFPG_ANY, [
                create_action(action = ofp.OFPAT_OUTPUT, port = egr_port1)
            ])
        ])

        group_add_msg2 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_FF, group_id = 1, buckets = [
            create_bucket(0, egr_port2, ofp.OFPG_ANY, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 2000),
                create_action(action = ofp.OFPAT_OUTPUT, port = egr_port2)
            ]),
            create_bucket(0, egr_port1, ofp.OFPG_ANY, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 3000),
                create_action(action = ofp.OFPAT_OUTPUT, port = egr_port1)
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg2, 'group add')
        self.send_ctrl_exp_noerror(group_add_msg1, 'group add')

        org1_pkt = testutils.simple_tcp_packet(tcp_sport=1000)
        new2_pkt = testutils.simple_tcp_packet(tcp_sport=2000)
        new3_pkt = testutils.simple_tcp_packet(tcp_sport=3000)

        flow_add_msg = \
        testutils.flow_msg_create(self, org1_pkt, ing_port = ing_port, action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 0)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg, 'flow add')

        rv = testutils.port_config_set(self.controller, egr_port2,
                             ofp.OFPPC_PORT_DOWN, ofp.OFPPC_PORT_DOWN, self.logger)
        self.assertTrue(rv != -1, "Error sending port mod")

        self.send_data(org1_pkt, ing_port)

        rv = testutils.port_config_set(self.controller, egr_port2,
                             0xffffffff ^ ofp.OFPPC_PORT_DOWN, ofp.OFPPC_PORT_DOWN, self.logger)
        self.assertTrue(rv != -1, "Error sending port mod")

        self.recv_data(egr_port2, None) #No packet received in port 3
        #self.recv_data(egr_port3, None) #No packet received in port 4
        self.recv_data(egr_port1, new3_pkt)



"""
Statistics
"""

#@todo A regular group added should increase the number of groups and buckets

class GroupStats(GroupTest):
    """
    A packet sent to the group should increase byte/packet counters of group
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()
        ing_port  = of_ports[0]
        egr_port1 = of_ports[1]
        egr_port2 = of_ports[2]

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 10, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 2000),
                create_action(action = ofp.OFPAT_OUTPUT, port = egr_port1)
            ]),
            create_bucket(0, 0, 0, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 3000),
                create_action(action = ofp.OFPAT_OUTPUT, port = egr_port2)
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg, 'group add')

        packet_in  = testutils.simple_tcp_packet(tcp_sport=1000)

        flow_add_msg = \
        testutils.flow_msg_create(self, packet_in, ing_port = ing_port, action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 10)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg, 'flow add')

        self.send_data(packet_in, ing_port)
        self.send_data(packet_in, ing_port)
        self.send_data(packet_in, ing_port)

        group_stats_req = \
        create_group_stats_req(10)

#        response = \
#        self.send_ctrl_exp_reply(group_stats_req,
#                                 ofp.OFPT_MULTIPART_REPLY, 'group stat')
        (response, _ ) = self.controller.transact(group_stats_req)
#        print(response.show())

        exp_len = ofp.OFP_HEADER_BYTES + \
                  ofp.OFP_STATS_REPLY_BYTES + \
                  ofp.OFP_GROUP_STATS_BYTES + \
                  ofp.OFP_BUCKET_COUNTER_BYTES * 2

        self.assertEqual(len(response), exp_len,
                         'Received packet length does not equal expected length')

        # XXX Zoltan: oftest group_stats_req handling needs to be fixed
        #             right now only the expected message length is checked
        #             responses should be checked in Wireshark



class GroupStatsAll(GroupTest):
    """
    A packet sent to the group should increase byte/packet counters of group
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()
        port1 = of_ports[0]
        port2 = of_ports[1]
        port3 = of_ports[2]

        group_add_msg1 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 10, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 2000),
                create_action(action = ofp.OFPAT_OUTPUT, port = port2)
            ]),
            create_bucket(0, 0, 0, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 3000),
                create_action(action = ofp.OFPAT_OUTPUT, port = port3)
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg1, 'group add 1')

        group_add_msg2 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 20, buckets = [
            create_bucket(0, 0, 0, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 2000),
                create_action(action = ofp.OFPAT_OUTPUT, port = port2)
            ]),
            create_bucket(0, 0, 0, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 3000),
                create_action(action = ofp.OFPAT_OUTPUT, port = port3)
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg2, 'group add 2')

        packet_in  = testutils.simple_tcp_packet(tcp_sport=1000)

        flow_add_msg1 = \
        testutils.flow_msg_create(self, packet_in, ing_port = port1, action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 10)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg1, 'flow add 1')

        flow_add_msg2 = \
        testutils.flow_msg_create(self, packet_in, ing_port = port2, action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 20)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg2, 'flow add 2')

        self.send_data(packet_in, port1)
        self.send_data(packet_in, port1)
        self.send_data(packet_in, port2)
        self.send_data(packet_in, port2)
        self.send_data(packet_in, port2)

        group_stats_req = \
        create_group_stats_req(ofp.OFPG_ALL)

#        response = \
#        self.send_ctrl_exp_reply(group_stats_req,
#                                 ofp.OFPT_MULTIPART_REPLY, 'group stat')
        (response, _ ) = self.controller.transact(group_stats_req)
#        print(response.show())

        exp_len = ofp.OFP_HEADER_BYTES + \
                  ofp.OFP_STATS_REPLY_BYTES + \
                  ofp.OFP_GROUP_STATS_BYTES + \
                  ofp.OFP_BUCKET_COUNTER_BYTES * 2 + \
                  ofp.OFP_GROUP_STATS_BYTES + \
                  ofp.OFP_BUCKET_COUNTER_BYTES * 2

        self.assertEqual(len(response), exp_len,
                         'Received packet length does not equal expected length')
        # XXX Zoltan: oftest group_stats_req handling needs to be fixed
        #             right now only the expected message length is checked
        #             responses should be checked in Wireshark



class GroupDescStats(GroupTest):
    """
    Desc stats of a group should work
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()

        b1 = create_bucket(0, 0, 0, [
                 create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 2000),
                 create_action(action = ofp.OFPAT_OUTPUT, port = of_ports[0])
            ])
        b2 =  create_bucket(0, 0, 0, [
                  create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 3000),
                  create_action(action = ofp.OFPAT_OUTPUT, port = of_ports[1])
            ])
        b3 = create_bucket(0, 0, 0, [
                 create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 4000),
                 create_action(action = ofp.OFPAT_OUTPUT, port = of_ports[2])
            ])

        group_add_msg = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 10, buckets = [b1, b2, b3])

        self.send_ctrl_exp_noerror(group_add_msg, 'group add')

        group_desc_stats_req = \
        create_group_desc_stats_req()

        response = \
        self.send_ctrl_exp_reply(group_desc_stats_req, ofp.OFPT_MULTIPART_REPLY,
                                 ofp.OFPMP_GROUP_DESC, 'group desc stat')

        exp_len = ofp.OFP_HEADER_BYTES + \
                  ofp.OFP_STATS_REPLY_BYTES + \
                  ofp.OFP_GROUP_DESC_STATS_BYTES + \
                  len(b1) + len(b2) + len(b3)

        self.assertEqual(len(response), exp_len,
                         'Received packet length does not equal expected length')
        # XXX Zoltan: oftest group_stats_req handling needs to be fixed
        #             right now only the expected message length is checked
        #             responses should be checked in Wireshark


#@todo: A flow added with group action should increase the ref counter of the ref. group
#@todo: A flow removed with group action should decrease the ref counter of the ref. group
#@todo: A group added with group action should increase the ref counter of the ref. group
#@todo: A group removed with group action should decrease the ref counter of the ref. group


"""
Flows
"""

#@todo: A deletion for existing group should remove flows referring to that group
#@todo: A flow added referencing a nonexisting group should return an error

"""
Flow select
"""

class GroupFlowSelect(GroupTest):
    """
    A group action select with group id should select the correct flows only
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()
        ing_port = of_ports[1]
        egr_port = of_ports[2]

        group_add_msg1 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 1, buckets = [])

        self.send_ctrl_exp_noerror(group_add_msg1, 'group add 1')

        group_add_msg2 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 2, buckets = [])

        self.send_ctrl_exp_noerror(group_add_msg2, 'group add 2')

        packet_in1 = testutils.simple_tcp_packet(tcp_sport=1000)

        flow_add_msg1 = \
        testutils.flow_msg_create(self, packet_in1, ing_port = ing_port, action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 1),
            create_action(action = ofp.OFPAT_OUTPUT, port = egr_port)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg1, 'flow add 1')

        packet_in2 = testutils.simple_tcp_packet(tcp_sport=2000)

        flow_add_msg2 = \
        testutils.flow_msg_create(self, packet_in2, ing_port = ing_port, action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 2),
            create_action(action = ofp.OFPAT_OUTPUT, port = egr_port)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg2, 'flow add 2')

        packet_in3 = testutils.simple_tcp_packet(tcp_sport=3000)

        flow_add_msg3 = \
        testutils.flow_msg_create(self, packet_in3, ing_port = ing_port, action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 2),
            create_action(action = ofp.OFPAT_OUTPUT, port = egr_port)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg3, 'flow add 3')

        packet_in4 = testutils.simple_tcp_packet(tcp_sport=4000)

        flow_add_msg4 = \
        testutils.flow_msg_create(self, packet_in4, ing_port = ing_port, action_list = [
            create_action(action = ofp.OFPAT_OUTPUT, port = egr_port)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg4, 'flow add 4')

        aggr_stat_req = message.aggregate_stats_request()
        aggr_stat_req.table_id = 0xff
        aggr_stat_req.out_port = ofp.OFPP_ANY
        aggr_stat_req.out_group = 2

        response = \
        self.send_ctrl_exp_reply(aggr_stat_req, ofp.OFPT_MULTIPART_REPLY,
                                 ofp.OFPMP_AGGREGATE, 'aggr stat')

        self.assertEqual(response.stats[0].flow_count, 2,
                         'Did not match expected flow count')

class GroupFlowSelectAll(GroupTest):
    """
    A group action select with OFPG_ALL should ignore output group action
    """

    def runTest(self):
        self.clean_switch()
        of_ports = group_port_map.keys()
        ing_port = of_ports[1]
        egr_port = of_ports[2]

        group_add_msg1 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 1, buckets = [])

        self.send_ctrl_exp_noerror(group_add_msg1, 'group add 1')

        group_add_msg2 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_ALL, group_id = 2, buckets = [])

        self.send_ctrl_exp_noerror(group_add_msg2, 'group add 2')

        packet_in1 = testutils.simple_tcp_packet(tcp_sport=1000)

        flow_add_msg1 = \
        testutils.flow_msg_create(self, packet_in1, ing_port = ing_port, action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 1),
            create_action(action = ofp.OFPAT_OUTPUT, port = egr_port)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg1, 'flow add 1')

        packet_in2 = testutils.simple_tcp_packet(tcp_sport=2000)

        flow_add_msg2 = \
        testutils.flow_msg_create(self, packet_in2, ing_port = ing_port, action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 2),
            create_action(action = ofp.OFPAT_OUTPUT, port = egr_port)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg2, 'flow add 2')

        packet_in3 = testutils.simple_tcp_packet(tcp_sport=3000)

        flow_add_msg3 = \
        testutils.flow_msg_create(self, packet_in3, ing_port = ing_port, action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 2),
            create_action(action = ofp.OFPAT_OUTPUT, port = egr_port)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg3, 'flow add 3')

        packet_in4 = testutils.simple_tcp_packet(tcp_sport=4000)

        flow_add_msg4 = \
        testutils.flow_msg_create(self, packet_in4, ing_port = ing_port, action_list = [
            create_action(action = ofp.OFPAT_OUTPUT, port = egr_port)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg4, 'flow add 4')

        aggr_stat_req = message.aggregate_stats_request()
        aggr_stat_req.table_id = 0xff
        aggr_stat_req.out_port = ofp.OFPP_ANY
        aggr_stat_req.out_group = ofp.OFPG_ANY

        response = \
        self.send_ctrl_exp_reply(aggr_stat_req, ofp.OFPT_MULTIPART_REPLY,
                                 ofp.OFPMP_AGGREGATE, 'aggr stat')

        self.assertEqual(response.stats[0].flow_count, 4,
                         'Did not match expected flow count')

'''
class GroupAddFFChooseOneBucket_Hard(GroupTest):
    """
    A fast failover group should use its only one bucket with a live port/group
    """

    def runTest(self):
        #of_ports = self.clean_switch()
        of_ports = testutils.clear_switch(self, group_port_map.keys(), group_logger)
        of_ports = group_port_map.keys()

        group_add_msg1 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_FF, group_id = 0, buckets = [
            create_bucket(0, of_ports[2], ofp.OFPG_ANY, [
                create_action(action = ofp.OFPAT_OUTPUT, port = of_ports[2])
            ]),
            #create_bucket(0, ofp.OFPP_ANY, 1, [
            #    create_action(action = ofp.OFPAT_GROUP,  group_id = 1)
            #]),
            create_bucket(0, of_ports[1], ofp.OFPG_ANY, [
                create_action(action = ofp.OFPAT_OUTPUT, port = of_ports[1])
            ])
        ])

        group_add_msg2 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_FF, group_id = 1, buckets = [
            create_bucket(0, of_ports[2], ofp.OFPG_ANY, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 2000),
                create_action(action = ofp.OFPAT_OUTPUT, port = of_ports[2])
            ]),
            create_bucket(0, of_ports[1], ofp.OFPG_ANY, [
                create_action(action = ofp.OFPAT_OUTPUT, port = of_ports[1])
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg2, 'group add')
        self.send_ctrl_exp_noerror(group_add_msg1, 'group add')

        org_pkt = testutils.simple_tcp_packet(tcp_sport=1000)
        new_pkt = testutils.simple_tcp_packet(tcp_sport=2000)

        #send flow mod2
        match1 = match.eth_dst(value = 0 )
        match2 = match.eth_src(value = 0 )
        match3 = match.eth_type(value = 0 )
        match4 = match.ipv4_dst(value = 0)
        match5 = match.ipv4_src(value = 0)
        match_fields = testutils.get_match_value([match1,match2,match3,match4,match5], org_pkt)

        flow_add_msg = \
        testutils.flow_msg_create(self, org_pkt, ing_port = of_ports[0], match_fields=match_fields, action_list = [
            create_action(action = ofp.OFPAT_GROUP, group_id = 0)
        ])

        self.send_ctrl_exp_noerror(flow_add_msg, 'flow add')

        rv = testutils.port_config_set(self.controller, of_ports[2],
                             ofp.OFPPC_PORT_DOWN, ofp.OFPPC_PORT_DOWN, self.logger)
        self.assertTrue(rv != -1, "Error sending port mod")

        self.send_data(org_pkt, of_ports[0])

        (port_rec, pkt_rec, _) = self.dataplane.poll(of_ports[2], 1)
        self.assertTrue(pkt_rec is None, "dataplane rec packet") #No packet received in port 3

        #rv = testutils.port_config_set(self.controller, of_ports[2],
        #                     0xffffffff ^ ofp.OFPPC_PORT_DOWN, ofp.OFPPC_PORT_DOWN, self.logger)
        #self.assertTrue(rv != -1, "Error sending port mod")

        testutils.receive_pkt_verify(self, of_ports[1], org_pkt)
        
        for loop in range(1,10):
             self.dataplane.send(of_ports[0], str(org_pkt))
             testutils.receive_pkt_verify(self, of_ports[1], org_pkt)
             #(port_rec, pkt_rec, _) = self.dataplane.poll(out_port, 2)
             #self.assertTrue(pkt_rec is not None, "dataplane did not receive packet")

        #5)users send pkts to the switch, the pkts would be forwarded by the hardware of the switch
        request = message.flow_stats_request()
        request.match_fields = match_fields
        request.out_port = ofp.OFPP_ANY
        request.out_group = ofp.OFPG_ANY
        request.table_id = testutils.WC_ACL_TABLE
        request.match.wildcards = 0 # ofp.OFPFW
        response, _ = self.controller.transact(request, timeout=2)
        self.assertTrue(response is not None, "Did not get response")
        print("flow counter = "+ str(response.stats[0].packet_count))
        self.assertTrue(isinstance(response,message.flow_stats_reply),"Not a flow_stats_reply")
        self.assertTrue(response.stats[0].packet_count >= 1, "Software layer receive nothing")
        self.assertTrue(response.stats[0].packet_count < 5, "more than 5 pkt was forwarded by software")
        
        rv = testutils.port_config_set(self.controller, of_ports[2],
                             0xffffffff ^ ofp.OFPPC_PORT_DOWN, ofp.OFPPC_PORT_DOWN, self.logger)
        self.assertTrue(rv != -1, "Error sending port mod")


class GroupAddFFChooseOneBucket_down(GroupTest):
    """
    A fast failover group should use its only one bucket with a live port/group
    """

    def runTest(self):
        #of_ports = self.clean_switch()
        of_ports = testutils.clear_switch(self, group_port_map.keys(), group_logger)
        of_ports = group_port_map.keys()

        group_add_msg1 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_FF, group_id = 0, buckets = [
            create_bucket(0, of_ports[2], ofp.OFPG_ANY, [
                create_action(action = ofp.OFPAT_OUTPUT, port = of_ports[2])
            ]),
            #create_bucket(0, ofp.OFPP_ANY, 1, [
            #    create_action(action = ofp.OFPAT_GROUP,  group_id = 1)
            #]),
            create_bucket(0, of_ports[1], ofp.OFPG_ANY, [
                create_action(action = ofp.OFPAT_OUTPUT, port = of_ports[1])
            ])
        ])

        group_add_msg2 = \
        create_group_mod_msg(ofp.OFPGC_ADD, ofp.OFPGT_FF, group_id = 1, buckets = [
            create_bucket(0, of_ports[2], ofp.OFPG_ANY, [
                create_action(action = ofp.OFPAT_SET_FIELD, tcp_sport = 2000),
                create_action(action = ofp.OFPAT_OUTPUT, port = of_ports[2])
            ]),
            create_bucket(0, of_ports[1], ofp.OFPG_ANY, [
                create_action(action = ofp.OFPAT_OUTPUT, port = of_ports[1])
            ])
        ])

        self.send_ctrl_exp_noerror(group_add_msg2, 'group add')
        self.send_ctrl_exp_noerror(group_add_msg1, 'group add')

        org_pkt = testutils.simple_tcp_packet(tcp_sport=1000)
        new_pkt = testutils.simple_tcp_packet(tcp_sport=2000)

        #send flow mod2
        match1 = match.eth_dst(value = 0 )
        match2 = match.eth_src(value = 0 )
        match3 = match.eth_type(value = 0 )
        match4 = match.ipv4_dst(value = 0)
        match5 = match.ipv4_src(value = 0)
        match_fields = testutils.get_match_value([match1,match2,match3,match4,match5], org_pkt)

        flow_add_msg = \
        testutils.flow_msg_create(self, org_pkt, ing_port = of_ports[0],\
                                  match_fields=match_fields, \
                                  action_list = [create_action(action = ofp.OFPAT_GROUP, group_id = 0)])

        self.send_ctrl_exp_noerror(flow_add_msg, 'flow add')

        for loop in range(0,10):
             self.dataplane.send(of_ports[0], str(org_pkt))
             testutils.receive_pkt_verify(self, of_ports[2], org_pkt)
             #(port_rec, pkt_rec, _) = self.dataplane.poll(out_port, 2)
             #self.assertTrue(pkt_rec is not None, "dataplane did not receive packet")

        #)users send pkts to the switch, the pkts would be forwarded by the hardware of the switch
        request = message.flow_stats_request()
        request.match_fields = match_fields
        request.out_port = ofp.OFPP_ANY
        request.out_group = ofp.OFPG_ANY
        request.table_id = testutils.WC_ACL_TABLE
        request.match.wildcards = 0 # ofp.OFPFW
        response, _ = self.controller.transact(request, timeout=2)
        self.assertTrue(response is not None, "Did not get response")
        print("flow counter = "+ str(response.stats[0].packet_count))
        self.assertTrue(isinstance(response,message.flow_stats_reply),"Not a flow_stats_reply")
        self.assertTrue(response.stats[0].packet_count >= 1, "Software layer receive nothing")
        self.assertTrue(response.stats[0].packet_count < 5, "more than 5 pkt was forwarded by software")

        rv = testutils.port_config_set(self.controller, of_ports[2],
                             ofp.OFPPC_PORT_DOWN, ofp.OFPPC_PORT_DOWN, self.logger)
        self.assertTrue(rv != -1, "Error sending port mod")

        for loop in range(0,10):
             self.dataplane.send(of_ports[0], str(org_pkt))
             testutils.receive_pkt_verify(self, of_ports[1], org_pkt)

        rv = testutils.port_config_set(self.controller, of_ports[2],
                             0xffffffff ^ ofp.OFPPC_PORT_DOWN, ofp.OFPPC_PORT_DOWN, self.logger)
    self.assertTrue(rv != -1, "Error sending port mod")
'''
if __name__ == "__main__":
    print "Please run through oft script:  ./oft --test_spec=basic"
