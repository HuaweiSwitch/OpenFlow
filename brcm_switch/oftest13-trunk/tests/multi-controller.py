#multi controller test case;

'''
multi controller test case
'''


import sys
import logging

import unittest
import random

import oftest.controller as controller
import oftest.cstruct as ofp
import oftest.message as message
import oftest.dataplane as dataplane
import oftest.action as action

import testutils

import basic

#@var basic_port_map Local copy of the configuration map from OF port
# numbers to OS interfaces
basic_port_map = None
#@var basic_logger Local logger object
basic_logger = None
#@var basic_config Local copy of global configuration data
basic_config = None


test_prio = {}

def test_set_init(config):
    """
    Set up function for basic test classes

    @param config The configuration dictionary; see oft
    """

    global basic_port_map
    global basic_logger
    global basic_config

    basic_logger = logging.getLogger("myecho")
    basic_logger.info("Initializing test set")
    basic_port_map = config["port_map"]
    basic_config = config

def GetGenerationID(controller):
    '''
    read current generation id
    '''
    request = message.role_request()
    request.role = ofp.OFPCR_ROLE_NOCHANGE
    response,_ = controller.transact(request)
    if response is None:
        return None
    elif(response.header.type == ofp.OFPT_ROLE_REPLY):
        if response.generation_id == 0xffffffffffffffff:
            return 0
        else:
            return response.generation_id + 1
    else:
        print('\n' + response.show())
        return None


class RoleRequestNoChange(basic.SimpleProtocol):
    """
    role_request_nochange
    """
    def runTest(self):
        request = message.role_request()
        request.role = ofp.OFPCR_ROLE_NOCHANGE
        request.generation_id = random.randint(0,0xffffffffffffffff)
        response,_ = self.controller.transact(request)
        self.assertEqual(response.header.type, ofp.OFPT_ROLE_REPLY,
                         'response is not role_reply')


class RoleRequestEqual(basic.SimpleProtocol):
    """
    role_request_equal
    """
    def runTest(self):
        request = message.role_request()
        request.role = ofp.OFPCR_ROLE_EQUAL
        request.generation_id = random.randint(0,0xffffffffffffffff)
        response,_ = self.controller.transact(request)
        self.assertEqual(response.header.type, ofp.OFPT_ROLE_REPLY,
                         'response is not role_reply')
        self.assertEqual(response.role, ofp.OFPCR_ROLE_EQUAL,
                         'response is not OFPCR_ROLE_EQUAL')


class RoleRequestMaster(basic.SimpleProtocol):
    """
    role_request_master
    """
    def runTest(self):
        request = message.role_request()
        request.role = ofp.OFPCR_ROLE_MASTER
        gener_id = GetGenerationID(self.controller)
        self.assertTrue(gener_id is not None, "Did not get generation_id")
        request.generation_id = gener_id
        response,_ = self.controller.transact(request)
        self.assertEqual(response.header.type, ofp.OFPT_ROLE_REPLY,
                         'response is not role_reply')
        self.assertEqual(response.role, ofp.OFPCR_ROLE_MASTER,
                         'response is not OFPCR_ROLE_MASTER')


class RoleRequestSlave(basic.SimpleProtocol):
    """
    role_request_slave
    """
    def runTest(self):
        request = message.role_request()
        request.role = ofp.OFPCR_ROLE_SLAVE
        gener_id = GetGenerationID(self.controller)
        self.assertTrue(gener_id is not None, "Did not get generation_id")
        request.generation_id = gener_id
        response,_ = self.controller.transact(request)
        self.assertEqual(response.header.type, ofp.OFPT_ROLE_REPLY,
                         'response is not role_reply')
        self.assertEqual(response.role, ofp.OFPCR_ROLE_SLAVE,
                         'response is not OFPCR_ROLE_SLAVE')
        request = message.role_request()
        request.role = ofp.OFPCR_ROLE_MASTER
        request.generation_id = gener_id + 1
        testutils.ofmsg_send(self, request)

