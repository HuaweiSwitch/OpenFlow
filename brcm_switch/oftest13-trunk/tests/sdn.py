#multi controller test case;

'''
packet test case
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
import oftest.instruction as instruction
import oftest.parse as parse
import oftest.match as match
from oftest.match_list import match_list

import testutils

import basic

import time

#@var sdn_port_map Local copy of the configuration map from OF port
# numbers to OS interfaces
sdn_port_map = None
#@var sdn_logger Local logger object
sdn_logger = None
#@var sdn_config Local copy of global configuration data
sdn_config = None


test_prio = {}

def test_set_init(config):
    """
    Set up function for basic test classes

    @param config The configuration dictionary; see oft
    """

    global sdn_port_map
    global sdn_logger
    global sdn_config

    sdn_logger = logging.getLogger("myecho")
    sdn_logger.info("Initializing test set")
    sdn_port_map = config["port_map"]
    sdn_config = config

class TempTestCase(basic.DataPlaneOnly):
    """
    TempTestCase
    """
    def runTest(self):
        pkt_in = testutils.simple_tcp_packet()
        matchs = parse.packet_to_flow_match(pkt_in)
        #print(matchs.show())
        self.logger.info(matchs.show())


class Port1InPort2Out(basic.DataPlaneOnly):
    ''''
    send packet to port1 recive data from port2
    '''
    def runTest(self):
        pkt = testutils.simple_tcp_packet()
        #print(sdn_port_map)
        self.logger.info(sdn_port_map)
        for of_port in sdn_port_map.keys():
            #print(str(of_port))
            self.logger.info(str(of_port))
            num = self.dataplane.send(of_port, str(pkt))
           # self.assertEqual(num, len(pkt),'send len error')


class WildcardTest(basic.SimpleDataPlane):
    """
    wildcart test
    """
    def runTest(self):
        pkt_in = testutils.simple_tcp_packet()
        #matchs = testutils.packet_to_flow_match(pkt_in)
        matchs = parse.packet_to_flow_match(pkt_in)
        request = message.flow_mod()
        request.table_id = 0
        request.match_fields = matchs
        #request.match_fields.add(in_port(1))
        request.match_fields.add(1)

class WildcardEntryFlowMod(basic.SimpleProtocol):
    """
    wildcard entry flow mod;
    """
    def runTest(self):
        ing_port = sdn_port_map.keys()[0]
        out_port1 = sdn_port_map.keys()[1]
        out_port2 = sdn_port_map.keys()[2]
        pkt = testutils.simple_tcp_packet()
        #testutils.delete_all_flows(self.controller, self.logger)
        fm_orig = testutils.flow_msg_create(self, pkt,
                                            ing_port=ing_port,
                                            egr_port=out_port1)

        rv = self.controller.message_send(fm_orig)
        self.assertEqual(rv, 0, "Failed to insert 1st flow_mod")
        testutils.do_barrier(self.controller)

        flow_stats = testutils.flow_stats_get(self)
        self.assertEqual(len(flow_stats.stats),1,
                         "Expected only one flow_mod")
        stat = flow_stats.stats[0]
        self.assertEqual(stat.match, fm_orig.match)
        self.assertEqual(stat.instructions, fm_orig.instructions)

'''
class PortsLookBackTest(basic.DataPlaneOnly):
    """
    send packet to port1 recive data from port2
    """
    def runTest(self):

        port_send = 1;
        port_rec = 2;

        pkt_send = testutils.simple_tcp_packet()
        print(sdn_port_map)

        num = self.dataplane.send(port_send, str(pkt_send))
        (port, pkt_rec, _) = self.dataplane.poll(timeout=1)

        self.assertTrue(pkt_rec is not None, 'Packet not received')
        if port is not None:
                self.assertEqual(port, port_send, "Unexpected receive port")
        self.assertEqual(str(pkt_send), str(pkt_rec),
                             'Response packet does not match send packet')
'''
#test_prio['WildCardFlowAdd'] = -1
class WildCardFlowAdd(basic.SimpleDataPlane):
    """
    wildcard test case 1;
    """
    def runTest(self):

        pkt = testutils.simple_tcp_packet()
        match_fields = parse.packet_to_flow_match(pkt)
#
#        request = message.flow_mod()
#        request.match_fields = match_fields
#        request.buffer_id = 0xffffffff
#        request.table_id = 0
#
#        act = action.action_output()
#        act.port = 1
#        inst = instruction.instruction_write_actions()
#        inst.actions.add(act)
#        request.instructions.add(inst)
#
#        rv = self.controller.message_send(request)
#        print(request)
#
#        self.dataplane.send(of_port, str(pkt))
#
#        (of_port, pkt, _) = self.dataplane.poll(timeout=1)11111111111111111


#test_prio['PortSendRecTest'] = -1
'''
class PortSendRecTest(basic.DataPlaneOnly):
    """
    PortSendRecTest
    """
    def runTest(self):
        print(sdn_port_map)
        ing_port = sdn_port_map.keys()[0]
        egr_port = sdn_port_map.keys()[1]
        pkt_send = testutils.simple_tcp_packet(dl_dst='11:22:33:44:55:66')

        #egr_port = (i+1) %4 + 1
        print("\ncount: " + str(ing_port))
        print("erg_port : " + str(egr_port) + " ing_port: " + str(ing_port))
        #pkt = testutils.simple_tcp_packet()
        testutils.delete_all_flows(self.controller, self.logger)

        request = testutils.flow_msg_create(self, pkt, ing_port = ing_port, egr_port = egr_port,check_expire=True)
        request.cookie = random.randint(0,9007199254740992)
        request.buffer_id = 0xffffffff
        request.hard_timeout = 1000
        request.idle_timeout = 1000

        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, "Error installing flow mod")
        testutils.do_barrier(self.controller)

        self.dataplane.send(ing_port, str(pkt_send))
        (rcv_port, rcv_pkt, _) = self.dataplane.poll(timeout=1)
        print("erg_port : " + str(rcv_port) + " pkt: %s" % str(rcv_pkt).encode("hex") )
        print("\n")
        self.assertTrue(rcv_pkt is not None, "Did not receive packet")
        self.assertEqual(str(pkt_send), str(pkt_rec),
                'Response packet does not match send packet')
'''


class SdnWildcardReadAllEntries(basic.SimpleProtocol):
    """
    wildcard read all entry;
    """
    def runTest(self):
        request = message.flow_stats_request()
        request.out_port = ofp.OFPP_ANY
        request.out_group = ofp.OFPG_ANY
        request.table_id = ofp.OFPTT_ALL
        response, _ = self.controller.transact(request, timeout=2)
        #print(response.show())
        self.logger.info(response.show())

class ReadTableStats(basic.SimpleProtocol):
    """
    wildcard read table stats;
    """
    def runTest(self):
        request = message.table_stats_request()
        response, _ = self.controller.transact(request, timeout=2)
        #print(response.show())
        self.logger.info(response.show())

class ReadSwitchFeatures(basic.SimpleProtocol):
    """
    read the switch's features;
    """
    def runTest(self):
        request = message.features_request()
        response,_ = self.controller.transact(request)
        #print(response.show())
        self.logger.info(response.show())

class ReadPortStats(basic.SimpleProtocol):
    """
    read port stats
    """
    def runTest(self):
        request = message.port_stats_request()
        request.port_no = ofp.OFPP_ANY
        response,_ = self.controller.transact(request)
        #print(response.show())
        self.logger.info(response.show())

class ReadSwitchDesc(basic.SimpleProtocol):
    """
    read switch's descripts
    """
    def runTest(self):
        request = message.desc_stats_request();
        response,_ = self.controller.transact(request)
        #print(response.show())
        self.logger.info(response.show())

class ReadGroupStats(basic.SimpleProtocol):
    """
    switch Group stats get test case;
    """
    def runTest(self):
        request = message.group_stats_request();
        request.group_id = ofp.OFPG_ALL;
        response,_ = self.controller.transact(request)
        #print(response.show())
        self.logger.info(response.show())

#test_prio['PortSendTest'] = -1
class PortSendTest(basic.DataPlaneOnly):
    """
    PortSendTest
    """
    def runTest(self):
        ing_port = sdn_port_map.keys()[0]
        for i in range(1, 1024*1000 + 1):
            #print("packet count:", i)
            self.logger.info("packet count:", i)
            pkt_send = testutils.simple_tcp_packet(dl_dst='11:22:33:44:55:66',tcp_sport = i % 5000 + 1000)
            num = self.dataplane.send(ing_port, str(pkt_send))


class PacketOutTest(basic.SimpleDataPlane):
    def runTest(self):
        outpkt = testutils.simple_tcp_packet()
        dp_port = 3
        for i in range(1, 5):
            msg = message.packet_out()
            msg.in_port = ofp.OFPP_CONTROLLER
            msg.data = str(outpkt)
            act = action.action_output()
            act.port = i
            self.assertTrue(msg.actions.add(act), 'Could not add action to msg')
            rv = self.controller.message_send(msg)

            (of_port, pkt, _) = self.dataplane.poll(timeout=2)
            #print('rec port: ' + str(of_port) )
            #print(str(pkt).encode("hex"))
            self.logger.info('rec port: ' + str(of_port) )
            self.logger.info(str(pkt).encode("hex"))


#test_prio['GmacMatchLookbackTest'] = -1
class GmacMatchLookbackTest(basic.SimpleDataPlane):
    def runTest(self):
        for of_port in sdn_port_map.keys():
            ing_port = of_port
            for egr_port in sdn_port_map.keys():
                if egr_port != of_port:
                    break
            #egr_port = (i+1) %4 + 1
            #print("\ncount: " + str(ing_port))
            #print("erg_port : " + str(egr_port) + " ing_port: " + str(ing_port))
            self.logger.info("\ncount: " + str(ing_port))
            self.logger.info("erg_port : " + str(egr_port) + " ing_port: " + str(ing_port))
            pkt = testutils.simple_tcp_packet()
            testutils.delete_all_flows(self.controller, self.logger)

            request = testutils.flow_msg_create(self, pkt, ing_port = ing_port, egr_port = egr_port,check_expire=True)
            request.cookie = random.randint(0,9007199254740992)
            request.buffer_id = 0xffffffff
            request.hard_timeout = 1000
            request.idle_timeout = 1000

            rv = self.controller.message_send(request)
            self.assertTrue(rv != -1, "Error installing flow mod")
            testutils.do_barrier(self.controller)

            self.dataplane.send(ing_port, str(pkt))
            (rcv_port, rcv_pkt, _) = self.dataplane.poll(timeout=1)
            #print("erg_port : " + str(rcv_port) + " pkt: %s" % str(rcv_pkt).encode("hex") )
            #print("\n")
            self.logger.info("erg_port : " + str(rcv_port) + " pkt: %s" % str(rcv_pkt).encode("hex") )
            self.logger.info("\n")
            self.assertTrue(rcv_pkt is not None, "Did not receive packet")

#test_prio['GmacPaseTest'] = -1
class GmacPaseTest(basic.DataPlaneOnly):
    def runTest(self):
        start_time = time.time()
        #ing_port = 2;
        for i in range(1, 10000):
#            len = i;
#            if len < 45:
#                len = 45
#            len = len % 1400
            len = 1445
            for ing_port in sdn_port_map.keys():
                #print("send data times:"+str(i)+"  len : "+str(len)+" port : "+str(ing_port))
                self.logger.info("send data times:"+str(i)+"  len : "+str(len)+" port : "+str(ing_port))
                pkt_send = testutils.simple_tcp_packet(payload_len = len)
                num = self.dataplane.send(ing_port, str(pkt_send))

        end_time = time.time()
        #print( "start :"+str(start_time) + " now :" + str(end_time) + " bytes :" + str(i*1449*4))
        self.logger.info( "start :"+str(start_time) + " now :" + str(end_time) + " bytes :" + str(i*1449*4))
        durations = end_time - start_time;
        #print( "durations :"+str(durations) + "s  data rate: " + str( i*1499*4 / durations ))
        self.logger.info( "durations :"+str(durations) + "s  data rate: " + str( i*1499*4 / durations ))


class SdnClearSwitch(basic.SimpleDataPlane):
    """
    sdn clear switch
    """
    def runTest(self):
        testutils.clear_switch(self, sdn_port_map, self.logger)


test_prio['Performance1'] = -1
'''
class Performance1(basic.SimpleDataPlane):
    """
    exact entry add test;
    """
    def runTest(self):
        #in_port = 1
        ing_port = sdn_port_map.keys()[0]
        table_id = 0
        "clear all "
        testutils.delete_all_flows(self.controller, self.logger)
        "add a flow"
        request = message.flow_mod()
        request.buffer_id = 0xffffffff
        request.table_id = table_id
#        request.match_fields.add(match.eth_src(value = [0x08,0x02,0x03,0x04,0x88,0x88]))
#        request.match_fields.add(match.eth_dst(value = [0x08,0x02,0x03,0x04,0x88,0x88]))
        request.match_fields.add(match.in_port(ing_port))
        request.match_fields.add(match.eth_type(0x0800))
        request.hard_timeout = 8;
        request.idle_timeout = 8;

        'actions'
        act = action.action_output()
        act.port = ofp.OFPP_IN_PORT
        inst = instruction.instruction_write_actions()
        inst.actions.add(act)
        request.instructions.add(inst)

#        print(request.show())
        self.controller.message_send(request)
        "get flow stats"
        stat_req = message.flow_stats_request()
        stat_req.buffer_id = 0xffffffff
        stat_req.table_id = table_id
        stat_req.match_fields = request.match_fields
#        print( stat_req.show())
        response, _ = self.controller.transact(stat_req, timeout=2)
        self.assertTrue(isinstance(response,message.flow_stats_reply),"Not a flow_stats_reply")
        print(response.show())
        self.assertEqual(len(response.stats),1, "len of stats is:"+str(len(response.stats)))

        pkt = testutils.simple_tcp_packet()
        "send a packet from port_in "
        self.dataplane.send(ing_port, str(pkt))
        "poll from the port_out port"
        (port_rec, pkt_rec, _) = self.dataplane.poll( timeout=1)
#        (port_rec, pkt, _) = self.dataplane.poll(timeout=1)
        print( 'rec port : ' + str(port_rec))
        print( str(pkt_rec).encode("hex") )
'''

