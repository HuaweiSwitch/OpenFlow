"""
Basic protocol and dataplane test cases

It is recommended that these definitions be kept in their own
namespace as different groups of tests will likely define
similar identifiers.

Current Assumptions:

  The function test_set_init is called with a complete configuration
dictionary prior to the invocation of any tests from this file.

  The switch is actively attempting to contact the controller at the address
indicated oin oft_config

"""
import sys
import logging
import unittest

import oftest.match as match
import oftest.controller as controller
import oftest.cstruct as ofp
import oftest.message as message
import oftest.dataplane as dataplane
import oftest.action as action
import oftest.instruction as instruction
import oftest.parse as parse

import testutils
import ipaddr

#@var basic_port_map Local copy of the configuration map from OF port
# numbers to OS interfaces
basic_port_map = None
#@var basic_logger Local logger object
basic_logger = None
#@var basic_config Local copy of global configuration data
basic_config = None

OFPFW_ALL = 1023
DEFAULT_MISS_SEND_LEN = 128
test_prio = {}

def test_set_init(config):
    """
    Set up function for basic test classes

    @param config The configuration dictionary; see oft
    """

    global basic_port_map
    global basic_logger
    global basic_config

    basic_logger = logging.getLogger("basic")
    basic_logger.info("Initializing test set")
    basic_port_map = config["port_map"]
    basic_config = config


class SimpleProtocol(unittest.TestCase):
    """
    Root class for setting up the controller
    """

    def sig_handler(self, v1, v2):
        basic_logger.critical("Received interrupt signal; exiting")
        print "Received interrupt signal; exiting"
        self.clean_shutdown = False
        self.tearDown()
        sys.exit(1)

    def setUp(self):
        self.logger = basic_logger
        self.config = basic_config
        #signal.signal(signal.SIGINT, self.sig_handler)
        basic_logger.info("** START TEST CASE " + str(self))
        self.controller = controller.Controller(
            host=basic_config["controller_host"],
            port=basic_config["controller_port"])
        # clean_shutdown should be set to False to force quit app
        self.clean_shutdown = True
        self.controller.start()
        #@todo Add an option to wait for a pkt transaction to ensure version
        # compatibilty?
        self.controller.connect(timeout=20)
        if not self.controller.active:
            print "Controller startup failed; exiting"
            sys.exit(1)
        basic_logger.info("Connected " + str(self.controller.switch_addr))

    def tearDown(self):
        basic_logger.info("** END TEST CASE " + str(self))
        self.controller.shutdown()
        #@todo Review if join should be done on clean_shutdown
        if self.clean_shutdown:
            self.controller.join()

    def runTest(self):
        # Just a simple sanity check as illustration
        basic_logger.info("Running simple proto test")
        self.assertTrue(self.controller.switch_socket is not None,
                        str(self) + 'No connection to switch')

    def assertTrue(self, cond, msg):
        if not cond:
            basic_logger.error("** FAILED ASSERTION: " + msg)
        unittest.TestCase.assertTrue(self, cond, msg)


class SimpleDataPlane(SimpleProtocol):
    """
    Root class that sets up the controller and dataplane
    """
    def setUp(self):
        SimpleProtocol.setUp(self)
        self.dataplane = dataplane.DataPlane()
        for of_port, ifname in basic_port_map.items():
            self.dataplane.port_add(ifname, of_port)

    def tearDown(self):
        basic_logger.info("Teardown for simple dataplane test")
        SimpleProtocol.tearDown(self)
        self.dataplane.kill(join_threads=self.clean_shutdown)
        basic_logger.info("Teardown done")

    def runTest(self):
        self.assertTrue(self.controller.switch_socket is not None,
                        str(self) + 'No connection to switch')
        # self.dataplane.show()
        # Would like an assert that checks the data plane


class DataPlaneOnly(unittest.TestCase):
    """
    Root class that sets up only the dataplane
    """

    def sig_handler(self, v1, v2):
        basic_logger.critical("Received interrupt signal; exiting")
        print "Received interrupt signal; exiting"
        self.clean_shutdown = False
        self.tearDown()
        sys.exit(1)

    def setUp(self):
        self.clean_shutdown = False
        self.logger = basic_logger
        self.config = basic_config
        #signal.signal(signal.SIGINT, self.sig_handler)
        basic_logger.info("** START DataPlaneOnly CASE " + str(self))
        self.dataplane = dataplane.DataPlane()
        for of_port, ifname in basic_port_map.items():
            self.dataplane.port_add(ifname, of_port)

    def tearDown(self):
        basic_logger.info("Teardown for simple dataplane test")
        self.dataplane.kill(join_threads=self.clean_shutdown)
        basic_logger.info("Teardown done")

    def runTest(self):
        basic_logger.info("DataPlaneOnly")
        # self.dataplane.show()
        # Would like an assert that checks the data plane


class Echo(SimpleProtocol):
    """
    Test echo response with no data
    """
    def runTest(self):
        testutils.echo_verify(self)


class EchoWithData(SimpleProtocol):
    """
    Test echo response with short string data
    """
    def runTest(self):
        testutils.echo_verify(self, 'OpenFlow Will Rule The World')


class FeaturesRequest(SimpleProtocol):
    """
    Test features_request to make sure we get a response

    Does NOT test the contents; just that we get a response
    """
    def runTest(self):
        request = message.features_request()
        response,_ = self.controller.transact(request)
        self.assertTrue(response,"Got no features_reply to features_request")
        self.assertEqual(response.header.type, ofp.OFPT_FEATURES_REPLY,
                         'response is not feature_reply')
        self.assertTrue(len(response) >= 32, "features_reply too short: %d < 32 " % len(response))

class GetConfigRequest(SimpleProtocol):
    """
        Test get_config_request to make sure we get a response
    """
    def runTest(self):
        testutils.get_config_reply_verify(self)

class SetConfig(SimpleProtocol):
    """
        Test get_config_request to make sure we get a response
    """
    def runTest(self):
        max_len = (DEFAULT_MISS_SEND_LEN + 14739) % ofp.OFPCML_MAX + 1
        testutils.set_config_verify(self, max_len = max_len)
        testutils.set_config_verify(self, max_len = DEFAULT_MISS_SEND_LEN)

class PacketIn(SimpleDataPlane):
    """
    Test packet in function

    Send a packet to each dataplane port and verify that a packet
    in message without data is received from the controller for each
    """
    def runTest(self):
        of_ports = testutils.clear_switch(self, basic_port_map.keys(), basic_logger)
        
        for max_len in [0, 99, DEFAULT_MISS_SEND_LEN, ofp.OFPCML_MAX, ofp.OFPCML_NO_BUFFER]:
            rc = testutils.delete_all_flows(self.controller, basic_logger)
            self.assertEqual(rc, 0, "Failed to delete all flows")
            testutils.set_config_verify(self, max_len = (max_len % ofp.OFPCML_MAX + 10))
            if max_len == ofp.OFPCML_NO_BUFFER:
                testutils.set_config_verify(self, max_len = max_len)
            testutils.set_flow_miss_entry(self, ofp.OFPTC_TABLE_MISS_CONTROLLER, max_len, 0)
            for of_port in basic_port_map.keys():
                basic_logger.info("PKT IN test, port " + str(of_port))
                pkt = testutils.simple_tcp_packet()
                self.dataplane.send(of_port, str(pkt))
                #@todo Check for unexpected messages?
                testutils.do_barrier(self.controller)
                testutils.packetin_verify(self, pkt, max_len)
                response,_ = self.controller.poll(ofp.OFPT_PACKET_IN, 1)
                while response != None:
                      response,_ = self.controller.poll(ofp.OFPT_PACKET_IN, 1)
        testutils.set_config_verify(self, max_len = DEFAULT_MISS_SEND_LEN)


class PacketInWithNoBuffer(SimpleDataPlane):
    """
    Test packet in function

    Send a packet to each dataplane port and verify that a packet
    in message is received from the controller for each
    """
    def runTest(self):
        # Construct packet to send to dataplane
        # Send packet to dataplane, once to each port
        # Poll controller with expect message type packet in
        of_ports = testutils.clear_switch(self, basic_port_map.keys(), basic_logger)

        testutils.set_table_config(self, 0, ofp.OFPTC_TABLE_MISS_CONTROLLER, True)
        #_,miss_send_len = testutils.get_config_reply_verify(self)
        testutils.set_config_verify(self, max_len = ofp.OFPCML_NO_BUFFER)
        for of_port in basic_port_map.keys():
            basic_logger.info("PKT IN test, port " + str(of_port))
            pkt = testutils.simple_tcp_packet()
            self.dataplane.send(of_port, str(pkt))
            #@todo Check for unexpected messages?
            testutils.packetin_verify(self, pkt, ofp.OFPCML_NO_BUFFER)
            response,_ = self.controller.poll(ofp.OFPT_PACKET_IN, 1)
            while response != None:
                  response,_ = self.controller.poll(ofp.OFPT_PACKET_IN, 1)
        testutils.set_config_verify(self, max_len = DEFAULT_MISS_SEND_LEN)

class PacketOut(SimpleDataPlane):
    """
    Test packet out function

    Send packet out message to controller for each dataplane port and
    verify the packet appears on the appropriate dataplane port
    """
    def runTest(self):
        # Construct packet to send to dataplane
        # Send packet to dataplane
        # Poll controller with expect message type packet in
        of_ports = testutils.clear_switch(self, basic_port_map.keys(), basic_logger)
        
        max_len = 40
        testutils.set_flow_miss_entry(self, ofp.OFPTC_TABLE_MISS_CONTROLLER, max_len, 0)
        # These will get put into function
        outpkt = testutils.simple_tcp_packet()
        of_ports = basic_port_map.keys()
        of_ports.sort()
        #_,miss_send_len = testutils.get_config_reply_verify(self)
        #testutils.set_config_verify(self, max_len = 40)
        
        for dp_port in of_ports:
            (response, _) = self.controller.poll(ofp.OFPT_PACKET_IN, 2)
            for egr_port in of_ports:
                if egr_port != dp_port:
                    break
            #_,max_len = testutils.get_config_reply_verify(self)
            self.dataplane.send(egr_port, str(outpkt))
            testutils.do_barrier(self.controller)
            buffer_id = testutils.packetin_verify(self, outpkt, max_len)
            response,_ = self.controller.poll(ofp.OFPT_PACKET_IN, 1)
            while response != None:
                  response,_ = self.controller.poll(ofp.OFPT_PACKET_IN, 1)
            msg = message.packet_out()
            msg.in_port = ofp.OFPP_CONTROLLER
            msg.buffer_id = buffer_id
            act = action.action_output()
            act.port = dp_port
            self.assertTrue(msg.actions.add(act), 'Could not add action to msg')

            basic_logger.info("PacketOut to: " + str(dp_port))
            testutils.ofmsg_send(self, msg)

            (of_port, pkt, _) = self.dataplane.poll(timeout=3)

            self.assertTrue(pkt is not None, 'Packet not received')
            basic_logger.info("PacketOut: got pkt from " + str(of_port))
            if of_port is not None:
                self.assertEqual(of_port, dp_port, "Unexpected receive port")
            self.assertEqual(str(outpkt), str(pkt),
                             'Response packet does not match send packet')
        #testutils.set_config_verify(self, max_len = DEFAULT_MISS_SEND_LEN)
 
class PacketInCookieCorrect(SimpleDataPlane):
    """
    Test packet in function

    Send a packet to each dataplane port and verify that a packet
    in message without data is received from the controller for each
    """
    def runTest(self):
        of_ports = testutils.clear_switch(self, basic_port_map.keys(), basic_logger)

        for max_len in [0, 99, DEFAULT_MISS_SEND_LEN, ofp.OFPCML_MAX, ofp.OFPCML_NO_BUFFER]:
            rc = testutils.delete_all_flows(self.controller, basic_logger)
            self.assertEqual(rc, 0, "Failed to delete all flows")
            testutils.set_config_verify(self, max_len = (max_len % ofp.OFPCML_MAX + 10))
            if max_len == ofp.OFPCML_NO_BUFFER:
                testutils.set_config_verify(self, max_len = max_len)
            
            request = message.flow_mod()
            request.table_id = 0
            request.priority = 0
            request.cookie = 123456
            act = action.action_output()
            act.max_len = max_len
            act.port = ofp.OFPP_CONTROLLER
            inst_packet_in = instruction.instruction_apply_actions()#apply
            inst_packet_in.actions.add(act)
            request.instructions.add(inst_packet_in)
            rv = self.controller.message_send(request)
             
            for of_port in basic_port_map.keys():
                basic_logger.info("PKT IN test, port " + str(of_port))
                pkt = testutils.simple_tcp_packet()
                self.dataplane.send(of_port, str(pkt))
                #@todo Check for unexpected messages?
                testutils.do_barrier(self.controller)
                #testutils.packetin_verify(self, pkt, max_len)
                response,_ = self.controller.poll(ofp.OFPT_PACKET_IN, 1)
                self.assertEqual(response.cookie, request.cookie, "cookie is not equal")
                #print(response.cookie)
                #print(request.cookie)
                #clear the msg
                response,_ = self.controller.poll(ofp.OFPT_PACKET_IN, 1)
                while response != None:
                      response,_ = self.controller.poll(ofp.OFPT_PACKET_IN, 1)
            #testutils.set_config_verify(self, max_len = DEFAULT_MISS_SEND_LEN)


class PacketOutWithNoBuffer(SimpleDataPlane):
    """
    Test packet out function

    Send packet out message to controller for each dataplane port and
    verify the packet appears on the appropriate dataplane port
    """
    def runTest(self):
        # Construct packet to send to dataplane
        # Send packet to dataplane
        # Poll controller with expect message type packet in

        of_ports = testutils.clear_switch(self, basic_port_map.keys(), basic_logger)

        # These will get put into function
        outpkt = testutils.simple_tcp_packet()
        of_ports = basic_port_map.keys()
        of_ports.sort()
        for dp_port in of_ports:
            msg = message.packet_out()
            msg.in_port = ofp.OFPP_CONTROLLER
            msg.data = str(outpkt)
            act = action.action_output()
            act.port = dp_port
            self.assertTrue(msg.actions.add(act), 'Could not add action to msg')

            basic_logger.info("PacketOut to: " + str(dp_port))
            testutils.ofmsg_send(self, msg)

            (of_port, pkt, _) = self.dataplane.poll(timeout=1)

            self.assertTrue(pkt is not None, 'Packet not received')
            basic_logger.info("PacketOut: got pkt from " + str(of_port))
            if of_port is not None:
                self.assertEqual(of_port, dp_port, "Unexpected receive port")
            self.assertEqual(str(outpkt), str(pkt),
                             'Response packet does not match send packet')


class FlowRemoveAll(SimpleProtocol):
    """
    Remove all flows; required for almost all tests

    Add a bunch of flows, remove them, and then make sure there are no flows left
    This is an intentionally naive test to see if the baseline functionality works
    and should be a precondition to any more complicated deletion test (e.g.,
    delete_strict vs. delete)
    """
    def runTest(self):
        basic_logger.info("Running StatsGet")
        basic_logger.info("Inserting trial flow")
        request = message.flow_mod()
        request.match.wildcards = OFPFW_ALL
        request.buffer_id = 0xffffffff
        for i in range(1,5):
            request.priority = i*1000
            basic_logger.debug("Adding flow %d" % i)
            testutils.ofmsg_send(self, request)
        basic_logger.info("Removing all flows")
        testutils.delete_all_flows(self.controller, basic_logger)
        basic_logger.info("Sending flow request")
        request = message.flow_stats_request()
        request.out_port = ofp.OFPP_ANY
        request.out_group = ofp.OFPG_ANY
        request.table_id = 0xff
        request.match.wildcards = 0 # ofp.OFPFW
        response, _ = self.controller.transact(request, timeout=2)
        self.assertTrue(response is not None, "Did not get response")
        self.assertTrue(isinstance(response,message.flow_stats_reply),"Not a flow_stats_reply")
        self.assertEqual(len(response.stats),0)
        basic_logger.debug(response.show())


class FlowStatsGet(SimpleProtocol):
    """
    Get stats

    Simply verify stats get transaction
    """
    def runTest(self):
        basic_logger.info("Running StatsGet")
        basic_logger.info("Inserting trial flow")
        request = message.flow_mod()
        request.match.wildcards = OFPFW_ALL
        request.buffer_id = 0xffffffff
        testutils.ofmsg_send(self, request)

        basic_logger.info("Sending flow request")
        response = testutils.flow_stats_get(self)
        basic_logger.debug(response.show())


class TableStatsGet(SimpleProtocol):
    """
    Get table stats

    Naively verify that we get a reply
    do better sanity check of data in stats.TableStats test
    """
    def runTest(self):
        basic_logger.info("Running TableStatsGet")
        basic_logger.info("Sending table stats request")
        request = message.table_stats_request()
        response, _ = self.controller.transact(request, timeout=2)
        self.assertTrue(response is not None, "Did not get response")
        self.assertEqual(response.header.type, ofp.OFPT_MULTIPART_REPLY,
                         'response is not OFPT_MULTIPART_REPLY')
        self.assertEqual(response.type, ofp.OFPMP_TABLE,
                         'response is not OFPMP_TABLE')
        basic_logger.debug(response.show())


class FlowMod(SimpleProtocol):
    """
    Insert a flow

    Simple verification of a flow mod transaction
    """

    def runTest(self):
        basic_logger.info("Running " + str(self))
        request = message.flow_mod()
        request.match.wildcards = OFPFW_ALL
        request.buffer_id = 0xffffffff
        testutils.ofmsg_send(self, request)


class PortConfigMod(SimpleProtocol):
    """
    Modify a bit in port config and verify changed

    Get the switch configuration, modify the port configuration
    and write it back; get the config again and verify changed.
    Then set it back to the way it was.
    """

    def runTest(self):
        basic_logger.info("Running " + str(self))
        for of_port, _ in basic_port_map.items(): # Grab first port
            break

        (_, config, _) = testutils.port_config_get(self.controller, of_port, basic_logger)
        self.assertTrue(config is not None, "Did not get port config")
        basic_logger.debug("No flood bit port " + str(of_port) + " is now " +
                           str(config & ofp.OFPPC_NO_PACKET_IN))

        rv = testutils.port_config_set(self.controller, of_port,
                             config ^ ofp.OFPPC_NO_PACKET_IN, ofp.OFPPC_NO_PACKET_IN,
                             basic_logger)
        self.assertTrue(rv != -1, "Error sending port mod")

        # Verify change took place with same feature request
        (_, config2, _) = testutils.port_config_get(self.controller, of_port, basic_logger)
        basic_logger.debug("No packet_in bit port " + str(of_port) + " is now " +
                           str(config2 & ofp.OFPPC_NO_PACKET_IN))
        self.assertTrue(config2 is not None, "Did not get port config2")
        self.assertTrue(config2 & ofp.OFPPC_NO_PACKET_IN !=
                        config & ofp.OFPPC_NO_PACKET_IN,
                        "Bit change did not take")
        # Set it back
        rv = testutils.port_config_set(self.controller, of_port, config,
                             ofp.OFPPC_NO_PACKET_IN, basic_logger)
        self.assertTrue(rv != -1, "Error sending port mod")


class PortDescRequest(SimpleProtocol):
    """
    PortDescRequest
    """
    def runTest(self):
        basic_logger.info("Running " + str(self))
        request = message.port_desc_request()
        response, _ = self.controller.transact(request)
        self.assertEqual(response.header.type, ofp.OFPT_MULTIPART_REPLY,
                         'response is not OFPT_MULTIPART_REPLY')
        self.assertEqual(request.header.xid, response.header.xid,
                         'response xid != request xid')



'''
class TableFeatureRequest(SimpleProtocol):
    """
    TableFeatureRequest
    """
    def runTest(self):
        count = 0
        basic_logger.info("Running " + str(self))
        request = message.table_feature_request()
        response, _ = self.controller.transact(request)
        print(response.show())
        self.assertEqual(response.header.type, ofp.OFPT_MULTIPART_REPLY,
                         'response is not OFPT_MULTIPART_REPLY')
        self.assertEqual(request.header.xid, response.header.xid,
                         'response xid != request xid')
        
        flag = response.flags
        while flag == 1:
            (next_resp, _) = self.controller.poll(ofp.OFPT_MULTIPART_REPLY, 1)
            print(next_resp.show() + "\n\r"+str(count))
            count = count + 1
            flag = next_resp.flags
'''

class MeterStats(SimpleProtocol):
    """
    MeterConfig
    """
    def runTest(self):
        count = 0
        basic_logger.info("Running " + str(self))

        #send multipart request message to get meter info
        basic_logger.info("Sending meter config request")
        request = message.meter_stats_request()
        request.meter_id = ofp.OFPM_ALL
        (response, _) = self.controller.transact(request, timeout=2)

        #No meter mod entry,it will return a errer message
        self.assertEqual(response.header.type, ofp.OFPT_MULTIPART_REPLY,
                         'response is not OFPT_MULTIPART_REPLY')
        self.assertEqual(request.header.xid, response.header.xid,
                         'response.heade.xid != request xid')
        self.assertEqual(response.type, ofp.OFPMP_METER,
                         'response.type != OFPMP_METER')

class MeterConfig(SimpleProtocol):
    """
    MeterConfig
    """
    def runTest(self):
        count = 0
        basic_logger.info("Running " + str(self))

        #send multipart request message to get meter info
        basic_logger.info("Sending meter config request")
        request = message.meter_config_request()
        request.meter_id = 0
        (response, _) = self.controller.transact(request, timeout=2)
        #print(response.show())
        #No meter mod entry,it will return a errer message
        self.assertEqual(response.header.type, ofp.OFPT_ERROR,
                         'response is not OFPT_ERROR')
        self.assertEqual(request.header.xid, response.header.xid,
                         'response xid != request xid')
        self.assertEqual(response.type, ofp.OFPET_METER_MOD_FAILED,
                         'response.type != expect type')
        self.assertEqual(response.code, ofp.OFPMMFC_UNKNOWN_METER,
                         'response code != expect code')

class MeterFeature(SimpleProtocol):
    """
    MeterConfig
    """
    def runTest(self):
        count = 0
        basic_logger.info("Running " + str(self))

        #send multipart request message to get meter info
        basic_logger.info("Sending meter config request")
        request = message.meter_feature_request()
        (response, _) = self.controller.transact(request, timeout=2)
        #print(response.show())

        self.assertEqual(response.header.type, ofp.OFPT_MULTIPART_REPLY,
                         'response is not OFPT_MULTIPART_REPLY')
        self.assertEqual(request.header.xid, response.header.xid,
                         'response xid != request xid')

class MeterModDrop(SimpleProtocol):
    """
    MeterModDrop
    """
    def runTest(self):
        count = 0
        basic_logger.info("Running " + str(self))
        metermoddrop = message.meter_mod_drop()
        metermoddrop.command = ofp.OFPMC_ADD
        metermoddrop.flags = ofp.OFPMF_KBPS
        #response, _ = self.controller.transact(metermoddrop)
        rv = self.controller.message_send(metermoddrop)
        self.assertTrue(rv == 0, "Error sending meter mod")

        #send multipart request message to get meter info
        basic_logger.info("Sending meter config request")
        request = message.meter_config_request()
        (response, _) = self.controller.transact(request, timeout=2)
        #print(response.show())

        #meter mod entry,it will return a reply message
        self.assertEqual(response.header.type, ofp.OFPT_MULTIPART_REPLY,
                         'response is not MULTIPART_REPLY')
        self.assertEqual(request.header.xid, response.header.xid,
                         'response xid != request xid')    

class MeterModDel(SimpleProtocol):
    """
    MeterModDrop
    """
    def runTest(self):
        count = 0
        basic_logger.info("Running " + str(self))
        metermoddrop = message.meter_mod_drop()
        metermoddrop.command = ofp.OFPMC_ADD
        metermoddrop.flags = ofp.OFPMF_KBPS
        #response, _ = self.controller.transact(metermoddrop)
        rv = self.controller.message_send(metermoddrop)
        self.assertTrue(rv == 0, "Error sending meter mod add")

        #send meter mod del message
        metermoddrop.command = ofp.OFPMC_DELETE
        rv = self.controller.message_send(metermoddrop)
        self.assertTrue(rv == 0, "Error sending meter mod del")

        #send multipart request message to get meter info
        basic_logger.info("Sending meter config request")
        request = message.meter_config_request()
        (response, _) = self.controller.transact(request, timeout=2)
        #print(response.show())

        #no meter mod entry,it will return a reply message
        self.assertEqual(response.header.type, ofp.OFPT_ERROR,
                         'response is not ERROR')
        self.assertEqual(request.header.xid, response.header.xid,
                         'response xid != request xid')
        self.assertEqual(response.type, ofp.OFPET_METER_MOD_FAILED,
                         'response.type != expect type')        
        self.assertEqual(response.code, ofp.OFPMMFC_UNKNOWN_METER,
                         'response code != expect code')   

class MeterModBadFlags(SimpleProtocol):
    """
    MeterModDrop
    """
    def runTest(self):
        count = 0
        basic_logger.info("Running " + str(self))
        #clear the environment
        msg = message.meter_mod()
        msg.meter_id = ofp.OFPM_ALL
        msg.command = ofp.OFPMC_DELETE
        self.controller.message_send(msg)
        metermoddrop = message.meter_mod_drop()
        metermoddrop.command = ofp.OFPMC_ADD
        metermoddrop.flags = ofp.OFPMF_KBPS+14
        rv = self.controller.message_send(metermoddrop)
        self.assertTrue(rv == 0, "Error sending meter mod")

        #print(metermoddrop.show())

        (response, raw) = self.controller.poll(ofp.OFPT_ERROR, 2)
        #print(response.show())
        self.assertTrue(response is not None, 'No error message received')
        self.assertEqual(ofp.OFPET_METER_MOD_FAILED, response.type,
                       'Error message type mismatch: ' +
                       str(ofp.OFPET_METER_MOD_FAILED,) + " != " +
                       str(response.type))
        self.assertEqual(ofp.OFPMMFC_BAD_FLAGS, response.code,
                       'Error message code mismatch: ' +
                       str(ofp.OFPMMFC_BAD_FLAGS) + " != " +
                       str(response.code))

if __name__ == "__main__":
    print "Please run through oft script:  ./oft --test_spec=basic"

