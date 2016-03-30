# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Maple Yip

"""
Test suite 10 verifies establishment of a control channel, version negotiation, 
and device behavior when the control channel is lost.

To satisfy basic conformance an OpenFlow enabled device must pass at least one of 
10.30, 10.40, 10.50 and 10.20, or 10.60 and 10.20. Additionally a device must pass 
either 10.110 and 10.130, or 10.120. For basic conformance test cases 10.10, and 
10.70 - 10.100 must be passed by all devices.
"""

import logging
import time
import sys

import unittest
import random

from oftest import config
import oftest.controller as controller
import ofp
import oftest.dataplane as dataplane
import oftest.parse as parse
import oftest.base_tests as base_tests
import oftest.illegal_message as illegal_message

from oftest.oflog import *
from oftest.testutils import *
from time import sleep



class Testcase_10_10_StartupBehavior(base_tests.DataPlaneOnly):
    """
    10.10 - Startup behavior without established control channel
    Startup from factory default mode. Expected behavior should be as defined in the switch documentation.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 10.10 - Startup behavior without established control channel test")
        port1, = openflow_ports(1)
        data = simple_arp_packet()
        logging.info("Sending dataplane packet")
        self.dataplane.send(port1, str(data))
        verify_packets(self, data, [])
        logging.info("No packet has been forworded as expected")
        
   
class Testcase_10_20_Certificate_configuration_TLS(base_tests.EncryptedProtocol):
	"""
	10.20 - Certificate configuration for TLS
	Purpose
    Check the configuration for TLS encrypted control plane connections.

	Methodology
    Configure test framework and switch for an TLS encrypted control channel. Prepare necessary management plane if necessary (pki).

	"""
	@wireshark_capture
	def runTest(self):
		logging.info("Running 10.20 Certificate configuration for TLS")
		req = ofp.message.echo_request()
		rv, _ = self.controller.transact(req)
		self.assertEqual(rv.type, ofp.OFPT_ECHO_REPLY, "Did not receive echo reply message")
		logging.info("Received Echo Reply from the switch")
		
		
		
class Testcase_10_30_TCPdefaultPort(base_tests.SimpleProtocol):
    """
    10.30 - TCP default Port
    Test unencrypted control channel establishment on default port
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 10.30 - TCP default Port test")
        timeout = 5
        request=ofp.message.echo_request()
        self.controller.message_send(request)
        (rv, pkt) = self.controller.poll(exp_msg=ofp.OFPT_ECHO_REPLY,timeout=timeout)
        self.assertIsNotNone(rv, 'Did not receive Echo reply')
        logging.info("Received echo reply with port "+str(config["controller_port"]))


        
class Testcase_10_40_TCPNondefaultPort(base_tests.SimpleProtocol):
    """
    10.40 - TCP non default Port
    Test unencrypted control channel establishment on non default port
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 10.40 - TCP non default Port test")
        timeout = 5
        request=ofp.message.echo_request()
        self.controller.message_send(request)
        (rv, pkt) = self.controller.poll(exp_msg=ofp.OFPT_ECHO_REPLY,timeout=timeout)
        self.assertIsNotNone(rv, 'Did not receive Echo reply')
        logging.info("Received echo reply with port "+str(config["controller_port"]))
		
		
class Testcase_10_50_TLS_with_default_TCP_port(base_tests.EncryptedProtocol):
	"""
    Purpose
    Test encrypted control channel establishment on default port

    Methodology
    Reference controller must be running and reachable at configured IP and Port 6653. Configure DUT to connect with reference controller using encrypted TLS. If required, manually configure switch to connect to controller using TCP port 6653.


	"""
	@wireshark_capture
	def runTest(self):
		logging.info("Running 10.50 TLS with default TCP port")
		self.assertEqual(config["controller_port"], 6653)
		req = ofp.message.echo_request()
		rv, _ = self.controller.transact(req)
		self.assertEqual(rv.type, ofp.OFPT_ECHO_REPLY, "Did not receive echo reply message")
		logging.info("Received Echo Reply from the switch")
		
class Testcase_10_60_TLS_with_nondefault_TCP_port(base_tests.EncryptedProtocol):
	"""
    Purpose
    Test encrypted control channel establishment on non-default port

    Methodology
    Reference controller must be running and reachable at configured IP and Port unequal 6653. Configure DUT to connect with reference controller using encrypted TLS. Manually configure switch to connect to controller using configured TCP port.



	"""
	@wireshark_capture
	def runTest(self):
		logging.info("Running 10.60 TLS with non default TCP port")
		#self.assertEqual(config["controller_port"], 6653)
		req = ofp.message.echo_request()
		rv, _ = self.controller.transact(req)
		self.assertEqual(rv.type, ofp.OFPT_ECHO_REPLY, "Did not receive echo reply message")
		logging.info("Received Echo Reply from the switch")
	
class Testcase_10_70_VersionNegotiationSuccess(base_tests.SimpleProtocol):
    """
    10.70 - Version negotiation on version field success
    Check that the switch negotiates the correct version with the controller, based on the version field.
    """

    def setUp(self):

        base_tests.BaseTest.setUp(self)

        self.controller = controller.Controller(
            switch=config["switch_ip"],
            host=config["controller_host"],
            port=config["controller_port"])
        self.controller.initial_hello = False
        #self.controller.start()
        #self.controller.connect(timeout=120)
        #self.controller.keep_alive = True
        """
        try:
            self.controller.connect(timeout=20)
            # By default, respond to echo requests
            self.controller.keep_alive = True

            if not self.controller.active:
                raise Exception("Controller startup failed")
            if self.controller.switch_addr is None:
                raise Exception("Controller startup failed (no switch addr)")
            logging.info("Connected " + str(self.controller.switch_addr))
        except:
            self.controller.kill()
            del self.controller
            raise
            """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 10.70 - Version negotiation on version field success test")
        timeout = 20
        nego_version = 4
        self.controller.start()
        #self.controller.connect(timeout=120)
        self.controller.keep_alive = True
        (rv, pkt) = self.controller.poll(exp_msg=ofp.OFPT_HELLO, timeout=timeout)
        self.assertIsNotNone(rv, 'Did not receive Hello msg')
        self.assertEqual(rv.version,nego_version, 'Received version of Hello msg is not 4')
        logging.info("Received Hello msg with correct version")
        reply = ofp.message.hello()
        reply.version=nego_version
        self.controller.message_send(reply)
        logging.info("Sending Hello msg with version 4")
        request=ofp.message.echo_request()
        self.controller.message_send(request)
        (rv, pkt) = self.controller.poll(exp_msg=ofp.OFPT_ECHO_REPLY,timeout=timeout)
        self.assertIsNotNone(rv, 'Did not receive Echo reply')
        self.assertEqual(rv.version,nego_version, 'Received version of Hello msg is not 4')
        logging.info("Received echo reply with correct version")


        


        


class Testcase_10_80_VersionNegotiationFailure(base_tests.SimpleProtocol):
    """
    10.80 - Version negotiation failure
    Verify correct behavior in case of version negotiation failure.
    """

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

        
        
class Testcase_10_90_VersionNegotiationBitmap(base_tests.SimpleProtocol):
    """
    10.90 - 10.90 - Version negotiation based on bitmap
    Verify that version negotiation based on bitmap is successful
    """

    def setUp(self):

        base_tests.BaseTest.setUp(self)

        self.controller = controller.Controller(
            switch=config["switch_ip"],
            host=config["controller_host"],
            port=config["controller_port"])
        self.controller.initial_hello = False
        #self.controller.start()

        """try:
            self.controller.connect(timeout=20)
            self.controller.keep_alive = True

            if not self.controller.active:
                raise Exception("Controller startup failed")
            if self.controller.switch_addr is None:
                raise Exception("Controller startup failed (no switch addr)")
            logging.info("Connected " + str(self.controller.switch_addr))
        except:
            self.controller.kill()
            del self.controller
            raise"""

    @wireshark_capture
    def runTest(self):
        logging.info("Running 10.90 - Version negotiation based on bitmap test")
        self.controller.start()
        #self.controller.connect(timeout=120)
        self.controller.keep_alive = True
        sleep(3)
        (rv, pkt) = self.controller.poll(exp_msg=ofp.OFPT_HELLO, timeout=5)
        logging.info("Received Hello msg with correct version")
        version = 1
        req = ofp.message.hello()
        self.controller.message_send(req)
        req.version=version
        bitmap = ofp.common.uint32(0x12) 
        hello_elem = ofp.common.hello_elem_versionbitmap(bitmaps=[bitmap])
        req.elements.append(hello_elem)
        logging.info("Sending Hello msg with bitmap")
        self.controller.message_send(req)
        #rv, _ = self.controller.poll(exp_msg = ofp.OFPT_HELLO, timeout = 5)
        #rv, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=5)
        #self.assertIsNone(rv, 'Received Error msg')
        #self.assertTrue(rv.elements != [], 'Hello msg does not include Bitmap')
        request=ofp.message.echo_request()
        self.controller.message_send(request)
        rv, _ = self.controller.poll(exp_msg=ofp.OFPT_ECHO_REPLY,timeout=5)
        self.assertIsNotNone(rv, 'Did not receive Echo reply')
        self.assertEqual(rv.version, 4, 'Received version of Hello msg is not 4')
        logging.info("Version negotiation Success")

    def tearDown(self):
        self.controller.shutdown()
        self.controller.join()
        del self.controller
        base_tests.BaseTest.tearDown(self)


        
class Testcase_10_100_ControlChannelFailureMode(base_tests.SimpleDataPlane):
    """
    10.100 - Control channel failure mode
    Verify the switch enters the correct state after loss of the controller connection.
    """

    """def setUp(self):

        base_tests.BaseTest.setUp(self)

        self.controller = controller.Controller(
            switch=config["switch_ip"],
            host=config["controller_host"],
            port=config["controller_port"])
        self.clean_shutdown = False
        self.controller.initial_hello = True
        self.controller.start()
        
        try:
            self.controller.connect(timeout=20)
            self.controller.keep_alive = False

            if not self.controller.active:
                raise Exception("Controller startup failed")
            if self.controller.switch_addr is None:
                raise Exception("Controller startup failed (no switch addr)")
            logging.info("Connected " + str(self.controller.switch_addr))
        except:
            self.controller.kill()
            del self.controller
            raise"""
            
    def tearDown(self):
        self.controller.shutdown()
        self.controller.join()
        del self.controller
        base_tests.BaseTest.tearDown(self)
            
    @wireshark_capture
    def runTest(self):
        logging.info("Running 10.100 - Control channel failure mode test")
        self.controller.keep_alive = False
        delete_all_flows(self.controller)
        in_port, out_port, = openflow_ports(2)
        table_id = test_param_get("table",0)
        
        logging.info("Inserting flow sending in_port matching packets to port %d", out_port)
        match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id = table_id,
                                    match = match,
                                    instructions=[ofp.instruction.apply_actions(
                                        actions = [ofp.action.output(
                                                                    port = out_port,
                                                                    max_len = 128)])],
                                    buffer_id = ofp.OFP_NO_BUFFER,
                                    priority = 1)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg = ofp.OFPT_ERROR, timeout = 3)
        self.assertIsNone(reply, "Received error message, could not install the flow")
        logging.info("Installed the flow successfully")
        (response, pkt) = self.controller.poll(exp_msg=ofp.OFPT_ECHO_REQUEST,
                                               timeout=60)
        self.assertTrue(response is not None, 
                               'Switch is not generating Echo-Requests') 
        logging.info("Received an Echo request, waiting for echo timeout")
        time.sleep(20)
        """(response1, pkt1) = self.controller.poll(exp_msg=ofp.OFPT_HELLO,
                                               timeout=180)
        self.assertTrue(response1 is not None, 
                               'Switch did not drop connection due to Echo Timeout') 
        logging.info("Received an OFPT_HELLO message after echo timeout")"""
        
        mode = test_param_get("mode",0)
        pkt = simple_tcp_packet()
        strpkt=str(pkt)
        self.dataplane.send(in_port, strpkt)
        if mode ==0:
            verify_packet(self, strpkt, out_port)
        else:
            verify_no_packet(self, strpkt, out_port)


            
class Testcase_10_110_FailSecureModeBehavior(base_tests.SimpleDataPlane):
    """
    10.110 - Fail secure mode behavior
    Verify the switch enters the correct state after loss of the controller connection.
    """

    def tearDown(self):
        self.controller.shutdown()
        self.controller.join()
        del self.controller
        base_tests.BaseTest.tearDown(self)
            
    @wireshark_capture
    def runTest(self):
        logging.info("Running 10.110 - Fail secure mode behavior test")
        self.controller.keep_alive = False
        delete_all_flows(self.controller)
        in_port, out_port, = openflow_ports(2)
        table_id = test_param_get("table",0)
        
        logging.info("Inserting flow sending in_port matching packets to port %d", out_port)
        match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id = table_id,
                                    match = match,
                                    instructions=[ofp.instruction.apply_actions(
                                        actions = [ofp.action.output(
                                                                    port = out_port,
                                                                    max_len = 128)])],
                                    buffer_id = ofp.OFP_NO_BUFFER,
                                    priority = 1,
                                    hard_timeout=50)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg = ofp.OFPT_ERROR, timeout = 3)
        self.assertIsNone(reply, "Received error message, could not install the flow")
        logging.info("Installed the flow successfully")
        (response, pkt) = self.controller.poll(exp_msg=ofp.OFPT_ECHO_REQUEST,
                                               timeout=20)
        self.assertTrue(response is not None, 
                               'Switch is not generating Echo-Requests') 
        logging.info("Received an Echo request, waiting for echo timeout")
        time.sleep(20)
        
        mode = test_param_get("mode",0)
        pkt = simple_tcp_packet()
        strpkt=str(pkt)
        if mode ==0:
            self.dataplane.send(in_port, strpkt)
            verify_no_packet_in(self, strpkt, in_port)
            verify_packet(self, strpkt, out_port)
            time.sleep(30)
            self.dataplane.send(in_port, strpkt)
            verify_no_packet_in(self, strpkt, in_port)
            verify_no_packet(self, strpkt, out_port)
        else:
            logging.info("DUT does not support fail secure mode")
            
            
            
class Testcase_10_120_FailStandaloneMode(base_tests.SimpleDataPlane):
    """
    10.120 - Fail standalone mode - OFPP_Normal - Hybrids
    We verify correct operation of fail-standalone mode. We currently expect  L2 learning switch behaviour. 
    If a switch supports other default behavior the test must check for this.
    """

    def tearDown(self):
        self.controller.shutdown()
        self.controller.join()
        del self.controller
        base_tests.BaseTest.tearDown(self)
            
    @wireshark_capture
    def runTest(self):
        logging.info("Running 10.120 - Fail standalone mode - OFPP_Normal - Hybrids")
        self.controller.keep_alive = False
        delete_all_flows(self.controller)
        ports = openflow_ports(4)      

        (response, pkt) = self.controller.poll(exp_msg=ofp.OFPT_ECHO_REQUEST,
                                               timeout=20)
        self.assertTrue(response is not None, 
                               'Switch is not generating Echo-Requests') 
        logging.info("Received an Echo request, waiting for echo timeout")
        time.sleep(20)
        
        mode = test_param_get("mode",0)
        pkt = simple_arp_packet()
        strpkt=str(pkt)
        if mode ==0:
            logging.info("DUT does not support fail standalone mode")
        else:
            self.dataplane.send(ports[0], strpkt)
            verify_packets(self, strpkt, ports[1:4])

            
            
class Testcase_10_130_FailSecureModeBehavior(base_tests.SimpleDataPlane):
    """
    10.130 - Existing flow entries stay active
    Verify that flows stay active and timeout as configured after control channel re-establishment
    """

    def tearDown(self):
        self.controller.shutdown()
        self.controller.join()
        del self.controller
        base_tests.BaseTest.tearDown(self)
            
    @wireshark_capture
    def runTest(self):
        logging.info("Running 10.130 - Existing flow entries stay active test")
        delete_all_flows(self.controller)
        in_port, out_port, = openflow_ports(2)
        table_id = test_param_get("table",0)
        
        logging.info("Inserting flow sending in_port matching packets to port %d", out_port)
        match = ofp.match([ofp.oxm.in_port(in_port)])
        req = ofp.message.flow_add(table_id = table_id,
                                    match = match,
                                    instructions=[ofp.instruction.apply_actions(
                                        actions = [ofp.action.output(
                                                                    port = out_port,
                                                                    max_len = 128)])],
                                    buffer_id = ofp.OFP_NO_BUFFER,
                                    priority = 1,
                                    hard_timeout=20)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg = ofp.OFPT_ERROR, timeout = 3)
        self.assertIsNone(reply, "Received error message, could not install the flow")
        logging.info("Installed the flow successfully")
        self.controller.shutdown()    
        time.sleep(5)
        
        self.controller.connect()
        sleep(5)
        
        pkt = simple_tcp_packet()
        strpkt=str(pkt)

        self.dataplane.send(in_port, strpkt)
        verify_packet(self, strpkt, out_port)
        time.sleep(10)
        self.dataplane.send(in_port, strpkt)
        verify_no_packet(self, strpkt, out_port)
