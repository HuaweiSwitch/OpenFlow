"""
Test cases for testing actions taken on packets

See basic.py for other info.

It is recommended that these definitions be kept in their own
namespace as different groups of tests will likely define
similar identifiers.

  The function test_set_init is called with a complete configuration
dictionary prior to the invocation of any tests from this file.

  The switch is actively attempting to contact the controller at the address
indicated oin oft_config

"""

import logging
import oftest.cstruct as ofp
import oftest.match as match
import oftest.message as message
import oftest.action as action
import oftest.parse as parse
import oftest.instruction as instruction
import basic

import ipaddr

#import oftest.controller as controller

import testutils

import os.path
import subprocess

#@var port_map Local copy of the configuration map from OF port
# numbers to OS interfaces
ipv6_port_map = None
#@var ipv6_logger Local logger object
ipv6_logger = None
#@var ipv6_config Local copy of global configuration data
ipv6_config = None

# For test priority
#@var test_prio Set test priority for local tests
test_prio = {}

# Cache supported features to avoid transaction overhead
cached_supported_actions = None

TEST_VID_DEFAULT = 2

IPV6_ETHERTYPE = 0x86dd
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_MPLS = 0x8847
TCP_PROTOCOL = 0x6
UDP_PROTOCOL = 0x11
ICMPV6_PROTOCOL = 0x3a

def test_set_init(config):
    """
    Set up function for IPv6 packet handling test classes

    @param config The configuration dictionary; see oft
    """

    global ipv6_port_map
    global ipv6_logger
    global ipv6_config

    ipv6_logger = logging.getLogger("ipv6")
    ipv6_logger.info("Initializing test set")
    ipv6_port_map = config["port_map"]
    ipv6_config = config


# TESTS
class MatchIPv6Simple(basic.SimpleDataPlane):
    """
    Just send a packet IPv6 to match a simple entry on the matching table
    """
    def runTest(self):

        of_ports = ipv6_port_map.keys()
        of_ports.sort()
        ing_port = of_ports[0]
        egr_port = of_ports[2]
        table_id = testutils.WC_L3_TABLE

        # Remove all entries Add entry match all
        rc = testutils.delete_all_flows(self.controller, self.logger)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        rv = testutils.set_table_config(self, table_id)
        self.assertEqual(rv, 0, "Failed to set table config")

        # Add entry match
        pkt = testutils.simple_ipv6_packet()
        request = testutils.flow_msg_create(self, pkt, ing_port = ing_port, egr_port = egr_port, table_id = table_id)
        testutils.flow_msg_install(self, request)

        #Send packet
        self.logger.info("Sending IPv6 packet to " + str(ing_port))
        self.logger.debug("Data: " + str(pkt).encode('hex'))
        self.dataplane.send(ing_port, str(pkt))

        #Receive packet
        testutils.receive_pkt_verify(self, egr_port, pkt)

        #Remove flows
        rc = testutils.delete_all_flows(self.controller, self.logger)
        self.assertEqual(rc, 0, "Failed to delete all flows")

class MatchICMPv6Simple(basic.SimpleDataPlane):
    """
    Match on an ICMPv6 packet
    """
    def runTest(self):
        of_ports = ipv6_port_map.keys()
        of_ports.sort()
        ing_port = of_ports[0]
        egr_port = of_ports[2]
        table_id = testutils.EX_ICMP_TABLE

        # Remove all entries Add entry match all
        rc = testutils.delete_all_flows(self.controller, ipv6_logger)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        rv = testutils.set_table_config(self, table_id)
        self.assertEqual(rv, 0, "Failed to set table config")

        # Add entry match
        pkt = testutils.simple_icmpv6_packet()
        request = testutils.flow_msg_create(self, pkt, ing_port = ing_port, egr_port = egr_port, table_id = table_id)
        testutils.flow_msg_install(self, request)

        #Send packet
        ipv6_logger.info("Sending IPv6 packet to " + str(ing_port))
        ipv6_logger.debug("Data: " + str(pkt).encode('hex'))
        self.dataplane.send(ing_port, str(pkt))

        #Receive packet
        exp_pkt = testutils.simple_icmpv6_packet()
        testutils.receive_pkt_verify(self, egr_port, exp_pkt)

        #Remove flows
        rc = testutils.delete_all_flows(self.controller, ipv6_logger)
        self.assertEqual(rc, 0, "Failed to delete all flows")


class IPv6SetField(basic.SimpleDataPlane):

    def runTest(self):
        of_ports = ipv6_port_map.keys()
        of_ports.sort()
        ing_port = of_ports[0]
        egr_port = of_ports[2]
        table_id1 = testutils.EX_L3_TABLE
        table_id2 = testutils.WC_ALL_TABLE

        # Remove all entries Add entry match all
        rc = testutils.delete_all_flows(self.controller, ipv6_logger)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        rv = testutils.set_table_config(self, table_id = table_id1)
        self.assertEqual(rv, 0, "Failed to set table config")

        # Add entry match
        pkt = testutils.simple_ipv6_packet(ip_dst='fe80::1:0:1234')
        pkt_metadata = {'metadata_val':0xabcdef0123456789,
                        'metadata_msk':0xffffffffffffffff}

        inst_ls1 = []
        inst1_write = instruction.instruction_write_metadata()
        inst1_write.metadata = pkt_metadata['metadata_val']
        inst1_write.metadata_mask = pkt_metadata['metadata_msk']

        inst1_goto = instruction.instruction_goto_table()
        inst1_goto.table_id = table_id2

        inst_ls1.append(inst1_write)
        inst_ls1.append(inst1_goto)
        request1 = testutils.flow_msg_create(self, pkt, ing_port = ing_port,
                            instruction_list = inst_ls1,
                            table_id = table_id1)

        testutils.flow_msg_install(self, request1)

        act_ls2 = []
        act2_setfld = action.action_set_field()
        act2_setfld.field = match.ipv6_dst(ipaddr.IPv6Address('fe80::1:6554:3e7f:1'))

        act2_out = action.action_output()
        act2_out.port = egr_port

        act_ls2.append(act2_setfld)
        act_ls2.append(act2_out)
        pkt_metadata = {'metadata_val':0xabcdef0100000000,
                        'metadata_msk':0xffffffff00000000}
        request2 = testutils.flow_msg_create(self, pkt, pkt_metadata, ing_port, 
                            action_list = act_ls2, table_id = table_id2)

        testutils.flow_msg_install(self, request2)

        #Send packet
        ipv6_logger.info("Sending IPv6 packet to " + str(ing_port))
        ipv6_logger.debug("Data: " + str(pkt).encode('hex'))
        self.dataplane.send(ing_port, str(pkt))

        #Receive packet
        exp_pkt = testutils.simple_ipv6_packet(ip_dst='fe80::1:6554:3e7f:1')
        testutils.receive_pkt_verify(self, egr_port, exp_pkt)

        #See flow match
        response = testutils.flow_stats_get(self)
        ipv6_logger.debug("Response" + response.show())

        #Remove flows
        rc = testutils.delete_all_flows(self.controller, ipv6_logger)
        self.assertEqual(rc, 0, "Failed to delete all flows")


class MatchIPv6TCP(basic.SimpleDataPlane):

    def runTest(self):
        # Config
        of_ports = ipv6_port_map.keys()
        of_ports.sort()
        ing_port = of_ports[0]
        egr_port = of_ports[2]
        table_id = testutils.WC_ACL_TABLE

        # Remove flows
        rc = testutils.delete_all_flows(self.controller, ipv6_logger)
        self.assertEqual(rc, 0, "Failed to delete all flows")

        # Add entry match
        pkt = testutils.simple_ipv6_packet(tcp_sport=80, tcp_dport=8080)
        request = testutils.flow_msg_create(self, pkt, ing_port = ing_port, egr_port = egr_port, table_id = table_id)
        testutils.flow_msg_install(self, request)

        #Send packet
        ipv6_logger.info("Sending IPv6 packet to " + str(ing_port))
        ipv6_logger.debug("Data: " + str(pkt).encode('hex'))

        self.dataplane.send(ing_port, str(pkt))

        #Receive packet
        exp_pkt = testutils.simple_ipv6_packet(tcp_sport=80, tcp_dport=8080)
        testutils.receive_pkt_verify(self, egr_port, exp_pkt)

        #Remove flows
        rc = testutils.delete_all_flows(self.controller, ipv6_logger)
        self.assertEqual(rc, 0, "Failed to delete all flows")
'''
class MatchIPv6Test(basic.SimpleDataPlane):
    def runTest(self):      
        pkt1 = testutils.simple_ipv6_allfield_packet()
        match_ls1 = testutils.packet_to_exact_flow_match(pkt1, table_id = testutils.WC_ALL_TABLE, ing_port = 1)
        pkt2 = testutils.simple_icmp_packet()
        match_ls2 = testutils.packet_to_exact_flow_match(pkt2, table_id = testutils.WC_ALL_TABLE, ing_port = 2)
        print(match_ls1.show())
        print(match_ls2.show())
'''
if __name__ == "__main__":
    print "Please run through oft script:  ./oft --test-spec=ipv6"
