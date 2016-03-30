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

import basic
import testutils

from oftest import cstruct as ofp
from oftest import message as message
from oftest import action as action
from oftest import parse as parse
from oftest import instruction as instruction
from oftest import match as match

#@var port_map Local copy of the configuration map from OF port
# numbers to OS interfaces
pa_port_map = None
#@var pa_logger Local logger object
pa_logger = None
#@var pa_config Local copy of global configuration data
pa_config = None

# For test priority
#@var test_prio Set test priority for local tests
test_prio = {}

WILDCARD_VALUES = [ 1 << ofp.OFPXMT_OFB_IN_PORT,
                    1 << ofp.OFPXMT_OFB_VLAN_VID,
                    1 << ofp.OFPXMT_OFB_ETH_TYPE,
                    1 << ofp.OFPXMT_OFB_IP_PROTO,
                    1 << ofp.OFPXMT_OFB_VLAN_PCP,
                    1 << ofp.OFPXMT_OFB_IP_DSCP]

MODIFY_ACTION_VALUES =  [1 << ofp.OFPXMT_OFB_VLAN_VID,
                         1 << ofp.OFPXMT_OFB_VLAN_PCP,
                         1 << ofp.OFPXMT_OFB_ETH_SRC,
                         1 << ofp.OFPXMT_OFB_ETH_DST,
                         1 << ofp.OFPXMT_OFB_IPV4_SRC,
                         1 << ofp.OFPXMT_OFB_IPV4_DST,
                         1 << ofp.OFPXMT_OFB_IP_DSCP,
                         1 << ofp.OFPXMT_OFB_TCP_SRC,
                         1 << ofp.OFPXMT_OFB_TCP_DST]

# Cache supported features to avoid transaction overhead
cached_supported_actions = None

TEST_VID_DEFAULT = 2

OFPFW_ALL = 1023

def test_set_init(config):
    """
    Set up function for packet action test classes

    @param config The configuration dictionary; see oft
    """

    global pa_port_map
    global pa_logger
    global pa_config

    pa_logger = logging.getLogger("pkt_act")
    pa_logger.info("Initializing test set")
    pa_port_map = config["port_map"]
    pa_config = config


class DirectPacket(basic.SimpleDataPlane):
    """
    Send packet to single egress port

    Generate a packet
    Generate and install a matching flow
    Add action to direct the packet to an egress port
    Send the packet to ingress dataplane port
    Verify the packet is received at the egress port only
    """
    def runTest(self):
        self.handleFlow()

    def handleFlow(self, pkttype='TCP'):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")

        if (pkttype == 'ICMP'):
                pkt = testutils.simple_icmp_packet()
                table_id = testutils.EX_ICMP_TABLE
        else:
                pkt = testutils.simple_tcp_packet()
                table_id = testutils.WC_ACL_TABLE
        
        for idx in range(len(of_ports)):
            rv = testutils.delete_all_flows(self.controller, pa_logger)
            self.assertEqual(rv, 0, "Failed to delete all flows")
            testutils.set_table_config(self, table_id, ofp.OFPTC_TABLE_MISS_CONTINUE)

            ingress_port = of_ports[idx]
            egress_port = of_ports[(idx + 1) % len(of_ports)]
            pa_logger.info("Ingress " + str(ingress_port) +
                             " to egress " + str(egress_port))
            
            #controller send flow mod to switch
            request = testutils.flow_msg_create(self,pkt, ing_port=ingress_port, 
                                                egr_port=egress_port, table_id=table_id)
            testutils.flow_msg_install(self, request)
            
            #user send pkt to switch
            pa_logger.info("Sending packet to dp port " + str(ingress_port))
            self.dataplane.send(ingress_port, str(pkt))
            testutils.receive_pkt_verify(self, egress_port, pkt)


class DirectPacketICMP(DirectPacket):
    """
    Send ICMP packet to single egress port

    Generate a ICMP packet
    Generate and install a matching flow
    Add action to direct the packet to an egress port
    Send the packet to ingress dataplane port
    Verify the packet is received at the egress port only
    Difference from DirectPacket test is that sent packet is ICMP
    """
    def runTest(self):
        self.handleFlow(pkttype='ICMP')

class DirectTwoPorts(basic.SimpleDataPlane):
    """
    Send packet to two egress ports

    Generate a packet
    Generate and install a matching flow
    Add action to direct the packet to two egress ports
    Send the packet to ingress dataplane port
    Verify the packet is received at the two egress ports
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")

        pkt = testutils.simple_tcp_packet()
        match_fields = testutils.packet_to_exact_flow_match(pkt)
        self.assertTrue(match_fields is not None,
                        "Could not generate flow match from pkt")
        act1 = action.action_output()
        act2 = action.action_output()

        for idx in range(len(of_ports)):
            rv = testutils.delete_all_flows(self.controller, pa_logger)
            self.assertEqual(rv, 0, "Failed to delete all flows")

            ingress_port = of_ports[idx]
            egress_port1 = of_ports[(idx + 1) % len(of_ports)]
            egress_port2 = of_ports[(idx + 2) % len(of_ports)]
            pa_logger.info("Ingress " + str(ingress_port) +
                           " to egress " + str(egress_port1) + " and " +
                           str(egress_port2))

            act1.port = egress_port1
            act2.port = egress_port2
            request = testutils.flow_msg_create(self, pkt, ing_port=ingress_port,
                            action_list=[act1, act2], inst_app_flag=testutils.APPLY_ACTIONS_INSTRUCTION)

            pa_logger.info("Inserting flow")
            testutils.ofmsg_send(self, request)

            pa_logger.info("Sending packet to dp port " +
                           str(ingress_port))
            self.dataplane.send(ingress_port, str(pkt))
            yes_ports = set([egress_port1, egress_port2])
            no_ports = set(of_ports).difference(yes_ports)

            testutils.receive_pkt_check(self.dataplane, pkt, yes_ports, no_ports,
                              self, pa_logger)

class DirectMCNonIngress(basic.SimpleDataPlane):
    """
    Multicast to all non-ingress ports

    Generate a packet
    Generate and install a matching flow
    Add action to direct the packet to all non-ingress ports
    Send the packet to ingress dataplane port
    Verify the packet is received at all non-ingress ports

    Does not use the flood action
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")

        pkt = testutils.simple_tcp_packet()

        for ingress_port in of_ports:
            rv = testutils.delete_all_flows(self.controller, pa_logger)
            self.assertEqual(rv, 0, "Failed to delete all flows")

            pa_logger.info("Ingress " + str(ingress_port) +
                           " all non-ingress ports")
            actions = []
            for egress_port in of_ports:
                act = action.action_output()
                if egress_port == ingress_port:
                    continue
                act.port = egress_port
                actions.append(act)
            request = testutils.flow_msg_create(self, pkt, ing_port=ingress_port,
                                action_list=actions, inst_app_flag=testutils.APPLY_ACTIONS_INSTRUCTION)

            pa_logger.info("Inserting flow")
            testutils.ofmsg_send(self, request)

            pa_logger.info("Sending packet to dp port " + str(ingress_port))
            self.dataplane.send(ingress_port, str(pkt))
            yes_ports = set(of_ports).difference([ingress_port])
            testutils.receive_pkt_check(self.dataplane, pkt, yes_ports, [ingress_port],
                              self, pa_logger)

class DirectMC(basic.SimpleDataPlane):
    """
    Multicast to all ports including ingress

    Generate a packet
    Generate and install a matching flow
    Add action to direct the packet to all non-ingress ports
    Send the packet to ingress dataplane port
    Verify the packet is received at all ports

    Does not use the flood action
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")

        pkt = testutils.simple_tcp_packet()

        for ingress_port in of_ports:
            rv = testutils.delete_all_flows(self.controller, pa_logger)
            self.assertEqual(rv, 0, "Failed to delete all flows")

            pa_logger.info("Ingress " + str(ingress_port) + " to all ports")
            actions = []
            for egress_port in of_ports:
                act = action.action_output()
                if egress_port == ingress_port:
                    act.port = ofp.OFPP_IN_PORT
                else:
                    act.port = egress_port
                actions.append(act)
            request = testutils.flow_msg_create(self, pkt, ing_port=ingress_port,
                                action_list=actions, inst_app_flag=testutils.APPLY_ACTIONS_INSTRUCTION)

            pa_logger.info("Inserting flow")
            testutils.ofmsg_send(self, request)

            pa_logger.info("Sending packet to dp port " + str(ingress_port))
            self.dataplane.send(ingress_port, str(pkt))
            testutils.receive_pkt_check(self.dataplane, pkt, of_ports, [], self,
                              pa_logger)

class All(basic.SimpleDataPlane):
    """
    Send to OFPP_ALL port

    Generate a packet
    Generate and install a matching flow
    Add action to forward to OFPP_ALL
    Send the packet to ingress dataplane port
    Verify the packet is received at all other ports
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")

        pkt = testutils.simple_tcp_packet()

        for ingress_port in of_ports:
            rv = testutils.delete_all_flows(self.controller, pa_logger)
            self.assertEqual(rv, 0, "Failed to delete all flows")

            pa_logger.info("Ingress " + str(ingress_port) + " to all ports")

            request = testutils.flow_msg_create(self, pkt, ing_port=ingress_port,
                                                egr_port=ofp.OFPP_ALL)

            pa_logger.info("Inserting flow")
            testutils.ofmsg_send(self, request)

            pa_logger.info("Sending packet to dp port " + str(ingress_port))
            self.dataplane.send(ingress_port, str(pkt))
            yes_ports = set(of_ports).difference([ingress_port])
            testutils.receive_pkt_check(self.dataplane, pkt, yes_ports, [ingress_port],
                              self, pa_logger)

class IngressOutput(basic.SimpleDataPlane):
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")

        pkt = testutils.simple_tcp_packet()

        act_ing = action.action_output()
        act_ing.port = ofp.OFPP_IN_PORT

        actions = [act_ing]

        for ingress_port in of_ports:
            rv = testutils.delete_all_flows(self.controller, pa_logger)
            self.assertEqual(rv, 0, "Failed to delete all flows")

            pa_logger.info("Ingress " + str(ingress_port) + " to all ports")

            flow_mod = testutils.flow_msg_create(self, pkt,
                                                 ing_port=ingress_port,
                                                 action_list=actions
                                                 )
            pa_logger.info(flow_mod.show())

            pa_logger.info("Inserting flow")
            testutils.ofmsg_send(self, flow_mod)

            pa_logger.info("Sending packet to dp port " + str(ingress_port))
            self.dataplane.send(ingress_port, str(pkt))
            no_ports = set(of_ports).difference([ingress_port])
            testutils.receive_pkt_check(self.dataplane, pkt, [ingress_port], no_ports,
                              self, pa_logger)

class AllPlusIngress(basic.SimpleDataPlane):
    """
    Send to OFPP_ALL port and ingress port

    Generate a packet
    Generate and install a matching flow
    Add action to forward to OFPP_ALL
    Add action to forward to ingress port
    Send the packet to ingress dataplane port
    Verify the packet is received at all other ports
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 1, "Not enough ports for test")

        pkt = testutils.simple_tcp_packet()

        act_all = action.action_output()
        act_all.port = ofp.OFPP_ALL
        act_ing = action.action_output()
        act_ing.port = ofp.OFPP_IN_PORT
        actions = [ act_all, act_ing]

        for ingress_port in of_ports:
            rv = testutils.delete_all_flows(self.controller, pa_logger)
            self.assertEqual(rv, 0, "Failed to delete all flows")

            pa_logger.info("Ingress " + str(ingress_port) + " to all ports")

            flow_mod = testutils.flow_msg_create(self, pkt,
                                                 ing_port=ingress_port,
                                                 action_list=actions,
                                                 inst_app_flag=testutils.APPLY_ACTIONS_INSTRUCTION
                                                 )
            pa_logger.info(flow_mod.show())

            pa_logger.info("Inserting flow")
            testutils.ofmsg_send(self, flow_mod)

            pa_logger.info("Sending packet to dp port " + str(ingress_port))
            self.dataplane.send(ingress_port, str(pkt))
            testutils.receive_pkt_check(self.dataplane, pkt, of_ports, [], self,
                              pa_logger)


################################################################

class BaseMatchCase(basic.SimpleDataPlane):
    def setUp(self):
        basic.SimpleDataPlane.setUp(self)
        self.logger = pa_logger
    def runTest(self):
        self.logger.info("BaseMatchCase")

class ExactMatch(BaseMatchCase):
    """
    Exercise exact matching for all port pairs

    Generate a packet
    Generate and install a matching flow without wildcard mask
    Add action to forward to a port
    Send the packet to the port
    Verify the packet is received at all other ports (one port at a time)
    """
    def runTest(self):
        testutils.flow_match_test(self, pa_port_map, max_test=2)


class ExactMatchTagged(BaseMatchCase):
    """
    Exact match for all port pairs with tagged pkts
    """
    def runTest(self):
        vid = testutils.test_param_get(self.config, 'vid', default=TEST_VID_DEFAULT)
        testutils.flow_match_test(self, pa_port_map, dl_vlan=vid, max_test=2)

class ExactMatchTaggedMany(BaseMatchCase):
    """
    ExactMatchTagged with many VLANS
    """
    def runTest(self):
        for vid in range(2,100,20):
            testutils.flow_match_test(self, pa_port_map, dl_vlan=vid, max_test=5)
        for vid in range(100,4000,500):
            testutils.flow_match_test(self, pa_port_map, dl_vlan=vid, max_test=5)
        testutils.flow_match_test(self, pa_port_map, dl_vlan=4094, max_test=5)

class SingleWildcardMatch(BaseMatchCase):
    """
    Exercise wildcard matching for all ports
    Generate a packet
    Generate and install a matching flow with wildcard mask
    Add action to forward to a port
    Send the packet to the port
    Verify the packet is received at all other ports (one port at a time)
    Verify flow_expiration message is correct when command option is set
    """
    def runTest(self):
        for wc in WILDCARD_VALUES:
            testutils.flow_match_test(self, pa_port_map, wildcards=wc, max_test=10)

class SingleWildcardMatchTagged(BaseMatchCase):
    """
    SingleWildcardMatch with tagged packets
    """
    def runTest(self):
        vid = testutils.test_param_get(self.config, 'vid', default=TEST_VID_DEFAULT)
        for wc in WILDCARD_VALUES:
            testutils.flow_match_test(self, pa_port_map, wildcards=wc, dl_vlan=vid,
                            max_test=10)

class AllExceptOneWildcardMatch(BaseMatchCase):
    """
    Match exactly one field
    Generate a packet
    Generate and install a matching flow with wildcard all except one filed
    Add action to forward to a port
    Send the packet to the port
    Verify the packet is received at all other ports (one port at a time)
    Verify flow_expiration message is correct when command option is set
    """
    def runTest(self):
        for wc in WILDCARD_VALUES:
            all_exp_one_wildcard = OFPFW_ALL ^ wc
            #print("%x"%(all_exp_one_wildcard))
            testutils.flow_match_test(self, pa_port_map, wildcards=all_exp_one_wildcard)

class AllExceptOneWildcardMatchTagged(BaseMatchCase):
    """
    Match one field with tagged packets
    """
    def runTest(self):
        vid = testutils.test_param_get(self.config, 'vid', default=TEST_VID_DEFAULT)
        for wc in WILDCARD_VALUES:
            all_exp_one_wildcard = OFPFW_ALL ^ wc
            testutils.flow_match_test(self, pa_port_map, wildcards=all_exp_one_wildcard,
                            dl_vlan=vid)

class AllWildcardMatch(BaseMatchCase):
    """
    Create Wildcard-all flow and exercise for all ports

    Generate a packet
    Generate and install a matching flow with wildcard-all
    Add action to forward to a port
    Send the packet to the port
    Verify the packet is received at all other ports (one port at a time)
    Verify flow_expiration message is correct when command option is set
    """
    def runTest(self):
        testutils.flow_match_test(self, pa_port_map, wildcards=OFPFW_ALL)

class AllWildcardMatchTagged(BaseMatchCase):
    """
    AllWildcardMatch with tagged packets
    """
    def runTest(self):
        vid = testutils.test_param_get(self.config, 'vid', default=TEST_VID_DEFAULT)
        testutils.flow_match_test(self, pa_port_map, wildcards=OFPFW_ALL,
                        dl_vlan=vid)

class AddVLANTag(BaseMatchCase):
    """
    Add a VLAN tag to an untagged packet
    """
    def runTest(self):
        new_vid = 4002
        # sup_acts = supported_actions_get(self)
        # if not(sup_acts & 1<<ofp.OFPXMT_OFB_VLAN_VID):
            # testutils.skip_message_emit(self, "Add VLAN tag test")
            # return
        pkt = testutils.simple_tcp_packet()
        exp_pkt = testutils.simple_tcp_packet(
                                    vlan_tags=[{'vid': new_vid}])
        push_act = action.action_push_vlan()
        push_act.ethertype = 0x8100
        vid_act = action.action_set_field()
        vid_act.field=match.vlan_vid(new_vid + ofp.OFPVID_PRESENT)
        #vid_act = action.action_set_vlan_vid()
        #vid_act.vlan_vid = new_vid
        testutils.flow_match_test(self, pa_port_map, pkt=pkt,
                        exp_pkt=exp_pkt, apply_action_list=[push_act, vid_act])

class PacketOnly(basic.DataPlaneOnly):
    """
    Just send a packet thru the switch
    """
    def runTest(self):
        pkt = testutils.simple_tcp_packet()
        of_ports = pa_port_map.keys()
        of_ports.sort()
        ing_port = of_ports[0]
        pa_logger.info("Sending packet to " + str(ing_port))
        pa_logger.debug("Data: " + str(pkt).encode('hex'))
        self.dataplane.send(ing_port, str(pkt))

class PacketOnlyTagged(basic.DataPlaneOnly):
    """
    Just send a packet thru the switch
    """
    def runTest(self):
        vid = testutils.test_param_get(self.config, 'vid', default=TEST_VID_DEFAULT)
        pkt = testutils.simple_tcp_packet(vlan_tags=[{'vid': vid}])
        of_ports = pa_port_map.keys()
        of_ports.sort()
        ing_port = of_ports[0]
        pa_logger.info("Sending packet to " + str(ing_port))
        pa_logger.debug("Data: " + str(pkt).encode('hex'))
        self.dataplane.send(ing_port, str(pkt))

class ModifyVID(BaseMatchCase):
    """
    Modify the VLAN ID in the VLAN tag of a tagged packet
    """
    def runTest(self):
        old_vid = 2
        new_vid = 3
        # sup_acts = supported_actions_get(self)
        # if not (sup_acts & 1 << ofp.OFPXMT_OFB_VLAN_VID):
            # testutils.skip_message_emit(self, "Modify VLAN tag test")
            # return
        pkt = testutils.simple_tcp_packet(vlan_tags=[{'vid': old_vid}])
        exp_pkt = testutils.simple_tcp_packet(vlan_tags=[{'vid': new_vid}])
        vid_act = action.action_set_field()
        vid_act.field = match.vlan_vid(new_vid + ofp.OFPVID_PRESENT)

        testutils.flow_match_test(self, pa_port_map, pkt=pkt, exp_pkt=exp_pkt,
                        apply_action_list=[vid_act])

class StripVLANTag(BaseMatchCase):
    """
    Strip the VLAN tag from a tagged packet
    """
    def runTest(self):
        old_vid = 2
        #sup_acts = supported_actions_get(self)
        #if not (sup_acts & 1 << ofp.OFPAT_POP_VLAN):
            #testutils.skip_message_emit(self, "Strip VLAN tag test")
            #return
        pkt = testutils.simple_tcp_packet(vlan_tags=[{'vid': old_vid}])
        exp_pkt = testutils.simple_tcp_packet()
        vid_act = action.action_pop_vlan()

        testutils.flow_match_test(self, pa_port_map,pkt=pkt, exp_pkt=exp_pkt,
                        apply_action_list=[vid_act] , max_test = 10)

def init_pkt_args():
    #Pass back a dictionary with default packet arguments
    args = {}
    args["dl_src"] = '00:23:45:67:89:AB'

    dl_vlan_enable=False
    dl_vlan=-1
    if pa_config["test-params"]["vid"]:
        dl_vlan_enable=True
        dl_vlan = pa_config["test-params"]["vid"]
# Unpack operator is ** on a dictionary
    return args

class ModifyL2Src(BaseMatchCase):
    """
    Modify the source MAC address (TP1)
    """
    def runTest(self):
        # sup_acts = supported_actions_get(self)
        # if not (sup_acts & 1 << ofp.OFPXMT_OFB_ETH_SRC):
            # testutils.skip_message_emit(self, "ModifyL2Src test")
            # return
        (pkt, exp_pkt, acts) = testutils.pkt_action_setup(self, mod_fields=['dl_src'],
                                                check_test_params=True)
        testutils.flow_match_test(self, pa_port_map, pkt=pkt, exp_pkt=exp_pkt,
                        apply_action_list=acts, max_test=2)

class ModifyL2Dst(BaseMatchCase):
    """
    Modify the dest MAC address (TP1)
    """
    def runTest(self):
        # sup_acts = supported_actions_get(self)
        # if not (sup_acts & 1 << ofp.OFPXMT_OFB_ETH_DST):
            # testutils.skip_message_emit(self, "ModifyL2dst test")
            # return
        (pkt, exp_pkt, acts) = testutils.pkt_action_setup(self, mod_fields=['dl_dst'],
                                                check_test_params=True)
        testutils.flow_match_test(self, pa_port_map, pkt=pkt, exp_pkt=exp_pkt,
                        apply_action_list=acts, max_test=2)

class ModifyL3Src(BaseMatchCase):
    """
    Modify the source IP address of an IP packet (TP1)
    """
    def runTest(self):
        # sup_acts = supported_actions_get(self)
        # if not (sup_acts & 1 << ofp.OFPXMT_OFB_IPV4_SRC):
            # testutils.skip_message_emit(self, "ModifyL3Src test")
            # return
        (pkt, exp_pkt, acts) = testutils.pkt_action_setup(self, mod_fields=['ip_src'],
                                                check_test_params=True)
        testutils.flow_match_test(self, pa_port_map, pkt=pkt, exp_pkt=exp_pkt,
                        apply_action_list=acts, max_test=2)

class ModifyL3Dst(BaseMatchCase):
    """
    Modify the dest IP address of an IP packet (TP1)
    """
    def runTest(self):
        # sup_acts = supported_actions_get(self)
        # if not (sup_acts & 1 << ofp.OFPXMT_OFB_IPV4_DST):
            # testutils.skip_message_emit(self, "ModifyL3Dst test")
            # return
        (pkt, exp_pkt, acts) = testutils.pkt_action_setup(self, mod_fields=['ip_dst'],
                                                check_test_params=True)
        testutils.flow_match_test(self, pa_port_map, pkt=pkt, exp_pkt=exp_pkt,
                        apply_action_list=acts, max_test=2)

class ModifyL4Src(BaseMatchCase):
    """
    Modify the source TCP port of a TCP packet (TP1)
    """
    def runTest(self):
        # sup_acts = supported_actions_get(self)
        # if not (sup_acts & 1 << ofp.OFPXMT_OFB_TCP_SRC):
            # testutils.skip_message_emit(self, "ModifyL4Src test")
            # return
        (pkt, exp_pkt, acts) = testutils.pkt_action_setup(self, mod_fields=['tcp_sport'],
                                                check_test_params=True)
        testutils.flow_match_test(self, pa_port_map, pkt=pkt, exp_pkt=exp_pkt,
                        apply_action_list=acts, max_test=2)

class ModifyL4Dst(BaseMatchCase):
    """
    Modify the dest TCP port of a TCP packet (TP1)
    """
    def runTest(self):
        # sup_acts = supported_actions_get(self)
        # if not (sup_acts & 1 << ofp.OFPXMT_OFB_TCP_DST):
            # testutils.skip_message_emit(self, "ModifyL4Dst test")
            # return
        (pkt, exp_pkt, acts) = testutils.pkt_action_setup(self, mod_fields=['tcp_dport'],
                                                check_test_params=True)
        testutils.flow_match_test(self, pa_port_map, pkt=pkt, exp_pkt=exp_pkt,
                        apply_action_list=acts, max_test=2)

class ModifyDSCP(BaseMatchCase):
    """
    Modify the IP differentiated services code point of an IP packet (TP1)
    """
    def runTest(self):
        # sup_acts = supported_actions_get(self)
        # print(str(sup_acts).encode('hex'))
        # if not (sup_acts & 1 << ofp.OFPXMT_OFB_IP_DSCP):
            # testutils.skip_message_emit(self, "ModifyTOS test")
            # return
        (pkt, exp_pkt, acts) = testutils.pkt_action_setup(self, mod_fields=['ip_dscp'],
                                                check_test_params=True)
        testutils.flow_match_test(self, pa_port_map, pkt=pkt, exp_pkt=exp_pkt,
                        apply_action_list=acts, max_test=2)

class ModifyECN(BaseMatchCase):
    """
    Modify the IP explicit congestion notification of an IP packet (TP1)
    """
    def runTest(self):
        (pkt, exp_pkt, acts) = testutils.pkt_action_setup(self, mod_fields=['ip_ecn'],
                                                check_test_params=True)
        testutils.flow_match_test(self, pa_port_map, pkt=pkt, exp_pkt=exp_pkt,
                        apply_action_list=acts, max_test=2)

#@todo Need to implement tagged versions of the above tests
#
#@todo Implement a test case that strips tag 2, adds tag 3
# and modifies tag 4 to tag 5.  Then verify (in addition) that
# tag 6 does not get modified.

class MixedVLAN(BaseMatchCase):
    """
    Test mixture of VLAN tag actions

    Strip tag 2 on port 1, send to port 2
    Add tag 3 on port 1, send to port 2
    Modify tag 4 to 5 on port 1, send to port 2
    All other traffic from port 1, send to port 3
    All traffic from port 2 sent to port 4
    Use exact matches with different packets for all mods
    Verify the following:  (port, vid)
        (port 1, vid 2) => VLAN tag stripped, out port 2
        (port 1, no tag) => tagged packet w/ vid 2 out port 2
        (port 1, vid 4) => tagged packet w/ vid 5 out port 2
        (port 1, vid 5) => tagged packet w/ vid 5 out port 2
        (port 1, vid 6) => tagged packet w/ vid 6 out port 2
        (port 2, no tag) => untagged packet out port 4
        (port 2, vid 2-6) => unmodified packet out port 4

    Variation:  Might try sending VID 5 to port 3 and check.
    If only VID 5 distinguishes pkt, this will fail on some platforms
    """
    def runTest(self):
        testutils.skip_message_emit(self, 'skip!')
        return


def supported_actions_get(parent, use_cache=True):
    """
    Get the bitmap of supported actions from the switch
    If use_cache is false, the cached value will be updated
    """
    global cached_supported_actions
    if cached_supported_actions is None or not use_cache:
        request = message.table_stats_request()
        (reply, _) = parent.controller.transact(request, timeout=2)
        parent.assertTrue(reply is not None, "Did not get response to tbl stats req")
#        cached_supported_actions = reply.stats[0].apply_actions
        cached_supported_actions = reply.stats[0].write_actions
        pa_logger.info("Supported actions: " + hex(cached_supported_actions))

    return cached_supported_actions

if __name__ == "__main__":
    print "Please run through oft script:  ./oft --test-spec=pktact"
