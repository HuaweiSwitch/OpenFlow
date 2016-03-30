"""
Test cases for mpls match with using multiple tables

It is recommended that these definitions be kept in their own
namespace as different groups of tests will likely define
similar identifiers.

  The function test_set_init is called with a complete configuration
dictionary prior to the invocation of any tests from this file.

  The switch is actively attempting to contact the controller at the address
indicated oin oft_config

"""

import logging
import random

import oftest.cstruct as ofp
import oftest.message as message
import oftest.action as action
import oftest.parse as parse
import oftest.instruction as instruction
import oftest.match as match
import basic
import pktact
#import mplsact

import testutils

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

ETHERTYPE_VLAN = 0x8100
ETHERTYPE_MPLS = 0x8847
ETYERTYPE_MPLS_MC = 0x8848
ETHERTYPE_IP = 0x0800

MAX_TABLE = 4

# Cache supported features to avoid transaction overhead
cached_supported_actions = None

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

###########################################################################

class MultiTableWriteActNontag1(pktact.BaseMatchCase):
    """
    Check exec order is correct among the action set against normal pkt
    Sent pkt: normal pkt w/o VLAN, MPLS
    Actions:
        Table0: Outport
        Table1: Modify a field
    Expectation: Rcv modified pkt
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")
        # For making the test simpler...
        ing_port = of_ports[0]
        egr_port = of_ports[1]

        #Modify L2 SRC
        (pkt, exp_pkt, mod_act_array) = \
             testutils.pkt_action_setup(self, mod_fields=['dl_src'],
                                        check_test_params=True)
        match_fields = parse.packet_to_flow_match(pkt)

        wildcards = 0

        # Create parameters for each table
        act_list = []
        next_avail = []
        chk_expire = []

        #Table 0
        act = action.action_output()
        act.port = egr_port
        act_list.append([act])
        #act = action.action_set_field()
        #act.field = match.eth_src(parse.parse_mac(mod_field_vals['dl_src']))
        next_avail.append(True)
        chk_expire.append(False)

        #Table 1
        #print(mod_act_array)
        act_list.append(mod_act_array)
        next_avail.append(False)
        chk_expire.append(False)

        write_action_test_multi_tables(self, ing_port, egr_port,
            match_fields = match_fields,
            wildcards = wildcards,
            act_list = act_list,
            next_avail = next_avail,
            chk_expire = chk_expire,
            pkt = pkt,
            exp_pkt = exp_pkt)

class MultiTableWriteActNontag2(pktact.BaseMatchCase):
    """
    Check exec order is correct among the action set against normal pkt
    Sent pkt: normal pkt w/o VLAN, MPLS
    Actions:
        Table0: Outport
        Table1: Modify VLAN ID
        Table2: Push VLAN
    Expectation: Rcv modified pkt w/ VLAN
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")
        # For making the test simpler...
        ing_port = of_ports[0]
        egr_port = of_ports[1]

        pkt = testutils.simple_tcp_packet()
        match_ls = parse.packet_to_flow_match(pkt)
        wildcards = 0

        dl_vlan = random.randint(1,0xfff)
        exp_pkt = testutils.simple_tcp_packet(vlan_tags=[{'vid': dl_vlan}])

        # Create parameters for each table
        act_list = []
        next_avail = []
        chk_expire = []

        #Table 0
        act = action.action_output()
        act.port = egr_port
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 1
        act = action.action_set_field()
        act.field = match.vlan_vid(dl_vlan + ofp.OFPVID_PRESENT)
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 2
        act = action.action_push_vlan()
        act.ethertype = ETHERTYPE_VLAN
        act_list.append([act])
        next_avail.append(False)
        chk_expire.append(False)

        write_action_test_multi_tables(self, ing_port, egr_port,
            match_fields = match_ls,
            wildcards = wildcards,
            act_list = act_list,
            next_avail = next_avail,
            chk_expire = chk_expire,
            pkt = pkt,
            exp_pkt = exp_pkt)

class MultiTableWriteActVlan1(pktact.BaseMatchCase):
    """
    Check exec order is correct among the action set against VLAN pkt
    Sent pkt: pkt w/ VLAN
    Actions:
        Table0: Outport
        Table1: Pop VLAN
    Expectation: Rcv pkt w/o VLAN
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")
        # For making the test simpler...
        ing_port = of_ports[0]
        egr_port = of_ports[1]

        dl_vlan = random.randint(1,0xfff)
        dl_vlan_pcp = random.randint(0,7)
        pkt = testutils.simple_tcp_packet(vlan_tags=[{'vid': dl_vlan, 'pcp': dl_vlan_pcp}])

        match_ls = parse.packet_to_flow_match(pkt)
        wildcards = 0

        exp_pkt = testutils.simple_tcp_packet()

        # Create parameters for each table
        act_list = []
        next_avail = []
        chk_expire = []

        #Table 0
        act = action.action_output()
        act.port = egr_port
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 1
        act = action.action_pop_vlan()
        act_list.append([act])
        next_avail.append(False)
        chk_expire.append(False)

        write_action_test_multi_tables(self, ing_port, egr_port,
            match_fields = match_ls,
            wildcards = wildcards,
            act_list = act_list,
            next_avail = next_avail,
            chk_expire = chk_expire,
            pkt = pkt,
            exp_pkt = exp_pkt)

class MultiTableWriteActVlan2(pktact.BaseMatchCase):
    """
    Check exec order is correct among the action set against VLAN pkt
    Sent pkt: pkt w/ VLAN
    Actions:
        Table0: Outport
        Table1: Push VLAN
        Table2: Pop VLAN
    Expectation: Rcv pkt w/ VLAN, VID, PCP must be 0
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")
        # For making the test simpler...
        ing_port = of_ports[0]
        egr_port = of_ports[1]

        dl_vlan = random.randint(2,0xfff)
        dl_vlan_pcp = random.randint(1,7)
        pkt = testutils.simple_tcp_packet(vlan_tags=[{'vid': dl_vlan, 'pcp': dl_vlan_pcp}])

        match_ls = parse.packet_to_flow_match(pkt)
        wildcards = 0

        #exp_pkt = testutils.simple_tcp_packet(vlan_tags=[{}])
        new_dl_vlan = 1
        exp_pkt = testutils.simple_tcp_packet(vlan_tags=[{'vid': new_dl_vlan, 'pcp': 0}])

        # Create parameters for each table
        act_list = []
        next_avail = []
        chk_expire = []

        #Table 0
        act = action.action_output()
        act.port = egr_port
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 1
        act = action.action_set_field()
        act.field = match.vlan_vid(new_dl_vlan + ofp.OFPVID_PRESENT)
        #act3 = action.action_set_field()
        #act3.field = match.vlan_pcp(dl_vlan_pcp)
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 2
        act = action.action_push_vlan()
        act.ethertype = ETHERTYPE_VLAN
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 3
        act = action.action_pop_vlan()
        act_list.append([act])
        next_avail.append(False)
        chk_expire.append(False)

        """
        in action set:
        pop fist , push next, setfield finally;
        """

        write_action_test_multi_tables(self, ing_port, egr_port,
            match_fields = match_ls,
            wildcards = wildcards,
            act_list = act_list,
            next_avail = next_avail,
            chk_expire = chk_expire,
            pkt = pkt,
            exp_pkt = exp_pkt)

class MultiTableWriteActVlan3(pktact.BaseMatchCase):
    """
    Check exec order is correct among the action set against VLAN pkt
    Sent pkt: pkt w/ VLAN
    Actions:
        Table0: Outport
        Table1: Set VLAN ID
        Table2: Push VLAN
    Expectation: Rcv pkt w/ VLAN, with modified VID
    """

    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")
        # For making the test simpler...
        ing_port = of_ports[0]
        egr_port = of_ports[1]

        dl_vlan = random.randint(1,0x7ff)
        dl_vlan_pcp = random.randint(0,7)
        pkt = testutils.simple_tcp_packet(vlan_tags=[{'vid': dl_vlan, 'pcp': dl_vlan_pcp}])

        match_ls = parse.packet_to_flow_match(pkt)
        wildcards = 0

        new_dl_vlan = random.randint(0x800,0xfff)
        exp_pkt = testutils.simple_tcp_packet(vlan_tags=[{'type': ETHERTYPE_VLAN, 'vid': new_dl_vlan, 'pcp': dl_vlan_pcp},
                                                         {'vid': dl_vlan, 'pcp': dl_vlan_pcp}])

        # Create parameters for each table
        act_list = []
        next_avail = []
        chk_expire = []

        #Table 0
        act = action.action_output()
        act.port = egr_port
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 1
        #act = action.action_set_vlan_vid()
        #act.vlan_vid = new_dl_vlan
        act = action.action_set_field()
        act.field = match.vlan_vid(new_dl_vlan + ofp.OFPVID_PRESENT)
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 2
        act = action.action_push_vlan()
        act.ethertype = ETHERTYPE_VLAN
        act_list.append([act])
        next_avail.append(False)
        chk_expire.append(False)

        write_action_test_multi_tables(self, ing_port, egr_port,
            match_fields = match_ls,
            wildcards = wildcards,
            act_list = act_list,
            next_avail = next_avail,
            chk_expire = chk_expire,
            pkt = pkt,
            exp_pkt = exp_pkt)

class MultiTableWriteAct2Vlan1(pktact.BaseMatchCase):
    """
    Check exec order is correct among the action set against pkt w/ 2VLANs
    Sent pkt: pkt w/ 2VLANs
    Actions:
        Table0: Outport
        Table1: Set VLAN ID
        Table2: Pop VLAN
    Expectation: Rcv pkt w/ 1VLAN, with modified VID
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")
        # For making the test simpler...
        ing_port = of_ports[0]
        egr_port = of_ports[1]

        dl_vlan = random.randint(1,0x3ff)
        dl_vlan_pcp = random.randint(0,7)
        outer_dl_vlan = random.randint(0x400,0x7ff)
        pkt = testutils.simple_tcp_packet(vlan_tags=[{'type' : ETHERTYPE_VLAN, 'vid': outer_dl_vlan},
                                                     {'vid': dl_vlan, 'pcp': dl_vlan_pcp}])
        match_ls = parse.packet_to_flow_match(pkt)
        wildcards = 0

        new_dl_vlan = random.randint(0x800,0xfff)
        exp_pkt = testutils.simple_tcp_packet(vlan_tags=[{'vid': new_dl_vlan, 'pcp': dl_vlan_pcp}])

        # Create parameters for each table
        act_list = []
        next_avail = []
        chk_expire = []

        #Table 0
        act = action.action_output()
        act.port = egr_port
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 1
        #act = action.action_set_vlan_vid()
        #act.vlan_vid = new_dl_vlan
        act = action.action_set_field()
        act.field = match.vlan_vid(new_dl_vlan + ofp.OFPVID_PRESENT)
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 2
        act = action.action_pop_vlan()
        act_list.append([act])
        next_avail.append(False)
        chk_expire.append(False)

        write_action_test_multi_tables(self, ing_port, egr_port,
            match_fields = match_ls,
            wildcards = wildcards,
            act_list = act_list,
            next_avail = next_avail,
            chk_expire = chk_expire,
            pkt = pkt,
            exp_pkt = exp_pkt)

class MultiTableWriteActMpls1(pktact.BaseMatchCase):
    """
    Check exec order is correct among the action set against MPLS pkt
    Sent pkt: pkt w/ MPLS
    Actions:
        Table0: Outport
        Table1: Pop MPLS
    Expectation: Rcv pkt w/o MPLS
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")
        # For making the test simpler...
        ing_port = of_ports[0]
        egr_port = of_ports[1]

        mpls_label = 0xa5f05 # no specific meaning
        mpls_tc = 5
        mpls_ttl = 129
        pkt = testutils.simple_tcp_packet_w_mpls(mpls_label=mpls_label,
                                                 mpls_tc=mpls_tc,
                                                 mpls_ttl=mpls_ttl)

        match_ls = parse.packet_to_flow_match(pkt)
        wildcards = 0

        exp_pkt = testutils.simple_tcp_packet_w_mpls()

        # Create parameters for each table
        act_list = []
        next_avail = []
        chk_expire = []

        #Table 0
        act = action.action_output()
        act.port = egr_port
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 1
        act = action.action_pop_mpls()
        act.ethertype = ETHERTYPE_IP
        act_list.append([act])
        next_avail.append(False)
        chk_expire.append(False)

        write_action_test_multi_tables(self, ing_port, egr_port,
            match_fields = match_ls,
            wildcards = wildcards,
            act_list = act_list,
            next_avail = next_avail,
            chk_expire = chk_expire,
            pkt = pkt,
            exp_pkt = exp_pkt)

class MultiTableWriteActMpls2(pktact.BaseMatchCase):
    """
    Check exec order is correct among the action set against MPLS pkt
    Sent pkt: pkt w/ MPLS
    Actions:
        Table0: Outport
        Table1: Set Label
        Table2: Push MPLS
    Expectation: Rcv pkt w/ 2MPLS, Outer tag must have modified Label
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")
        # For making the test simpler...
        ing_port = of_ports[0]
        egr_port = of_ports[1]

        mpls_label = 0xa5f05 # no specific meaning
        mpls_tc = 5
        mpls_ttl = 129
        pkt = testutils.simple_tcp_packet_w_mpls(mpls_label=mpls_label,
                                                 mpls_tc=mpls_tc,
                                                 mpls_ttl=mpls_ttl)

        match_ls = parse.packet_to_flow_match(pkt)
        wildcards = 0

        new_mpls_label = 0x5a0fa
        exp_pkt = testutils.simple_tcp_packet_w_mpls(
                                      mpls_label_ext=new_mpls_label,
                                      mpls_tc_ext=mpls_tc,
                                      mpls_ttl_ext=mpls_ttl,
                                      mpls_label=mpls_label,
                                      mpls_tc=mpls_tc,
                                      mpls_ttl=mpls_ttl)

        # Create parameters for each table
        act_list = []
        next_avail = []
        chk_expire = []

        #Table 0
        act = action.action_output()
        act.port = egr_port
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 1
        #act = action.action_set_mpls_label()
        #act.mpls_label = new_mpls_label
        act = action.action_set_field()
        act.field = match.mpls_label(new_mpls_label)

        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 2
        act = action.action_push_mpls()
        act.ethertype = ETHERTYPE_MPLS
        act_list.append([act])
        next_avail.append(False)
        chk_expire.append(False)

        write_action_test_multi_tables(self, ing_port, egr_port,
            match_fields = match_ls,
            wildcards = wildcards,
            act_list = act_list,
            next_avail = next_avail,
            chk_expire = chk_expire,
            pkt = pkt,
            exp_pkt = exp_pkt)

class MultiTableWriteActMpls3(pktact.BaseMatchCase):
    """
    Check exec order is correct among the action set against MPLS pkt
    Sent pkt: pkt w/ MPLS
    Actions:
        Table0: Outport
        Table1: Set TTL
        Table2: Decrement TTL
    Expectation: Rcv pkt w/ MPLS with modified TTL. Not decremented
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")
        # For making the test simpler...
        ing_port = of_ports[0]
        egr_port = of_ports[1]

        mpls_label = 0xa5f05 # no specific meaning
        mpls_tc = 5
        mpls_ttl = 129
        pkt = testutils.simple_tcp_packet_w_mpls(mpls_label=mpls_label,
                                                 mpls_tc=mpls_tc,
                                                 mpls_ttl=mpls_ttl)

        match_ls = parse.packet_to_flow_match(pkt)
        wildcards = 0

        new_mpls_ttl = mpls_ttl+1
        exp_pkt = testutils.simple_tcp_packet_w_mpls(mpls_label=mpls_label,
                                                     mpls_tc=mpls_tc,
                                                     mpls_ttl=new_mpls_ttl)

        # Create parameters for each table
        act_list = []
        next_avail = []
        chk_expire = []

        #Table 0
        act = action.action_output()
        act.port = egr_port
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 1
        act = action.action_set_mpls_ttl()
        act.mpls_ttl = new_mpls_ttl
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 2
        act = action.action_dec_mpls_ttl()
        act_list.append([act])
        next_avail.append(False)
        chk_expire.append(False)

        write_action_test_multi_tables(self, ing_port, egr_port,
            match_fields = match_ls,
            wildcards = wildcards,
            act_list = act_list,
            next_avail = next_avail,
            chk_expire = chk_expire,
            pkt = pkt,
            exp_pkt = exp_pkt)

class MultiTableWriteActMpls4(pktact.BaseMatchCase):
    """
    Check exec order is correct among the action set against MPLS pkt
    Sent pkt: pkt w/ MPLS
    Actions:
        Table0: Outport
        Table1: Pop MPLS
        Table2: Copy TTL inwards
    Expectation: Rcv pkt w/o MPLS. MPLS TTL must be copied to IP TTL
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")
        # For making the test simpler...
        ing_port = of_ports[0]
        egr_port = of_ports[1]

        mpls_label = 0xa5f05 # no specific meaning
        mpls_tc = 5
        mpls_ttl = 129
        pkt = testutils.simple_tcp_packet_w_mpls(mpls_label=mpls_label,
                                                 mpls_tc=mpls_tc,
                                                 mpls_ttl=mpls_ttl)

        match_ls = parse.packet_to_flow_match(pkt)
        wildcards = 0

        exp_pkt = testutils.simple_tcp_packet_w_mpls(ip_ttl=mpls_ttl)

        # Create parameters for each table
        act_list = []
        next_avail = []
        chk_expire = []

        #Table 0
        act = action.action_output()
        act.port = egr_port
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 1
        act = action.action_pop_mpls()
        act.ethertype = ETHERTYPE_IP
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 2
        act = action.action_copy_ttl_in()
        act_list.append([act])
        next_avail.append(False)
        chk_expire.append(False)

        write_action_test_multi_tables(self, ing_port, egr_port,
            match_fields = match_ls,
            wildcards = wildcards,
            act_list = act_list,
            next_avail = next_avail,
            chk_expire = chk_expire,
            pkt = pkt,
            exp_pkt = exp_pkt)

class MultiTableWriteActMpls5(pktact.BaseMatchCase):
    """
    Check exec order is correct among the action set against MPLS pkt
    Sent pkt: pkt w/ MPLS
    Actions:
        Table0: Outport
        Table1: Push MPLS
        Table2: Pop MPLS
        Table3: Copy TTL inwards
    Expectation: Rcv pkt w/ MPLS with Label value 0 and orig TTL
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")
        # For making the test simpler...
        ing_port = of_ports[0]
        egr_port = of_ports[1]

        mpls_label = 0xa5f05 # no specific meaning
        mpls_tc = 5
        mpls_ttl = 129
        pkt = testutils.simple_tcp_packet_w_mpls(mpls_label=mpls_label,
                                                 mpls_tc=mpls_tc,
                                                 mpls_ttl=mpls_ttl)

        match_ls = parse.packet_to_flow_match(pkt)
        wildcards = 0

        exp_pkt = testutils.simple_tcp_packet_w_mpls(mpls_label=0,
                                                     mpls_tc=0,
                                                     mpls_ttl=mpls_ttl,
                                                     ip_ttl=mpls_ttl)

        # Create parameters for each table
        act_list = []
        next_avail = []
        chk_expire = []

        #Table 0
        act = action.action_output()
        act.port = egr_port
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 1
        act = action.action_push_mpls()
        act.ethertype = ETHERTYPE_MPLS
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 2
        act = action.action_pop_mpls()
        act.ethertype = ETHERTYPE_IP
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table3
        act = action.action_copy_ttl_in()
        act_list.append([act])
        next_avail.append(False)
        chk_expire.append(False)

        write_action_test_multi_tables(self, ing_port, egr_port,
            match_fields = match_ls,
            wildcards = wildcards,
            act_list = act_list,
            next_avail = next_avail,
            chk_expire = chk_expire,
            pkt = pkt,
            exp_pkt = exp_pkt)

class MultiTableWriteActMpls6(pktact.BaseMatchCase):
    """
    Check exec order is correct among the action set against MPLS pkt
    Sent pkt: pkt w/ MPLS
    Actions:
        Table0: Outport
        Table1: Copy TTL Outwards
        Table2: Push MPLS
    Expectation: Rcv pkt w/ 2MPLS with same value as in orig MPLS
                 Orig MPLS must have orig TTL
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")
        # For making the test simpler...
        ing_port = of_ports[0]
        egr_port = of_ports[1]

        mpls_label = 0xa5f05 # no specific meaning
        mpls_tc = 5
        mpls_ttl = 129
        pkt = testutils.simple_tcp_packet_w_mpls(mpls_label=mpls_label,
                                                 mpls_tc=mpls_tc,
                                                 mpls_ttl=mpls_ttl)

        match_ls = parse.packet_to_flow_match(pkt)
        wildcards = 0

        exp_pkt = testutils.simple_tcp_packet_w_mpls(
                                      mpls_label_ext=mpls_label,
                                      mpls_tc_ext=mpls_tc,
                                      mpls_ttl_ext=mpls_ttl,
                                      mpls_label=mpls_label,
                                      mpls_tc=mpls_tc,
                                      mpls_ttl=mpls_ttl)

        # Create parameters for each table
        act_list = []
        next_avail = []
        chk_expire = []

        #Table 0
        act = action.action_output()
        act.port = egr_port
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 1
        act = action.action_copy_ttl_out()
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 2
        act = action.action_push_mpls()
        act.ethertype = ETHERTYPE_MPLS
        act_list.append([act])
        next_avail.append(False)
        chk_expire.append(False)

        write_action_test_multi_tables(self, ing_port, egr_port,
            match_fields = match_ls,
            wildcards = wildcards,
            act_list = act_list,
            next_avail = next_avail,
            chk_expire = chk_expire,
            pkt = pkt,
            exp_pkt = exp_pkt)

class MultiTableWriteActMpls7(pktact.BaseMatchCase):
    """
    Check exec order is correct among the action set against MPLS pkt
    Sent pkt: pkt w/ MPLS
    Actions:
        Table0: Outport
        Table1: Decrement TTL
        Table1: Copy TTL inwards
    Expectation: Rcv pkt w/ MPLS. MPLS TTL to be decremented
                 IP TTL has orig MPLS TTL value
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")
        # For making the test simpler...
        ing_port = of_ports[0]
        egr_port = of_ports[1]

        mpls_label = 0xa5f05 # no specific meaning
        mpls_tc = 5
        mpls_ttl = 129
        pkt = testutils.simple_tcp_packet_w_mpls(mpls_label=mpls_label,
                                                 mpls_tc=mpls_tc,
                                                 mpls_ttl=mpls_ttl)

        match_ls = parse.packet_to_flow_match(pkt)
        wildcards = 0

        exp_pkt = testutils.simple_tcp_packet_w_mpls(mpls_label=mpls_label,
                                                     mpls_tc=mpls_tc,
                                                     mpls_ttl=mpls_ttl-1,
                                                     ip_ttl=mpls_ttl)

        # Create parameters for each table
        act_list = []
        next_avail = []
        chk_expire = []

        #Table 0
        act = action.action_output()
        act.port = egr_port
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 1
        act = action.action_dec_mpls_ttl()
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 2
        act = action.action_copy_ttl_in()
        act_list.append([act])
        next_avail.append(False)
        chk_expire.append(False)

        write_action_test_multi_tables(self, ing_port, egr_port,
            match_fields = match_ls,
            wildcards = wildcards,
            act_list = act_list,
            next_avail = next_avail,
            chk_expire = chk_expire,
            pkt = pkt,
            exp_pkt = exp_pkt)

class MultiTableWriteActMpls8(pktact.BaseMatchCase):
    """
    Check exec order is correct among the action set against MPLS pkt
    Sent pkt: pkt w/ MPLS
    Actions:
        Table0: Outport
        Table1: Set MPLS TTL
        Table2: Decrement MPLS TTL
        Table3: Copy TTL inwards
    Expectation: Rcv pkt w/ MPLS. MPLS TTL must be set value
                 IP TTL has orig MPLS TTL value
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")
        # For making the test simpler...
        ing_port = of_ports[0]
        egr_port = of_ports[1]

        mpls_label = 0xa5f05 # no specific meaning
        mpls_tc = 5
        mpls_ttl = 129
        pkt = testutils.simple_tcp_packet_w_mpls(mpls_label=mpls_label,
                                                 mpls_tc=mpls_tc,
                                                 mpls_ttl=mpls_ttl)

        match_ls = parse.packet_to_flow_match(pkt)
        wildcards = 0

        new_mpls_ttl = mpls_ttl+1
        exp_pkt = testutils.simple_tcp_packet_w_mpls(mpls_label=mpls_label,
                                                     mpls_tc=mpls_tc,
                                                     mpls_ttl=new_mpls_ttl,
                                                     ip_ttl=mpls_ttl)

        # Create parameters for each table
        act_list = []
        next_avail = []
        chk_expire = []

        #Table 0
        act = action.action_output()
        act.port = egr_port
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 1
        act = action.action_set_mpls_ttl()
        act.mpls_ttl = new_mpls_ttl
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 2
        act = action.action_dec_mpls_ttl()
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 3
        act = action.action_copy_ttl_in()
        act_list.append([act])
        next_avail.append(False)
        chk_expire.append(False)

        write_action_test_multi_tables(self, ing_port, egr_port,
            match_fields = match_ls,
            wildcards = wildcards,
            act_list = act_list,
            next_avail = next_avail,
            chk_expire = chk_expire,
            pkt = pkt,
            exp_pkt = exp_pkt)

class MultiTableWriteActMpls9(pktact.BaseMatchCase):
    """
    Check exec order is correct among the action set against MPLS pkt
    Sent pkt: pkt w/ MPLS
    Actions:
        Table0: Outport
        Table1: Decrement IP TTL
        Table2: Pop MPLS
        Table3: Copy TTL inwards
    Expectation: Rcv pkt w/o MPLS. IP TTL must be orig MPLS TTL - 1
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")
        # For making the test simpler...
        ing_port = of_ports[0]
        egr_port = of_ports[1]

        mpls_label = 0xa5f05 # no specific meaning
        mpls_tc = 5
        mpls_ttl = 129
        pkt = testutils.simple_tcp_packet_w_mpls(mpls_label=mpls_label,
                                                 mpls_tc=mpls_tc,
                                                 mpls_ttl=mpls_ttl)

        match_ls = parse.packet_to_flow_match(pkt)
        wildcards = 0

        exp_pkt = testutils.simple_tcp_packet_w_mpls(ip_ttl=mpls_ttl-1)

        # Create parameters for each table
        act_list = []
        next_avail = []
        chk_expire = []

        #Table 0
        act = action.action_output()
        act.port = egr_port
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 1
        act = action.action_dec_nw_ttl()
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 2
        act = action.action_pop_mpls()
        act.ethertype = ETHERTYPE_IP
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 3
        act = action.action_copy_ttl_in()
        act_list.append([act])
        next_avail.append(False)
        chk_expire.append(False)

        write_action_test_multi_tables(self, ing_port, egr_port,
            match_fields = match_ls,
            wildcards = wildcards,
            act_list = act_list,
            next_avail = next_avail,
            chk_expire = chk_expire,
            pkt = pkt,
            exp_pkt = exp_pkt)

class MultiTableWriteAct2Mpls1(pktact.BaseMatchCase):
    """
    Check exec order is correct among the action set against MPLS pkt
    Sent pkt: pkt w/ 2MPLS
    Actions:
        Table0: Outport
        Table1: Pop MPLS
        Table2: Copy TTL inwards
    Expectation: Rcv pkt w/ MPLS. MPLS TTL must have orig Outer tag's value
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")
        # For making the test simpler...
        ing_port = of_ports[0]
        egr_port = of_ports[1]

        mpls_label = 0xa5f05 # no specific meaning
        mpls_tc = 5
        mpls_ttl = 129
        mpls_label_int = 0x5a0fa
        mpls_tc_int = 4
        mpls_ttl_int = 193
        pkt = testutils.simple_tcp_packet_w_mpls(
                                  mpls_label=mpls_label,
                                  mpls_tc=mpls_tc,
                                  mpls_ttl=mpls_ttl,
                                  mpls_label_int=mpls_label_int,
                                  mpls_tc_int=mpls_tc_int,
                                  mpls_ttl_int=mpls_ttl_int)

        match_ls = parse.packet_to_flow_match(pkt)
        wildcards = 0

        exp_pkt = testutils.simple_tcp_packet_w_mpls(
                                      mpls_label=mpls_label_int,
                                      mpls_tc=mpls_tc_int,
                                      mpls_ttl=mpls_ttl)

        # Create parameters for each table
        act_list = []
        next_avail = []
        chk_expire = []

        #Table 0
        act = action.action_output()
        act.port = egr_port
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 1
        act = action.action_pop_mpls()
        act.ethertype = ETHERTYPE_MPLS
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 2
        act = action.action_copy_ttl_in()
        act_list.append([act])
        next_avail.append(False)
        chk_expire.append(False)

        write_action_test_multi_tables(self, ing_port, egr_port,
            match_fields = match_ls,
            wildcards = wildcards,
            act_list = act_list,
            next_avail = next_avail,
            chk_expire = chk_expire,
            pkt = pkt,
            exp_pkt = exp_pkt)

class MultiTableWriteAct2Mpls2(pktact.BaseMatchCase):
    """
    Check exec order is correct among the action set against MPLS pkt
    Sent pkt: pkt w/ 2MPLS
    Actions:
        Table0: Outport
        Table1: Copy TTL outwards
        Table2: Pop MPLS
    Expectation: Rcv pkt w/ MPLS. MPLS TTL must have IP TTL's value
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")
        # For making the test simpler...
        ing_port = of_ports[0]
        egr_port = of_ports[1]

        mpls_label = 0xa5f05 # no specific meaning
        mpls_tc = 5
        mpls_ttl = 129
        mpls_label_int = 0x5a0fa
        mpls_tc_int = 4
        mpls_ttl_int = 193
        ip_ttl = 63
        pkt = testutils.simple_tcp_packet_w_mpls(
                                  mpls_label=mpls_label,
                                  mpls_tc=mpls_tc,
                                  mpls_ttl=mpls_ttl,
                                  mpls_label_int=mpls_label_int,
                                  mpls_tc_int=mpls_tc_int,
                                  mpls_ttl_int=mpls_ttl_int,
                                  ip_ttl=ip_ttl)

        match_ls = parse.packet_to_flow_match(pkt)
        wildcards = 0

        exp_pkt = testutils.simple_tcp_packet_w_mpls(
                                      mpls_label=mpls_label_int,
                                      mpls_tc=mpls_tc_int,
                                      mpls_ttl=ip_ttl,
                                      ip_ttl=ip_ttl)

        # Create parameters for each table
        act_list = []
        next_avail = []
        chk_expire = []

        #Table 0
        act = action.action_output()
        act.port = egr_port
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 1
        act = action.action_copy_ttl_out()
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 2
        act = action.action_pop_mpls()
        act.ethertype = ETHERTYPE_MPLS
        act_list.append([act])
        next_avail.append(False)
        chk_expire.append(False)

        write_action_test_multi_tables(self, ing_port, egr_port,
            match_fields = match_ls,
            wildcards = wildcards,
            act_list = act_list,
            next_avail = next_avail,
            chk_expire = chk_expire,
            pkt = pkt,
            exp_pkt = exp_pkt)

class MultiTableWriteAct2Mpls3(pktact.BaseMatchCase):
    """
    Check exec order is correct among the action set against MPLS pkt
    Sent pkt: pkt w/ 2MPLS
    Actions:
        Table0: Outport
        Table1: Push MPLS
        Table2: Pop MPLS
    Expectation: Rcv pkt w/ 2MPLS. Outer MPLS has same val as in inner.
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")
        # For making the test simpler...
        ing_port = of_ports[0]
        egr_port = of_ports[1]

        mpls_label = 0xa5f05 # no specific meaning
        mpls_tc = 5
        mpls_ttl = 129
        mpls_label_int = 0x5a0fa
        mpls_tc_int = 4
        mpls_ttl_int = 193

        pkt = testutils.simple_tcp_packet_w_mpls(
                                  mpls_label=mpls_label,
                                  mpls_tc=mpls_tc,
                                  mpls_ttl=mpls_ttl,
                                  mpls_label_int=mpls_label_int,
                                  mpls_tc_int=mpls_tc_int,
                                  mpls_ttl_int=mpls_ttl_int)

        match_ls = parse.packet_to_flow_match(pkt)
        wildcards = 0

        exp_pkt = testutils.simple_tcp_packet_w_mpls(
                                      mpls_label=mpls_label_int,
                                      mpls_tc=mpls_tc_int,
                                      mpls_ttl=mpls_ttl_int,
                                      mpls_label_int=mpls_label_int,
                                      mpls_tc_int=mpls_tc_int,
                                      mpls_ttl_int=mpls_ttl_int)

        # Create parameters for each table
        act_list = []
        next_avail = []
        chk_expire = []

        #Table 0
        act = action.action_output()
        act.port = egr_port
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 1
        act = action.action_push_mpls()
        act.ethertype = ETHERTYPE_MPLS
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 2
        act = action.action_pop_mpls()
        act.ethertype = ETHERTYPE_MPLS
        act_list.append([act])
        next_avail.append(False)
        chk_expire.append(False)

        write_action_test_multi_tables(self, ing_port, egr_port,
            match_fields = match_ls,
            wildcards = wildcards,
            act_list = act_list,
            next_avail = next_avail,
            chk_expire = chk_expire,
            pkt = pkt,
            exp_pkt = exp_pkt)

class MultiTableWriteAct2Mpls4(pktact.BaseMatchCase):
    """
    Check exec order is correct among the action set against MPLS pkt
    Sent pkt: pkt w/ 2MPLS
    Actions:
        Table0: Outport
        Table1: Set TTL
        Table2: Copy TTL outwards
    Expectation: Rcv pkt w/ 2MPLS. Outer MPLS has set value
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")
        # For making the test simpler...
        ing_port = of_ports[0]
        egr_port = of_ports[1]

        mpls_label = 0xa5f05 # no specific meaning
        mpls_tc = 5
        mpls_ttl = 129
        mpls_label_int = 0x5a0fa
        mpls_tc_int = 4
        mpls_ttl_int = 193
        pkt = testutils.simple_tcp_packet_w_mpls(
                                  mpls_label=mpls_label,
                                  mpls_tc=mpls_tc,
                                  mpls_ttl=mpls_ttl,
                                  mpls_label_int=mpls_label_int,
                                  mpls_tc_int=mpls_tc_int,
                                  mpls_ttl_int=mpls_ttl_int)

        match_ls = parse.packet_to_flow_match(pkt)

        wildcards = 0

        new_mpls_ttl = mpls_ttl+1
        exp_pkt = testutils.simple_tcp_packet_w_mpls(
                                      mpls_label=mpls_label,
                                      mpls_tc=mpls_tc,
                                      mpls_ttl=new_mpls_ttl,
                                      mpls_label_int=mpls_label_int,
                                      mpls_tc_int=mpls_tc_int,
                                      mpls_ttl_int=mpls_ttl_int)

        # Create parameters for each table
        act_list = []
        next_avail = []
        chk_expire = []

        #Table 0
        act = action.action_output()
        act.port = egr_port
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 1
        act = action.action_set_mpls_ttl()
        act.mpls_ttl = new_mpls_ttl
        act_list.append([act])
        next_avail.append(True)
        chk_expire.append(False)

        #Table 2
        act = action.action_copy_ttl_out()
        act_list.append([act])
        next_avail.append(False)
        chk_expire.append(False)

        write_action_test_multi_tables(self, ing_port, egr_port,
            match_fields = match_ls,
            wildcards = wildcards,
            act_list = act_list,
            next_avail = next_avail,
            chk_expire = chk_expire,
            pkt = pkt,
            exp_pkt = exp_pkt)

###########################################################################

def write_action_test_multi_tables(parent, ing_port, egr_port,
        match_fields = None,
        wildcards = 0,
        act_list = None,
        next_avail = None,
        chk_expire = None,
        pkt = None,
        exp_pkt = None):
    """
    Testing framework for write_action tests with multiple tables

    @param parent Must implement controller, dataplane, assertTrue, assertEqual
    and logger
    @param ing_port Ingress OF port
    @param egr_port Egress OF port
    @match Match field in flow_mod commans for all the tables
    @param wildcard Match.wildcard filed in flow_mod commands for all the tables
    @param act_list Array of action list for each table
    @param next_avail Array. Indicate False for no more tables are used
    @param chk_expire Array. Indicate True if you want flow_removed msg
    @param pkt Pkt to be sent
    @param exp_pkt Expected pkt
    """

    parent.assertTrue(match_fields is not None, "Match param doesn't exist")
    parent.assertTrue(act_list is not None, "act_list param doesn't exist")
    parent.assertTrue(next_avail is not None, "next_avail param doesn't exist")
    parent.assertTrue(chk_expire is not None, "chk_expire param doesn't exist")
    #wildcards = wildcards & 0xfffffffff # mask out anything out of range

    request_list = []
    for table_id in range(MAX_TABLE):
        inst_list = []
        inst = instruction.instruction_write_actions()
        inst_list.append(inst)
        action_list = act_list[table_id]
        match_fields = testutils.packet_to_exact_flow_match(pkt,None,table_id,ing_port)
        check_expire = chk_expire[table_id]
        if next_avail[table_id]:
            inst = instruction.instruction_goto_table()
            inst.table_id = table_id + 1
            inst_list.append(inst)
        else:
            pass

        request = testutils.flow_msg_create(parent, pkt, ing_port=ing_port,
                              instruction_list=inst_list,
                              action_list=action_list,
                              wildcards=wildcards,
                              match_fields=match_fields,
                              check_expire=check_expire,
                              table_id=table_id)
        request_list.append(request)
        #print("request::\n%s" % request_list[table_id].show())
        testutils.flow_msg_install(parent, request_list[table_id], True)

        if next_avail[table_id]:
            pass
        else:
            num_table_used = table_id + 1
            break

    parent.logger.debug("Send packet: " + str(ing_port)
        + " to " + str(egr_port))
    parent.dataplane.send(ing_port, str(pkt))

    # Check response from switch
    #@todo Not all HW supports both pkt and byte counters
    #@todo We shouldn't expect the order of coming response..
    for table_id in range(num_table_used):
        if chk_expire[table_id]:
            flow_removed_verify(parent, request_list[table_id], pkt_count=1,
                            byte_count=len(pkt))

    testutils.receive_pkt_verify(parent, egr_port, exp_pkt)
