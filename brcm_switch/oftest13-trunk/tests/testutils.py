
import sys
import logging
import copy

from cStringIO import StringIO
#import types

#import oftest.controller as controller
from oftest import cstruct as ofp

#import oftest.cstruct as ofp
import oftest.match as match
import oftest.message as message
#import oftest.dataplane as dataplane
import oftest.action as action
import oftest.parse as parse
from oftest import instruction
from oftest.packet import Packet
from oftest.match_list import match_list

try:
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import *
    load_contrib("mpls")
    #TODO This should really be in scapy!
    bind_layers(MPLS, MPLS, s=0)
except:
    sys.exit("Need to install scapy for packet parsing")

global skipped_test_count
skipped_test_count = 0

# Some useful defines
IP_ETHERTYPE = 0x800
IPV6_ETHERTYPE = 0x86dd
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_MPLS = 0x8847
TCP_PROTOCOL = 0x6
UDP_PROTOCOL = 0x11
ICMPV6_PROTOCOL = 0x3a


#add table defination,fengqiang00107390
MT_TEST_IP = "192.168.0.1"

EX_ACL_TABLE = 0
WC_ACL_TABLE = 0
WC_SERV_TABLE = 1
EX_L2_TABLE = 2
EX_VLAN_TABLE = 3
EX_MPLS_TABLE = 4
EX_L3_TABLE = 5
WC_L3_TABLE = 6
EX_ICMP_TABLE = 7
WC_ALL_TABLE = 8

#softswitch to use
#EX_ACL_TABLE = 0
#WC_ACL_TABLE = 1
#WC_SERV_TABLE = 2
#EX_L2_TABLE = 3
#EX_VLAN_TABLE = 4
#EX_MPLS_TABLE = 5
#EX_L3_TABLE = 6
#WC_L3_TABLE = 7
#EX_ICMP_TABLE = 8
#WC_ALL_TABLE = 8

switch_table_list = [EX_ACL_TABLE, WC_ACL_TABLE, WC_SERV_TABLE, EX_L2_TABLE,
                     EX_VLAN_TABLE, EX_MPLS_TABLE, EX_L3_TABLE, WC_L3_TABLE,
                     EX_ICMP_TABLE, WC_ALL_TABLE]
LAST_TABLE_NUM = 8

APPLY_ACTIONS_INSTRUCTION = 1
WRITE_ACTIONS_INSTRUCTION = 0

#OFPFW_ALL = 0x0000000fffffffff
OFPFW_ALL = 0xffffffffffffffff


def clear_switch(parent, port_list, logger):
    """
    Clear the switch configuration

    @param parent Object implementing controller and assert equal
    @param logger Logging object
    """
    parent.assertTrue(len(port_list) > 2, "Not enough ports for test")

    #set the initial value of port in the switch
    for port in port_list:
        clear_port_config(parent, port, logger)

    #initialize_table_config(parent)

    #clear the flow entry and group entry in the switch
    delete_all_flows(parent.controller, logger)
    delete_all_groups(parent.controller, logger)

    #ensure no OFPT_PORT_STATUS in buffer of oftest
    response,_ = parent.controller.poll(ofp.OFPT_PORT_STATUS, 1)
    while response != None:
        response,_ = parent.controller.poll(ofp.OFPT_PORT_STATUS, 1)

    #clear the flow removed msg in the oftest
    response,_ = parent.controller.poll(ofp.OFPT_FLOW_REMOVED, 1)
    while response != None:
        response,_ = parent.controller.poll(ofp.OFPT_FLOW_REMOVED, 1)

    #clear the packet_in msg in the oftest
    response,_ = parent.controller.poll(ofp.OFPT_PACKET_IN, 1)
    while response != None:
        response,_ = parent.controller.poll(ofp.OFPT_PACKET_IN, 1)
    return port_list

def initialize_table_config(parent):
    """
    Initialize all table configs to default setting ("CONTROLLER")
    @param ctrl The controller object for the test
    """
    parent.logger.info("Initializing all table configs")
    rv = set_table_config(parent, ofp.OFPTT_ALL, ofp.OFPTC_TABLE_MISS_CONTROLLER)
    return rv

def set_table_config(parent, table_id = ofp.OFPTT_ALL,
                    config = ofp.OFPTC_TABLE_MISS_CONTINUE, one_table = False):
    """
    1)"one_table=true" && "table_id != ofp.OFPTT_ALL" will just set one table
    2) "table_id = n" will set table0 to table(n-1)
    3)the last table can use MISS_CONTROLLER to test switch's processing
    4)max_len is reserved here,if used, can change its value
    @param ctrl The controller object for the test
    """
    max_len = 128
    if one_table and (table_id != ofp.OFPTT_ALL):
        rv = set_flow_miss_entry(parent, config, max_len, table_id)
    else:
        if table_id == ofp.OFPTT_ALL:
            table_id = LAST_TABLE_NUM
        rv = set_flow_miss_entry(parent, ofp.OFPTC_TABLE_MISS_CONTROLLER, max_len, table_id)
        for xid in range(table_id):
            rv |= set_flow_miss_entry(parent, config, max_len, xid)
    parent.assertTrue(rv == 0, "Error sending out message:flow_miss_entry")
    return rv

def set_flow_miss_entry(parent, config = ofp.OFPTC_TABLE_MISS_CONTINUE,
                    max_len = 128, table_id = 0):
    """
    Set table miss entry "goto next table"/"packet in"/"drop"
    @param ctrl The controller object for the test
    """
    parent.logger.info("Setting flow miss entries")
    rv = 0
    request = message.flow_mod()
    request.table_id = table_id
    request.priority = 0

    if config == ofp.OFPTC_TABLE_MISS_CONTROLLER:
        act = action.action_output()
        act.max_len = max_len
        act.port = ofp.OFPP_CONTROLLER
        inst_packet_in = instruction.instruction_write_actions()
        inst_packet_in.actions.add(act)
        request.instructions.add(inst_packet_in)
        rv = parent.controller.message_send(request)
    elif config == ofp.OFPTC_TABLE_MISS_CONTINUE:
        inst_goto_table = instruction.instruction_goto_table()
        inst_goto_table.table_id = table_id + 1
        request.instructions.add(inst_goto_table)
        rv = parent.controller.message_send(request)
    elif config == ofp.OFPTC_TABLE_MISS_DROP:
        rv = parent.controller.message_send(request)
    else:
        pass
    return rv

def delete_all_flows(ctrl, logger):
    """
    Delete all flows on the switch
    @param ctrl The controller object for the test
    @param logger Logging object
    """

    logger.info("Deleting all flows")
    #DEFAULT_TABLE_COUNT = 4
    return delete_all_flows_one_table(ctrl, logger, table_id=ofp.OFPTT_ALL)

def delete_all_flows_one_table(ctrl, logger, table_id=0):
    """
    Delete all flows on a table
    @param ctrl The controller object for the test
    @param logger Logging object
    @param table_id Table ID
    """
    logger.info("Deleting all flows on table ID: " + str(table_id))
    msg = message.flow_mod()
    msg.match.length = 0
    msg.match_tlvs = [0,0,0,0]
    msg.out_port = ofp.OFPP_ANY
    msg.out_group = ofp.OFPG_ANY
    msg.command = ofp.OFPFC_DELETE
    msg.buffer_id = 0xffffffff
    msg.table_id = table_id
    logger.debug(msg.show())

    return ctrl.message_send(msg)

def delete_all_groups(ctrl, logger):
    """
    Delete all groups on the switch
    @param ctrl The controller object for the test
    @param logger Logging object
    """

    logger.info("Deleting all groups")
    msg = message.group_mod()
    msg.group_id = ofp.OFPG_ALL
    msg.command = ofp.OFPGC_DELETE
    logger.debug(msg.show())
    return ctrl.message_send(msg)

def clear_port_config(parent, port, logger):
    """
    Clear the port configuration

    @param parent Object implementing controller and assert equal
    @param logger Logging object
    """
    rv = port_config_set(parent.controller, port,
                         0, 0xffffffff, logger)
    parent.assertEqual(rv, 0, "Failed to reset port config")

def simple_arp_packet(dl_dst='ff:ff:ff:ff:ff:ff',
                      dl_src='00:06:07:08:09:0a',
                      op = 1,
                      srcpa = '192.168.0.1',
                      tgtpa = '192.168.0.2',
                      srcha = '00:06:07:08:09:0a',
                      tgtha = '00:00:00:00:00:00',
                      pkt_len = 64):
    pkt = Ether(dst=dl_dst, src=dl_src) / ARP(op=op, psrc=srcpa, pdst=tgtpa, hwsrc=srcha, hwdst=tgtha)
    if pkt_len > len(pkt) :
        pkt = pkt/("D" * (pkt_len - len(pkt)))

    return pkt

def simple_tcp_packet(dl_dst='00:01:02:03:04:05',
                      dl_src='00:06:07:08:09:0a',
                      vlan_tags=[],  # {type,vid,pcp,cfi}  TODO type
                      mpls_tags=[],  # {type,label,tc,ttl} TODO type
                      ip_src='192.168.0.1',
                      ip_dst='192.168.0.2',
                      ip_dscp=0,
                      ip_ecn=0,
                      ip_ttl=64,
                      tcp_sport=1234,
                      tcp_dport=80,
                      payload_len = 46):
    pkt = Ether(dst=dl_dst, src=dl_src)

    vlans_num = 0
    while len(vlan_tags):
        tag = vlan_tags.pop(0)
        dot1q = Dot1Q()
        if 'vid' in tag:
            dot1q.vlan = tag['vid']
        if 'pcp' in tag:
            dot1q.prio = tag['pcp']
        if 'cfi' in tag:
            dot1q.id = tag['cfi']
        pkt = pkt / dot1q
        if 'type' in tag:
            if vlans_num == 0:
                pkt[Ether].setfieldval('type', tag['type'])
            else:
                pkt[Dot1Q:vlans_num].setfieldval('type', tag['type'])
        vlans_num+=1

    mplss_num = 0
    while len(mpls_tags):
        tag = mpls_tags.pop(0)
        mpls = MPLS()
        if 'label' in tag:
            mpls.label = tag['label']
        if 'tc' in tag:
            mpls.cos = tag['tc']
        if 'ttl' in tag:
            mpls.ttl = tag['ttl']
        pkt = pkt / mpls
        if 'type' in tag:
            if mplss_num == 0:
                if vlans_num == 0:
                    pkt[Ether].setfieldval('type', tag['type'])
                else:
                    pkt[Dot1Q:vlans_num].setfieldval('type', tag['type'])
        mplss_num+=1
    ip_tos = ((ip_dscp << 2) + ip_ecn) & 0xff

    pkt = pkt / IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl) \
              / TCP(sport=tcp_sport, dport=tcp_dport)

    pkt = pkt / ("X" * payload_len)

    return pkt

def simple_ipv6_tcp_packet(dl_dst='00:01:02:03:04:05',
                      dl_src='00:06:07:08:09:0a',
                      vlan_tags=[],  # {type,vid,pcp,cfi}  TODO type
                      mpls_tags=[],  # {type,label,tc,ttl} TODO type
                      ip_src='fe80::2420:52ff:fe8f:5189',
                      ip_dst='fe80::2420:52ff:fe8f:5190',
                      ip_dscp=0,
                      ip_ecn=0,
                      ip_ttl=64,
                      tcp_sport=1234,
                      tcp_dport=80,
                      payload_len = 46):
    pkt = Ether(dst=dl_dst, src=dl_src)

    vlans_num = 0
    while len(vlan_tags):
        tag = vlan_tags.pop(0)
        dot1q = Dot1Q()
        if 'vid' in tag:
            dot1q.vlan = tag['vid']
        if 'pcp' in tag:
            dot1q.prio = tag['pcp']
        if 'cfi' in tag:
            dot1q.id = tag['cfi']
        pkt = pkt / dot1q
        if 'type' in tag:
            if vlans_num == 0:
                pkt[Ether].setfieldval('type', tag['type'])
            else:
                pkt[Dot1Q:vlans_num].setfieldval('type', tag['type'])
        vlans_num+=1

    mplss_num = 0
    while len(mpls_tags):
        tag = mpls_tags.pop(0)
        mpls = MPLS()
        if 'label' in tag:
            mpls.label = tag['label']
        if 'tc' in tag:
            mpls.cos = tag['tc']
        if 'ttl' in tag:
            mpls.ttl = tag['ttl']
        pkt = pkt / mpls
        if 'type' in tag:
            if mplss_num == 0:
                if vlans_num == 0:
                    pkt[Ether].setfieldval('type', tag['type'])
                else:
                    pkt[Dot1Q:vlans_num].setfieldval('type', tag['type'])
        mplss_num+=1
    ip_tos = ((ip_dscp << 2) + ip_ecn) & 0xff

    pkt = pkt / IPv6(src=ip_src, dst=ip_dst, tc=ip_tos, hlim=ip_ttl) \
              / TCP(sport=tcp_sport, dport=tcp_dport)

    pkt = pkt / ("V" * payload_len)

    return pkt

def simple_icmp_packet(dl_dst='00:01:02:03:04:05',
                       dl_src='00:06:07:08:09:0a',
                       vlan_tags=[],  # {type,vid,pcp,cfi}  TODO type
                       mpls_tags=[],  # {type,label,tc,ttl} TODO type
                       ip_src='192.168.0.1',
                       ip_dst='192.168.0.2',
                       ip_tos=0,
                       ip_ttl=64,
                       icmp_type=8, # ICMP_ECHO_REQUEST
                       icmp_code=0,
                       payload_len=62):

    #TODO simple_ip_packet
    pkt = Ether(dst=dl_dst, src=dl_src)

    vlans_num = 0
    while len(vlan_tags):
        tag = vlan_tags.pop(0)
        dot1q = Dot1Q()
        if 'vid' in tag:
            dot1q.vlan = tag['vid']
        if 'pcp' in tag:
            dot1q.prio = tag['pcp']
        if 'cfi' in tag:
            dot1q.id = tag['cfi']
        pkt = pkt / dot1q
        if 'type' in tag:
            if vlans_num == 0:
                pkt[Ether].setfieldval('type', tag['type'])
            else:
                pkt[Dot1Q:vlans_num].setfieldval('type', tag['type'])
        vlans_num+=1

    mplss_num = 0
    while len(mpls_tags):
        tag = mpls_tags.pop(0)
        mpls = MPLS()
        if 'label' in tag:
            mpls.label = tag['label']
        if 'tc' in tag:
            mpls.cos = tag['tc']
        if 'ttl' in tag:
            mpls.ttl = tag['ttl']
        pkt = pkt / mpls
        if 'type' in tag:
            if mplss_num == 0:
                if vlans_num == 0:
                    pkt[Ether].setfieldval('type', tag['type'])
                else:
                    pkt[Dot1Q:vlans_num].setfieldval('type', tag['type'])
        mplss_num+=1

    pkt = pkt / IP(src=ip_src, dst=ip_dst, tos=ip_tos, ttl=ip_ttl) \
              / ICMP(type=icmp_type, code=icmp_code)

    pkt = pkt / ("D" * payload_len)

    return pkt

def simple_ipv6_packet(pktlen=100,
                      dl_dst='00:01:02:03:04:05',
                      dl_src='00:06:07:08:09:0a',
                      dl_vlan_enable=False,
                      dl_vlan=0,
                      dl_vlan_pcp=0,
                      dl_vlan_cfi=0,
                      ip_src='fe80::2420:52ff:fe8f:5189',
                      ip_dst='fe80::2420:52ff:fe8f:5190',
                      ip_tos=0,
                      is_tcp = True,
                      tcp_sport=0,
                      tcp_dport=0,
                      EH = False,
                      EHpkt = IPv6ExtHdrDestOpt()
                      ):

    """
    Return a simple IPv6 packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param dl_dst Destinatino MAC
    @param dl_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param dl_vlan VLAN ID
    @param dl_vlan_pcp VLAN priority
    @param ip_src IPv6 source
    @param ip_dst IPv6 destination
    @param ip_tos IP ToS
    @param tcp_dport TCP destination port
    @param ip_sport TCP source port

    """
    # Note Dot1Q.id is really CFI
    if (dl_vlan_enable):
        pkt = Ether(dst=dl_dst, src=dl_src)/ \
            Dot1Q(prio=dl_vlan_pcp, id=dl_vlan_cfi, vlan=dl_vlan)/ \
            IPv6(src=ip_src, dst=ip_dst)

    else:
        pkt = Ether(dst=dl_dst, src=dl_src)/ \
            IPv6(src=ip_src, dst=ip_dst)

    # Add IPv6 Extension Headers
    if EH:
        pkt = pkt / EHpkt

    if (is_tcp == True):
        if (tcp_sport >0 and tcp_dport >0):
            pkt = pkt / TCP(sport=tcp_sport, dport=tcp_dport)
    else:
        if (tcp_sport >0 and tcp_dport >0):
             pkt = pkt / UDP(sport=tcp_sport, dport=tcp_dport)

    if pktlen > len(pkt) :
        pkt = pkt/("D" * (pktlen - len(pkt)))

    return pkt

def simple_ipv6_allfield_packet(pktlen=100,
                      dl_dst='00:01:02:03:04:05',
                      dl_src='00:06:07:08:09:0a',
                      dl_vlan=37,
                      dl_vlan_pcp=3,
                      dl_vlan_cfi=0,
                      mpls_lb=6,
                      mpls_tc=1,
                      mpls_ttl=255,
                      ip_src='fe80::2420:52ff:fe8f:1119',
                      ip_dst='fe80::1777:4df5:6fd4:7510'
                      ):

    """
    Return a simple dataplane ICMPv6 packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param dl_dst Destination MAC
    @param dl_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param dl_vlan VLAN ID
    @param dl_vlan_pcp VLAN priority
    @param ip_src IPv6 source
    @param ip_dst IPv6 destination

    """

    pkt = Ether(dst=dl_dst, src=dl_src)/ \
            Dot1Q(prio=dl_vlan_pcp, id=dl_vlan_cfi, vlan=dl_vlan)/ \
            MPLS(label=mpls_lb,cos=mpls_tc,ttl=mpls_ttl)/ \
            IPv6(src=ip_src, dst=ip_dst, fl=2 ,tc=6)/ \
            ICMPv6ND_NS(tgt='fe80::1:176f:2243:17dd')/ \
            ICMPv6NDOptSrcLLAddr(type=1, len=1, lladdr='8c:02:11:7f:6e:58')
    if pktlen > len(pkt) :
        pkt = pkt/("D" * (pktlen - len(pkt)))

    return pkt

def simple_icmpv6_packet(pktlen=100,
                      dl_dst='00:01:02:03:04:05',
                      dl_src='00:06:07:08:09:0a',
                      dl_vlan_enable=False,
                      dl_vlan=0,
                      dl_vlan_pcp=0,
                      dl_vlan_cfi=0,
                      dl_flow_lable = False,
                      ip_src='fe80::2420:52ff:fe8f:5189',
                      ip_dst='fe80::2420:52ff:fe8f:5190',
                      ip_tos=0,
                      tcp_sport=0,
                      tcp_dport=0,
                      EH = False,
                      EHpkt = IPv6ExtHdrDestOpt(),
                      route_adv = False,
                      sll_enabled = False
                      ):

    """
    Return a simple dataplane ICMPv6 packet

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param dl_dst Destination MAC
    @param dl_src Source MAC
    @param dl_vlan_enable True if the packet is with vlan, False otherwise
    @param dl_vlan VLAN ID
    @param dl_vlan_pcp VLAN priority
    @param ip_src IPv6 source
    @param ip_dst IPv6 destination
    @param ip_tos IP ToS
    @param tcp_dport TCP destination port
    @param tcp_sport TCP source port

    """
    if (dl_vlan_enable):
        pkt = Ether(dst=dl_dst, src=dl_src)/ \
            Dot1Q(prio=dl_vlan_pcp, id=dl_vlan_cfi, vlan=dl_vlan)/ \
            IPv6(src=ip_src, dst=ip_dst)

    else:
        pkt = Ether(dst=dl_dst, src=dl_src)/ \
            IPv6(src=ip_src, dst=ip_dst)

    if( dl_flow_lable == True):
        pkt = Ether(dst=dl_dst, src=dl_src)/ \
            IPv6(src=ip_src, dst=ip_dst, fl=3, tc=5)

    # Add IPv6 Extension Headers
    if EH:
        pkt = pkt / EHpkt

    if route_adv:
        pkt = pkt/ \
        ICMPv6ND_RA(chlim=255, H=0L, M=0L, O=1L, routerlifetime=1800, P=0L, retranstimer=0, prf=0L, res=0L)/ \
        ICMPv6NDOptPrefixInfo(A=1L, res2=0, res1=0L, L=1L, len=4, prefix='fd00:141:64:1::', R=0L, validlifetime=1814400, prefixlen=64, preferredlifetime=604800, type=3)
        if sll_enabled :
            pkt = pkt/ \
            ICMPv6NDOptSrcLLAddr(type=1, len=1, lladdr='66:6f:df:2d:7c:9c')
    else :
        pkt = pkt/ \
            ICMPv6EchoRequest()
    if (tcp_sport >0 and tcp_dport >0):
        pkt = pkt / TCP(sport=tcp_sport, dport=tcp_dport)

    if pktlen > len(pkt) :
        pkt = pkt/("D" * (pktlen - len(pkt)))

    return pkt

def do_barrier(ctrl):
    b = message.barrier_request()
    ctrl.transact(b)


def port_config_get(controller, port_no, logger):
    """
    Get a port's configuration

    Gets the switch feature configuration and grabs one port's
    configuration

    @returns (hwaddr, config, advert) The hwaddress, configuration and
    advertised values
    """
    request = message.port_desc_request()
    reply, _ = controller.transact(request, timeout=2)
    #print(reply.show())
    if reply is None:
        logger.warn("Get feature request failed")
        return None, None, None
    logger.debug(reply.show())
    for idx in range(len(reply.ports)):
        if reply.ports[idx].port_no == port_no:
            return (reply.ports[idx].hw_addr, reply.ports[idx].config,
                    reply.ports[idx].advertised)

    logger.warn("Did not find port number for port config")
    return None, None, None

def port_config_set(controller, port_no, config, mask, logger):
    """
    Set the port configuration according the given parameters

    Gets the switch feature configuration and updates one port's
    configuration value according to config and mask
    """
    logger.info("Setting port " + str(port_no) + " to config " + str(config))

    (hw_addr,conf,advertised) = port_config_get(controller, port_no, logger)
    if (hw_addr,conf,advertised) == (None, None, None):
        return -1
    mod = message.port_mod()
    mod.port_no = port_no
    mod.hw_addr = hw_addr
    mod.config = config
    mod.mask = mask
    mod.advertise = advertised
    rv = controller.message_send(mod)
    do_barrier(controller)
    return rv

def receive_pkt_check(dataplane, pkt, yes_ports, no_ports, assert_if, logger):
    """
    Check for proper receive packets across all ports
    @param dataplane The dataplane object
    @param pkt Expected packet; may be None if yes_ports is empty
    @param yes_ports Set or list of ports that should recieve packet
    @param no_ports Set or list of ports that should not receive packet
    @param assert_if Object that implements assertXXX
    """
    for ofport in yes_ports:
        logger.debug("Checking for pkt on port " + str(ofport))
        (_, rcv_pkt, _) = dataplane.poll(
            port_number=ofport, timeout=1)
        assert_if.assertTrue(rcv_pkt is not None,
                             "Did not receive pkt on " + str(ofport))
        assert_if.assertEqual(str(pkt), str(rcv_pkt),
                              "Response packet does not match send packet " +
                              "on port " + str(ofport))

    for ofport in no_ports:
        logger.debug("Negative check for pkt on port " + str(ofport))
        (_, rcv_pkt, _) = dataplane.poll(
            port_number=ofport, timeout=1)
        assert_if.assertTrue(rcv_pkt is None,
                             "Unexpected pkt on port " + str(ofport))


def pkt_verify(parent, rcv_pkt, exp_pkt):
    if str(exp_pkt) != str(rcv_pkt):
        parent.logger.error("ERROR: Packet match failed.")
        parent.logger.debug("Expected (" + str(len(exp_pkt)) + ")")
        parent.logger.debug(str(exp_pkt).encode('hex'))
        sys.stdout = tmpout = StringIO()
        exp_pkt.show()
        sys.stdout = sys.__stdout__
        parent.logger.debug(tmpout.getvalue())
        parent.logger.debug("Received (" + str(len(rcv_pkt)) + ")")
        parent.logger.debug(str(rcv_pkt).encode('hex'))
        sys.stdout = tmpout = StringIO()
        Ether(rcv_pkt).show()
        sys.stdout = sys.__stdout__
        parent.logger.debug(tmpout.getvalue())
    parent.assertEqual(str(exp_pkt), str(rcv_pkt),
                       "Packet match error")
    return rcv_pkt

def receive_pkt_verify(parent, egr_port, exp_pkt):
    """
    Receive a packet and verify it matches an expected value

    parent must implement dataplane, assertTrue and assertEqual
    """
    (rcv_port, rcv_pkt, _) = parent.dataplane.poll(port_number=egr_port,
                                                          timeout=1)
    ######Open if to debug#######
    #print("++++++++++++++++++++++exp_pkt++++++++++++++++++++++")
    #print(str(exp_pkt).encode('hex'))
    #print("++++++++++++++++++++++rcv_pkt++++++++++++++++++++++")
    #if rcv_pkt is None:
    #    print(str(rcv_pkt))
    #else:
    #    print(str(rcv_pkt).encode('hex'))

    if exp_pkt is None:
        if rcv_pkt is None:
            return None
        else:
            parent.logger.error("ERROR: Received unexpected packet from " + str(egr_port));
            return rcv_pkt

    if rcv_pkt is None:
        parent.logger.error("ERROR: No packet received from " + str(egr_port))

    parent.assertTrue(rcv_pkt is not None,
                      "Did not receive packet port " + str(egr_port))
    parent.logger.debug("Packet len " + str(len(rcv_pkt)) + " in on " +
                    str(rcv_port))

    return pkt_verify(parent, rcv_pkt, exp_pkt)

def packetin_verify(parent, exp_pkt, miss_send_len=128):
    """
    Receive packet_in and verify it matches an expected value
    """
    (response, _) = parent.controller.poll(ofp.OFPT_PACKET_IN, 2)
    #print(response.show())
    #print("miss_send_len:"+str(miss_send_len))
    parent.assertTrue(response is not None, 'Packet in message not received')
    if miss_send_len <= len(str(exp_pkt)):
        if len(str(response.data)) != miss_send_len:
            parent.logger.debug("miss_send_len " + str(miss_send_len))
            parent.logger.debug("resp len " + str(len(str(response.data))))
        parent.assertTrue(response.buffer_id != ofp.OFP_NO_BUFFER, "packetin with unexpect OFP_NO_BUFFER")
        parent.assertEqual(len(str(response.data)), miss_send_len,
                     'PACKET_IN packet data len does not equal to miss_send_len')
    else:
        if miss_send_len == ofp.OFPCML_NO_BUFFER:
            parent.assertTrue(response.buffer_id == ofp.OFP_NO_BUFFER,
                                        "packetin without expect OFP_NO_BUFFER")
        if str(exp_pkt) != response.data:
            parent.logger.debug("pkt  len " + str(len(str(exp_pkt))) + ": "
                                + str(exp_pkt).encode('hex'))
            parent.logger.debug("resp len " + str(len(str(response.data))) + ": "
                                + str(response.data).encode('hex'))
        parent.assertEqual(str(exp_pkt), response.data,
                     'PACKET_IN packet does not match send packet')
    #print(response.show())
    return response.buffer_id

def match_verify(parent, req_match, res_match):
    """
    Verify flow matches agree; if they disagree, report where

    parent must implement assertEqual
    Use str() to ensure content is compared and not pointers
    """

    parent.assertEqual(req_match.wildcards, res_match.wildcards,
                       'Match failed: wildcards: ' + hex(req_match.wildcards) +
                       " != " + hex(res_match.wildcards))
    parent.assertEqual(req_match.in_port, res_match.in_port,
                       'Match failed: in_port: ' + str(req_match.in_port) +
                       " != " + str(res_match.in_port))
    parent.assertEqual(str(req_match.dl_src), str(res_match.dl_src),
                       'Match failed: dl_src: ' + str(req_match.dl_src) +
                       " != " + str(res_match.dl_src))
    parent.assertEqual(str(req_match.dl_dst), str(res_match.dl_dst),
                       'Match failed: dl_dst: ' + str(req_match.dl_dst) +
                       " != " + str(res_match.dl_dst))
    parent.assertEqual(req_match.dl_vlan, res_match.dl_vlan,
                       'Match failed: dl_vlan: ' + str(req_match.dl_vlan) +
                       " != " + str(res_match.dl_vlan))
    parent.assertEqual(req_match.dl_vlan_pcp, res_match.dl_vlan_pcp,
                       'Match failed: dl_vlan_pcp: ' +
                       str(req_match.dl_vlan_pcp) + " != " +
                       str(res_match.dl_vlan_pcp))
    parent.assertEqual(req_match.dl_type, res_match.dl_type,
                       'Match failed: dl_type: ' + str(req_match.dl_type) +
                       " != " + str(res_match.dl_type))

    if (not(req_match.wildcards & ofp.OFPFW_DL_TYPE)
        and (req_match.dl_type == IP_ETHERTYPE)):
        parent.assertEqual(req_match.nw_tos, res_match.nw_tos,
                           'Match failed: nw_tos: ' + str(req_match.nw_tos) +
                           " != " + str(res_match.nw_tos))
        parent.assertEqual(req_match.nw_proto, res_match.nw_proto,
                           'Match failed: nw_proto: ' + str(req_match.nw_proto) +
                           " != " + str(res_match.nw_proto))
        parent.assertEqual(req_match.nw_src, res_match.nw_src,
                           'Match failed: nw_src: ' + str(req_match.nw_src) +
                           " != " + str(res_match.nw_src))
        parent.assertEqual(req_match.nw_dst, res_match.nw_dst,
                           'Match failed: nw_dst: ' + str(req_match.nw_dst) +
                           " != " + str(res_match.nw_dst))

        if (not(req_match.wildcards & ofp.OFPFW_NW_PROTO)
            and ((req_match.nw_proto == TCP_PROTOCOL)
                 or (req_match.nw_proto == UDP_PROTOCOL))):
            parent.assertEqual(req_match.tp_src, res_match.tp_src,
                               'Match failed: tp_src: ' +
                               str(req_match.tp_src) +
                               " != " + str(res_match.tp_src))
            parent.assertEqual(req_match.tp_dst, res_match.tp_dst,
                               'Match failed: tp_dst: ' +
                               str(req_match.tp_dst) +
                               " != " + str(res_match.tp_dst))

def flow_removed_verify(parent, request=None, pkt_count=-1, byte_count=-1):
    """
    Receive a flow removed msg and verify it matches expected

    @params parent Must implement controller, assertEqual
    @param pkt_count If >= 0, verify packet count
    @param byte_count If >= 0, verify byte count
    """
    (response, _) = parent.controller.poll(ofp.OFPT_FLOW_REMOVED, 2)
    parent.assertTrue(response is not None, 'No flow removed message received')

    if request is None:
        return

    parent.assertEqual(request.cookie, response.cookie,
                       "Flow removed cookie error: " +
                       hex(request.cookie) + " != " + hex(response.cookie))

    req_match = request.match
    res_match = response.match
    verifyMatchField(req_match, res_match)

    if (req_match.wildcards != 0):
        parent.assertEqual(request.priority, response.priority,
                           'Flow remove prio mismatch: ' +
                           str(request.priority) + " != " +
                           str(response.priority))
        parent.assertEqual(response.reason, ofp.OFPRR_HARD_TIMEOUT,
                           'Flow remove reason is not HARD TIMEOUT:' +
                           str(response.reason))
        if pkt_count >= 0:
            parent.assertEqual(response.packet_count, pkt_count,
                               'Flow removed failed, packet count: ' +
                               str(response.packet_count) + " != " +
                               str(pkt_count))
        if byte_count >= 0:
            parent.assertEqual(response.byte_count, byte_count,
                               'Flow removed failed, byte count: ' +
                               str(response.byte_count) + " != " +
                               str(byte_count))
def flow_msg_create(parent, pkt, pkt_metadata=None, ing_port=None, match_fields=None,
                    instruction_list=None, action_list=None,wildcards=0, egr_port=None,
                    inst_app_flag=WRITE_ACTIONS_INSTRUCTION,
                    egr_queue=None, table_id=0, check_expire=False):
    """
    Multi-purpose flow_mod creation utility

    Match on packet with given wildcards.
    See flow_match_test for other parameter descriptoins

    if egr_queue is set
             append an out_queue action to egr_queue to the actions_list
    else if egr_port is set:
             append an output action to egr_port to the actions_list
    if the instruction_list is empty,
        append an APPLY instruction to it
    Add the action_list to the first write or apply instruction

    @param egr_queue if not None, make the output an enqueue action
    @param table_id Table ID for writing a flow_mod
    """

    if match_fields is None:
        #match_fields = parse.packet_to_flow_match(pkt)
        match_fields = packet_to_exact_flow_match(pkt, pkt_metadata, table_id, ing_port)

    match_fields2=copy.deepcopy( match_fields);
    parent.logger.info("test......")

    parent.assertTrue(match_fields is not None, "Flow match from pkt failed")
    #in_port = match.in_port(ing_port)
    #match_fields2.add(in_port)
    #print("len:"+str(len(match_fields2)))
    request = message.flow_mod()
    request.match_fields = match_fields2
    request.table_id = table_id

    if check_expire:
        request.flags |= ofp.OFPFF_SEND_FLOW_REM
        request.hard_timeout = 3

    if action_list is None:
        action_list = []
    if instruction_list is None:
        instruction_list = []

    # Set up output/enqueue action if directed
    if egr_queue is not None:
        parent.assertTrue(egr_port is not None, "Egress port not set")
        act = action.action_set_queue()
        act.port = egr_port
        act.queue_id = egr_queue
        action_list.append(act)
    elif egr_port is not None:
        act = action.action_output()
        act.port = egr_port
        action_list.append(act)

    inst = None
    if len(instruction_list) != 0:
        if inst_app_flag == APPLY_ACTIONS_INSTRUCTION:
            for i in instruction_list:
                if (i.type == ofp.OFPIT_APPLY_ACTIONS):
                    inst = i
                break
        else:
            for i in instruction_list:
                if (i.type == ofp.OFPIT_WRITE_ACTIONS):
                    inst = i
                break

    if len(action_list) !=0:
        if inst == None:
            if inst_app_flag == APPLY_ACTIONS_INSTRUCTION:
                inst = instruction.instruction_apply_actions()
            else:
                inst = instruction.instruction_write_actions()
            instruction_list.append(inst)

    # add all the actions to the last inst
    for act in action_list:
        parent.logger.debug("Adding action " + act.show())
        rv = inst.actions.add(act)
        parent.assertTrue(rv, "Could not add action" + act.show())
    # NOTE that the inst has already been added to the flow_mod

    # add all the instrutions to the flow_mod
    for i in instruction_list:
        parent.logger.debug("Adding instruction " + i.show())
        rv = request.instructions.add(i)
        parent.assertTrue(rv, "Could not add instruction " + i.show())

    parent.logger.info(request.show())
    return request

def flow_msg_install(parent, request, clear_table=False):
    """
    Install a flow mod message in the switch

    @param parent Must implement controller, assertEqual, assertTrue
    @param request The request, all set to go
    @param clear_table If true, clear the flow table before installing
    """
    if clear_table:
        parent.logger.debug("Clear flow table")
        if request.table_id:
            table_id = request.table_id
        else:
            table_id = 0
        rc = delete_all_flows_one_table(parent.controller,
                                        parent.logger,
                                        table_id)
        parent.assertEqual(rc, 0, "Failed to delete all flows on table: "
                           + str(table_id))
        do_barrier(parent.controller)

    parent.logger.debug("Insert flow::\n%s" % request.show())
    rv = parent.controller.message_send(request)
    parent.assertTrue(rv != -1, "Error installing flow mod")
    do_barrier(parent.controller)

def error_verify(parent, exp_type, exp_code):
    """
    Receive an error msg and verify if it is as expected

    @param parent Must implement controller, assertEqual
    @param exp_type Expected error type
    @param exp_code Expected error code
    """
    (response, raw) = parent.controller.poll(ofp.OFPT_ERROR, 2)
    parent.assertTrue(response is not None, 'No error message received')

    if (exp_type is None) or (exp_code is None):
        parent.logger.debug("Parametrs are not sufficient")
        return

    parent.assertEqual(exp_type, response.type,
                       'Error message type mismatch: ' +
                       str(exp_type) + " != " +
                       str(response.type))
    parent.assertEqual(exp_code, response.code,
                       'Error message code mismatch: ' +
                       str(exp_code) + " != " +
                       str(response.code))

def get_match_value( exp_list = [], pkt = None):

    if exp_list == None:
        print(" match_fields or exp_list is none!!!")
        return

    field_exist = False
    if pkt == None:
        pkt = testutils.simple_tcp_packet()
    match_field_src = parse.packet_to_flow_match(pkt)
    match_ls = match_list()
    for member in exp_list:
        for item in match_field_src.tlvs:
            if item.field == member.field:
                member.value = item.value
                field_exist = True
                break
        if field_exist or member.field == ofp.OFPXMT_OFB_METADATA:
            match_ls.add(member)
            field_exist = False
    return match_ls

def packet_to_exact_flow_match(pkt = None, pkt_metadata = None, table_id = EX_ACL_TABLE, ing_port = None):

    if pkt == None:
        pkt = simple_tcp_packet();
    if ing_port == None:
        if table_id == WC_SERV_TABLE or table_id == WC_ALL_TABLE:
            print("Error : in port not setted, default port 0 has been set!!!")
        ing_port = 0

    metadata_val = 0
    metadata_msk = None
    if pkt_metadata is not None:
        metadata_val = pkt_metadata['metadata_val']
        metadata_msk = pkt_metadata['metadata_msk']

    if table_id == EX_ACL_TABLE or table_id == WC_ACL_TABLE:
        match1 = match.eth_type(value = 0)
        match2 = match.ip_proto(value = 0)
        match3 = match.ipv4_src(value = 0)
        match4 = match.ipv4_dst(value = 0)
        match5 = match.ipv6_src(value = 0)
        match6 = match.ipv6_dst(value = 0)
        match7 = match.tcp_src(value = 0)
        match8 = match.tcp_dst(value = 0)
        match9 = match.udp_src(value = 0)
        match10 = match.udp_dst(value = 0)
        match11 = match.sctp_src(value = 0)
        match12 = match.sctp_dst(value = 0)
        match_ls = get_match_value([match1, match2, match3, match4, match5, match6,
                                        match7, match8, match9, match10, match11, match12], pkt)

    elif table_id == WC_SERV_TABLE:
        match1 = match.in_port(value = ing_port)
        match2 = match.metadata(value = metadata_val, mask = metadata_msk)
        match3 = match.eth_dst(value = [0,0,0,0,0,0])
        match4 = match.eth_type(value = 0)
        match5 = match.vlan_vid(value =ofp.OFPVID_NONE)
        match6 = match.ip_dscp(value =0)
        match_ls = get_match_value([match1, match2, match3, match4, match5, match6], pkt)

    elif table_id == EX_L2_TABLE:
        match1 = match.metadata(value = metadata_val)
        match2 = match.eth_dst(value = [0,0,0,0,0,0])
        match3 = match.eth_src(value = [0,0,0,0,0,0])
        match_ls = get_match_value([match1, match2, match3], pkt)

    elif table_id == EX_VLAN_TABLE:
        match1 = match.metadata(value = metadata_val)
        match2 = match.vlan_vid(value =ofp.OFPVID_NONE)
        match3 = match.vlan_pcp(value = 0)
        match_ls = get_match_value([match1, match2, match3], pkt)

    elif table_id == EX_MPLS_TABLE:
        match1 = match.metadata(value = metadata_val)
        match2 = match.eth_type(value = 0)
        match3 = match.mpls_label(value = 0)
        match4 = match.mpls_tc(value =0)
        match_ls = get_match_value([match1, match2, match3, match4], pkt)

    elif table_id == EX_L3_TABLE:
        match1 = match.metadata(value = metadata_val)
        match2 = match.eth_type(value = 0)
        match3 = match.ipv4_src(value = 0)
        match4 = match.ipv4_dst(value = 0)
        match5 = match.ipv6_src(value = 0)
        match6 = match.ipv6_dst(value = 0)
        match_ls = get_match_value([match1, match2, match3, match4, match5, match6], pkt)

    elif table_id == WC_L3_TABLE:
        match1 = match.metadata(value = metadata_val, mask = metadata_msk)
        match2 = match.eth_type(value = 0)
        match3 = match.ipv4_src(value = 0)
        match4 = match.ipv4_dst(value = 0)
        match5 = match.ipv6_src(value = 0)
        match6 = match.ipv6_dst(value = 0)
        match_ls = get_match_value([match1, match2, match3, match4, match5, match6], pkt)

    elif table_id == EX_ICMP_TABLE:
        match1 = match.metadata(value = metadata_val)
        match2 = match.eth_type(value = 0)
        match3 = match.ip_proto(value = 0)
        match4 = match.icmpv4_type(value = 0)
        match5 = match.icmpv4_code(value = 0)
        match6 = match.icmpv6_type(value = 0)
        match7 = match.icmpv6_code(value = 0)
        match_ls = get_match_value([match1, match2, match3, match4,match5, match6, match7], pkt)

    elif table_id == WC_ALL_TABLE:
        match1 = match.in_port(value = ing_port)
        match2 = match.metadata(value = metadata_val, mask = metadata_msk)
        match_ls = parse.packet_to_flow_match(pkt)
        match_ls.add(match1)
        match_ls.add(match2)

    else:
        match_ls = match_list()

    return match_ls

def flow_match_test_port_pair(parent, ing_port, egr_port, match_ls=None,
                              wildcards=0, mask=None,
                              dl_vlan=-1, pkt=None, exp_pkt=None,
                              apply_action_list=None, table_id = 0, check_expire=False):
    """
    Flow match test on single TCP packet

    Run test with packet through switch from ing_port to egr_port
    See flow_match_test for parameter descriptions
    """

    parent.logger.info("Pkt match test: " + str(ing_port) + " to " + str(egr_port))
    parent.logger.debug("  WC: " + hex(wildcards) + " vlan: " + str(dl_vlan) +
                    " expire: " + str(check_expire))
    if pkt is None:
        if dl_vlan >= 0 and dl_vlan != -1:
            pkt = simple_tcp_packet(vlan_tags=[{'vid': dl_vlan}])
        else:
            pkt = simple_tcp_packet()

    if mask is not None:
        match_ls = parse.packet_to_flow_match(pkt)
        parent.assertTrue(match_ls is not None, "Flow match from pkt failed")

        idx = 0
        eth_src_index = 0
        eth_dst_index = 0
        ipv4_src_index = 0
        ipv4_dst_index = 0

        for obj in match_ls.items:
            if obj.field == ofp.OFPXMT_OFB_ETH_SRC:
                eth_src_index = idx
            if obj.field == ofp.OFPXMT_OFB_ETH_DST:
                eth_dst_index = idx
            if obj.field == ofp.OFPXMT_OFB_IPV4_SRC:
                ipv4_src_index = idx
            if obj.field == ofp.OFPXMT_OFB_IPV4_DST:
                ipv4_dst_index = idx
            idx = idx + 1

        match_ls.items[eth_src_index] = match.eth_src(match_ls.items[eth_src_index].value,mask = mask['eth_src'])
        match_ls.items[eth_dst_index] = match.eth_dst(match_ls.items[eth_dst_index].value,mask = mask['eth_dst'])
        match_ls.items[ipv4_src_index] = match.ipv4_src(match_ls.items[ipv4_src_index].value,mask = mask['ipv4_src'])
        match_ls.items[ipv4_dst_index] = match.ipv4_dst(match_ls.items[ipv4_dst_index].value,mask = mask['ipv4_dst'])
        for i in range(ofp.OFP_ETH_ALEN):
            match_ls.items[eth_src_index].value[i] = match_ls.items[eth_src_index].value[i] & mask['eth_src'][i]
            match_ls.items[eth_dst_index].value[i] = match_ls.items[eth_dst_index].value[i] & mask['eth_dst'][i]
        match_ls.items[ipv4_src_index].value = match_ls.items[ipv4_src_index].value & mask['ipv4_src']
        match_ls.items[ipv4_dst_index].value = match_ls.items[ipv4_dst_index].value & mask['ipv4_dst']
        #print(match_ls.show())

        pkt[Ether].src = ""
        pkt[Ether].dst = ""
        str_nw_src = ""
        str_nw_dst = ""

        for i in range(ofp.OFP_ETH_ALEN):
            dl_src = match_ls.items[eth_src_index].value[i] | (~mask['eth_src'][i] & 0xFF)
            dl_dst = match_ls.items[eth_dst_index].value[i] | (~mask['eth_dst'][i] & 0xFF)
            if i == 0 and (dl_src & 0x01):
                dl_src &= 0xfe
            pkt[Ether].src += hex(dl_src)
            pkt[Ether].dst += hex(dl_dst)
            if i != ofp.OFP_ETH_ALEN - 1:
                pkt[Ether].src += ":"
                pkt[Ether].dst += ":"

        nw_src = match_ls.items[ipv4_src_index].value | (~mask['ipv4_src'] & 0xFFFFFFFF)
        nw_dst = match_ls.items[ipv4_dst_index].value | (~mask['ipv4_dst'] & 0xFFFFFFFF)
        for i in [24, 16, 8, 0]:
            str_nw_src += str((nw_src >> i) & 0xFF)
            str_nw_dst += str((nw_dst >> i) & 0xFF)
            if i != 0:
                str_nw_src += "."
                str_nw_dst += "."
        pkt[IP].src = str_nw_src
        pkt[IP].dst = str_nw_dst

    delete_all_flows(parent.controller,parent.logger)
    set_table_config(parent, table_id)

    request = flow_msg_create(parent, pkt, ing_port=ing_port,
                              match_fields=match_ls,
                              wildcards=wildcards, egr_port=egr_port,
                              action_list=apply_action_list,
                              table_id = table_id)
    flow_msg_install(parent, request)

    parent.logger.debug("Send packet: " + str(ing_port) + " to " + str(egr_port))
    parent.dataplane.send(ing_port, str(pkt))

    if exp_pkt is None:
        exp_pkt = pkt
    receive_pkt_verify(parent, egr_port, exp_pkt)

    if check_expire:
        #@todo Not all HW supports both pkt and byte counters
        flow_removed_verify(parent, request, pkt_count=1, byte_count=len(pkt))

def flow_match_test(parent, port_map, match_ls=None, wildcards=0,
                    mask=None, dl_vlan=-1, pkt=None,
                    exp_pkt=None, apply_action_list=None,
                    table_id=0, check_expire=False,  max_test=0):
    """
    Run flow_match_test_port_pair on all port pairs

    @param max_test If > 0 no more than this number of tests are executed.
    @param parent Must implement controller, dataplane, assertTrue, assertEqual
    and logger
    @param pkt If not None, use this packet for ingress
    @param match_ls If not None, use this value in flow_mod
    @param wildcards For flow match entry
    @param mask DL/NW address bit masks as a dictionary. If set, it is tested
    against the corresponding match fields with the opposite values
    @param dl_vlan If not -1, and pkt is None, create a pkt w/ VLAN tag
    @param exp_pkt If not None, use this as the expected output pkt; els use pkt
    @param action_list Additional actions to add to flow mod
    @param check_expire Check for flow expiration message
    """
    of_ports = port_map.keys()
    of_ports.sort()
    parent.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    test_count = 0

    for ing_idx in range(len(of_ports)):
        ingress_port = of_ports[ing_idx]
        for egr_idx in range(len(of_ports)):
            if egr_idx == ing_idx:
                continue
            egress_port = of_ports[egr_idx]
            flow_match_test_port_pair(parent, ingress_port, egress_port,
                                      match_ls=match_ls, wildcards=wildcards,
                                      dl_vlan=dl_vlan, mask=mask,
                                      pkt=pkt, exp_pkt=exp_pkt,
                                      apply_action_list=apply_action_list,
                                      table_id=table_id,
                                      check_expire=check_expire)
            test_count += 1
            if (max_test > 0) and (test_count >= max_test):
                parent.logger.info("Ran " + str(test_count) + " tests; exiting")
                return

def flow_match_test_port_pair_vlan(parent, ing_port, egr_port, wildcards=0,
                                   dl_vlan=-1, dl_vlan_pcp=0,
                                   dl_vlan_type=ETHERTYPE_VLAN,
                                   dl_vlan_int=-1, dl_vlan_pcp_int=0,
                                   vid_match=ofp.OFPVID_NONE, pcp_match=0,
                                   exp_vid=-1, exp_pcp=0,
                                   exp_vlan_type=ETHERTYPE_VLAN,
                                   match_exp=True,
                                   add_tag_exp=False,
                                   exp_msg=ofp.OFPT_FLOW_REMOVED,
                                   exp_msg_type=0, exp_msg_code=0,
                                   pkt=None, exp_pkt=None,
                                   action_list=None,
                                   inst_app_flag=WRITE_ACTIONS_INSTRUCTION,
                                   table_id=None,
                                   check_expire=False):
    """
    Flow match test for various vlan matching patterns on single TCP packet

    Run test with packet through switch from ing_port to egr_port
    See flow_match_test_vlan for parameter descriptions
    """
    parent.logger.info("Pkt match test: " + str(ing_port) + " to " + str(egr_port))
    parent.logger.debug("  WC: " + hex(wildcards) + " vlan: " + str(dl_vlan) +
                    " expire: " + str(check_expire))
    if pkt is None:
        if dl_vlan >= 0  and dl_vlan != -1:
            if dl_vlan_int >= 0 and dl_vlan_int != -1:
                pkt = simple_tcp_packet(
                        vlan_tags=[{'type': dl_vlan_type, 'vid': dl_vlan, 'pcp': dl_vlan_pcp},
                                   {'vid': dl_vlan_int, 'pcp': dl_vlan_pcp_int}])
            else:
                pkt = simple_tcp_packet(
                        vlan_tags=[{'type': dl_vlan_type, 'vid': dl_vlan, 'pcp': dl_vlan_pcp}])
        else:
            pkt = simple_tcp_packet()

    if exp_pkt is None:
        if exp_vid >= 0 and exp_vid != -1:
            if add_tag_exp:
                if dl_vlan >= 0 and dl_vlan != -1:
                    if dl_vlan_int > 0 and dl_vlan_int != -1:
                        exp_pkt = simple_tcp_packet(
                                    vlan_tags=[{'type': exp_vlan_type, 'vid': exp_vid, 'pcp': exp_pcp},
                                               {'type': dl_vlan_type, 'vid': dl_vlan, 'pcp': dl_vlan_pcp},
                                               {'vid': dl_vlan_int, 'pcp': dl_vlan_pcp_int}])
                    else:
                        exp_pkt = simple_tcp_packet(
                                    vlan_tags=[{'type': exp_vlan_type, 'vid': exp_vid, 'pcp': exp_pcp},
                                               {'type': dl_vlan_type, 'vid': dl_vlan, 'pcp': dl_vlan_pcp}])
                else:
                    exp_pkt = simple_tcp_packet(
                                vlan_tags=[{'type': exp_vlan_type, 'vid': exp_vid, 'pcp': exp_pcp}])
            else:
                if dl_vlan_int >= 0:
                    exp_pkt = simple_tcp_packet(
                                vlan_tags=[{'type': exp_vlan_type, 'vid': exp_vid, 'pcp': exp_pcp},
                                           {'vid': dl_vlan_int, 'pcp': dl_vlan_pcp_int}])

                else:
                    exp_pkt = simple_tcp_packet(
                                vlan_tags=[{'type': exp_vlan_type, 'vid': exp_vid, 'pcp': exp_pcp}])
        else:
            #subtract action
            if dl_vlan_int >= 0:
                exp_pkt = simple_tcp_packet(
                            vlan_tags=[{'vid': dl_vlan_int, 'pcp': dl_vlan_pcp_int}])
            else:
                exp_pkt = simple_tcp_packet()

    if table_id is None:
        table_id = WC_ALL_TABLE
        if vid_match != ofp.OFPVID_PRESENT:
            if wildcards & (1 << ofp.OFPXMT_OFB_VLAN_VID) == 0:
                if wildcards & (1 << ofp.OFPXMT_OFB_VLAN_PCP) == 0:
                    table_id = EX_VLAN_TABLE
        if action_list is not None:
            if dl_vlan == -1:
                table_id = EX_ACL_TABLE

    match_pkt = simple_tcp_packet()

    match_fields = packet_to_exact_flow_match(match_pkt, None, table_id, ing_port)
    parent.assertTrue(match is not None, "Flow match from pkt failed")

    if wildcards & (1 << ofp.OFPXMT_OFB_VLAN_VID):
        if vid_match != ofp.OFPVID_NONE:
            obj = match.vlan_vid(vid_match, ofp.OFPVID_PRESENT)
            match_fields.add(obj)
    else:
        if vid_match != ofp.OFPVID_NONE and vid_match != ofp.OFPVID_PRESENT:
            obj = match.vlan_vid(vid_match + ofp.OFPVID_PRESENT)
            match_fields.add(obj)
        else:
            obj = match.vlan_vid(vid_match)
            match_fields.add(obj)

    if not (wildcards & (1 << ofp.OFPXMT_OFB_VLAN_PCP)):
        obj = match.vlan_pcp(pcp_match)
        match_fields.add(obj)

    #for obj in match_fields.items:
        #if obj.field == ofp.OFPXMT_OFB_VLAN_VID:
            #obj.value = vid_match
        #if obj.field == ofp.OFPXMT_OFB_VLAN_PCP:
            #obj.value = pcp_match

    #match.dl_vlan = vid_match
    #match.dl_vlan_pcp = pcp_match
    #match.wildcards = wildcards
    delete_all_flows(parent.controller,parent.logger)
    set_table_config(parent, table_id)
    request = flow_msg_create(parent, pkt, ing_port=ing_port,
                              wildcards=wildcards,
                              match_fields=match_fields,
                              egr_port=egr_port,
                              action_list=action_list,
                              inst_app_flag=inst_app_flag,
                              table_id=table_id)
    #########Open if to debug##########
    #print(request.show())
    #print("++++++++++++++++++++++++++pkt++++++++++++++++++++++")
    #print(str(pkt).encode('hex'))

    flow_msg_install(parent, request)

    parent.logger.debug("Send packet: " + str(ing_port) + " to " + str(egr_port))
    parent.logger.debug("Sent:" + str(pkt).encode('hex'))
    parent.dataplane.send(ing_port, str(pkt))

    if match_exp:
        receive_pkt_verify(parent, egr_port, exp_pkt)
        if check_expire:
            #@todo Not all HW supports both pkt and byte counters
            flow_removed_verify(parent, request, pkt_count=1, byte_count=len(pkt))

        else:
            parent.logger.debug("Receive packet from egr_port " + str(egr_port))

    else:
        if exp_msg is ofp.OFPT_FLOW_REMOVED:
            if check_expire:
                flow_removed_verify(parent, request, pkt_count=0, byte_count=0)
        elif exp_msg is ofp.OFPT_ERROR:
            error_verify(parent, exp_msg_type, exp_msg_code)
        else:
            parent.assertTrue(0, "Rcv: Unexpected Message: " + str(exp_msg))

        (_, rcv_pkt, _) = parent.dataplane.poll(timeout=1)
        parent.assertFalse(rcv_pkt is not None, "Packet on dataplane")

def flow_match_test_vlan(parent, port_map, wildcards=0,
                         dl_vlan=-1, dl_vlan_pcp=0, dl_vlan_type=ETHERTYPE_VLAN,
                         dl_vlan_int=-1, dl_vlan_pcp_int=0,
                         vid_match=ofp.OFPVID_NONE, pcp_match=0,
                         exp_vid=-1, exp_pcp=0,
                         exp_vlan_type=ETHERTYPE_VLAN,
                         match_exp=True,
                         add_tag_exp=False,
                         exp_msg=ofp.OFPT_FLOW_REMOVED,
                         exp_msg_type=0, exp_msg_code=0,
                         pkt=None, exp_pkt=None,
                         action_list=None,
                         inst_app_flag=WRITE_ACTIONS_INSTRUCTION,
                         table_id=None,
                         check_expire=False,
                         max_test=0):
    """
    Run flow_match_test_port_pair on all port pairs

    @param max_test If > 0 no more than this number of tests are executed.
    @param parent Must implement controller, dataplane, assertTrue, assertEqual
    and logger
    @param wildcards For flow match entry
    @param dl_vlan If not -1, and pkt is not None, create a pkt w/ VLAN tag
    @param dl_vlan_pcp VLAN PCP associated with dl_vlan
    @param dl_vlan_type VLAN ether type associated with dl_vlan
    @param dl_vlan_int If not -1, create pkt w/ Inner Vlan tag
    @param dl_vlan_pcp_int VLAN PCP associated with dl_vlan_2nd
    @param vid_match Matching value for VLAN VID field
    @param pcp_match Matching value for VLAN PCP field
    @param exp_vid Expected VLAN VID value. If -1, no VLAN expected
    @param exp_vlan_type Expected VLAN ether type
    @param exp_pcp Expected VLAN PCP value
    @param match_exp Set whether packet is expected to receive
    @param add_tag_exp If True, expected_packet has an additional vlan tag,
    If not, expected_packet's vlan tag is replaced as specified
    @param exp_msg Expected message
    @param exp_msg_type Expected message type associated with the message
    @param exp_msg_code Expected message code associated with the msg_type
    @param pkt If not None, use this packet for ingress
    @param exp_pkt If not None, use this as the expected output pkt
    @param action_list Additional actions to add to flow mod
    @param check_expire Check for flow expiration message
    """
    of_ports = port_map.keys()
    of_ports.sort()
    parent.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    test_count = 0

    for ing_idx in range(len(of_ports)):
        ingress_port = of_ports[ing_idx]
        for egr_idx in range(len(of_ports)):
            if egr_idx == ing_idx:
                continue
            egress_port = of_ports[egr_idx]
            flow_match_test_port_pair_vlan(parent, ingress_port, egress_port,
                                           wildcards=wildcards,
                                           dl_vlan=dl_vlan,
                                           dl_vlan_pcp=dl_vlan_pcp,
                                           dl_vlan_type=dl_vlan_type,
                                           dl_vlan_int=dl_vlan_int,
                                           dl_vlan_pcp_int=dl_vlan_pcp_int,
                                           vid_match=vid_match,
                                           pcp_match=pcp_match,
                                           exp_vid=exp_vid,
                                           exp_pcp=exp_pcp,
                                           exp_vlan_type=exp_vlan_type,
                                           exp_msg=exp_msg,
                                           exp_msg_type=exp_msg_type,
                                           exp_msg_code=exp_msg_code,
                                           match_exp=match_exp,
                                           add_tag_exp=add_tag_exp,
                                           pkt=pkt, exp_pkt=exp_pkt,
                                           action_list=action_list,
                                           inst_app_flag=inst_app_flag,
                                           table_id=table_id,
                                           check_expire=check_expire)
            test_count += 1
            if (max_test > 0) and (test_count >= max_test):
                parent.logger.info("Ran " + str(test_count) + " tests; exiting")
                return

def test_param_get(config, key, default=None):
    """
    Return value passed via test-params if present

    @param config The configuration structure for OFTest
    @param key The lookup key
    @param default Default value to use if not found

    If the pair 'key=val' appeared in the string passed to --test-params
    on the command line, return val (as interpreted by exec).  Otherwise
    return default value.
    """
    try:
        exec config["test_params"]
    except:
        return default

    s = "val = " + str(key)
    try:
        val = None
        exec s
        return val
    except:
        return default

def action_generate(parent, field_to_mod, mod_field_vals):
    """
    Create an action to modify the field indicated in field_to_mod

    @param parent Must implement, assertTrue
    @param field_to_mod The field to modify as a string name
    @param mod_field_vals Hash of values to use for modified values
    """

    act = None

    if field_to_mod in ['pktlen']:
        return None

    if field_to_mod == 'dl_dst':
        #act = action.action_set_dl_dst()
        #act.dl_addr = parse.parse_mac(mod_field_vals['dl_dst'])
        act = action.action_set_field()
        act.field = match.eth_dst(parse.parse_mac(mod_field_vals['dl_dst']))
    elif field_to_mod == 'dl_src':
        #act = action.action_set_dl_src()
        #act.dl_addr = parse.parse_mac(mod_field_vals['dl_src'])
        act = action.action_set_field()
        act.field = match.eth_src(parse.parse_mac(mod_field_vals['dl_src']))
    elif field_to_mod == 'vlan_tags':
        if len(mod_field_vals['vlan_tags']):
            act = action.action_pop_vlan()
        else:
            pass
#    elif field_to_mod == 'dl_vlan_enable':
#        if not mod_field_vals['dl_vlan_enable']: # Strip VLAN tag
#            act = action.action_pop_vlan()
#        # Add VLAN tag is handled by dl_vlan field
#        # Will return None in this case
    elif field_to_mod == 'dl_vlan':
        #act = action.action_set_vlan_vid()
        #act.vlan_vid = mod_field_vals['dl_vlan']
        act = action.action_set_field()
        act.field = match.vlan_vid(mod_field_vals['dl_vlan']+ofp.OFPVID_PRESENT)
    elif field_to_mod == 'dl_vlan_pcp':
        #act = action.action_set_vlan_pcp()
        #act.vlan_pcp = mod_field_vals['dl_vlan_pcp']
        act = action.action_set_field()
        act.field = match.vlan_pcp(mod_field_vals['dl_vlan_pcp'])
    elif field_to_mod == 'ip_src':
        #act = action.action_set_nw_src()
        #act.nw_addr = parse.parse_ip(mod_field_vals['ip_src'])
        #print(mod_field_vals['ip_src'])
        act = action.action_set_field()
        act.field = match.ipv4_src(parse.parse_ip(mod_field_vals['ip_src']))
    elif field_to_mod == 'ip_dst':
        #act = action.action_set_nw_dst()
        #act.nw_addr = parse.parse_ip(mod_field_vals['ip_dst'])
        act = action.action_set_field()
        act.field = match.ipv4_dst(parse.parse_ip(mod_field_vals['ip_dst']))
    elif field_to_mod == 'ip_dscp':
        #act = action.action_set_nw_tos()
        #act.nw_tos = mod_field_vals['ip_tos']
        act = action.action_set_field()
        act.field = match.ip_dscp(mod_field_vals['ip_dscp'])
    elif field_to_mod == 'ip_ecn':
        act = action.action_set_field()
        act.field = match.ip_ecn(mod_field_vals['ip_ecn'])
    elif field_to_mod == 'tcp_sport':
        act = action.action_set_field()
        act.field = match.tcp_src(mod_field_vals['tcp_sport'])
    elif field_to_mod == 'tcp_dport':
        act = action.action_set_field()
        act.field = match.tcp_dst(mod_field_vals['tcp_dport'])
    else:
        parent.assertTrue(0, "Unknown field to modify: " + str(field_to_mod))

    return act

def pkt_action_setup(parent, start_field_vals={}, mod_field_vals={},
                     mod_fields={}, check_test_params=False):
    """
    Set up the ingress and expected packet and action list for a test

    @param parent Must implement, assertTrue, config hash and logger
    @param start_field_values Field values to use for ingress packet (optional)
    @param mod_field_values Field values to use for modified packet (optional)
    @param mod_fields The list of fields to be modified by the switch in the test.
    @params check_test_params If True, will check the parameters vid, add_vlan
    and strip_vlan from the command line.

    Returns a triple:  pkt-to-send, expected-pkt, action-list
    """

    new_actions = []


    base_pkt_params = {}
    base_pkt_params['dl_dst'] = '00:DE:F0:12:34:56'
    base_pkt_params['dl_src'] = '00:23:45:67:89:AB'
    #base_pkt_params['dl_vlan_enable'] = False
    #base_pkt_params['dl_vlan'] = 2
    #base_pkt_params['dl_vlan_pcp'] = 0
    base_pkt_params['ip_src'] = '192.168.0.1'
    base_pkt_params['ip_dst'] = '192.168.0.2'
    base_pkt_params['ip_dscp'] = 0
    base_pkt_params['ip_ecn'] = 0
    base_pkt_params['tcp_sport'] = 1234
    base_pkt_params['tcp_dport'] = 80
    for keyname in start_field_vals.keys():
        base_pkt_params[keyname] = start_field_vals[keyname]

    mod_pkt_params = {}
    mod_pkt_params['dl_dst'] = '00:21:0F:ED:CB:A9'
    mod_pkt_params['dl_src'] = '00:ED:CB:A9:87:65'
    #mod_pkt_params['dl_vlan_enable'] = False
    #mod_pkt_params['dl_vlan'] = 3
    #mod_pkt_params['dl_vlan_pcp'] = 7
    mod_pkt_params['ip_src'] = '10.20.30.40'
    mod_pkt_params['ip_dst'] = '50.60.70.80'
    mod_pkt_params['ip_dscp'] = 0x3f
    mod_pkt_params['ip_ecn'] = 3
    mod_pkt_params['tcp_sport'] = 4321
    mod_pkt_params['tcp_dport'] = 8765
    for keyname in mod_field_vals.keys():
        mod_pkt_params[keyname] = mod_field_vals[keyname]

    # Check for test param modifications
    strip = False
    if check_test_params:
        add_vlan = test_param_get(parent.config, 'add_vlan')
        strip_vlan = test_param_get(parent.config, 'strip_vlan')
        vid = test_param_get(parent.config, 'vid')

        if add_vlan and strip_vlan:
            parent.assertTrue(0, "Add and strip VLAN both specified")

        if vid:
            base_pkt_params['dl_vlan_enable'] = True
            base_pkt_params['dl_vlan'] = vid
            if 'dl_vlan' in mod_fields:
                mod_pkt_params['dl_vlan'] = vid + 1

        if add_vlan:
            base_pkt_params['dl_vlan_enable'] = False
            mod_pkt_params['dl_vlan_enable'] = True
            mod_pkt_params['pktlen'] = base_pkt_params['pktlen'] + 4
            mod_fields.append('pktlen')
            mod_fields.append('dl_vlan_enable')
            if 'dl_vlan' not in mod_fields:
                mod_fields.append('dl_vlan')
        elif strip_vlan:
            base_pkt_params['dl_vlan_enable'] = True
            mod_pkt_params['dl_vlan_enable'] = False
            mod_pkt_params['pktlen'] = base_pkt_params['pktlen'] - 4
            mod_fields.append('dl_vlan_enable')
            mod_fields.append('pktlen')

    # Build the ingress packet
    ingress_pkt = simple_tcp_packet(**base_pkt_params)

    # Build the expected packet, modifying the indicated fields
    for item in mod_fields:
        base_pkt_params[item] = mod_pkt_params[item]
        act = action_generate(parent, item, mod_pkt_params)
        if act:
            new_actions.append(act)

    expected_pkt = simple_tcp_packet(**base_pkt_params)

    return (ingress_pkt, expected_pkt, new_actions)

def wildcard_all_set(match):
    match.wildcards = OFPFW_ALL
    match.nw_dst_mask = 0xffffffff
    match.nw_src_mask = 0xffffffff
    match.dl_dst_mask = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    match.dl_src_mask = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    match.metadata_mask = 0xffffffffffffffff

def skip_message_emit(parent, s):
    """
    Print out a 'skipped' message to stderr

    @param s The string to print out to the log file
    @param parent Must implement config and logger objects
    """
    global skipped_test_count

    skipped_test_count += 1
    parent.logger.info("Skipping: " + s)
    if parent.config["dbg_level"] < logging.WARNING:
        sys.stderr.write("(skipped) ")
    else:
        sys.stderr.write("(S)")

def echo_verify(parent, data=None):
    """
        send a echo message w/o data
        verify the two xids and two data are same
    """
    request = message.echo_request()
    if data is not None:
        request.data = data
    response, _ = parent.controller.transact(request)
    parent.assertTrue(response is not None,
                     'response is none')
    parent.assertEqual(response.header.type, ofp.OFPT_ECHO_REPLY,
                     'response is not echo_reply')
    parent.assertEqual(request.header.xid, response.header.xid,
                     'response xid != request xid')
    if data is not None:
        parent.assertEqual(data, response.data,
                     'response data does not match request')
    else:
        parent.assertEqual(len(response.data), 0, 'response data non-empty')

def get_config_reply_verify(parent):
    """
        send get_config_request and verify get a OFPT_GET_CONFIG_REPLY message
        return current configs
    """
    request = message.get_config_request()
    response,_ = parent.controller.transact(request)
    parent.assertTrue(response,"Got no get_config_reply to get_config_request")
    parent.assertEqual(response.header.type, ofp.OFPT_GET_CONFIG_REPLY,
                     'response is not get_config_reply')
    flags = response.flags
    miss_send_len = response.miss_send_len
    return (flags, miss_send_len)

def set_config_verify(parent, set_flag=ofp.OFPC_FRAG_NORMAL, max_len=ofp.OFPCML_MAX):
    """
        send set_config message and verify it works
    """
    flags, miss_send_len = get_config_reply_verify(parent)
    if ((miss_send_len == max_len) and (flags == set_flag)):
        parent.logger.info("Warnning: SetConfig value is no change from GetConfigReply")
    request = message.set_config()
    request.flags = set_flag
    request.miss_send_len = max_len
    parent.logger.info("SetConfig: flags is" + str(set_flag))
    parent.logger.info("SetConfig: miss_send_len is" + str(max_len))
    rv = parent.controller.message_send(request)
    parent.assertTrue(rv == 0, "Error sending out message")
    flags, miss_send_len = get_config_reply_verify(parent)
    parent.assertEqual(flags, set_flag,
            'set config failed: ' + str(flags) + '!=' + str(set_flag))
    parent.assertEqual(miss_send_len, max_len,
            'set config failed: ' + str(miss_send_len) + '!=' + str(max_len))

def match_all_generate():
    #match = ofp.ofp_match()
    match_ls = match_list()
    return match_ls

def oxm_match_generate():
    match_ls = match_list()
    return match_ls

def simple_tcp_packet_w_mpls(
                      dl_dst='00:01:02:03:04:05',
                      dl_src='00:06:07:08:09:0a',
                      mpls_type=0x8847,
                      mpls_label=-1,
                      mpls_tc=0,
                      mpls_ttl=64,
                      mpls_label_int=-1,
                      mpls_tc_int=0,
                      mpls_ttl_int=32,
                      mpls_label_ext=-1,
                      mpls_tc_ext=0,
                      mpls_ttl_ext=128,
                      ip_src='192.168.0.1',
                      ip_dst='192.168.0.2',
                      ip_dscp=0,
                      ip_ecn=0,
                      ip_ttl=192,
                      tcp_sport=1234,
                      tcp_dport=80
                      ):
    """
    Return a simple dataplane TCP packet w/wo MPLS tags

    Supports a few parameters:
    @param len Length of packet in bytes w/o CRC
    @param dl_dst Destinatino MAC
    @param dl_src Source MAC
    @param mpls_type MPLS type as ether type
    @param mpls_label MPLS LABEL if not -1
    @param mpls_tc MPLS TC
    @param mpls_ttl MPLS TTL
    @param mpls_label_int Inner MPLS LABEL if not -1. The shim will be added
    inside of mpls_label shim.
    @param mpls_tc_int Inner MPLS TC
    @param mpls_ttl_int Inner MPLS TTL
    @param mpls_label_ext External MPLS LABEL if not -1. The shim will be
    added outside of mpls_label shim
    @param mpls_tc_ext External MPLS TC
    @param mpls_ttl_ext External MPLS TTL
    @param ip_src IP source
    @param ip_dst IP destination
    @param ip_tos IP ToS
    @param tcp_dport TCP destination port
    @param ip_sport TCP source port

    Generates a simple MPLS/IP/TCP request.  Users
    shouldn't assume anything about this packet other than that
    it is a valid ethernet/IP/TCP frame.
    """

    mpls_tags = []

    if mpls_label_ext >= 0:
        mpls_tags.append({'type': mpls_type, 'label': mpls_label_ext, 'tc': mpls_tc_ext, 'ttl': mpls_ttl_ext})

    if mpls_label >= 0:
        mpls_tags.append({'type': mpls_type, 'label': mpls_label, 'tc': mpls_tc, 'ttl': mpls_ttl})

    if mpls_label_int >= 0:
        mpls_tags.append({'type': mpls_type, 'label': mpls_label_int, 'tc': mpls_tc_int, 'ttl': mpls_ttl_int})

    pkt = simple_tcp_packet(dl_dst=dl_dst,
                            dl_src=dl_src,
                            mpls_tags=mpls_tags,
                            ip_src=ip_src,
                            ip_dst=ip_dst,
                            ip_dscp=0,
                            ip_ecn=0,
                            ip_ttl=ip_ttl,
                            tcp_sport=tcp_sport,
                            tcp_dport=tcp_dport)
    return pkt

def flow_match_test_port_pair_mpls(parent, ing_port, egr_port, wildcards=0,
                                   mpls_type=0x8847,
                                   mpls_label=-1, mpls_tc=0,mpls_ttl=64,
                                   mpls_label_int=-1, mpls_tc_int=0,
                                   mpls_ttl_int=32,
                                   ip_ttl=192,
                                   exp_mpls_type=0x8847,
                                   exp_mpls_label=-1, exp_mpls_tc=0,
                                   exp_mpls_ttl=64,
                                   exp_mpls_ttl_int=32,
                                   exp_ip_ttl=192,
                                   label_match=0, tc_match=0,
                                   dl_type_match=ETHERTYPE_MPLS,
                                   match_exp=True,
                                   add_tag_exp=False,
                                   exp_msg=ofp.OFPT_FLOW_REMOVED,
                                   exp_msg_type=0, exp_msg_code=0,
                                   pkt=None,
                                   exp_pkt=None, action_list=None,
                                   check_expire=False, tag_mpls=0,table_id=EX_MPLS_TABLE):
    """
    Flow match test on single packet w/ MPLS tags

    Run test with packet through switch from ing_port to egr_port
    See flow_match_test for parameter descriptions
    """
    parent.logger.info("Pkt match test: " + str(ing_port) + " to " + str(egr_port))
    parent.logger.debug("  WC: " + hex(wildcards) + " MPLS: " +
                    str(mpls_label) + " expire: " + str(check_expire))

    if pkt is None:
        pkt = simple_tcp_packet_w_mpls(mpls_type=mpls_type,
                                       mpls_label=mpls_label,
                                       mpls_tc=mpls_tc,
                                       mpls_ttl=mpls_ttl,
                                       mpls_label_int=mpls_label_int,
                                       mpls_tc_int=mpls_tc_int,
                                       mpls_ttl_int=mpls_ttl_int,
                                       ip_ttl=ip_ttl)

    if exp_pkt is None:
        if add_tag_exp:
            exp_pkt = simple_tcp_packet_w_mpls(
                                           mpls_type=exp_mpls_type,
                                           mpls_label_ext=exp_mpls_label,
                                           mpls_tc_ext=exp_mpls_tc,
                                           mpls_ttl_ext=exp_mpls_ttl,
                                           mpls_label=mpls_label,
                                           mpls_tc=mpls_tc,
                                           mpls_ttl=mpls_ttl,
                                           mpls_label_int=mpls_label_int,
                                           mpls_tc_int=mpls_tc_int,
                                           mpls_ttl_int=exp_mpls_ttl_int,
                                           ip_ttl=exp_ip_ttl)
        else:
            if (exp_mpls_label < 0) and (mpls_label_int >= 0):
                exp_pkt = simple_tcp_packet_w_mpls(
                                           mpls_type=mpls_type,
                                           mpls_label=mpls_label_int,
                                           mpls_tc=mpls_tc_int,
                                           mpls_ttl=exp_mpls_ttl_int,
                                           ip_ttl=exp_ip_ttl)
            else:
                exp_pkt = simple_tcp_packet_w_mpls(
                                           mpls_type=exp_mpls_type,
                                           mpls_label=exp_mpls_label,
                                           mpls_tc=exp_mpls_tc,
                                           mpls_ttl=exp_mpls_ttl,
                                           mpls_label_int=mpls_label_int,
                                           mpls_tc_int=mpls_tc_int,
                                           mpls_ttl_int=exp_mpls_ttl_int,
                                           ip_ttl=exp_ip_ttl)
    wildcards = (OFPFW_ALL & ~( (1<< ofp.OFPXMT_OFB_ETH_TYPE) | (1 << ofp.OFPXMT_OFB_MPLS_LABEL) | (1<< ofp.OFPXMT_OFB_MPLS_TC))) | wildcards
    #print("%x" % wildcards)
    #print(pkt.show())

    """
    match = parse.packet_to_flow_match(pkt)
    parent.assertTrue(match is not None, "Flow match from pkt failed")

    match.mpls_label = label_match
    match.mpls_tc = tc_match
    match.wildcards = wildcards

    match.dl_type = dl_type_match
    match.nw_tos = 0
    match.nw_proto = 0
    match.nw_src = 0
    match.nw_src_mask = 0xFFFFFFFF
    match.nw_dst = 0
    match.nw_dst_mask = 0xFFFFFFFF
    match.tp_src = 0
    match.tp_dst = 0
    """

    pkt_mpls = simple_tcp_packet_w_mpls(mpls_type=mpls_type,
                                       mpls_label=label_match,
                                       mpls_tc=tc_match,
                                       mpls_ttl=mpls_ttl,
                                       mpls_label_int=mpls_label_int,
                                       mpls_tc_int=mpls_tc_int,
                                       mpls_ttl_int=mpls_ttl_int,
                                       ip_ttl=ip_ttl)
    #print("tag_mpls:"+str(tag_mpls))
    if (tag_mpls == 1)or(tag_mpls==2):
        match_ls = parse.packet_to_flow_match(pkt_mpls)
    else:
        match_ls = parse.packet_to_flow_match(pkt)
    #match_ls = parse.packet_to_flow_match(pkt)
    #print(match_ls.show())

    if wildcards & (1<< ofp.OFPXMT_OFB_MPLS_LABEL) == 0:
        for obj in match_ls.items:
            if obj.field == ofp.OFPXMT_OFB_ETH_TYPE:
                if tag_mpls == 2:
                   obj.value = 0x0800
            if obj.field == ofp.OFPXMT_OFB_MPLS_LABEL:
                obj.value = label_match
                break;
    else:
        for i in range(len(match_ls.items)):
            if match_ls.items[i].field == ofp.OFPXMT_OFB_ETH_TYPE:
                if tag_mpls == 2:
                   match_ls.items[i].value = 0x0800
            if match_ls.items[i].field == ofp.OFPXMT_OFB_MPLS_LABEL:
                del match_ls.items[i]
                break

    if wildcards & (1<< ofp.OFPXMT_OFB_MPLS_TC) == 0:
        for obj in match_ls.items:
            if obj.field == ofp.OFPXMT_OFB_ETH_TYPE:
                if tag_mpls == 2:
                   obj.value = 0x0800
            if obj.field == ofp.OFPXMT_OFB_MPLS_TC:
                obj.value = tc_match
                break;
    else:
        for i in range(len(match_ls.items)):
            if match_ls.items[i].field == ofp.OFPXMT_OFB_ETH_TYPE:
                if tag_mpls == 2:
                   match_ls.items[i].value = 0x0800
            if match_ls.items[i].field == ofp.OFPXMT_OFB_MPLS_TC:
                del match_ls.items[i]
                break

    #for obj in match_ls.items:
    #        if obj.field == ofp.OFPXMT_OFB_ETH_TYPE:
    #            obj.value = dl_type_match


    #print(match_ls.show())
    request = flow_msg_create(parent, pkt, ing_port=ing_port,
                              wildcards=wildcards,
                              match_fields=match_ls,
                              egr_port=egr_port,
                              action_list=action_list,
                              table_id=table_id)
    delete_all_flows(parent.controller,parent.logger)
    set_table_config(parent, EX_MPLS_TABLE)
    flow_msg_install(parent, request)

    parent.logger.debug("Send packet: " + str(ing_port) + " to " + str(egr_port))
    #parent.logger.debug(str(pkt).encode("hex"))
    parent.dataplane.send(ing_port, str(pkt))

    if match_exp:
        receive_pkt_verify(parent, egr_port, exp_pkt)
        if check_expire:
            #@todo Not all HW supports both pkt and byte counters
            flow_removed_verify(parent, request, pkt_count=1, byte_count=len(pkt))
    else:
        if exp_msg == ofp.OFPT_FLOW_REMOVED:
            if check_expire:
                flow_removed_verify(parent, request, pkt_count=0, byte_count=0)
        elif exp_msg == ofp.OFPT_ERROR:
            error_verify(parent, exp_msg_type, exp_msg_code)
        else:
            parent.assertTrue(0, "Rcv: Unexpected Message: " + str(exp_msg))
        (_, rcv_pkt, _) = parent.dataplane.poll(timeout=1)
        parent.assertFalse(rcv_pkt is not None, "Packet on dataplane")

def flow_match_test_mpls(parent, port_map, wildcards=0,
                         mpls_type=0x8847,
                         mpls_label=-1, mpls_tc=0, mpls_ttl=64,
                         mpls_label_int=-1, mpls_tc_int=0, mpls_ttl_int=32,
                         ip_ttl = 192,
                         label_match=0, tc_match=0,
                         dl_type_match=ETHERTYPE_MPLS,
                         exp_mpls_type=0x8847,
                         exp_mpls_label=-1, exp_mpls_tc=0, exp_mpls_ttl=64,
                         exp_mpls_ttl_int=32,
                         exp_ip_ttl=192,
                         match_exp=True,
                         add_tag_exp=False,
                         exp_msg=ofp.OFPT_FLOW_REMOVED,
                         exp_msg_type=0, exp_msg_code=0,
                         pkt=None,
                         exp_pkt=None, action_list=None, check_expire=False,
                         max_test=0, tag_mpls=0):
    """
    Run flow_match_test_port_pair on all port pairs

    @param max_test If > 0 no more than this number of tests are executed.
    @param parent Must implement controller, dataplane, assertTrue, assertEqual
    and logger
    @param wildcards For flow match entry
    @param mpls_type MPLS type
    @param mpls_label If not -1 create a pkt w/ MPLS tag
    @param mpls_tc MPLS TC associated with MPLS label
    @param mpls_ttl MPLS TTL associated with MPLS label
    @param mpls_label_int If not -1 create a pkt w/ Inner MPLS tag
    @param mpls_tc_int MPLS TC associated with Inner MPLS label
    @param mpls_ttl_int MPLS TTL associated with Inner MPLS label
    @param ip_ttl IP TTL
    @param label_match Matching value for MPLS LABEL field
    @param tc_match Matching value for MPLS TC field
    @param exp_mpls_label Expected MPLS LABEL value. If -1, no MPLS expected
    @param exp_mpls_tc Expected MPLS TC value
    @param exp_mpls_ttl Expected MPLS TTL value
    @param exp_mpls_ttl_int Expected Inner MPLS TTL value
    @param ip_ttl Expected IP TTL
    @param match_exp Set whether packet is expected to receive
    @param add_tag_exp If True, expected_packet has an additional MPLS shim,
    If not expected_packet's MPLS shim is replaced as specified
    @param exp_msg Expected message
    @param exp_msg_type Expected message type associated with the message
    @param exp_msg_code Expected message code associated with the msg_type
    @param pkt If not None, use this packet for ingress
    @param exp_pkt If not None, use this as the expected output pkt; els use pkt
    @param action_list Additional actions to add to flow mod
    @param check_expire Check for flow expiration message
    """
    of_ports = port_map.keys()
    of_ports.sort()
    parent.assertTrue(len(of_ports) > 1, "Not enough ports for test")
    test_count = 0

    for ing_idx in range(len(of_ports)):
        ingress_port = of_ports[ing_idx]
        for egr_idx in range(len(of_ports)):
            if egr_idx == ing_idx:
                continue
            egress_port = of_ports[egr_idx]
            flow_match_test_port_pair_mpls(parent, ingress_port, egress_port,
                                      wildcards=wildcards,
                                      mpls_type=mpls_type,
                                      mpls_label=mpls_label,
                                      mpls_tc=mpls_tc,
                                      mpls_ttl=mpls_ttl,
                                      mpls_label_int=mpls_label_int,
                                      mpls_tc_int=mpls_tc_int,
                                      mpls_ttl_int=mpls_ttl_int,
                                      ip_ttl=ip_ttl,
                                      label_match=label_match,
                                      tc_match=tc_match,
                                      dl_type_match=dl_type_match,
                                      exp_mpls_type=exp_mpls_type,
                                      exp_mpls_label=exp_mpls_label,
                                      exp_mpls_tc=exp_mpls_tc,
                                      exp_mpls_ttl=exp_mpls_ttl,
                                      exp_mpls_ttl_int=exp_mpls_ttl_int,
                                      exp_ip_ttl=exp_ip_ttl,
                                      match_exp=match_exp,
                                      exp_msg=exp_msg,
                                      exp_msg_type=exp_msg_type,
                                      exp_msg_code=exp_msg_code,
                                      add_tag_exp=add_tag_exp,
                                      pkt=pkt, exp_pkt=exp_pkt,
                                      action_list=action_list,
                                      check_expire=check_expire,
                                      tag_mpls=tag_mpls)
            test_count += 1
            if (max_test > 0) and (test_count >= max_test):
                parent.logger.info("Ran " + str(test_count) + " tests; exiting")
                return

def flow_stats_get(parent, match_fields = None, table_id = ofp.OFPTT_ALL):
    """ Get the flow_stats from the switch
    Test the response to make sure it's really a flow_stats object
    """
    request = message.flow_stats_request()
    request.out_port = ofp.OFPP_ANY
    request.out_group = ofp.OFPG_ANY
    request.table_id = table_id
    if match_fields != None:
        request.match_fields = match_fields
    response, _ = parent.controller.transact(request, timeout=2)
    parent.assertTrue(response is not None, "Did not get response")
    parent.assertTrue(isinstance(response,message.flow_stats_reply),
                      "Expected a flow_stats_reply, but didn't get it")
    return response

def ofmsg_send(parent, msg):
    """
    controller send msg to switch
    @param ctrl The controller object for the test
    @param logger Logging object
    """
    parent.logger.info("Sending ofp message.")
    parent.logger.debug(msg.show())
    rv = parent.controller.message_send(msg)
    parent.assertTrue(rv != -1, "Controller failed to send msg to switch")
    do_barrier(parent.controller)
    return rv

def write_output(parent, set_id, egr_port, ing_port=None, ip_src=MT_TEST_IP, match_fields=None, clear_table=False):
    """
    Make flow_mod of Write_action instruction of Output
    """
    #genarate matach file automately,fengqiang00107390
    pkt = simple_tcp_packet(ip_src= ip_src)
    request = flow_msg_create(parent, pkt, None, ing_port, match_fields, egr_port=egr_port, inst_app_flag=WRITE_ACTIONS_INSTRUCTION, table_id=set_id)
    flow_msg_install(parent, request, clear_table=clear_table)
    #print(request.show())


def write_goto(parent, set_id, next_id, ing_port=None, ip_src=MT_TEST_IP, add_inst=None, clear_tag=True):
    """
    Make flow_mod of Goto table instruction
    """
    pkt = simple_tcp_packet(ip_src= ip_src)
    inst = instruction.instruction_goto_table()
    inst.table_id = next_id

    inst_ls = [inst]
    if add_inst is not None:
        inst_ls.append(add_inst)

    request = flow_msg_create(parent, pkt, ing_port=ing_port, instruction_list=inst_ls, inst_app_flag=WRITE_ACTIONS_INSTRUCTION, table_id=set_id)
    flow_msg_install(parent, request, clear_table=clear_tag)


def write_goto_action(parent, set_id, next_id, act, ing_port=None, ip_src=MT_TEST_IP, clear_tag=True):
    """
    Make Goto instruction with/without write_action
    """
    inst = instruction.instruction_write_actions()
    parent.assertTrue(inst.actions.add(act), "Can't add action")
    write_goto(parent, set_id, next_id, ing_port, ip_src=ip_src, add_inst=inst, clear_tag=clear_tag)


def write_goto_output(parent, set_id, next_id, egr_port, ing_port=None, ip_src=MT_TEST_IP):
    """
    Make flow_mod of Goto table and Write_action instruction of Output
    """
    act = action.action_output()
    act.port = egr_port
    write_goto_action(parent, set_id, next_id, act, ing_port, ip_src=ip_src)


def apply_output(parent, set_id, egr_port, ing_port=None, ip_src=MT_TEST_IP, match_fields=None):
    """
    Make flow_mod of Write_action instruction of Output
    """
    #genarate matach file automately,fengqiang00107390
    pkt = simple_tcp_packet(ip_src= ip_src)
    request = flow_msg_create(parent, pkt, None, ing_port, match_fields, egr_port=outport, inst_app_flag=APPLY_ACTIONS_INSTRUCTION, table_id=set_id)
    flow_msg_install(parent, request)


def apply_goto(parent, set_id, next_id, ing_port=None, ip_src=MT_TEST_IP, inst_ls=None):
    """
    Make flow_mod of Goto table instruction
    """
    #genarate matach file automately,fengqiang00107390
    pkt = simple_tcp_packet(ip_src= ip_src)
    inst = instruction.instruction_goto_table()
    inst.table_id = next_id
    if inst_ls is None:
        inst_ls = []
    parent.assertTrue(inst_ls.append(inst), "Can't add inst")

    request = flow_msg_create(parent, pkt, ing_port=ing_port, instruction_list=inst_ls, inst_app_flag=APPLY_ACTIONS_INSTRUCTION, table_id=set_id)
    flow_msg_install(parent, request)


def apply_goto_action(parent,  set_id, next_id, act, ing_port=None, ip_src=MT_TEST_IP):
    """
    Make Goto instruction with/without write_action
    """
    inst = instruction.instruction_apply_actions()
    inst_ls =[inst]
    parent.assertTrue(inst.actions.add(act), "Can't add action")
    apply_goto(parent, set_id, next_id, ing_port, ip_src=ip_src, inst_ls=inst_ls)


def apply_goto_output(parent, set_id, next_id, egr_port, ing_port=None, ip_src=MT_TEST_IP):
    """
    Make flow_mod of Goto table and Write_action instruction of Output
    """
    act = action.action_output()
    act.port = egr_port
    apply_goto_action(parent, set_id, next_id, act, ing_port, ip_src=ip_src)

#fengqiang remove func check_dp&check_ctl from multi-table to here
def reply_check_dp(parent, ip_src=MT_TEST_IP, tcp_sport=10,
               exp_pkt=None, ing_port=0, egr_port=1):
    """
    Receiving and received packet check on dataplane
    """
    pkt = simple_tcp_packet(ip_src=ip_src, tcp_sport=tcp_sport)
    parent.dataplane.send(ing_port, str(pkt))
    if exp_pkt is None:
        exp_pkt = pkt
    receive_pkt_verify(parent, egr_port, exp_pkt)

#fengqiang remove func check_dp&check_ctl from multi-table to here
def reply_check_ctrl(parent, ip_src=MT_TEST_IP, tcp_sport=10,
                 exp_pkt=None, ing_port=0):
    """
    Receiving and received packet check on controlplane
    """
    pkt = simple_tcp_packet(ip_src=ip_src, tcp_sport=tcp_sport)
    parent.dataplane.send(ing_port, str(pkt))
    if exp_pkt is None:
        exp_pkt = pkt
    packetin_verify(parent, exp_pkt)

