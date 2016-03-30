"""
Basic capabilities and capacities tests

"""

import logging

import unittest
import oftest.controller as controller
import oftest.cstruct as ofp
import oftest.message as message
import oftest.dataplane as dataplane
import oftest.action as action
import oftest.parse as parse
import basic

from testutils import *

#@var caps_port_map Local copy of the configuration map from OF port
# numbers to OS interfaces
caps_port_map = None
#@var caps_logger Local logger object
caps_logger = None
#@var caps_config Local copy of global configuration data
caps_config = None

#Define max_entries:
MAX_ENTRY_EX_TABLE = 10000
MAX_ENTRY_WC_TABLE = 10000

# For test priority
test_prio = {}

def test_set_init(config):
    """
    Set up function for caps test classes

    @param config The configuration dictionary; see oft
    """

    global caps_port_map
    global caps_logger
    global caps_config

    caps_logger = logging.getLogger("caps")
    caps_logger.info("Initializing caps test set")
    caps_port_map = config["port_map"]
    caps_config = config

def flow_caps_common(obj, is_exact=True):
    """
    The common function for

    @param obj The calling object
    @param is_exact If True, checking exact match; else wildcard
    """

    obj.logger = caps_logger
    obj.config = caps_config
    
    global caps_port_map
    of_ports = caps_port_map.keys()
    of_ports.sort()
    #rv = delete_all_flows(obj.controller, caps_logger)
    #obj.assertEqual(rv, 0, "Failed to delete all flows")
    
    pkt = simple_tcp_packet(ip_src='0.0.0.0',
                                vlan_tags=[{'type': ETHERTYPE_VLAN, 'vid': 2, 'pcp': 7}])
    
    pkt_metadata = {'metadata_val':0x0000000000000000, 'metadata_msk':None}
    
    for ing_port in of_ports:
        break
    if is_exact:
        table_list = [EX_VLAN_TABLE]#, EX_L2_TABLE, EX_VLAN_TABLE, EX_MPLS_TABLE, EX_L3_TABLE, EX_ICMP_TABLE]
        max_entry = MAX_ENTRY_EX_TABLE
    else:
        table_list = [WC_ACL_TABLE]#, WC_SERV_TABLE, WC_L3_TABLE, WC_ALL_TABLE]
        max_entry = MAX_ENTRY_WC_TABLE
    
    for table_idx in table_list:
        #tfeature = message.table_feature_request()
        #response,_ = obj.controller.transact(tfeature, timeout=1)
        #obj.assertTrue(response is not None, "Get tab feature failed")
        #print response.show()
        #for feature in table_features:
        #    if feature.table_id = table_idx:
        #        max_entries = feature.max_entries
        #        break
        #max_entry = response.table_features[table_idx].max_entries
        #print str(max_entry)

        request = flow_msg_create(obj,pkt,pkt_metadata,ing_port,egr_port=ofp.OFPP_IN_PORT,table_id=table_idx)
        #print(request.show())

        count_check = max_entry/10 + 1
        #print(str(count_check))

        tstats = message.table_stats_request()
        #response, pkt = obj.controller.transact(tstats, timeout=2)
        #print(response.show())
        #Make sure we can install at least one flow
        flow_msg_install(obj, request, True)
        flow_count = 1

        caps_logger.info("Table idx: " + str(table_idx))
        caps_logger.info("Check every " + str(count_check) + " inserts")

        while True:
            for member in request.match_fields.tlvs:
                if member.field == ofp.OFPXMT_OFB_IPV4_SRC:
                    if member.value < 1<<32:
                        member.value += 1
                if member.field == ofp.OFPXMT_OFB_VLAN_VID:
                    if member.value < 0x1000:
                        member.value += 1
                if member.field == ofp.OFPXMT_OFB_MPLS_LABEL:
                    if member.value < 0x100000:
                        member.value += 1
                if member.field == ofp.OFPXMT_OFB_METADATA:
                    member.value += 1

            flow_msg_install(obj, request, False)
            flow_count += 1
            #print(flow_count)
            if flow_count % count_check == 0:
                response, pkt = obj.controller.transact(tstats, timeout=2)
                obj.assertTrue(response is not None, "Get tab stats failed")
                #caps_logger.info(response.show())
                #print(response.stats[table_idx].show())
                if table_idx == -1:  # Accumulate for all tables
                    active_flows = 0
                    for stats in response.stats:
                        active_flows += stats.active_count
                else: # Table index to use specified in config
                    active_flows = response.stats[table_idx].active_count
                if active_flows != flow_count:
                    break
        #if active_flows != max_entry:
        if active_flows < max_entry:
            caps_logger.error("RESULT: " + str(max_entry) + " support")
            caps_logger.error("RESULT: " + str(active_flows) + " flows reported")
        error_verify(obj, ofp.OFPET_FLOW_MOD_FAILED, ofp.OFPFMFC_TABLE_FULL)
        #obj.assertTrue(active_flows == max_entry, "active_flows is not full filled")
        obj.assertTrue(active_flows >= max_entry, "active_flows is not fullfill max entry requirement")


class FillTableExact(basic.SimpleProtocol):
    """
    Fill the flow table with exact matches; can take a while

    Fill table until no more flows can be added.  Report result.
    Increment the source IP address.  Assume the flow table will
    fill in less than 4 billion inserts

    To check the number of flows in the tables is expensive, so
    it's only done periodically.  This is controlled by the
    count_check variable.

    A switch may have multiple tables.  The default behaviour
    is to count all the flows in all the tables.  By setting
    the parameter "caps_table_idx" in the configuration array,
    you can control which table to check.
    """
    def runTest(self):
        caps_logger.info("Running " + str(self))
        flow_caps_common(self)

# mark these tests as optional

class FillTableWC(basic.SimpleProtocol):
    """
    Fill the flow table with wildcard matches

    Fill table using wildcard entries until no more flows can be
    added.  Report result.
    Increment the source IP address.  Assume the flow table will
    fill in less than 4 billion inserts

    To check the number of flows in the tables is expensive, so
    it's only done periodically.  This is controlled by the
    count_check variable.

    A switch may have multiple tables.  The default behaviour
    is to count all the flows in all the tables.  By setting
    the parameter "caps_table_idx" in the configuration array,
    you can control which table to check.

    """
    def runTest(self):
        caps_logger.info("Running " + str(self))
        flow_caps_common(self, is_exact=False)
