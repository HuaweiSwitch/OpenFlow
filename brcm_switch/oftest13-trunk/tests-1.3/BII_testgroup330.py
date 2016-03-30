# Copyright (c) 2014, 2015 Beijing Internet Institute(BII)
###Testcases implemented for Openflow 1.3 conformance certification test @Author: Maple Yip

"""
Test suite 330 verifies the correct implementation of the fields contained in each of the following message structs; 
ofp_table_feature_prop_oxm, and oxm_ids.

To satisfy the basic requirements an OpenFlow enabled device must pass test cases 330.20 - 330.120.
"""

import logging
import time
import sys
import pdb

import unittest
import random
from oftest import config
import oftest.controller as controller
import ofp
import oftest.dataplane as dataplane
import oftest.parse as parse
import oftest.base_tests as base_tests
import oftest.illegal_message as illegal_message
import BII_testgroup330

from oftest.oflog import *
from oftest.testutils import *
from time import sleep
from loxi.of13.oxm import *



class Testcase_330_20_TableFeaturesWildcards(base_tests.SimpleDataPlane):
    """
    330.20 - Table features wildcards
    Verify that the n_tables ofp_table_stats messages are returned in response to a multipart table request.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 330.20 - Table features wildcards test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        in_port, out_port, = openflow_ports(2)
        table_id=test_param_get("table", 0)
        prop_type=ofp.const.OFPTFPT_WILDCARDS
        reported_oxm_ids = []
        
        req = ofp.message.table_features_stats_request()
        reply = get_stats(self, req)
        self.assertIsNotNone(reply, "Did not receive table features reply.")
        logging.info("Received table features reply")
        for features in reply:
            if features.table_id == table_id:
               for prop in features.properties:
                   if prop.type == prop_type:
                       for ids in prop.oxm_ids:
                           try:
                               reported_oxm_ids.append(oxm.subtypes[ids.value].__name__)
                           except KeyError:
                               logging.warn("Invalid oxm_id reported %d"%ids.value)
                               continue
                   else:
                       continue
                       
        self.assertIsNotNone(reported_oxm_ids, "DUT did not return omx_ids for prop %s"%prop_type)
        
        match = ofp.match()
        actions=[ofp.action.output(port=out_port,max_len=128)]
        instructions=[ofp.instruction.apply_actions(actions=actions)]
        priority = 1000
        req = ofp.message.flow_add(table_id=table_id,
                                   match=match,
                                   buffer_id=ofp.OFP_NO_BUFFER,
                                   instructions=instructions,
                                   priority=priority)
        self.controller.message_send(req)
        reply, _ = self.controller.poll(exp_msg=ofp.OFPT_ERROR, timeout=3)
        self.assertIsNone(reply, "DUT returned an error msg")
        #logging.info("oxm_id that is reported by the DUT tested in match.py")
        for oxm_id in reported_oxm_ids:
            try:
                getattr(ofp.match_field,oxm_id)(self,in_port,out_port)
                
            except AttributeError:
                logging.warn("No method defined for oxm {0}".format(oxm_id))
                continue
        
        
        
class Testcase_330_30_TableFeaturesWriteSetField(base_tests.SimpleDataPlane):
    """
    330.30 - Table features write set fields
    Verify all reported write set field OXMs can be set.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 330.30 - Table features write set fields test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        in_port, out_port, = openflow_ports(2)
        table_id=test_param_get("table", 0)
        prop_type=ofp.const.OFPTFPT_WRITE_SETFIELD
        reported_oxm_ids = []
        
        req = ofp.message.table_features_stats_request()
        reply = get_stats(self, req)
        self.assertIsNotNone(reply, "Did not receive table features reply.")
        logging.info("Received table features reply")
        for features in reply:
            if features.table_id == table_id:
               for prop in features.properties:
                   if prop.type == prop_type:
                       for ids in prop.oxm_ids:
                           try:
                               reported_oxm_ids.append(oxm.subtypes[ids.value].__name__)
                           except KeyError:
                               logging.warn("Invalid oxm_id reported %d"%ids.value)
                               continue
                   else:
                       continue
                       
        self.assertIsNotNone(reported_oxm_ids, "DUT did not return omx_ids for prop %s"%prop_type)
        
        #logging.info("oxm_id that is reported by the DUT tested in write_match.py")
        for oxm_id in reported_oxm_ids:
            try:
                getattr(ofp.write_match,oxm_id)(self,table_id,in_port,out_port,instructions_type="write")
                
            except AttributeError:
                logging.warn("No function defined for oxm %s",oxm_id)
                continue
                
                
                
class Testcase_330_40_TableFeaturesWriteSetFieldMiss(base_tests.SimpleDataPlane):
    """
    330.40 - Table features write set fields miss
    Verify all reported write set field OXMs can be set.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 330.40 - Table features write set fields miss test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        in_port, out_port, = openflow_ports(2)
        table_id=test_param_get("table", 0)
        prop_type=ofp.const.OFPTFPT_WRITE_SETFIELD_MISS
        reported_oxm_ids = []
        
        req = ofp.message.table_features_stats_request()
        reply = get_stats(self, req)
        self.assertIsNotNone(reply, "Did not receive table features reply.")
        logging.info("Received table features reply")
        for features in reply:
            if features.table_id == table_id:
               for prop in features.properties:
                   if prop.type == prop_type:
                       for ids in prop.oxm_ids:
                           try:
                               reported_oxm_ids.append(oxm.subtypes[ids.value].__name__)
                           except KeyError:
                               logging.warn("Invalid oxm_id reported %d"%ids.value)
                               continue
                   else:
                       continue
                       
        for oxm_id in reported_oxm_ids:
            try:
                getattr(ofp.write_match,oxm_id)(self,table_id,in_port,out_port,instructions_type="write",table_miss=True)
                
            except AttributeError:
                logging.warn("No function defined for oxm %s",oxm_id)
                continue
                       

                       
                       
class Testcase_330_50_TableFeaturesApplySetField(base_tests.SimpleDataPlane):
    """
    330.50 - Table features apply set fields
    Verify all reported apply set field OXMs can be set.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 330.50 - Table features apply set fields test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        in_port, out_port, = openflow_ports(2)
        table_id=test_param_get("table", 0)
        prop_type=ofp.const.OFPTFPT_APPLY_SETFIELD
        reported_oxm_ids = []
        
        req = ofp.message.table_features_stats_request()
        reply = get_stats(self, req)
        self.assertIsNotNone(reply, "Did not receive table features reply.")
        logging.info("Received table features reply")
        for features in reply:
            if features.table_id == table_id:
               for prop in features.properties:
                   if prop.type == prop_type:
                       for ids in prop.oxm_ids:
                           try:
                               reported_oxm_ids.append(oxm.subtypes[ids.value].__name__)
                           except KeyError:
                               logging.warn("Invalid oxm_id reported %d"%ids.value)
                               continue
                   else:
                       continue
                       
        for oxm_id in reported_oxm_ids:
            try:
                getattr(ofp.write_match,oxm_id)(self,table_id,in_port,out_port,instructions_type="apply")
                
            except AttributeError:
                logging.warn("No function defined for oxm %s",oxm_id)
                continue
                
                
                
class Testcase_330_60_TableFeaturesApplySetFieldMiss(base_tests.SimpleDataPlane):
    """
    330.60 - Table features apply set fields miss
    Verify all reported apply set field OXMs can be set on a table miss entry.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 330.60 - Table features apply set fields miss test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        in_port, out_port, = openflow_ports(2)
        table_id=test_param_get("table", 0)
        prop_type=ofp.const.OFPTFPT_APPLY_SETFIELD
        reported_oxm_ids = []
        
        req = ofp.message.table_features_stats_request()
        reply = get_stats(self, req)
        self.assertIsNotNone(reply, "Did not receive table features reply.")
        logging.info("Received table features reply")
        for features in reply:
            if features.table_id == table_id:
               for prop in features.properties:
                   if prop.type == prop_type:
                       for ids in prop.oxm_ids:
                           try:
                               reported_oxm_ids.append(oxm.subtypes[ids.value].__name__)
                           except KeyError:
                               logging.warn("Invalid oxm_id reported %d"%ids.value)
                               continue
                   else:
                       continue
                       
        for oxm_id in reported_oxm_ids:
            try:
                getattr(ofp.write_match,oxm_id)(self,table_id,in_port,out_port,instructions_type="apply")
                
            except AttributeError:
                logging.warn("No function defined for oxm %s",oxm_id)
                continue
                
                
                
                
class Testcase_330_70_TableFeaturesMatch(base_tests.SimpleDataPlane):
    """
    330.70 - Table features match
    Verify all reported match OXMs can be matched against.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 330.60 - 330.70 - Table features match test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        in_port, out_port, = openflow_ports(2)
        table_id=test_param_get("table", 0)
        prop_type=ofp.const.OFPTFPT_MATCH
        reported_oxm_ids = []
        
        req = ofp.message.table_features_stats_request()
        reply = get_stats(self, req)
        self.assertIsNotNone(reply, "Did not receive table features reply.")
        logging.info("Received table features reply")
        for features in reply:
            if features.table_id == table_id:
               for prop in features.properties:
                   if prop.type == prop_type:
                       for ids in prop.oxm_ids:
                           try:
                               reported_oxm_ids.append(oxm.subtypes[ids.value].__name__)
                           except KeyError:
                               logging.warn("Invalid oxm_id reported %d"%ids.value)
                               continue
                   else:
                       continue
                       
        for oxm_id in reported_oxm_ids:
            try:
                getattr(ofp.match_field,oxm_id)(self,in_port,out_port,table_id=table_id,match=True,table_miss=True)
                
            except AttributeError:
                logging.warn("No function defined for oxm %s",oxm_id)
                continue
                
                
                
class Testcase_330_80_TableFeaturesMatchandWildcard(base_tests.SimpleDataPlane):
    """
    330.80 - Table features match and wildcard
    Verify all reported match OXMs can be wildcarded, and matched against.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 330.80 - Table features match and wildcard test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        in_port, out_port, = openflow_ports(2)
        table_id=test_param_get("table", 0)
        prop_type=ofp.const.OFPTFPT_MATCH
        reported_oxm_ids = []
        
        req = ofp.message.table_features_stats_request()
        reply = get_stats(self, req)
        self.assertIsNotNone(reply, "Did not receive table features reply.")
        logging.info("Received table features reply")
        for features in reply:
            if features.table_id == table_id:
               for prop in features.properties:
                   if prop.type == prop_type:
                       for ids in prop.oxm_ids:
                           try:
                               reported_oxm_ids.append(oxm.subtypes[ids.value].__name__)
                           except KeyError:
                               logging.warn("Invalid oxm_id reported %d"%ids.value)
                               continue
                   else:
                       continue
                       
        for oxm_id in reported_oxm_ids:
            try:
                getattr(ofp.match_field,oxm_id)(self,in_port,out_port,table_id=table_id,match=True,table_miss=False)
                
            except AttributeError:
                logging.warn("No function defined for oxm %s",oxm_id)
                continue
                
                  
    
    
class Testcase_330_110_TableFeaturesReadOnly(base_tests.SimpleDataPlane):
    """
    330.110 - Table features read only
    Verify that the max_entries field is read only.
    """

    @wireshark_capture
    def runTest(self):
        logging.info("Running 330.110 - Table features read only test")
        logging.info("Delete all flows on DUT")
        rv = delete_all_flows(self.controller)
        self.assertEqual(rv, 0, "Failed to delete all flows")
        
        table_id=test_param_get("table", 0)
        config=test_param_get("config", 2)
        
        req = ofp.message.table_features_stats_request()
        stats = get_stats(self, req)
        self.assertIsNotNone(stats, "Did not receive table features reply.")
        logging.info("Received table features reply")

        max_entries = stats[table_id].max_entries
        stats[table_id].max_entries = stats[table_id].max_entries + 5

        
        req = ofp.message.table_features_stats_request(entries=stats)
        if config == 0:
            self.controller.message_send(req)
            err, _ = self.controller.poll(exp_msg=ofp.const.OFPT_ERROR)
            if err:
                self.assertEqual(err.err_type, ofp.const.OFPET_TABLE_FEATURES_FAILED,
                                 "Error type was not OFPET_TABLE_FEATURES_FAILED.")
                logging.info("Received correct error message type.")
                return
                
            req = ofp.message.table_features_stats_request()
            stats = get_stats(self, req)
            self.assertIsNotNone(stats, "Did not receive table features reply.")

            self.assertEqual(stats[table_id].max_entries, max_entries,
                                     "DUT modified max entries.")
            logging.info("DUT behaviour was correct")
        elif config == 1:
            self.controller.message_send(req)
            err, _ = self.controller.poll(exp_msg=ofp.const.OFPT_ERROR)
            self.assertIsNotNone(err, "Did not receive error message.")
        
            self.assertEqual(err.err_type, ofp.const.OFPET_TABLE_FEATURES_FAILED,
                             "Error type was not OFPET_TABLE_FEATURES_FAILED.")
            self.assertEqual(err.code, ofp.const.OFPTFFC_EPERM,
                             "Error code was not expected OFPTFFC_EPERM.")
            logging.info("Received correct error message.")
        elif config == 2:
            self.controller.message_send(req)
            err, _ = self.controller.poll(exp_msg=ofp.const.OFPT_ERROR)
            self.assertIsNotNone(err, "Did not receive error message.")
        
            self.assertEqual(err.err_type, ofp.const.OFPET_BAD_REQUEST,
                             "Error type was not OFPET_BAD_REQUEST.")
            self.assertEqual(err.code, ofp.const.OFPBRC_BAD_LEN,
                             "Error code was not OFPBRC_BAD_LEN.")
            logging.info("Received correct error message.")
        else:
            raise Exception("Configuration was unknown.")
