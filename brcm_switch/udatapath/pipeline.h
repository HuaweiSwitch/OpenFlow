/* Copyright (c) 2011, TrafficLab, Ericsson Research, Hungary
 * Copyright (c) 2012, CPqD, Brazil
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the Ericsson Research nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef PIPELINE_H
#define PIPELINE_H 1


#include "datapath.h"
#include "packet.h"
#include "flow_table.h"
#include "oflib/ofl.h"
#include "oflib/ofl-messages.h"



struct sender;
enum BRCM_PATH
{
    /* represent all openflow path */
    PATH_OPENFLOW,

    /* L2 forwarding based on mac address table MATCH : VLAN+DMAC */
    PATH_B_L2,
    
    /* L2 forwarding based on acl table MATCH : VLAN+SMAC+DMAC+ETHTYPE */
    PATH_A_L1,

    /* L3(IPV4/IPV6) forwarding based on L3 table and acl table
       include L3_TABLE_T3H, L3_DEFIP_T3R, L3_IFP_T3R MATCH : DstIp+MASK
       Note by fengqiang,PATH_F_T3R split as DIF and ACL two class
    */
    PATH_F_T3H,
    PATH_F_T3R_DIF,
    PATH_F_T3R_ACL,

    /* L2/L3 IP multicast forwarding on multicast table MATCH : SrcIp+DstIP+L3_INTF */
    PATH_G_T3M,

    /* L2(IPV4) forwarding based on acl table MATCH : VLAN+SrcIP+DstIP+SrcPort+DstPort */
    PATH_C_T1_L2,

    /* L3(IPV4) forwarding based on acl table MATCH : VLAN+SrcIP+DstIP+SrcPort+DstPort */
    PATH_C_T1_L3,

    /* L2 forwarding based on acl table MATCH : DstIP */
    PATH_D_T2,

    /* L2(IPV4) forwarding based on acl table MATCH : all fields in L2 and L3 headers
       Modify name from PATH_E_L3_L2 to PATH_E_L2_L3 by fengqiang
    */
    PATH_E_L2_L3,

    /* L3(IPV4) forwarding based on acl table MATCH : all fields in L2 and L3 headers */
    PATH_E_L3_L3,

    PATH_BRCM_MAX
};

enum table_class
{
    OPENFLOW_TABLE,
    LOGIC_TABLE,
    BRCM_MAC,
    BRCM_FP,
    BRCM_L3_TABLE,
    BRCM_L3_DEFIP,
    BRCM_L2L3_T3M,
    ALTA_ARP,
    CLASS_TUPLE5,
    TABLE_CLASS_MAX
};

#define INV_VLAN_ID   0xFFFF
#define INV_VLAN_PCP  0xFF

#define TABLE_CLASS_ID(table_class, table_id)   (((table_class) << 16) | ((table_id) & 0xff))

/* A pipeline structure */
struct pipeline {
    struct datapath    *dp;
    struct flow_table  *tables[PIPELINE_TABLES];

    struct flow_table  *miss_table;
};


struct path_meter
{
    void *meter_entry;
    int   policer_id;
    void *pol_cfg;
};

struct path_desc
{
    unsigned long long int match;
    unsigned int write_actions;
    unsigned int apply_actions;
    unsigned long long int write_setfields;
    unsigned long long int apply_setfields;
    unsigned int instructions;
};

struct path_entry
{
    struct list node;
    int table_class_id;
    int clear_actions;      /* include clear actions? */
    struct path_desc desc;
    void *entry;            /* openflow entry or physic entry */
};

struct ofp_path
{
    struct list node;
    unsigned int hash;
    unsigned int *key;
    struct path_entry **path_entry;
};

struct path
{
    struct list head;
    enum BRCM_PATH path_type;
    struct path_desc desc;

    struct path_meter meter;
};

struct path_contex
{
    struct path *path;
    struct packet *pkt;
    unsigned long long int provi_mac;
    int mcast_flag;
    int mcast_group;
    int out_glort;
    unsigned short int ivlan;
    unsigned short int evlan;
    unsigned char ipri;
    unsigned char epri;
    unsigned char dscp;
    unsigned char ecn;

    /****mpls****/
    /* 1.label swapping */
    unsigned int group_id1;     /* for phase 1 [popping] */
    unsigned int group_id2;     /* for phase 2 [pushing] */
    /* 2.common */
    unsigned int impls;
    unsigned int empls[4];/*0xfffffff*/
    unsigned short int  mpls_push_ethtype[4];
    unsigned short int  mpls_pop_ethtype[4];
    unsigned char impls_cnt;
    unsigned char empls_cnt;
    bool     loopback;
    bool     l2_push;

    /****physic layer****/
    /* if the existing hardware entry hit the packet before downloading any hardware entries */
    unsigned short int  exist;        
    unsigned short int  tbl1_cond;    /* for chained tables */
    unsigned int  ecmp_group;   /* for L3 routing */
    unsigned int  mcast_ecmp_group;
    bool      aging;
    void *data_type;
//    fm_ipAddr arp;
    unsigned char usr_data[1024]; /* use static memory for simple */
};


/* Creates a pipeline. */
struct pipeline *
pipeline_create(struct datapath *dp);

/* Processes a packet in the pipeline. */
void
pipeline_process_packet(struct pipeline *pl, struct packet *pkt);


/* Handles a flow_mod message. */
ofl_err
pipeline_handle_flow_mod(struct pipeline *pl, struct ofl_msg_flow_mod *msg,
                         const struct sender *sender);

/* Handles a table_mod message. */
ofl_err
pipeline_handle_table_mod(struct pipeline *pl,
                          struct ofl_msg_table_mod *msg,
                          const struct sender *sender);

/* Handles a flow stats request. */
ofl_err
pipeline_handle_stats_request_flow(struct pipeline *pl,
                                   struct ofl_msg_multipart_request_flow *msg,
                                   const struct sender *sender);

/* Handles a table stats request. */
ofl_err
pipeline_handle_stats_request_table(struct pipeline *pl,
                                    struct ofl_msg_multipart_request_header *msg,
                                    const struct sender *sender);

/* Handles a table feature  request. */
ofl_err
pipeline_handle_stats_request_table_features_request(struct pipeline *pl,
                                    struct ofl_msg_multipart_request_header *msg,
                                    const struct sender *sender);

/* Handles an aggregate stats request. */
ofl_err
pipeline_handle_stats_request_aggregate(struct pipeline *pl,
                                  struct ofl_msg_multipart_request_flow *msg,
                                  const struct sender *sender);


/* Commands pipeline to check if any flow in any table is timed out. */
void
pipeline_timeout(struct pipeline *pl);

/* Detroys the pipeline. */
void
pipeline_destroy(struct pipeline *pl);

void send_packet_to_controller(struct pipeline *pl, struct packet *pkt, unsigned char table_id, unsigned char reason);

int  pi_pkt2ofp_send2controller(struct pipeline *pl, struct packet *pkt, unsigned char table_id, unsigned char reason);

void pipeline_del_path_ref(struct flow_entry *fe);

#endif /* PIPELINE_H */
