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

#ifndef FLOW_entry_H
#define FLOW_entry_H 1


#include <stdbool.h>
#include <sys/types.h>
#include "datapath.h"
#include "list.h"
#include "hlist.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl-messages.h"
#include "timeval.h"

#include "timer_wheel.h"
/****************************************************************************
 * Implementation of a flow table entry.
 ****************************************************************************/
#define BITMAP_CONTAINS(map, submap)    ((map & submap) == submap)

struct path_ref_entry
{
    struct list node;
    struct ofp_path *path;
};

struct flow_entry {
    struct hlist_node        hash_node;
    struct list              match_node;  /* list nodes in flow table lists. */
    struct list              hard_node;
    struct list              idle_node;
    //struct list              l2o_node[PATH_BRCM_MAX];    /* openflow to logic node */
    struct list              o2l_head;    /* openflow to logic head */

    struct datapath         *dp;
    struct flow_table       *table;
    struct ofl_flow_stats   *stats;
    struct ofl_match_header *match; /* Original match structure is stored in stats;
                                       this one is a modified version, which reflects
                                       1.2 matching rules. */
    unsigned long long int                 created;  /* time the entry was created at. */
    unsigned long long int                 remove_at; /* time the entry should be removed at
                                           due to its hard timeout. */
    unsigned long long int                 last_used; /* last time the flow entry matched a packet */
    unsigned long long int                 read_hardware; /*last time read the hard ware counter.*/
    bool                     send_removed; /* true if a flow removed should be sent
                                              when removing a flow. */

    bool                     no_pkt_count; /* true if doesn't keep track of flow matched packets*/
    bool                     no_byt_count; /* true if doesn't keep track of flow matched bytes*/
    struct list              group_refs;  /* list of groups referencing the flow. */
    struct list              meter_refs;  /* list of meters referencing the flow. */
    struct timer            *entry_timer;

    unsigned long long int                 modify_time;
    struct list              path_refs;
    unsigned int                 flow_id;

    unsigned int                 hash;
    unsigned char                 *key;                        /*  以字节流的方式存放match fields */
    int                      key_len;

    //unsigned long long int                old_byte_count;
    //unsigned long long int                cycle;
    //unsigned long long int                add_count;
    //bool                    count_pass;
    //bool                    add_timeout_list;
    //bool                    age_flag;
    unsigned short int                path_type;
    unsigned long long int                old_packet_count;
};

struct packet;

enum E_DEL_REASON
{
    /*Hard time out */
    HARD_TIMEOUT,

    /* idle time out */
    IDLE_TIMEOUT,

    /* flow replace */
    FLOW_REPLACE,

    /* flow delete*/
    FLOW_DELETE,

    /* flow modify*/
    FLOW_MODIFY,

    /* flow destroy */
    FLOW_DESTROY,

    /* group destroy */
    GROUP_DESTROY,

    METER_DESTROY

};

/* Returns true if the flow entry matches the match in the flow mod message. */
bool
flow_entry_matches(struct flow_entry *entry, struct ofl_msg_flow_mod *mod, bool strict, bool check_cookie);

/* Returns true if the flow entry overlaps with the match in the flow mod message. */
bool
flow_entry_overlaps(struct flow_entry *entry, struct ofl_msg_flow_mod *mod);

/* Replaces the current instructions of the entry with the given ones. */
void
flow_entry_replace_instructions(struct flow_entry *entry,
                                      size_t instructions_num,
                                      struct ofl_instruction_header **instructions);

/* Checks if the entry should time out because of its idle timeout. If so, the
 * packet is freed, flow removed message is generated, and true is returned. */
bool
flow_entry_idle_timeout(struct flow_entry *entry);

/* Checks if the entry should time out because of its hard timeout. If so, the
 * packet is freed, flow removed message is generated, and true is returned. */
bool
flow_entry_hard_timeout(struct flow_entry *entry);

/* Returns true if the flow entry has an output action to the given port. */
bool
flow_entry_has_out_port(struct flow_entry *entry, unsigned int port);

/* Returns true if the flow entry has a group action to the given group. */
bool
flow_entry_has_out_group(struct flow_entry *entry, unsigned int group);

/* Updates the time fields of the flow entry statistics. Used before generating
 * flow statistics messages. */
void
flow_entry_update(struct flow_entry *entry);

/* Creates a flow entry. */
struct flow_entry *
flow_entry_create(struct datapath *dp, struct flow_table *table, struct ofl_msg_flow_mod *mod);

/* Destroys a flow entry. */
void
flow_entry_destroy(struct flow_entry *entry);

/* Removes a flow entry with the given reason. A flow removed message is sent if needed. */
void
flow_entry_remove(struct flow_entry *entry, unsigned char reason);

bool flow_entry_match_outport(struct flow_entry *entry, struct ofl_msg_flow_mod *mod);

int flow_entry_inst_scan(struct flow_entry *entry,
                         void *param,
                         int (* callback)(struct ofl_instruction_header *inst, void *usr_data));

int flow_entry_action_scan(struct ofl_instruction_actions *inst,
                           void *param,
                           int (* callback)(struct ofl_action_header *act, void *usr_data));

int flow_bucket_action_scan(struct ofl_bucket * bucket,
                           void *param,
                           int (* callback)(struct ofl_action_header *act, void *usr_data));

int alta_logic_entry_remove(struct flow_entry *entry,enum E_DEL_REASON e_reason);
void alta_logic_set_entry_count(struct flow_entry *entry,unsigned long long int packet_count,unsigned long long int byte_count);
void alta_logic_get_entry_count(struct flow_entry *entry,unsigned long long int *p_pkt_counter,unsigned long long int *p_byte_counter);
int alta_logic_entry_count(struct flow_entry *entry);

bool flow_entry_instruction_equal(struct flow_entry *new_entry,struct flow_entry *old_entry);

bool flow_entry_equal(struct flow_entry *new_entry,struct flow_entry *old_entry);

char * flow_entry_to_string(struct flow_entry *entry);

void flow_entry_print(struct flow_entry *entry,FILE *stream);

void alta_entry_delete_dump(enum E_DEL_REASON e_reason);
void flow_entry_del_path_ref(struct ofp_path *path, struct flow_entry *entry);

void flow_entry_add_path_refs(struct ofp_path *path,struct flow_entry *entry);


bool flow_entry_action_equal(struct datapath *dp,
                                         int actions_num,
                                         unsigned long long int modify_time,
                                         struct ofl_action_header **actions,
                                         struct ofl_action_header **old_actions);
void del_group_refs(struct flow_entry *entry);
#if 0
void flow_entry_delete(struct datapath *datap,int del_count);
#endif

bool alta_logic_entry_exist(struct flow_entry *entry);
bool is_exact_flow_entry(struct flow_table *table,struct ofl_match  *match,
                                            unsigned short int cmd_type);
int alta_logic_entry_debug(struct flow_entry *entry);

#endif /* FLOW_entry_H 1 */
