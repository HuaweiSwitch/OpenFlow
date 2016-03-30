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

#include <stdbool.h>
#include <stdlib.h>
#include "datapath.h"
#include "dp_actions.h"
#include "dp_capabilities.h"
#include "dp_buffers.h"
#include "flow_table.h"
#include "flow_entry.h"
#include "group_table.h"
#include "group_entry.h"
#include "meter_table.h"
#include "meter_entry.h"
#include "oflib/ofl-messages.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl-actions.h"
#include "oflib/ofl-utils.h"
#include "oflib/oxm-match.h"
#include "oflib/ofl-print.h"
#include "packets.h"
#include "timeval.h"
#include "util.h"
#include "pipeline.h"

#include "rbuff.h"

#include "timer_wheel.h"
#include "flow_entry_exact.h"

#include "vlog.h"
#include "dpal_pub.h"

#define LOG_MODULE VLM_flow_e
#define READ_HW_CYCLE 2

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

typedef struct ofl_match logic_match;
typedef struct ofl_instruction_actions logic_action;


enum physic_path_type
{
      MAC_PATH = 1,
      ROUTER_PATH = 2,
      MCAST_PATH = 4,
      ACL_PATH = 8,
      MIX_PATH  = 15
};

struct path_command
{
    enum physic_path_type path_type;
    unsigned char   reason;
};

struct group_ref_entry {
    struct list   node;
    unsigned int      group_id;
};

struct meter_ref_entry {
    struct list   node;
    unsigned int      meter_id;
};

struct table_count
{
  unsigned long long int packet_count;
  unsigned long long int byte_count;
};

/* get from openflow1.2 */
typedef struct alta_table_desc
{
    unsigned char table_id;        /* Identifier of table. Lower numbered tables
                                are consulted first. */
    unsigned char pad[7];          /* Align to 64-bits. */
    char name[OFP_MAX_TABLE_NAME_LEN];
    unsigned long long int match;          /* Bitmap of (1 << OFPXMT_*) that indicate the
                               fields the table can match on. */
    unsigned long long int wildcards;      /* Bitmap of (1 << OFPXMT_*) wildcards that are
                                supported by the table. */
    unsigned int write_actions;  /* Bitmap of OFPAT_* that are supported
                               by the table with OFPIT_WRITE_ACTIONS. */
    unsigned int apply_actions;  /* Bitmap of OFPAT_* that are supported
                                by the table with OFPIT_APPLY_ACTIONS. */
    unsigned long long int write_setfields;/* Bitmap of (1 << OFPXMT_*) header fields that
                                can be set with OFPIT_WRITE_ACTIONS. */
    unsigned long long int apply_setfields;/* Bitmap of (1 << OFPXMT_*) header fields that
                                unsigned long long int metadata_match;*/
    unsigned long long int metadata_match; /* Bits of metadata table can match. */
    unsigned long long int metadata_write; /* Bits of metadata table can write. */
    unsigned int instructions;   /* Bitmap of OFPIT_* values supported. */
    unsigned int config;         /* Bitmap of OFPTC_* values */
    unsigned int max_entries;    /* Max number of entries supported. */
    unsigned int active_count;   /* Number of active entries. */
    unsigned long long int lookup_count;   /* Number of packets looked up in table. */
    unsigned long long int matched_count;  /* Number of packets that hit table. */
}table_stats;

struct port_vlan
{
    int act;        /* one of enum vlan_act */
    unsigned int port;  /* changed port */
    unsigned short int vlan;  /* changed vlan */
};

typedef struct logic_entry_port_conf
{
    int count;
    struct port_vlan *change;   /* record logic entry changed */
}logic_portcfg;

struct alta_table
{
    struct list head;   /* we can use hmap for physic table, will be optimized later */
    int table_class; /*it is goup id witch multi-table*/
    table_stats stats;
};


struct logic_entry
{
    struct list node;
    struct list o2l_node[10];       /* openflow to logic node */
    //struct list l2o_head;       /* openflow path: logic to openflow map */
    struct list l2p_head;       /* logic to physic map */
    struct alta_table *table;
    logic_match *match;         /* for fast forwarding in software layer */
    logic_action *action;       /* for fast forwarding in software layer */
    logic_portcfg config;       /* for vlan port management */
    void *data_type;
};


static void
init_group_refs(struct flow_entry *entry);


static void
init_meter_refs(struct flow_entry *entry);

static void
del_meter_refs(struct flow_entry *entry);

void flow_entry_print(struct flow_entry *entry,FILE *stream);


bool
flow_entry_has_out_port(struct flow_entry *entry, unsigned int port) {
    size_t i;

    for (i=0; i<entry->stats->instructions_num; i++) {
        if (entry->stats->instructions[i]->type == OFPIT_APPLY_ACTIONS ||
            entry->stats->instructions[i]->type == OFPIT_WRITE_ACTIONS) {
            struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)entry->stats->instructions[i];
            if (dp_actions_list_has_out_port(ia->actions_num, ia->actions, port)) {
                return true;
            }
        }
    }
    return false;
}


bool
flow_entry_has_out_group(struct flow_entry *entry, unsigned int group) {
    size_t i;

    for (i=0; i<entry->stats->instructions_num; i++) {
        if (entry->stats->instructions[i]->type == OFPIT_APPLY_ACTIONS ||
            entry->stats->instructions[i]->type == OFPIT_WRITE_ACTIONS) {
            struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)entry->stats->instructions[i];
            if (dp_actions_list_has_out_group(ia->actions_num, ia->actions, group)) {
                return true;
            }
        }
    }
    return false;
}


bool
flow_entry_matches(struct flow_entry *entry, struct ofl_msg_flow_mod *mod, bool strict, bool check_cookie) {

    if (check_cookie && ((entry->stats->cookie & mod->cookie_mask) != (mod->cookie & mod->cookie_mask))) {
        return false;
    }

    if (strict) {
        return ( (entry->stats->priority == mod->priority) &&
                 match_std_strict((struct ofl_match *)mod->match,
                                (struct ofl_match *)entry->stats->match));
    } else {
        return match_std_nonstrict((struct ofl_match *)mod->match,
                                   (struct ofl_match *)entry->stats->match);
    }
}

bool
flow_entry_overlaps(struct flow_entry *entry, struct ofl_msg_flow_mod *mod) {
        return (entry->stats->priority == mod->priority &&
            match_std_overlap((struct ofl_match *)entry->stats->match,
                                            (struct ofl_match *)mod->match));
}

static struct ofl_instruction_header *find_flow_entry_instruction(struct flow_entry *entry,int type)
{
    int i;
    struct ofl_instruction_header *inst;

    for ( i = 0; i < entry->stats->instructions_num; i++)
    {
        inst = entry->stats->instructions[i];
        if ( inst->type == type)
        {
            return inst;
        }
    }
    return NULL;

}

static struct ofl_action_header *find_flow_entry_action(struct ofl_action_header **actions,int type,int num)
{
    int i;
    struct ofl_action_header *act_entry;

    for (i = 0; i < num; i++)
    {
       act_entry = actions[i];
       if(act_entry->type == type)
       {
           return act_entry;
       }
    }
    return NULL;
}
static struct ofl_action_header *find_flow_entry_set_field(struct ofl_action_header **actions,unsigned int type,
                                                        unsigned int header,int num)
{
    int i;
    struct ofl_action_header *act_entry;
    struct ofl_match_tlv *field ;

    for ( i = 0; i < num; i++ )
    {
       act_entry = actions[i];
       if(act_entry->type == type)
       {
           field = ((struct ofl_action_set_field *)act_entry)->field;
           if(field->header == header)
           {
               return act_entry;
           }
       }
    }
    return NULL;
}


bool flow_entry_action_equal(struct datapath *dp,
                                         int actions_num,
                                         unsigned long long int modify_time,
                                         struct ofl_action_header **actions,
                                         struct ofl_action_header **old_actions)
{
    int i;
    struct ofl_action_header *act_entry;
    (void)dp;
    (void)modify_time;

    for ( i = 0; i< actions_num; i++)
    {
       act_entry =  actions[i];
       switch(act_entry->type)
       {
            case OFPAT_SET_FIELD:
            {
                struct ofl_action_set_field *sf_act;
                struct ofl_action_set_field *old_sf_act;

                sf_act = (struct ofl_action_set_field*)act_entry;

                old_sf_act = (struct ofl_action_set_field*)find_flow_entry_set_field(old_actions,
                                                                    act_entry->type,sf_act->field->header,actions_num);

                if (!old_sf_act || memcmp(sf_act->field->value,old_sf_act->field->value,OXM_LENGTH(sf_act->field->header)))
                {
                    return false;
                }
                break;
            }
            case OFPAT_OUTPUT:
            {
                struct ofl_action_output *o_action ;
                struct ofl_action_output *old_o_action;

                o_action = (struct ofl_action_output *)act_entry;
                old_o_action = (struct ofl_action_output *)find_flow_entry_action(old_actions,
                    act_entry->type,actions_num);

                if (!old_o_action || (o_action->port != old_o_action->port))
                {
                    return false;
                }
                break;
            }
            case OFPAT_PUSH_MPLS:
            case OFPAT_PUSH_VLAN:
            {
                struct ofl_action_push *push_vlan;
                struct ofl_action_push *old_push_vlan;

                push_vlan = (struct ofl_action_push *)act_entry;
                old_push_vlan = (struct ofl_action_push *)find_flow_entry_action(old_actions,
                                      act_entry->type,actions_num);

                if (!old_push_vlan || (push_vlan->ethertype != old_push_vlan->ethertype))
                {
                    return false;
                }
                break;
            }
            case OFPAT_GROUP:
            {
               struct ofl_action_group *act_group;
               struct ofl_action_group *old_act_group;
               /*struct group_entry *g_entry;*/

               act_group = (struct ofl_action_group *)act_entry;
               old_act_group = (struct ofl_action_group *)find_flow_entry_action(old_actions,
                                    act_entry->type,actions_num);

               if(!old_act_group || (act_group->group_id != old_act_group->group_id))
               {
                  return false;
               }

               /*g_entry = group_table_find(dp->groups,old_act_group);
               if (g_entry)
               {
                   if(modify_time < g_entry->modify_time)
                   {
                      return false;
                   }
               }*/
               break;
            }
            case OFPAT_COPY_TTL_IN:
            case OFPAT_COPY_TTL_OUT:
            case OFPAT_SET_MPLS_TTL:
            case OFPAT_DEC_MPLS_TTL:
            case OFPAT_POP_VLAN:
            case OFPAT_POP_MPLS:
            case OFPAT_SET_QUEUE:
            case OFPAT_SET_NW_TTL:
            case OFPAT_DEC_NW_TTL:
            case OFPAT_PUSH_PBB:
            case OFPAT_POP_PBB:
            case OFPAT_PUSH_FHID:
            case OFPAT_EXPERIMENTER:
            {
                break;
            }
            default:
            {
                break;
            }
       }
    }

    return true;
}

static bool flow_entry_match_equal(struct flow_entry *new_entry,struct flow_entry *old_entry)
{

     return ( (new_entry->stats->priority == old_entry->stats->priority) &&
                     match_std_strict((struct ofl_match *)old_entry->stats->match,
                                    (struct ofl_match *)new_entry->stats->match));

}


bool flow_entry_equal(struct flow_entry *new_entry,struct flow_entry *old_entry)
{

    if ( !flow_entry_match_equal(new_entry,old_entry))
    {
        return false;
    }

    if ( !flow_entry_instruction_equal(new_entry,old_entry))
    {
        return false;
    }

    return true;
}

int get_hash_bucket_index(struct flow_table *table,unsigned long long int new_match)
{
    int i;

    for ( i = 0; i < MAX_HASH_BUCKETS_NUM; i++) {
        if (table->hash_match[i] == new_match || table->hash_match[i] == 0) {
            return i;
        }
    }

    if ( i == MAX_HASH_BUCKETS_NUM)
        return -1;
}

bool is_exact_flow_entry(struct flow_table *table,struct ofl_match  *match,
                                     unsigned short int cmd_type)
{
    int         index = 0;
    bool        has_mask = false;
    unsigned long long int    new_match = 0;
    struct  ofl_match_tlv *match_tlv;

    if(table->dp->use_exact_table != true)
        return false;

    if (match->header.length == 0)
        return false;

    HMAP_FOR_EACH(match_tlv, struct ofl_match_tlv, hmap_node, &match->match_fields) {
         has_mask |= OXM_HASMASK(match_tlv->header);
         new_match |= (1ULL) << OXM_FIELD(match_tlv->header);
    }

    if (!has_mask) {
        index = get_hash_bucket_index(table,new_match);
        if (index == -1 )//精确表已满，保存到通配表中
            return false;
        table->cur_index  = index;

        if (cmd_type == OFPFC_ADD)
            table->hash_match[index] = new_match;
        return true;
    }
    else {
        return false;
    }
}

bool flow_entry_instruction_equal(struct flow_entry *new_entry,struct flow_entry *old_entry)
{
    int i;
    struct ofl_instruction_header *inst;
    /*struct ofl_instruction_header *old_inst;*/

    //return false;
    if (new_entry->stats->instructions_num != old_entry->stats->instructions_num)
    {
        return false;
    }

    for (i = 0; i < new_entry->stats->instructions_num; i++)
    {
        inst = new_entry->stats->instructions[i];
        switch (inst->type)
        {
            case OFPIT_GOTO_TABLE:
            {
                 struct ofl_instruction_goto_table *gi;
                 struct ofl_instruction_goto_table *old_gi;
                 gi = (struct ofl_instruction_goto_table *)inst;
                 old_gi = (struct ofl_instruction_goto_table *)find_flow_entry_instruction(old_entry,inst->type);

                 if (!old_gi || (gi->table_id != old_gi->table_id))
                 {
                    return false;
                 }
                 break;
            }
            case OFPIT_WRITE_METADATA:
            {
                 struct ofl_instruction_write_metadata *wi;
                 struct ofl_instruction_write_metadata *old_wi;

                 wi = (struct ofl_instruction_write_metadata *)inst;
                 old_wi = (struct ofl_instruction_write_metadata *)find_flow_entry_instruction(old_entry,inst->type);

                 if (!old_wi || (wi->metadata != old_wi->metadata) || (wi->metadata_mask != old_wi->metadata_mask))
                 {
                    return false;
                 }
                 break;
            }
            case OFPIT_APPLY_ACTIONS:
            case OFPIT_WRITE_ACTIONS:
            {
                struct ofl_instruction_actions *wa = (struct ofl_instruction_actions *)inst;
                struct ofl_instruction_actions *old_wa = (struct ofl_instruction_actions *)find_flow_entry_instruction(old_entry,inst->type);

                if (!old_wa
                    || (wa->actions_num != old_wa->actions_num)
                    || !flow_entry_action_equal(old_entry->dp,wa->actions_num,old_entry->modify_time,
                                                  wa->actions,old_wa->actions))
                {
                    return false;
                }
                break;
            }
            case OFPIT_METER:
            {
                struct ofl_instruction_meter *im;
                struct ofl_instruction_meter *old_im;
                struct meter_entry *m_entry;

                im = (struct ofl_instruction_meter *)inst;
                old_im = (struct ofl_instruction_meter *)find_flow_entry_instruction(old_entry,inst->type);

                if (!old_im || (im->meter_id != old_im->meter_id))
                {
                    return false;
                }

                m_entry =  meter_table_find(old_entry->dp->groups,old_im);
                if ( m_entry != NULL && old_entry->modify_time < m_entry->modify_time)
                {
                  return false;
                }
                break;
            }
            case OFPIT_CLEAR_ACTIONS:
            {
                struct ofl_instruction_header *old_iheader;

                old_iheader = find_flow_entry_instruction(old_entry,inst->type);
                if (!old_iheader)
                {
                    return false;
                }
                break;
            }
            case OFPAT_EXPERIMENTER:
            {
                break;
            }
            default:
            {
                break;
            }
        }
    }
    return true;
}

void
flow_entry_replace_instructions(struct flow_entry *entry,
                                      size_t instructions_num,
                                      struct ofl_instruction_header **instructions) {

    /* TODO Zoltan: could be done more efficiently, but... */
    del_group_refs(entry);
    del_meter_refs(entry);
    OFL_UTILS_FREE_ARR_FUN2(entry->stats->instructions, entry->stats->instructions_num,
                            ofl_structs_free_instruction, entry->dp->exp);

    entry->stats->instructions_num = instructions_num;
    entry->stats->instructions     = instructions;

    init_group_refs(entry);
    init_meter_refs(entry);
}

bool
flow_entry_idle_timeout(struct flow_entry *entry) {
    unsigned long long int packet_count = 0;
    unsigned long long int byte_count = 0;
    bool need_timeout = false;

    if (BITMAP_CONTAINS(entry->path_type, MAC_PATH))
    {
        /* MAC PATH没有ACL统计，通过硬件表自行老化 */
        if (!alta_logic_entry_exist(entry))
        {
            need_timeout = true;
        }
    }
    else if(BITMAP_CONTAINS(entry->path_type, ROUTER_PATH) ||
            BITMAP_CONTAINS(entry->path_type, MCAST_PATH))
    {
        /* ROUTER & MCAST PATH没有ACL统计，且不能自行老化，通过检查hit bit老化 */
        if (alta_logic_entry_exist(entry))
        {
            entry->last_used = time_now_msec();
        }
        else if(time_now_msec() - entry->last_used > ((entry->stats->idle_timeout > 1)?(entry->stats->idle_timeout - 1):entry->stats->idle_timeout) * 1000)
        {
            need_timeout = true;
        }
    }
    else
    {
        /* 其他PATH通过ACL统计判断是否老化 */
        alta_logic_get_entry_count(entry,&packet_count,&byte_count);
        if (entry->stats->packet_count != packet_count)
        {
            entry->last_used = time_now_msec();
            alta_logic_set_entry_count(entry, packet_count, byte_count);
        }
        else if (time_now_msec() - entry->last_used > ((entry->stats->idle_timeout > 1)?(entry->stats->idle_timeout - 1):entry->stats->idle_timeout) * 1000)
        {
            need_timeout = true;
        }
    }

    if(need_timeout)
    {
        alta_logic_entry_remove(entry, IDLE_TIMEOUT);
        if( entry->table->wildcards  == EXACT_TABLE)
        {
            exact_flow_entry_timeout(entry);
        }
        flow_entry_remove(entry, OFPRR_IDLE_TIMEOUT);
    }
    return need_timeout;
}

bool
flow_entry_hard_timeout(struct flow_entry *entry) {
    if (time_now_msec() > entry->remove_at)
    {
        alta_logic_entry_remove(entry,HARD_TIMEOUT);
        if (entry->key_len != 0)
        {
            exact_flow_entry_timeout(entry);
        }
        flow_entry_remove(entry, OFPRR_HARD_TIMEOUT);
        return true;
    }
    return false;
}

void
flow_entry_update(struct flow_entry *entry) {
    entry->stats->duration_sec  =  (time_now_msec() - entry->created) / 1000;
    entry->stats->duration_nsec = ((time_now_msec() - entry->created) % 1000) * 1000;
}

/* Returns true if the flow entry has a reference to the given group. */
static bool
has_group_ref(struct flow_entry *entry, unsigned int group_id) {
    struct group_ref_entry *g;

    LIST_FOR_EACH(g, struct group_ref_entry, node, &entry->group_refs)
    {
        if (g->group_id == group_id) {
            return true;
        }
    }
    return false;
}


void flow_entry_add_path_refs(struct ofp_path *path,struct flow_entry *entry)
{
    struct path_ref_entry *path_e;
    path_e = xmalloc(sizeof(struct path_ref_entry));

    path_e->path = path;
    list_insert(&entry->path_refs, &path_e->node);
}

void flow_entry_del_path_ref(struct ofp_path *path, struct flow_entry *entry)
{
    struct path_ref_entry *f, *next;

    LIST_FOR_EACH_SAFE(f, next, struct path_ref_entry, node, &entry->path_refs)
    {
        if (f->path == path)
        {
            list_remove(&f->node);
            free(f);
        }
    }
}

/* Initializes the group references of the flow entry. */
static void
init_group_refs(struct flow_entry *entry) {
    struct group_ref_entry *e;
    size_t i,j;

    for (i=0; i<entry->stats->instructions_num; i++) {
        if (entry->stats->instructions[i]->type == OFPIT_APPLY_ACTIONS ||
            entry->stats->instructions[i]->type == OFPIT_WRITE_ACTIONS) {
            struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)entry->stats->instructions[i];

            for (j=0; j < ia->actions_num; j++) {
                if (ia->actions[j]->type == OFPAT_GROUP) {
                    struct ofl_action_group *ag = (struct ofl_action_group *)(ia->actions[j]);
                    if (!has_group_ref(entry, ag->group_id)) {
                        struct group_ref_entry *gre = xmalloc(sizeof(struct group_ref_entry));
                        gre->group_id = ag->group_id;
                        list_insert(&entry->group_refs, &gre->node);
                    }
                }
            }
        }
    }

    /* notify groups of the new referencing flow entry */
    LIST_FOR_EACH(e, struct group_ref_entry, node, &entry->group_refs) {
    	struct group_entry *group = group_table_find(entry->dp->groups, e->group_id);
    	if (group != NULL) {
    	    group_entry_add_flow_ref(group, entry);
    	} else {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to access non-existing group(%u), while init_group_refs", e->group_id);
    	}
    }
}

/* Deletes group references from the flow, and also deletes the flow references
 * from the referecenced groups. */
void
del_group_refs(struct flow_entry *entry) {
    struct group_ref_entry *gre, *next;

    LIST_FOR_EACH_SAFE(gre, next, struct group_ref_entry, node, &entry->group_refs)
    {
    	struct group_entry *group = group_table_find(entry->dp->groups, gre->group_id);
    	if (group != NULL)
        {
    	    group_entry_del_flow_ref(group, entry);
    	}
        else
        {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to access non-existing group(%u), while del_group_refs", gre->group_id);
    	}
    	list_remove(&gre->node);
        free(gre);
    }
}


/* Returns true if the flow entry has a reference to the given meter. */
static bool
has_meter_ref(struct flow_entry *entry, unsigned int meter_id) {
    struct meter_ref_entry *m;

    LIST_FOR_EACH(m, struct meter_ref_entry, node, &entry->meter_refs) {
        if (m->meter_id == meter_id) {
            return true;
        }
    }
    return false;
}

/* Initializes the meter references of the flow entry. */
static void
init_meter_refs(struct flow_entry *entry) {
    struct meter_ref_entry *e;
    size_t i;

    for (i=0; i<entry->stats->instructions_num; i++) {
        if (entry->stats->instructions[i]->type == OFPIT_METER ) {
            struct ofl_instruction_meter *ia = (struct ofl_instruction_meter *)entry->stats->instructions[i];

			if (!has_meter_ref(entry, ia->meter_id)) {
				struct meter_ref_entry *mre = xmalloc(sizeof(struct meter_ref_entry));
				mre->meter_id = ia->meter_id;
				list_insert(&entry->meter_refs, &mre->node);
			}

        }
    }

    /* notify meter of the new referencing flow entry */
    LIST_FOR_EACH(e, struct meter_ref_entry, node, &entry->meter_refs) {
    	struct meter_entry *meter = meter_table_find(entry->dp->meters, e->meter_id);
    	if (meter != NULL) {
    		meter_entry_add_flow_ref(meter, entry);
    	} else {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to access non-existing meter(%u).", e->meter_id);
    	}
    }
}

/* Deletes meter references from the flow, and also deletes the flow references
 * from the referecenced groups. */
static void
del_meter_refs(struct flow_entry *entry) {
    struct meter_ref_entry *mre, *next;

    LIST_FOR_EACH_SAFE(mre, next, struct meter_ref_entry, node, &entry->meter_refs) {

    	struct meter_entry *meter = meter_table_find(entry->dp->meters, mre->meter_id);
    	if (meter != NULL) {
    		meter_entry_del_flow_ref(meter, entry);
    	} else {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to access non-existing meter(%u).", mre->meter_id);
    	}
    	list_remove(&mre->node);
        free(mre);
    }
}


struct flow_entry *
flow_entry_create(struct datapath *dp, struct flow_table *table, struct ofl_msg_flow_mod *mod) {
    /*int i;*/
    struct flow_entry *entry;
    unsigned long long int now;

    now = time_now_msec();

    entry = xmalloc(sizeof(struct flow_entry));
    entry->dp    = dp;
    entry->table = table;

    entry->stats = xmalloc(sizeof(struct ofl_flow_stats));

    entry->stats->table_id         = mod->table_id;
    entry->stats->duration_sec     = 0;
    entry->stats->duration_nsec    = 0;
    entry->stats->priority         = mod->priority;
    entry->stats->idle_timeout     = mod->idle_timeout;
    entry->stats->hard_timeout     = mod->hard_timeout;
    entry->stats->cookie           = mod->cookie;
    entry->no_pkt_count = ((mod->flags & OFPFF_NO_PKT_COUNTS) != 0 );
    entry->no_byt_count = ((mod->flags & OFPFF_NO_BYT_COUNTS) != 0 );
    entry->stats->flags = mod->flags;

    if (entry->no_pkt_count)
        entry->stats->packet_count     = 0xffffffffffffffff;
    else
    {
        entry->stats->packet_count     = 0;
        entry->stats->ofp_packet_count = 0;
    }

    if (entry->no_byt_count)
        entry->stats->byte_count       = 0xffffffffffffffff;
    else
    {
        entry->stats->byte_count       = 0;
        entry->stats->ofp_byte_count   = 0;
    }

    entry->stats->match            = mod->match;
    entry->stats->instructions_num = mod->instructions_num;
    entry->stats->instructions     = mod->instructions;
    entry->path_type = 0;
    entry->old_packet_count = 0;
    //entry->age_flag = false;
    entry->match = mod->match; /* TODO: MOD MATCH? */
    entry->key_len = 0;
    entry->created      = now;
    entry->remove_at    = mod->hard_timeout == 0 ? 0
                                  : now + mod->hard_timeout * 1000;
    entry->last_used    = now;
    entry->read_hardware =  now;
    entry->send_removed = ((mod->flags & OFPFF_SEND_FLOW_REM) != 0);
    entry->entry_timer = NULL;
    list_init(&entry->match_node);
    list_init(&entry->idle_node);
    list_init(&entry->hard_node);
    list_init(&entry->o2l_head);

    entry->modify_time = now;
    //memset(entry->l2o_node, 0, sizeof(entry->l2o_node));
    /*for (i = 0; i < PATH_BRCM_MAX; i++)
    {
        list_init(&entry->l2o_node[i]);
    }*/

    list_init(&entry->group_refs);
    init_group_refs(entry);

    list_init(&entry->meter_refs);
    init_meter_refs(entry);

    list_init(&entry->path_refs);

    return entry;
}

void
flow_entry_destroy(struct flow_entry *entry) {
    // NOTE: This will be called when the group entry itself destroys the
    //       flow; but it won't be a problem.
    del_group_refs(entry);
    del_meter_refs(entry);
    ofl_structs_free_flow_stats(entry->stats, entry->dp->exp);
    // assumes it is a standard match
    //free(entry->match);
    free(entry);
}

void
flow_entry_remove(struct flow_entry *entry, unsigned char reason) {

    if (VLOG_IS_DBG_ENABLED(ALTA_LOG_MODULE))
    {
        char *str = NULL;
        str = flow_table_print(entry->table);
        if (str != NULL) {
            VLOG_DBG(ALTA_LOG_MODULE, "Remove: %s", str);
            free(str);
            str = NULL;
        }

        str = ofl_structs_match_to_string(entry->stats->match, NULL);
        if (str != NULL) {
            VLOG_DBG(ALTA_LOG_MODULE, "%s", str);
            free(str);
            str = NULL;
        }
    }

    if (entry->send_removed) {
        flow_entry_update(entry);
        {
            struct ofl_msg_flow_removed msg =
                    {{.type = OFPT_FLOW_REMOVED},
                     .reason = reason,
                     .stats  = entry->stats};

            dp_send_message(entry->dp, (struct ofl_msg_header *)&msg, NULL);
        }
    }

    list_remove(&entry->match_node);
    list_remove(&entry->hard_node);
    list_remove(&entry->idle_node);
    entry->table->stats->active_count--;
    flow_entry_destroy(entry);
}

bool flow_entry_match_outport(struct flow_entry *entry, struct ofl_msg_flow_mod *mod)
{
    if ((mod->out_port == OFPP_ANY || flow_entry_has_out_port(entry, mod->out_port)) &&
        (mod->out_group == OFPG_ANY || flow_entry_has_out_group(entry, mod->out_group)))
    {
        return true;
    }

    return false;
}

int flow_entry_inst_scan(struct flow_entry *entry,
                         void *param,
                         int (* callback)(struct ofl_instruction_header *inst, void *usr_data))
{
    int i;
    int err = 0;

    if (!entry->stats)
    {
        return -1;
    }

    for (i = 0; i < entry->stats->instructions_num; i++)
    {
        err += callback(entry->stats->instructions[i], param);
    }

    return err;
}

int flow_entry_action_scan(struct ofl_instruction_actions *inst,
                           void *param,
                           int (* callback)(struct ofl_action_header *act, void *usr_data))
{
    int i;
    int err = 0;

    for (i = 0; i < inst->actions_num; i++)
    {
        err += callback(inst->actions[i], param);
    }

    return err;
}

int flow_bucket_action_scan(struct ofl_bucket * bucket,
                           void *param,
                           int (* callback)(struct ofl_action_header *act, void *usr_data))
{
    int i;
    int err = 0;

    for (i = 0; i < bucket->actions_num; i++)
    {
        err += callback(bucket->actions[i], param);
    }

    return err;
}

void alta_logic_get_entry_count(struct flow_entry *entry,unsigned long long int *p_pkt_counter,unsigned long long int *p_byte_counter)
{
    unsigned int uiRet;
    DPAL_MESSAGE_DATA_S stMSGData = {0};
    struct logic_entry *logic_entry;
    //struct alta_table_class *logic_tabe_class = logic_class();
    struct table_count  t_count;
    unsigned long long int  packet_count = 0;
    unsigned long long int byte_count = 0;

    (void)p_byte_counter;
    memset(&t_count,0,sizeof(struct table_count));

    LIST_FOR_EACH(logic_entry,struct logic_entry,o2l_node[entry->stats->table_id],&entry->o2l_head)
    {
        //logic_tabe_class->count(0,0,logic_entry,&t_count);
        uiRet = DPAL_TranslatePkt(DPAL_MSG_TYPE_FLOWTABLE_STATISTCS, logic_entry, &stMSGData);
        if (uiRet)
        {
            VLOG_ERR(LOG_MODULE, "DPAL_TranslatePkt flow table statics failed!\n");
            continue;
        }

        //发送报文
        uiRet = Hybrid_Chatwith_V8_new(&stMSGData);
        if (uiRet)
        {
            VLOG_ERR(LOG_MODULE, "alta logic get entry count, send to v8 failed!\n");
            free(stMSGData.pData);
            continue;
        }

        free(stMSGData.pData);

        // 以后处理查询到的消息响应
        packet_count += t_count.packet_count;
        byte_count += t_count.byte_count;
    }

    // 以后处理查询到的消息响应
    *p_pkt_counter = packet_count + entry->stats->ofp_packet_count;
    *p_byte_counter = byte_count + entry->stats->ofp_byte_count;

     return;

}

void alta_logic_set_entry_count(struct flow_entry *entry,unsigned long long int packet_count,unsigned long long int byte_count)
{
    entry->stats->packet_count =  packet_count;
    entry->stats->byte_count =  byte_count;
    return;
}

bool alta_logic_entry_exist(struct flow_entry *entry)
{
    bool ret = false;
    struct logic_entry *logic_entry = NULL;
    unsigned int uiRet;
    DPAL_MESSAGE_DATA_S stMSGData = {0};
    //struct alta_table_class *logic_tabe_class = logic_class();

    LIST_FOR_EACH(logic_entry,struct logic_entry,o2l_node[entry->stats->table_id],&entry->o2l_head)
    {
        //ret = logic_tabe_class->exist(0,0,logic_entry);
        uiRet = DPAL_TranslatePkt(DPAL_MSG_TYPE_FLOWTABLE_EXIST, logic_entry, &stMSGData);
        if (uiRet)
        {
            VLOG_ERR(LOG_MODULE, "DPAL_TranslatePkt flow table exist failed!\n");
            continue;
        }

        //发送报文
        uiRet = Hybrid_Chatwith_V8_new(&stMSGData);
        if(VOS_OK != uiRet)
        {
            VLOG_ERR(LOG_MODULE, "Send to V8 new Fail\n");
            free(stMSGData.pData);
            return VOS_ERR;
        }

        free(stMSGData.pData);
    }

    return ret;
}

int alta_logic_entry_debug(struct flow_entry *entry)
{
    int ret = 0;
    struct logic_entry *logic_entry;
    // struct alta_table_class *logic_tabe_class = logic_class();
    unsigned long long int  flow_count = 0;

    LIST_FOR_EACH(logic_entry,struct logic_entry,o2l_node[entry->stats->table_id],&entry->o2l_head)
    {
         flow_count ++;
    }

    VLOG_DBG(LOG_MODULE, "has entry number:%d\n",flow_count);
    return ret;
}

int alta_logic_entry_count(struct flow_entry *entry)
{
    int ret = 0;
    struct logic_entry *logic_entry;
    // 先注释掉
    // struct alta_table_class *logic_tabe_class = logic_class();
    struct table_count  t_count = {0,0};
    unsigned long long int  packet_count = 0;
    unsigned long long int byte_count = 0;
    unsigned long long int ret_byte_count = 0;

    LIST_FOR_EACH(logic_entry,struct logic_entry,o2l_node[entry->stats->table_id],&entry->o2l_head)
    {
        t_count.byte_count = 0;
        t_count.packet_count = 0;

      // 先注释掉
      //  ret += logic_tabe_class->count(0,0,logic_entry,&t_count);
        packet_count += t_count.packet_count;
        byte_count += t_count.byte_count;
    }
    if (!entry->no_pkt_count)
    {
        entry->stats->packet_count = entry->stats->ofp_packet_count + packet_count;
    }
    if (!entry->no_byt_count)
    {
        entry->stats->byte_count = entry->stats->ofp_byte_count + byte_count;
    }

    entry->table->stats->matched_count = entry->table->ofp_matched_count + packet_count;
    entry->table->stats->lookup_count = entry->table->ofp_lookup_count + packet_count;

    return ret;

}

int alta_logic_entry_remove(struct flow_entry *entry,enum E_DEL_REASON e_reason)
{
    struct logic_entry *logic_entry,*flow_next;
    // 先注释掉
    //struct alta_table_class *logic_tabe_class = logic_class();
    struct meter_ref_entry *mre;
    struct group_ref_entry *gre;
    struct path_command  path_cmd;
    unsigned int uiRet;
    DPAL_MESSAGE_DATA_S stMSGData = {0};
    //first,read counter
    alta_logic_entry_count(entry);
    //write to group and meter

    LIST_FOR_EACH(gre, struct group_ref_entry, node, &entry->group_refs)
    {
        struct group_entry *group = group_table_find(entry->dp->groups, gre->group_id);
        if (group != NULL) {
        group->byte_count_bak += entry->stats->byte_count;
        group->packet_count_bak += entry->stats->packet_count;
        } else {
        //VLOG_WARN_RL(LOG_MODULE, &rl, "find non-existing group(%u), while del_group_refs", gre->group_id);
        }
    }

    LIST_FOR_EACH(mre, struct meter_ref_entry, node, &entry->meter_refs)
    {
        struct meter_entry *meter = meter_table_find(entry->dp->meters, mre->meter_id);
        if (meter != NULL)
        {
            meter->byte_count_bak += entry->stats->byte_count;
            meter->packet_count_bak += entry->stats->packet_count;
        }
        else
        {
            //VLOG_WARN_RL(LOG_MODULE, &rl, "find non-existing meter(%u).", mre->meter_id);
        }
    }

    LIST_FOR_EACH_SAFE(logic_entry,flow_next,struct logic_entry,o2l_node[entry->stats->table_id],&entry->o2l_head)
    {
        path_cmd.path_type = entry->path_type;
        path_cmd.reason = e_reason;
        dp_delete_data_type(entry->dp->data_buffers, logic_entry->data_type);
        /* MAC_PATH和ROUTER_PATH在idle老化时硬件表项已经删除，调用底层删除时可能会报错 */
        //先注释掉
        //logic_tabe_class->delete(0,0,logic_entry,&path_cmd);
        //ret = logic_tabe_class->exist(0,0,logic_entry);
        uiRet = DPAL_TranslatePkt(DPAL_MSG_TYPE_FLOWTABLE_DELETE, logic_entry, &stMSGData);
        if (uiRet)
        {
            VLOG_ERR(LOG_MODULE, "DPAL_TranslatePkt flow table exist failed!\n");
            continue;
        }

        //发送报文
        uiRet = Hybrid_Chatwith_V8_new(&stMSGData);
        if(VOS_OK != uiRet)
        {
            VLOG_ERR(LOG_MODULE, "Send to V8 new Fail\n");
            free(stMSGData.pData);
            return VOS_ERR;
        }

        free(stMSGData.pData);
    }
    if(VLOG_IS_DBG_ENABLED(ALTA_LOG_MODULE))
    {
        alta_entry_delete_dump(e_reason);
    }

    return 0;
}

char *
flow_entry_to_string(struct flow_entry *entry) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    flow_entry_print(entry, stream);
    fclose(stream);
    return str;
}

void flow_entry_print(struct flow_entry *entry, FILE *stream)
{
   size_t i;

   fprintf(stream, "table id:");
   ofl_table_print(stream, entry->stats->table_id);
   fprintf(stream, ", match:");
   ofl_structs_match_print(stream, entry->stats->match, NULL);
    //ofl_structs_match_print(stream, entry->match, NULL);
   fprintf(stream, ", instructions:[");

   for(i=0; i<entry->stats->instructions_num; i++)
   {
       ofl_structs_instruction_print(stream, entry->stats->instructions[i], NULL);
       if (i < entry->stats->instructions_num - 1)
       {
          fprintf(stream, ", ");
       }
   }
   fprintf(stream, "]\n");

}

void alta_entry_delete_dump(enum E_DEL_REASON e_reason)
{
    switch(e_reason)
        {
            case HARD_TIMEOUT:
                VLOG_DBG(LOG_MODULE, "openflow: del entry because of hard time out!\n");
            break;
            case IDLE_TIMEOUT:
                VLOG_DBG(LOG_MODULE, "openflow: del entry because of idle time out!\n");
            break;
            case FLOW_REPLACE:
                VLOG_DBG(LOG_MODULE, "openflow: del entry because of flow replace!\n");
            break;
            case FLOW_DELETE:
                VLOG_DBG(LOG_MODULE, "openflow: del entry because of flow delete command!\n");
            break;
            case FLOW_MODIFY:
                VLOG_DBG(LOG_MODULE, "openflow: del entry because of flow modify command!\n");
            break;
            case FLOW_DESTROY:
                VLOG_DBG(LOG_MODULE, "openflow: del entry because of flow destroy!\n");
            break;
            case GROUP_DESTROY:
                VLOG_DBG(LOG_MODULE, "openflow: del entry because of group destroy!\n");
            break;
            case METER_DESTROY:
                VLOG_DBG(LOG_MODULE, "openflow:del meter table because of meter destroy\n");
            break;
            default:
                VLOG_DBG(LOG_MODULE, "openflow: del entry unexcept reason!\n");
            break;
        }
}

