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
#include <string.h>
#include "dynamic-string.h"
#include "datapath.h"
#include "flow_table.h"
#include "flow_table_exact.h"
#include "flow_entry_exact.h"
#include "flow_entry.h"
#include "oflib/ofl.h"
#include "oflib/oxm-match.h"
#include "oflib/ofl-print.h"
#include "time.h"
#include "dp_capabilities.h"
#include "table_miss.h"
//#include "packet_handle_std.h"
#include "timer_wheel.h"
#include "vlog.h"
#define LOG_MODULE VLM_flow_t

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

/*unsigned int  oxm_ids[]={OXM_OF_IN_PORT,OXM_OF_IN_PHY_PORT,OXM_OF_METADATA,OXM_OF_ETH_DST,
                        OXM_OF_ETH_SRC,OXM_OF_ETH_TYPE, OXM_OF_VLAN_VID, OXM_OF_VLAN_PCP, OXM_OF_IP_DSCP,
                        OXM_OF_IP_ECN, OXM_OF_IP_PROTO, OXM_OF_IPV4_SRC, OXM_OF_IPV4_DST, OXM_OF_TCP_SRC,
                        OXM_OF_TCP_DST, OXM_OF_UDP_SRC, OXM_OF_UDP_DST, OXM_OF_SCTP_SRC, OXM_OF_SCTP_DST,
                        OXM_OF_ICMPV4_TYPE, OXM_OF_ICMPV4_CODE, OXM_OF_ARP_OP, OXM_OF_ARP_SPA,OXM_OF_ARP_TPA,
                        OXM_OF_ARP_SHA, OXM_OF_ARP_THA, OXM_OF_IPV6_SRC, OXM_OF_IPV6_DST, OXM_OF_IPV6_FLABEL,
                        OXM_OF_ICMPV6_TYPE, OXM_OF_ICMPV6_CODE, OXM_OF_IPV6_ND_TARGET, OXM_OF_IPV6_ND_SLL,
                        OXM_OF_IPV6_ND_TLL, OXM_OF_MPLS_LABEL, OXM_OF_MPLS_TC, OXM_OF_MPLS_BOS, OXM_OF_PBB_ISID,
                        OXM_OF_TUNNEL_ID, OXM_OF_IPV6_EXTHDR};

unsigned int wildcarded[] = {OXM_OF_METADATA, OXM_OF_ETH_DST, OXM_OF_ETH_SRC, OXM_OF_VLAN_VID, OXM_OF_IPV4_SRC,
                               OXM_OF_IPV4_DST, OXM_OF_ARP_SPA, OXM_OF_ARP_TPA, OXM_OF_ARP_SHA, OXM_OF_ARP_THA, OXM_OF_IPV6_SRC,
                               OXM_OF_IPV6_DST , OXM_OF_IPV6_FLABEL, OXM_OF_PBB_ISID, OXM_OF_TUNNEL_ID, OXM_OF_IPV6_EXTHDR};


struct ofl_instruction_header instructions[] = { {OFPIT_GOTO_TABLE},
                  {OFPIT_WRITE_METADATA },{OFPIT_WRITE_ACTIONS},{OFPIT_APPLY_ACTIONS},
                  {OFPIT_CLEAR_ACTIONS},{OFPIT_METER}} ;

struct ofl_action_header actions[] = { {OFPAT_OUTPUT, 4},
                  {OFPAT_COPY_TTL_OUT, 4},{OFPAT_COPY_TTL_IN, 4},{OFPAT_SET_MPLS_TTL, 4},
                  {OFPAT_DEC_MPLS_TTL, 4},{OFPAT_PUSH_VLAN, 4},{OFPAT_POP_VLAN, 4}, {OFPAT_PUSH_MPLS, 4},
                  {OFPAT_POP_MPLS, 4},{OFPAT_SET_QUEUE, 4},{OFPAT_GROUP, 4}, {OFPAT_SET_NW_TTL, 4}, {OFPAT_DEC_NW_TTL, 4},
                  {OFPAT_SET_FIELD, 4}, {OFPAT_PUSH_PBB, 4}, {OFPAT_POP_PBB, 4} } ;

*/

unsigned int  oxm_ids[]={OXM_OF_IN_PORT,OXM_OF_IN_PHY_PORT,OXM_OF_METADATA,OXM_OF_ETH_DST,
                    OXM_OF_ETH_SRC,OXM_OF_ETH_TYPE, OXM_OF_VLAN_VID, OXM_OF_VLAN_PCP, OXM_OF_IP_DSCP,
                    OXM_OF_IP_ECN, OXM_OF_IP_PROTO, OXM_OF_IPV4_SRC, OXM_OF_IPV4_DST, OXM_OF_TCP_SRC,
                    OXM_OF_TCP_DST, OXM_OF_UDP_SRC, OXM_OF_UDP_DST, OXM_OF_SCTP_SRC, OXM_OF_SCTP_DST,
                    OXM_OF_ICMPV4_TYPE, OXM_OF_ICMPV4_CODE, OXM_OF_ARP_OP, OXM_OF_ARP_SPA,OXM_OF_ARP_TPA,
                    OXM_OF_ARP_SHA, OXM_OF_ARP_THA, OXM_OF_IPV6_SRC, OXM_OF_IPV6_DST, OXM_OF_IPV6_FLABEL,
                    OXM_OF_ICMPV6_TYPE, OXM_OF_ICMPV6_CODE, OXM_OF_IPV6_ND_TARGET, OXM_OF_IPV6_ND_SLL,
                    OXM_OF_IPV6_ND_TLL, OXM_OF_MPLS_LABEL, OXM_OF_MPLS_TC};

unsigned int wildcarded[] = {OXM_OF_IN_PORT,OXM_OF_IN_PHY_PORT,OXM_OF_METADATA,OXM_OF_ETH_DST,
                        OXM_OF_ETH_SRC,OXM_OF_ETH_TYPE, OXM_OF_VLAN_VID, OXM_OF_VLAN_PCP, OXM_OF_IP_DSCP,
                        OXM_OF_IP_ECN, OXM_OF_IP_PROTO, OXM_OF_IPV4_SRC, OXM_OF_IPV4_DST, OXM_OF_TCP_SRC,
                        OXM_OF_TCP_DST, OXM_OF_UDP_SRC, OXM_OF_UDP_DST, OXM_OF_SCTP_SRC, OXM_OF_SCTP_DST,
                        OXM_OF_ICMPV4_TYPE, OXM_OF_ICMPV4_CODE, OXM_OF_ARP_OP, OXM_OF_ARP_SPA,OXM_OF_ARP_TPA,
                        OXM_OF_ARP_SHA, OXM_OF_ARP_THA, OXM_OF_IPV6_SRC, OXM_OF_IPV6_DST, OXM_OF_IPV6_FLABEL,
                        OXM_OF_ICMPV6_TYPE, OXM_OF_ICMPV6_CODE, OXM_OF_IPV6_ND_TARGET, OXM_OF_IPV6_ND_SLL,
                        OXM_OF_IPV6_ND_TLL, OXM_OF_MPLS_LABEL, OXM_OF_MPLS_TC};

struct ofl_instruction_header instructions[] = { {OFPIT_GOTO_TABLE},
                            {OFPIT_WRITE_METADATA },{OFPIT_WRITE_ACTIONS},{OFPIT_APPLY_ACTIONS},
                                {OFPIT_CLEAR_ACTIONS},{OFPIT_METER}} ;

struct ofl_action_header actions[] = { {OFPAT_OUTPUT, 4},
                    {OFPAT_COPY_TTL_OUT, 4},{OFPAT_COPY_TTL_IN, 4},{OFPAT_SET_MPLS_TTL, 4},
                        {OFPAT_DEC_MPLS_TTL, 4},{OFPAT_PUSH_VLAN, 4},{OFPAT_POP_VLAN, 4}, {OFPAT_PUSH_MPLS, 4},
                            {OFPAT_POP_MPLS, 4},{OFPAT_SET_QUEUE, 4}, {OFPAT_GROUP, 4}, {OFPAT_SET_NW_TTL, 4},
                                {OFPAT_DEC_NW_TTL, 4},{OFPAT_SET_FIELD, 4} } ;

/* When inserting an entry, this function adds the flow entry to the list of
 * hard and idle timeout entries, if appropriate. */
void
add_to_timeout_lists(struct flow_table *table, struct flow_entry *entry) {
    if (entry->stats->idle_timeout > 0) {
        list_insert(&table->idle_entries, &entry->idle_node);
    }

    if (entry->remove_at > 0) {
        struct flow_entry *e;

        /* hard timeout entries are ordered by the time they should be removed at. */
        LIST_FOR_EACH (e, struct flow_entry, hard_node, &table->hard_entries) {
            if (e->remove_at > entry->remove_at) {
                list_insert(&e->hard_node, &entry->hard_node);
                return;
            }
        }
        list_insert(&e->hard_node, &entry->hard_node);
    }
}

static ofl_err
flow_table_priority(struct flow_table *table, struct ofl_msg_flow_mod *mod)
{
    struct flow_entry *entry = NULL, *ret_entry = NULL;

    LIST_FOR_EACH (entry, struct flow_entry, match_node, &table->match_entries)
    {
        if (match_std_strict((struct ofl_match *)mod->match,
                                (struct ofl_match *)entry->stats->match))
        {
            //flow_entry_print(entry, stdout);
            VLOG_DBG(LOG_MODULE, "entry priority:%d,mod priority:%d\n", entry->stats->priority, mod->priority);
            if (entry->stats->priority < mod->priority) {
               ret_entry = entry;
               break;
            }
        }
    }

    if (ret_entry != NULL)
        alta_logic_entry_remove(ret_entry,FLOW_DELETE);

    return 0;
}

/* Handles flow mod messages with ADD command. */
static ofl_err
flow_table_add(struct flow_table *table, struct ofl_msg_flow_mod *mod, bool check_overlap, bool *match_kept, bool *insts_kept) {
    // Note: new entries will be placed behind those with equal priority
    struct flow_entry *entry, *new_entry;
    if (table->stats->active_count >= table->dp->flow_table_max_entries)
    {
        return ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_TABLE_FULL);
    }
    LIST_FOR_EACH (entry, struct flow_entry, match_node, &table->match_entries)
    {
        if (check_overlap && flow_entry_overlaps(entry, mod)) {
            return ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_OVERLAP);
        }

        /* if the entry equals, replace the old one */
        // modified , according to ofp1.3.2 p 66, cookie is not checked in flow entry adding;
        if (flow_entry_matches(entry, mod, true/*strict*/, false/*check_cookie*/) )
        {
            new_entry = flow_entry_create(table->dp, table, mod);
            *match_kept = true;
            *insts_kept = true;

            if(0 == (OFPFF_RESET_COUNTS & mod->flags) )
            {
                new_entry->stats->byte_count = entry->stats->byte_count;
                new_entry->stats->ofp_byte_count = entry->stats->ofp_byte_count;
                new_entry->stats->packet_count= entry->stats->packet_count;
                new_entry->stats->ofp_packet_count= entry->stats->ofp_packet_count;
                }

            table->dp->enty_xid ++;
            new_entry->flow_id = table->dp->enty_xid;

            /* NOTE: no flow removed message should be generated according to spec. */
            list_replace(&new_entry->match_node, &entry->match_node);
            list_remove(&entry->hard_node);
            list_remove(&entry->idle_node);

            //del_entry_form_timer(entry);

            //if action is equal ,do not delete brcm flow entry
            alta_logic_entry_remove(entry,FLOW_REPLACE);


            flow_entry_destroy(entry);
            add_to_timeout_lists(table, new_entry);
            return 0;
        }


        if (mod->priority > entry->stats->priority)
        {
            break;
        }
    }


    table->stats->active_count++;
    table->dp->enty_xid ++;

    new_entry = flow_entry_create(table->dp, table, mod);
    new_entry->flow_id = table->dp->enty_xid;
    *match_kept = true;
    *insts_kept = true;

    list_insert(&entry->match_node, &new_entry->match_node);
    add_to_timeout_lists(table, new_entry);

    if (VLOG_IS_DBG_ENABLED(ALTA_LOG_MODULE))
    {
        char *str = NULL;
        str = flow_table_print(table);
        if (str != NULL) {
            VLOG_DBG(ALTA_LOG_MODULE, "Add: %s", str);
            free(str);
            str = NULL;
        }
    }

    flow_table_priority(table, mod);

    return 0;
}

static struct ofl_instruction_header **
ofl_structs_instructions_clone(struct ofl_instruction_header **instructions, size_t instructions_num, struct ofl_exp *exp){
    struct ofl_instruction_header ** new_ins = NULL;
    struct ofp_instruction * ofp_ins = NULL;
    unsigned char *ptr;
    unsigned char *buf;
    size_t plen = 0;
    size_t pcount = 0;
    ofl_err error = 0;
    int i;
    size_t buf_len = ofl_structs_instructions_ofp_total_len(instructions, instructions_num, exp);
    buf_len = ROUND_UP(buf_len, 8);
    buf     = (unsigned char *)malloc(buf_len);
    ptr = buf;
    for (i=0; i<instructions_num; i++) {
        ptr += ofl_structs_instructions_pack(instructions[i], (struct ofp_instruction *)ptr, exp);
    }
     plen = buf_len;
     ofp_ins = (struct ofp_instruction *)buf;
     error = ofl_utils_count_ofp_instructions(ofp_ins, plen, &pcount);
    if (error||pcount!=instructions_num) {
        free(buf);
        return NULL;
    }
   new_ins = (struct ofl_instruction_header **)malloc(pcount * sizeof(struct ofl_instruction_header *));
   for (i = 0; i < pcount; i++) {
        error = ofl_structs_instructions_unpack(NULL, ofp_ins, &plen, &(new_ins[i]), exp);
        ofp_ins = (struct ofp_instruction *)((unsigned char *)ofp_ins + ntohs(ofp_ins->len));
    }
   free(buf);
   return new_ins;
}
/* Handles flow mod messages with MODIFY command.
    If the flow doesn't exists don't do nothing*/
static ofl_err
flow_table_modify(struct flow_table *table, struct ofl_msg_flow_mod *mod, bool strict, bool *insts_kept) {
    struct flow_entry *entry;

    LIST_FOR_EACH (entry, struct flow_entry, match_node, &table->match_entries)
    {
        if (flow_entry_matches(entry, mod, strict, true/*check_cookie*/))
        {
            entry->modify_time = time_now_msec();
            entry->last_used = time_now_msec();
            flow_entry_replace_instructions(entry, mod->instructions_num, mod->instructions);
            mod->instructions = ofl_structs_instructions_clone(mod->instructions, mod->instructions_num, NULL);
            if(OFPFF_RESET_COUNTS & mod->flags)
            {
                entry->stats->byte_count = 0;
                entry->stats->ofp_byte_count = 0;
                entry->stats->packet_count = 0;
                entry->stats->ofp_packet_count = 0;
            }
            *insts_kept = false;
            alta_logic_entry_remove(entry,FLOW_MODIFY);
            list_remove(&entry->idle_node);
            list_init(&entry->idle_node);
        }
    }

    return 0;
}

/* Handles flow mod messages with DELETE command. */
static ofl_err
flow_table_delete(struct flow_table *table, struct ofl_msg_flow_mod *mod, bool strict) {
    struct flow_entry *entry, *next;

    LIST_FOR_EACH_SAFE (entry, next, struct flow_entry, match_node, &table->match_entries)
    {

        if ( flow_entry_match_outport(entry, mod)
            && flow_entry_matches(entry, mod, strict, true/*check_cookie*/))
            {
         //        del_entry_form_timer(entry);
                 flow_entry_print(entry, stdout);
                 alta_logic_entry_remove(entry,FLOW_DELETE);
                 flow_entry_remove(entry, OFPRR_DELETE);
            }
    }
    return 0;
}

ofl_err
flow_table_flow_mod(struct flow_table *table, struct ofl_msg_flow_mod *mod, bool *match_kept, bool *insts_kept) {
    ofl_err ret = 0;

    switch (mod->command)
    {
        case (OFPFC_ADD):
        {
            bool overlap = ((mod->flags & OFPFF_CHECK_OVERLAP) != 0);

            if (is_exact_flow_entry(table,(struct ofl_match *)mod->match,OFPFC_ADD))
            {
                return exact_flow_table_add(table, mod,match_kept, insts_kept);
            }
            else
            {
                ret = flow_table_add(table, mod, overlap, match_kept, insts_kept);
            }
            break;
        }
        case (OFPFC_MODIFY):
        {
            if (is_exact_flow_entry(table,(struct ofl_match *)mod->match,OFPFC_MODIFY))
            {
                return exact_flow_table_modify(table, mod,false, insts_kept);
            }
            else
            {
                ret = flow_table_modify(table, mod, false, insts_kept);
            }
            break;
        }
        case (OFPFC_MODIFY_STRICT):
        {
            if (is_exact_flow_entry(table,(struct ofl_match *)mod->match,OFPFC_MODIFY_STRICT))
            {
                return exact_flow_table_modify(table, mod,true, insts_kept);
            }
            else
            {
                ret = flow_table_modify(table, mod, true, insts_kept);
            }
            break;
        }
        case (OFPFC_DELETE):
        {
            if(false == table->dp->no_del_flow_entry)
            {
                if(table->dp->use_exact_table == true)
                {
                    exact_flow_table_delete(table, mod,false);
                    return flow_table_delete(table, mod, false);
                }
                else
                {
                    return flow_table_delete(table, mod, false);
                }
            }
            break;
        }
        case (OFPFC_DELETE_STRICT):
        {
            if(table->dp->use_exact_table == true)
            {
                exact_flow_table_delete(table, mod,true);

                return flow_table_delete(table, mod, true);
            }
            else
            {
                return flow_table_delete(table, mod, true);
            }
            break;
        }
        default:
        {
            return ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_COMMAND);
        }
    }

    //if (0 == ret)
    //    flow_table_refresh(table, mod);

    return ret;
}

static struct flow_entry *wildcard_flow_table_lookup(struct flow_table *table, struct packet *pkt)
{
    struct flow_entry *entry;
    struct flow_entry *ret_entry = NULL;
    unsigned short int priority = 0;

    table->ofp_lookup_count++;

    LIST_FOR_EACH(entry, struct flow_entry, match_node, &table->match_entries) {
        struct ofl_match_header *m;

        m = entry->match == NULL ? entry->stats->match : entry->match;

        /* select appropriate handler, based on match type of flow entry. */
        switch (m->type)
        {
            case (OFPMT_OXM):
            {
               if (packet_handle_std_match(pkt->handle_std,(struct ofl_match *)m))
               {
                    if (entry->stats->priority >= priority)
                    {
                        ret_entry = entry;
                    }

                    priority = entry->stats->priority;
                }
                break;
            }
            default:
            {
                VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to process flow entry with unknown match type (%u).", m->type);
            }
        }
    }

    if (ret_entry) {
        if (!ret_entry->no_byt_count)
            ret_entry->stats->ofp_byte_count += pkt->buffer->size;
        if (!ret_entry->no_pkt_count)
            ret_entry->stats->ofp_packet_count++;

        ret_entry->last_used = time_now_msec();

        table->ofp_matched_count ++;
    }
    return ret_entry;
}

struct flow_entry *flow_table_lookup(struct flow_table *table, struct packet *pkt)
{
    struct flow_entry *entry = NULL;
    if(table->dp->use_exact_table == true)
    {
        entry = exact_flow_table_lookup(table,pkt);
        if (entry == NULL ) {
            entry = wildcard_flow_table_lookup(table,pkt);
        }
    }
    else
    {
    entry = wildcard_flow_table_lookup(table,pkt);
    }
    return entry;
}



void
flow_table_timeout(struct flow_table *table) {
    struct flow_entry *entry, *next;
    unsigned int i = 0;
    unsigned int j = 0;
    //bool need_timeout = false;
    unsigned int start_entry = table->timeout_entries.start_entry;

#if 1
    /* NOTE: hard timeout entries are ordered by the time they should be removed at,
     * so if one is not removed, the rest will not be either. */
    LIST_FOR_EACH_SAFE (entry, next, struct flow_entry, hard_node, &table->hard_entries) {
        if (!flow_entry_hard_timeout(entry)) {
            break;
        } else {
            j ++;
            if(j > NUM_TIMEOUT_ONTIME)
            {
                /* 大于500条后等待下一次老化遍历 */
                table->timeout_entries.need_timeout = true;
                return;
            }
        }
    }

    LIST_FOR_EACH_SAFE (entry, next, struct flow_entry, idle_node, &table->idle_entries) {
        if(i < start_entry)
        {
            i++;
        }
        else
        {
            j++;
            table->timeout_entries.start_entry ++;
            flow_entry_idle_timeout(entry);
            if(j > NUM_TIMEOUT_ONTIME)
            {
                /* 大于500条后等待下一次老化遍历 */
                table->timeout_entries.need_timeout = true;
                return;
            }
        }
    }
    /* 全部entry遍历完后，标记该table老化遍历完成，并将start entry清零 */
    table->timeout_entries.need_timeout = false;
    table->timeout_entries.start_entry = 0;
#endif

}


static void
flow_table_create_property(struct ofl_table_feature_prop_header **prop, enum ofp_table_feature_prop_type type,struct flow_table *table)
{
    switch(type)
    {
        case OFPTFPT_INSTRUCTIONS:
        case OFPTFPT_INSTRUCTIONS_MISS:
        {
            struct ofl_table_feature_prop_instructions *inst_capabilities;
            inst_capabilities = xmalloc(sizeof(struct ofl_table_feature_prop_instructions));
            inst_capabilities->header.type = type;
            inst_capabilities->ids_num = N_INSTRUCTIONS;
            inst_capabilities->instruction_ids = instructions;
            inst_capabilities->header.length = ofl_structs_table_features_properties_ofp_len(&inst_capabilities->header, NULL);
            (*prop) =  (struct ofl_table_feature_prop_header*) inst_capabilities;
            break;
        }
        case OFPTFPT_NEXT_TABLES:
        case OFPTFPT_NEXT_TABLES_MISS:
        {
              struct ofl_table_feature_prop_next_tables *tbl_reachable;
              int i,j;
              tbl_reachable = xmalloc(sizeof(struct ofl_table_feature_prop_next_tables));
              tbl_reachable->header.type = type;
              //tbl_reachable->table_num = PIPELINE_TABLES;
              tbl_reachable->table_num = PIPELINE_TABLES - table->stats->table_id - 1;
              tbl_reachable->next_table_ids = xmalloc(sizeof(unsigned char) * tbl_reachable->table_num);
              j = table->stats->table_id + 1;
              for (i = 0; i < tbl_reachable->table_num; i++)
              {
                    tbl_reachable->next_table_ids[i] = j++;
              }
              tbl_reachable->header.length = ofl_structs_table_features_properties_ofp_len(&tbl_reachable->header, NULL);
              *prop = (struct ofl_table_feature_prop_header*) tbl_reachable;
             break;
        }
        case OFPTFPT_APPLY_ACTIONS:
        case OFPTFPT_APPLY_ACTIONS_MISS:
        case OFPTFPT_WRITE_ACTIONS:
        case OFPTFPT_WRITE_ACTIONS_MISS:
        {
             struct ofl_table_feature_prop_actions *act_capabilities;
             act_capabilities = xmalloc(sizeof(struct ofl_table_feature_prop_actions));
             act_capabilities->header.type =  type;
             act_capabilities->actions_num= sizeof(actions) / sizeof(struct ofl_action_header); //N_ACTIONS;
             act_capabilities->action_ids = actions;
             act_capabilities->header.length = ofl_structs_table_features_properties_ofp_len(&act_capabilities->header, NULL);
             *prop =  (struct ofl_table_feature_prop_header*) act_capabilities;
             break;
        }
        case OFPTFPT_MATCH:
        case OFPTFPT_APPLY_SETFIELD:
        case OFPTFPT_APPLY_SETFIELD_MISS:
        case OFPTFPT_WRITE_SETFIELD:
        case OFPTFPT_WRITE_SETFIELD_MISS:
        {
            struct ofl_table_feature_prop_oxm *oxm_capabilities;
            /*int i;*/
            oxm_capabilities = xmalloc(sizeof(struct ofl_table_feature_prop_oxm));
            oxm_capabilities->header.type = type;
            switch(table->dp->flow_table_type)
            {
                case AFTT_FULL_WILDCARD:
                {
                    oxm_capabilities->oxm_num = sizeof(oxm_ids)/sizeof(int);  //N_OXM_FIELDS;
                    oxm_capabilities->oxm_ids = oxm_ids;
                    break;
                }
                case AFTT_EXACT:
                {
                    oxm_capabilities->oxm_num = global_table_match_count[table->stats->table_id];
                    oxm_capabilities->oxm_ids = global_table_match_fields[table->stats->table_id];
                    break;
                }
            }

            oxm_capabilities->header.length = ofl_structs_table_features_properties_ofp_len(&oxm_capabilities->header, NULL);
            *prop =  (struct ofl_table_feature_prop_header*) oxm_capabilities;
            break;
        }
        case OFPTFPT_WILDCARDS:
        {
            struct ofl_table_feature_prop_oxm *oxm_capabilities;
            oxm_capabilities = xmalloc(sizeof(struct ofl_table_feature_prop_oxm));
            oxm_capabilities->header.type = type;
            switch(table->dp->flow_table_type)
            {
                case AFTT_FULL_WILDCARD:
                {
                    oxm_capabilities->oxm_num = sizeof( wildcarded) /sizeof(int);  //N_WILDCARDED;
                    oxm_capabilities->oxm_ids = wildcarded;
                    break;
                }
                case AFTT_EXACT:
                {
                     oxm_capabilities->oxm_num = global_table_wildcard_count[table->stats->table_id];
                    if (oxm_capabilities->oxm_num != 0)
                        oxm_capabilities->oxm_ids = global_table_wildcard_fields[table->stats->table_id];
                    else
                        oxm_capabilities->oxm_ids = NULL;
                    break;
                }
            }
            oxm_capabilities->header.length = ofl_structs_table_features_properties_ofp_len(&oxm_capabilities->header, NULL);
            *prop =  (struct ofl_table_feature_prop_header*) oxm_capabilities;
            break;
        }
        case OFPTFPT_EXPERIMENTER:
        case OFPTFPT_EXPERIMENTER_MISS:{
            break;
        }
    }
}

static void
flow_table_features(struct flow_table *table)
{

    int type, j = 0;
    struct ofl_table_features *features = table->features;

    features->properties = xmalloc(sizeof(struct ofl_table_feature_prop_header *) * features->properties_num);

    for(type = OFPTFPT_INSTRUCTIONS; type <= OFPTFPT_APPLY_SETFIELD_MISS; type++)
    {
        features->properties[j] = xmalloc(sizeof(struct ofl_table_feature_prop_header *));
        flow_table_create_property(&features->properties[j], type,table);
        if(type == OFPTFPT_MATCH || type == OFPTFPT_WILDCARDS)
        {
            type++;
        }
        j++;
    }
}

struct flow_table *
flow_table_create(struct datapath *dp, unsigned char table_id)
{
    int i,j;
    struct flow_table *table;
    struct ds string = DS_EMPTY_INITIALIZER;

    ds_put_format(&string, "table_%u", table_id);

    table = xmalloc(sizeof(struct flow_table));
    table->dp = dp;

    /*Init table stats */
    table->stats = xmalloc(sizeof(struct ofl_table_stats));
    table->stats->table_id      = table_id;
    table->stats->active_count  = 0;
    table->stats->lookup_count  = 0;
    table->stats->matched_count = 0;
    table->ofp_matched_count = 0;
    table->ofp_lookup_count = 0;

    /* Init Table features */
    table->features = xmalloc(sizeof(struct ofl_table_features));
    table->features->table_id = table_id;
    table->features->name          = ds_cstr(&string);
    table->features->metadata_match = 0xffffffffffffffff;
    table->features->metadata_write = 0xffffffffffffffff;
    table->features->config        =  0;//OFPTC_TABLE_MISS_DROP;
    table->features->max_entries   = dp->flow_table_max_entries;
    table->features->properties_num = TABLE_FEATURES_NUM;


    list_init(&table->match_entries);
    list_init(&table->hard_entries);
    list_init(&table->idle_entries);

    if(dp->flow_table_type == AFTT_FULL_WILDCARD)
    {
        table->wildcards  = 0xffffffffffffffff;
    }
    else
    {
        table->wildcards  = g_table_type[table_id];
        table->match      = g_table_match[table_id];
        //table->hash_seed = random_uint32();
    }

    //精确表分配哈希通的内存
    if (table->wildcards == EXACT_TABLE)
    {
        table->features->max_entries = dp->flow_table_max_entries;
        table->buckets[0] = xmalloc(sizeof(struct hlist_head *) * EXACT_FLOW_TABLE_MAX_ENTRIES);
        for (i = 0; i < EXACT_FLOW_TABLE_MAX_ENTRIES; i++)
        {
            INIT_HLIST_HEAD(&table->buckets[0][i]);
        }
    }
    else
    {
         table->features->max_entries = dp->flow_table_max_entries;

         for (j = 0; j < MAX_HASH_BUCKETS_NUM; j++)
         {
             table->buckets[j] = xmalloc(sizeof(struct hlist_head *) * EXACT_FLOW_TABLE_MAX_ENTRIES);
             for (i = 0; i < EXACT_FLOW_TABLE_MAX_ENTRIES; i++)
             {
                 INIT_HLIST_HEAD(&table->buckets[j][i]);
             }
             table->hash_seed[j] = random_uint32();
         }
    }
    flow_table_features(table);
    table->timeout_entries.need_timeout = true;
    table->timeout_entries.start_entry = 0;
    return table;
}

void
flow_table_destroy(struct flow_table *table) {
    struct flow_entry *entry, *next;

    LIST_FOR_EACH_SAFE (entry, next, struct flow_entry, match_node, &table->match_entries) {
        alta_logic_entry_remove(entry,FLOW_DESTROY); 
  //      del_entry_form_timer(entry); //
        flow_entry_destroy(entry);
    }
    free(table->features);
    free(table->stats);
    free(table);
}

static void
wildcard_flow_table_stats(struct flow_table *table, struct ofl_msg_multipart_request_flow *msg,
                 struct ofl_flow_stats ***stats, size_t *stats_size, size_t *stats_num) {
    struct flow_entry *entry;

    LIST_FOR_EACH(entry, struct flow_entry, match_node, &table->match_entries) {
        if ((msg->out_port == OFPP_ANY || flow_entry_has_out_port(entry, msg->out_port)) &&
            (msg->out_group == OFPG_ANY || flow_entry_has_out_group(entry, msg->out_group)) &&
            match_std_nonstrict((struct ofl_match *)msg->match,
                                (struct ofl_match *)entry->stats->match)&&
                                ((entry->stats->cookie & msg->cookie_mask) == (msg->cookie & msg->cookie_mask)) ) {

            flow_entry_update(entry);

            alta_logic_entry_count(entry);

            if ((*stats_size) == (*stats_num)) {
                (*stats) = xrealloc(*stats, (sizeof(struct ofl_flow_stats *)) * (*stats_size) * 2);
                *stats_size *= 2;
            }
            (*stats)[(*stats_num)] = entry->stats;
            (*stats_num)++;
        }
    }
}

void
flow_table_stats(struct flow_table *table,
                               struct ofl_msg_multipart_request_flow *msg,
                               struct ofl_flow_stats ***stats,
                               size_t *stats_size, size_t *stats_num)
{
    wildcard_flow_table_stats(table,msg, stats,stats_size,stats_num);

    if(true == table->dp->use_exact_table)
    {
        exact_flow_table_stats(table,msg, stats,stats_size,stats_num);
    }
}

void
flow_table_aggregate_stats(struct flow_table *table, struct ofl_msg_multipart_request_flow *msg,
                           unsigned long long int *packet_count, unsigned long long int *byte_count, unsigned int *flow_count) {
    struct flow_entry *entry;

    LIST_FOR_EACH(entry, struct flow_entry, match_node, &table->match_entries) {
        if ((msg->out_port == OFPP_ANY || flow_entry_has_out_port(entry, msg->out_port)) &&
            (msg->out_group == OFPG_ANY || flow_entry_has_out_group(entry, msg->out_group)) &&
            match_std_nonstrict((struct ofl_match *)msg->match,
                                (struct ofl_match *)entry->stats->match))
        {

            alta_logic_entry_count(entry);


            if((entry->stats->cookie & msg->cookie_mask) == (msg->cookie & msg->cookie_mask))
            {
                if (!entry->no_pkt_count)
                    (*packet_count) += entry->stats->packet_count;
                if (!entry->no_byt_count)
                    (*byte_count)   += entry->stats->byte_count ;
                (*flow_count)++;
                VLOG_DBG(LOG_MODULE, "++\n");
            }
        }
    }
}

char *
flow_table_print(struct flow_table *table)
{
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    size_t i;
    struct flow_entry *entry;

    if (NULL == stream)
    {
        return NULL;
    }

    LIST_FOR_EACH (entry, struct flow_entry, match_node, &table->match_entries)
    {
        fprintf(stream, "added table:");
        ofl_table_print(stream, table->stats->table_id);
        fprintf(stream, ", match:");
        //ofl_structs_match_print(stream, entry->stats->match, NULL);
        ofl_structs_match_print(stream, entry->match, NULL);
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

    fclose(stream);
    return str;
}

char * flow_table_refresh_malloc_icmp(struct flow_table *table, struct ofl_msg_flow_mod *mod){
    char * icmpPkt = NULL;
    struct eth_header *eth;
    struct ip_header * ipv4;
    struct ofl_match * match;
    struct ofl_match_tlv *match_tlv;

    icmpPkt = (char *)xmalloc(64);
    if (NULL == icmpPkt)
        return NULL;

    (void)memset(icmpPkt, 0, 64);

    eth = (struct eth_header *)icmpPkt;

    eth->eth_type = 0x0800;

    ipv4 = (struct ip_header *)(icmpPkt + sizeof(struct eth_header));
    ipv4->ip_ihl_ver = 0x45;
    ipv4->ip_tot_len = 0x20;
    ipv4->ip_proto = 0x01;
    ipv4->ip_ttl   = 64;

    match = (struct ofl_match *)(void *)mod->match;
    HMAP_FOR_EACH(match_tlv, struct ofl_match_tlv, hmap_node, &(match->match_fields))
    {
        if (OXM_FIELD(match_tlv->header) == OFPXMT_OFB_IPV4_DST)
        {
            ipv4->ip_dst = *((unsigned int *)(match_tlv->value));
        }

        if (OXM_FIELD(match_tlv->header) == OFPXMT_OFB_IPV4_SRC)
        {
            ipv4->ip_src = *((unsigned int *)(match_tlv->value));
        }
    }

    return icmpPkt;
}

void flow_table_refresh_malloc_pkt(struct flow_table *table, struct ofl_msg_flow_mod *mod){
    struct datapath * dp = table->dp;
    struct packet * pkt = NULL;
    struct ofpbuf * buf = NULL;
    char * icmpPkt = NULL;
    unsigned int in_port = 0;

    if (0 == dp->ports_num)
        return;

    in_port = dp->ports[0].port_no;

    /* 构造报文 */
    icmpPkt = flow_table_refresh_malloc_icmp(table, mod);
    if (NULL == icmpPkt)
        return;

    buf = ofpbuf_new_with_headroom(64, 128);
    if (NULL == buf){
        free(icmpPkt);
        return;
    }

    ofpbuf_put(buf, icmpPkt, 64);

    pkt = packet_create(dp, in_port, buf, false);
    if (NULL == pkt){
        ofpbuf_delete(buf);
        return;
    }

    pkt->reason = true;

    pipeline_process_packet(dp->pipeline, pkt);

    return;
}

bool flow_table_refresh_filter(struct flow_table *table, struct ofl_msg_flow_mod *mod){
    /* scale out 项目只在动作匹配group资源时触发 */
    int i;
    int j;
    struct ofl_instruction_actions * action_set;

    for (i = 0; i < mod->instructions_num; i++){
        if (OFPIT_WRITE_ACTIONS == mod->instructions[i]->type){
            action_set = (struct ofl_instruction_actions *)(void *)(mod->instructions[i]);

            for (j = 0; j < action_set->actions_num; j++) {
                if (action_set->actions[j]->type == OFPAT_GROUP) {
                    return true;
                }
            }
        }
    }

    return false;
}

/* 构造报文触发流表下发硬件 */
void flow_table_refresh(struct flow_table *table, struct ofl_msg_flow_mod *mod){
    bool is_filter = false;
    struct packet *pkt = NULL;

    /* 判断是否需要构造报文触发流表下发硬件 */
    if (true != flow_table_refresh_filter(table, mod))
        return;

    /* 构造匹配流表的报文 */
    flow_table_refresh_malloc_pkt(table, mod);

    return;
}


