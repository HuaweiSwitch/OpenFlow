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

#include <stdlib.h>
#include "action_set.h"
#include "dp_actions.h"
#include "datapath.h"
#include "packet.h"
#include "oflib/ofl.h"
#include "oflib/ofl-actions.h"
#include "oflib/ofl-print.h"
#include "packet.h"
#include "list.h"
#include "util.h"

#include "vlog.h"
#define LOG_MODULE VLM_action_set

struct action_set_entry;

struct action_set {
    struct list     actions;   /* the list of actions in the action set,
+                                   stored in the order of precedence as defined
+                                   by the specification. */
    struct ofl_exp *exp;       /* experimenter callbacks */
};

struct action_set_entry {
    struct list                node;

    struct ofl_action_header  *action;  /* these actions point to actions in
+                                        * flow table entry instructions */
    int                        order;   /* order of the entry as defined */
};




/* Returns the priority of the action it should be executed in
 * according to the spec. Note, that the actions are already
 * stored in this order.
 */
static int
action_set_order(struct ofl_action_header *act) {
    switch (act->type) {
        case (OFPAT_COPY_TTL_OUT):   return 40;
        case (OFPAT_COPY_TTL_IN):    return 10;
        case (OFPAT_SET_FIELD):      return 60;
        case (OFPAT_SET_MPLS_TTL):   return 60;
        case (OFPAT_DEC_MPLS_TTL):   return 50;
        case (OFPAT_PUSH_PBB):       return 30;
        case (OFPAT_POP_PBB):        return 20;
        case (OFPAT_PUSH_VLAN):      return 30;
        case (OFPAT_POP_VLAN):       return 20;
        case (OFPAT_PUSH_MPLS):      return 30;
        case (OFPAT_POP_MPLS):       return 20;
        case (OFPAT_SET_QUEUE):      return 70;
        case (OFPAT_GROUP):          return 80;
        case (OFPAT_SET_NW_TTL):     return 60;
        case (OFPAT_DEC_NW_TTL):     return 50;
        case (OFPAT_OUTPUT):         return 90;
        case (OFPAT_EXPERIMENTER):   return 75;
        default:                     return 79;
    }
}


/* Creates a new set entry */
struct action_set *
action_set_create(struct ofl_exp *exp) {
    struct action_set *set = xmalloc(sizeof(struct action_set));
    list_init(&set->actions);
    set->exp = exp;

    return set;
}

void action_set_destroy(struct action_set *set) {
    action_set_clear_actions(set);
    free(set);
}

static struct action_set_entry *
action_set_create_entry(struct ofl_action_header *act) {
    struct action_set_entry *entry;

    entry = xmalloc(sizeof(struct action_set_entry));
    entry->action = act;
    entry->order = action_set_order(act);

    return entry;
}

struct action_set *
action_set_clone(struct action_set *set) {
    struct action_set *s = xmalloc(sizeof(struct action_set));
    struct action_set_entry *entry, *new_entry;

    list_init(&s->actions);
    s->exp = set->exp;

    LIST_FOR_EACH(entry, struct action_set_entry, node, &set->actions) {
        new_entry = action_set_create_entry(entry->action);
        list_push_back(&s->actions, &new_entry->node);
    }

    return s;
}


/* Writes a single action to the action set. Overwrites existing actions with
 * the same type in the set. The list order is based on the precedence defined
 * in the specification. */
static void
action_set_write_action(struct action_set *set,
                        struct ofl_action_header *act) {
    struct action_set_entry *entry, *new_entry;

    new_entry = action_set_create_entry(act);

    LIST_FOR_EACH(entry, struct action_set_entry, node, &set->actions) {
	// add for multi setfild actions, complie to oftest
       if ((entry->action->type == new_entry->action->type) &&
	   	(OFPAT_SET_FIELD != entry->action->type))
	 {
            /* replace same type of action */
            list_replace(&new_entry->node, &entry->node);
            /* NOTE: action in entry must not be freed, as it is owned by the
             *       write instruction which added the action to the set */
            free(entry);

            return;
        }
        if (new_entry->order < entry->order) {
            /* insert higher order action before */
            list_insert(&entry->node, &new_entry->node);

            return;
        }
    }

    /* add action to the end of set */
    list_insert(&entry->node, &new_entry->node);
}


void
action_set_write_actions(struct action_set *set,
                         size_t actions_num,
                         struct ofl_action_header **actions) {
    size_t i;

    for (i=0; i<actions_num; i++) {
        action_set_write_action(set, actions[i]);
    }
}

void
action_set_clear_actions(struct action_set *set) {
    struct action_set_entry *entry, *next;

    LIST_FOR_EACH_SAFE(entry, next, struct action_set_entry, node, &set->actions) {
        list_remove(&entry->node);
        // NOTE: action in entry must not be freed, as it is owned by the write instruction
        //       which added the action to the set
        free(entry);
    }
}

void
action_set_execute(struct action_set *set, struct packet *pkt, unsigned long long int cookie) {
    struct action_set_entry *entry, *next;

    LIST_FOR_EACH_SAFE(entry, next, struct action_set_entry, node, &set->actions) {
        dp_execute_action(pkt, entry->action);
        list_remove(&entry->node);
        free(entry);

        /* According to the spec. if there was a group action, the output
         * port action should be ignored */
        if (pkt->out_group != OFPG_ANY) {
            unsigned int group_id = pkt->out_group;
            pkt->out_group = OFPG_ANY;

            action_set_clear_actions(pkt->action_set);
            group_table_execute(pkt->dp->groups, pkt, group_id);

            return;
        } else if (pkt->out_port != OFPP_ANY) {
            unsigned int port_id = pkt->out_port;
            unsigned int queue_id = pkt->out_queue;
            unsigned short int max_len = pkt->out_port_max_len;
            pkt->out_port = OFPP_ANY;
            //pkt->out_port_max_len = 0;
            //pkt->out_queue = 0;

            /* FE_XGS_NI_SendPkt发送报文时，queue_id必须与
               vlan pcp对应，否则发送出的报文中pcp值错误
            */
            /*if (pkt->buffer->size > ETH_HEADER_LEN &&
                *((unsigned short int *)(pkt->buffer->data + ETH_ADDR_LEN * 2)) == 0x8100)
                queue_id = (*((unsigned short int *)(pkt->buffer->data + ETH_HEADER_LEN)) >> VLAN_PCP_SHIFT) & VLAN_PCP_BITMASK;
            */
            if (pkt->handle_std->proto->vlan != NULL)
                queue_id = (pkt->handle_std->proto->vlan->vlan_tci >> VLAN_PCP_SHIFT) & VLAN_PCP_BITMASK;
            /* end add */

            action_set_clear_actions(pkt->action_set);
            dp_actions_output_port(pkt, port_id, queue_id, max_len, cookie);
            return;
        }
    }
}

char *
action_set_to_string(struct action_set *set) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    action_set_print(stream, set);

    fclose(stream);
    return str;
}

void
action_set_print(FILE *stream, struct action_set *set) {
    struct action_set_entry *entry;

    VLOG_DBG(LOG_MODULE, stream, "[");

    LIST_FOR_EACH(entry, struct action_set_entry, node, &set->actions) {
        ofl_action_print(stream, entry->action, set->exp);
        if (entry->node.next != &set->actions) { VLOG_DBG(LOG_MODULE, stream, ", "); }
    }

    VLOG_DBG(LOG_MODULE, stream, "]");
}


int
action_is_multi_entry(struct action_set *set,struct packet *pkt,struct group_listner *listner, int* mcast_group) {
    struct action_set_entry *entry, *next;
    struct ofl_action_header *action;
    struct group_entry *g_entry;
    struct ofl_action_output *act;
    struct ofl_bucket **bucket;
    int group_id;
    int i,j;
    int v_ret = 0;

    LIST_FOR_EACH_SAFE(entry, next, struct action_set_entry, node, &set->actions)
    {
         action = entry->action;
         switch (action->type)
         {
             case (OFPAT_GROUP):
             {
                 group_id = ((struct ofl_action_group *)action)->group_id;
                 g_entry = group_table_find(pkt->dp->groups, group_id);
                 if(NULL == g_entry)
                 {
                    return v_ret;
                 }
                 if(OFPGT_ALL == g_entry->desc->type)
                 {
                     v_ret = 1;
                 }
                 else if(OFPGT_FF == g_entry->desc->type)
                 {
                    v_ret = 2;
                 }
                 else if(OFPGT_SELECT == g_entry->desc->type)
                 {
                   v_ret = 4;
                 }
                 else
                 {
                     pkt->alta_supported = false;
                     v_ret = -1;

                 }

                 bucket = g_entry->desc->buckets;

                 for (i=0; i<g_entry->desc->buckets_num; i++)
                 {

                     for(j = 0;j < bucket[i]->actions_num;j++)
                     {
                         if(bucket[i]->actions[j]->type == OFPAT_OUTPUT)
                         {
                             act = (struct ofl_action_output *)bucket[i]->actions[j];
                             listner->vlan =  1;
                             listner->port = act->port;
                             listner->para = (void*)bucket[i];
                             listner++;
                         }
                         else if(bucket[i]->actions[j]->type == OFPAT_GROUP)
                         {
                            pkt->alta_supported = false;
                            v_ret = -1;
                         }
                     }
                 }
                 *mcast_group = group_id;
                 break;
             }
            case OFPAT_OUTPUT:
            case OFPAT_COPY_TTL_IN:
            case OFPAT_COPY_TTL_OUT:
            case OFPAT_SET_MPLS_TTL:
            case OFPAT_DEC_MPLS_TTL:
            case OFPAT_PUSH_VLAN:
            case OFPAT_POP_VLAN:
            case OFPAT_PUSH_MPLS:
            case OFPAT_POP_MPLS:
            case OFPAT_SET_QUEUE:
            case OFPAT_SET_FIELD:
            case OFPAT_SET_NW_TTL:
            case OFPAT_DEC_NW_TTL:
            case OFPAT_PUSH_PBB:
            case OFPAT_POP_PBB:
            case OFPAT_PUSH_FHID:
            case OFPAT_EXPERIMENTER:{
                break;
            }
            default:
                break;
          }
     }

    listner->vlan =  0;
    listner->port = 0xff;
    return v_ret;
}
