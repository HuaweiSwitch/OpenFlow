/* Copyright (c) 2011, TrafficLab, Ericsson Research, Hungary
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
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <sys/types.h>
#include "compiler.h"
#include "group_table.h"
#include "datapath.h"
#include "dp_actions.h"
#include "dp_capabilities.h"
#include "hmap.h"
#include "list.h"
#include "packet.h"
#include "util.h"
#include "openflow/openflow.h"
#include "oflib/ofl.h"
#include "oflib/ofl-messages.h"

#include "vlog.h"
#define LOG_MODULE VLM_group_t

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

static bool
is_in(unsigned int id, struct list *list);

static void
is_loop_free_visit(struct ofl_bucket **buckets, size_t buckets_num, struct list *visited, struct list *to_be_visited);

static bool
is_loop_free(struct group_table *table, struct ofl_msg_group_mod *mod);


struct group_entry *
group_table_find(struct group_table *table, unsigned int group_id) {
    struct hmap_node *hnode;

    hnode = hmap_first_with_hash(&table->entries, group_id);

    if (hnode == NULL) {
        return NULL;
    }

    return CONTAINER_OF(hnode, struct group_entry, node);
}

bool group_entry_loop_chain_check(struct group_table *table, struct ofl_msg_group_mod *mod)
{
    //int i;
    return true;
}
ofl_err group_entry_watch_check(struct group_table *table, struct ofl_msg_group_mod *mod)
{
    int i,j;
    bool port_live = false;
    struct group_entry * group;
    for( i=0; i<mod->buckets_num; i++)
    {
        struct ofl_bucket *bucket = mod->buckets[i];
        if( OFPGT_FF != mod->type )
        {
            return 0;
        }
        if( (NULL == dp_ports_lookup(table->dp, bucket->watch_port )) && ( bucket->watch_port != OFPP_ANY) )
        {
            return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_BAD_WATCH);
        }
        if(OFPG_ANY!=bucket->watch_group)
        {
            group = group_table_find(table, bucket->watch_group);
            if( NULL == group )
            {
                return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_BAD_WATCH);
            }
            else
            {
                for( j=0; j<group->desc->buckets_num; j++)
                {
                    struct ofl_bucket *sub_bucket = group->desc->buckets[j];
                    if( sub_bucket->watch_port != OFPP_ANY)
                    {
                        if( NULL != dp_ports_lookup(table->dp, sub_bucket->watch_port) )
                        {
                            port_live = true;
                        }
                    }
                }
                if( true != port_live)
                {
                    return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_BAD_WATCH);
                }
            }
        }
    }
    return 0;
}
/* Handles group mod messages with ADD command. */
static ofl_err
group_table_add(struct group_table *table, struct ofl_msg_group_mod *mod) {

    struct group_entry *entry;
    ofl_err err;

    if (hmap_first_with_hash(&table->entries, mod->group_id) != NULL) {
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_GROUP_EXISTS);
    }

    if (table->entries_num >= GROUP_TABLE_MAX_ENTRIES) {
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_OUT_OF_GROUPS);
    }

    if (table->buckets_num + mod->buckets_num > GROUP_TABLE_MAX_BUCKETS) {
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_OUT_OF_BUCKETS);
    }
    err = group_entry_watch_check(table, mod);
    if( 0 != err)
        return err;

    entry = group_entry_create(table->dp, table, mod);

    hmap_insert(&table->entries, &entry->node, entry->stats->group_id);

    table->entries_num++;
    table->buckets_num += entry->desc->buckets_num;

    ofl_msg_free_group_mod(mod, false, table->dp->exp);
    return 0;
}

/* Handles group_mod messages with MODIFY command. */
static ofl_err
group_table_modify(struct group_table *table, struct ofl_msg_group_mod *mod) {
    struct group_entry *entry, *new_entry;

    entry = group_table_find(table, mod->group_id);
    if (entry == NULL) {
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_UNKNOWN_GROUP);
    }

    if (table->buckets_num - entry->desc->buckets_num + mod->buckets_num > GROUP_TABLE_MAX_BUCKETS) {
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_OUT_OF_BUCKETS);
    }

    if (!is_loop_free(table, mod)) {
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_LOOP);
    }

    if (mod->buckets_num != entry->desc->buckets_num ||
            !group_entry_equal(table->dp,mod->buckets_num,mod->buckets,entry->desc->buckets))
    {
        new_entry = group_entry_create(table->dp, table, mod);

        hmap_remove(&table->entries, &entry->node);
        hmap_insert_fast(&table->entries, &new_entry->node, mod->group_id);

        table->buckets_num = table->buckets_num - entry->desc->buckets_num + new_entry->desc->buckets_num;

        new_entry->modify_time = time_now_msec();

        /* keep flow references from old group entry */
        list_replace(&new_entry->flow_refs, &entry->flow_refs);
        new_entry->stats->ref_count = entry->stats->ref_count;

        /*  delete hardware and openflow flow entry */
        group_entry_destroy_physic(new_entry);

        list_init(&entry->flow_refs);

        group_entry_destroy(entry);
    }

    ofl_msg_free_group_mod(mod, false, table->dp->exp);
    return 0;
}

/* Handles group mod messages with DELETE command. */
static ofl_err
group_table_delete(struct group_table *table, struct ofl_msg_group_mod *mod) {
    if (mod->group_id == OFPG_ALL) {
        struct group_entry *entry, *next;

        HMAP_FOR_EACH_SAFE(entry, next, struct group_entry, node, &table->entries) {
            group_entry_destroy(entry);
        }
        hmap_destroy(&table->entries);
        hmap_init(&table->entries);

        table->entries_num = 0;
        table->buckets_num = 0;

        ofl_msg_free_group_mod(mod, true, table->dp->exp);
        return 0;

    } else {
        struct group_entry *entry, *e;

        entry = group_table_find(table, mod->group_id);

        if (entry != NULL) {

            /* NOTE: The spec. does not define what happens when groups refer to groups
                     which are being deleted. For now deleting such a group is not allowed. */
            HMAP_FOR_EACH(e, struct group_entry, node, &table->entries) {
                if (group_entry_has_out_group(e, entry->stats->group_id)) {
                    return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_CHAINING_UNSUPPORTED);
                }
            }

            table->entries_num--;
            table->buckets_num -= entry->desc->buckets_num;

            hmap_remove(&table->entries, &entry->node);
            group_entry_destroy(entry);
        }

        /* NOTE: In 1.1 no error should be sent, if delete is for a non-existing group. */

        ofl_msg_free_group_mod(mod, true, table->dp->exp);
        return 0;
    }
}

ofl_err
group_table_handle_group_mod(struct group_table *table, struct ofl_msg_group_mod *mod,
                                                          const struct sender *sender) {
    ofl_err error;
    size_t i;

    if(sender->remote->role == OFPCR_ROLE_SLAVE)
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_IS_SLAVE);

    for (i=0; i< mod->buckets_num; i++) {
        error = dp_actions_validate(table->dp, mod->buckets[i]->actions_num, mod->buckets[i]->actions);
        if (error) {
            return error;
        }
    }

    switch (mod->command) {
        case (OFPGC_ADD): {
            return group_table_add(table, mod);
        }
        case (OFPGC_MODIFY): {
            return group_table_modify(table, mod);
        }
        case (OFPGC_DELETE): {
            return group_table_delete(table, mod);
        }
        default: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
        }
    }
}

ofl_err
group_table_handle_stats_request_group(struct group_table *table,
                                  struct ofl_msg_multipart_request_group *msg,
                                  const struct sender *sender UNUSED) {
    struct group_entry *entry;

    if (msg->group_id == OFPG_ALL) {
        entry = NULL;
    } else {
        entry = group_table_find(table, msg->group_id);

        if (entry == NULL) {
            return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_UNKNOWN_GROUP);
        }
    }

    {
        struct ofl_msg_multipart_reply_group reply =
                {{{.type = OFPT_MULTIPART_REPLY},
                  .type = OFPMP_GROUP, .flags = 0x0000},
                 .stats_num = msg->group_id == OFPG_ALL ? table->entries_num : 1,
                 .stats     = xmalloc(sizeof(struct ofl_group_stats *) * (msg->group_id == OFPG_ALL ? table->entries_num : 1))
                };

        if (msg->group_id == OFPG_ALL) {
            struct group_entry *e;
            size_t i = 0;

            HMAP_FOR_EACH(e, struct group_entry, node, &table->entries) {
                 group_entry_update(e);
                 alta_group_entry_count(e);
                 if(e->stats->packet_count < 3000 && e->packet_count_bak >= 3000)
                 {
                     e->stats->packet_count = e->packet_count_bak;
                     e->stats->byte_count = e->byte_count_bak;
                 }
                 reply.stats[i] = e->stats;
                 i++;
             }

        } else {
            group_entry_update(entry);
            alta_group_entry_count(entry);
            if(entry->stats->packet_count < 3000  && entry->packet_count_bak >= 3000)
            {
                entry->stats->packet_count = entry->packet_count_bak;
                entry->stats->byte_count = entry->byte_count_bak;
            }
            reply.stats[0] = entry->stats;
        }

        dp_send_message(table->dp, (struct ofl_msg_header *)&reply, sender);

        free(reply.stats);
        ofl_msg_free((struct ofl_msg_header *)msg, table->dp->exp);
        return 0;
    }
}

ofl_err
group_table_handle_stats_request_group_desc(struct group_table *table,
                                  struct ofl_msg_multipart_request_header *msg UNUSED,
                                  const struct sender *sender) {
    struct group_entry *entry;
    size_t i = 0;

    struct ofl_msg_multipart_reply_group_desc reply =
            {{{.type = OFPT_MULTIPART_REPLY},
              .type = OFPMP_GROUP_DESC, .flags = 0x0000},
             .stats_num = table->entries_num,
             .stats     = xmalloc(sizeof(struct ofl_group_desc_stats *) * table->entries_num)
            };

    HMAP_FOR_EACH(entry, struct group_entry, node, &table->entries) {
        reply.stats[i] = entry->desc;
        i++;
    }
    dp_send_message(table->dp, (struct ofl_msg_header *)&reply, sender);

    free(reply.stats);
    ofl_msg_free((struct ofl_msg_header *)msg, table->dp->exp);
    return 0;
}

ofl_err
group_table_handle_stats_request_group_features(struct group_table *table,
                                  struct ofl_msg_multipart_request_header *msg UNUSED,
                                  const struct sender *sender) {
    size_t i = 0;

    struct ofl_msg_multipart_reply_group_features reply =
            {{{.type = OFPT_MULTIPART_REPLY},
              .type = OFPMP_GROUP_FEATURES, .flags = 0x0000},
             .types = table->features->types,
			 .capabilities = table->features->capabilities
            };

	for(i = 0; i < 4; i++){
		reply.max_groups[i] = table->features->max_groups[i];
		reply.actions[i] = table->features->actions[i];
	}

    dp_send_message(table->dp, (struct ofl_msg_header *)&reply, sender);

    ofl_msg_free((struct ofl_msg_header *)msg, table->dp->exp);
    return 0;
}

void
group_table_execute(struct group_table *table, struct packet *packet, unsigned int group_id) {
    struct group_entry *entry;

    entry = group_table_find(table, group_id);

    if (entry == NULL) {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute non-existing group (%u).", group_id);
        return;
    }

   group_entry_execute(entry, packet);
}

struct group_table *
group_table_create(struct datapath *dp) {
    struct group_table *table;
	size_t i;

    table = xmalloc(sizeof(struct group_table));
    table->dp = dp;

	table->features = (struct ofl_msg_multipart_reply_group_features*) xmalloc(sizeof(struct ofl_msg_multipart_reply_group_features));
	table->features->types = DP_SUPPORTED_GROUPS;
	table->features->capabilities = DP_SUPPORTED_GROUP_CAPABILITIES;
	for(i = 0; i < 4; i++){
		table->features->max_groups[i] = OFPG_MAX;
		table->features->actions[i] = DP_SUPPORTED_ACTIONS;
	}
    table->entries_num = 0;
    hmap_init(&table->entries);
    table->buckets_num = 0;

    return table;
}

void
group_table_destroy(struct group_table *table) {
    struct group_entry *entry, *next;

    HMAP_FOR_EACH_SAFE(entry, next, struct group_entry, node, &table->entries) {
        group_entry_destroy(entry);
    }

    free(table);
}


struct group_visit {
	struct list   node;
	unsigned int      group_id;
};

static bool
is_in(unsigned int id, struct list *list) {
	struct group_visit *gv;

	LIST_FOR_EACH(gv, struct group_visit, node, list) {
		if (gv->group_id == id) {
			return true;
		}
	}
	return false;
}

static void
is_loop_free_visit(struct ofl_bucket **buckets, size_t buckets_num, struct list *visited, struct list *to_be_visited) {
	size_t ib;
	for (ib=0; ib<buckets_num; ib++) {
		size_t ia;

		for (ia=0; ia<buckets[ib]->actions_num; ia++) {
			if (buckets[ib]->actions[ia]->type == OFPAT_GROUP) {
				struct ofl_action_group *act = (struct ofl_action_group *) buckets[ib]->actions[ia];
				if (!is_in(act->group_id, visited) &&
					!is_in(act->group_id, to_be_visited)) {
					struct group_visit *gv = xmalloc(sizeof(struct group_visit));

					gv->group_id = act->group_id;
					list_insert(to_be_visited, &(gv->node));

				}

			}
		}
	}
}


static bool
is_loop_free(struct group_table *table, struct ofl_msg_group_mod *mod) {
/* Note: called when a modify is called on group. Table is the actual
 *       table, and mod is the modified entry. Returns true if the
 *       table would remain loop free after the modification.
 *       It is assumed that table is loop free without the modification.
 */
	struct list visited, to_be_visited;
	bool loop_free;
	struct group_visit *gv, *gvn;

	list_init(&visited);
	list_init(&to_be_visited);

	is_loop_free_visit(mod->buckets, mod->buckets_num, &visited, &to_be_visited);

	while(!list_is_empty(&to_be_visited)) {
		struct group_entry *entry;

		// if modified entry is to be visited, there is a loop
		if (is_in(mod->group_id, &to_be_visited)) {
			break;
		}

		gv = CONTAINER_OF(list_pop_front(&to_be_visited), struct group_visit, node);

		entry = group_table_find(table, gv->group_id);
		if (entry != NULL) {
			is_loop_free_visit(entry->desc->buckets, entry->desc->buckets_num, &visited, &to_be_visited);
		} else {
	        VLOG_WARN_RL(LOG_MODULE, &rl, "is_loop_free cannot find group (%u).", gv->group_id);
		}

		list_insert(&visited, &(gv->node));
	}

	loop_free = list_is_empty(&to_be_visited);

	// free list_nodes
	LIST_FOR_EACH_SAFE(gv, gvn, struct group_visit, node, &visited) {
		free(gv);
	}
	LIST_FOR_EACH_SAFE(gv, gvn, struct group_visit, node, &to_be_visited) {
		free(gv);
	}


	return loop_free;
}
