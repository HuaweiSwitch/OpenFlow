#include <string.h>
#include "dynamic-string.h"
#include "datapath.h"
#include "flow_table.h"
#include "flow_entry.h"
#include "table_miss.h"

#include "vlog.h"
#define LOG_MODULE VLM_table_miss

struct flow_table *miss_table_create(struct datapath *dp,
                                         unsigned char table_id)
{
    /*int i;*/
    struct flow_table *table;
    struct ds string = DS_EMPTY_INITIALIZER;

    ds_put_format(&string, "table_%u", table_id);

    table = xmalloc(sizeof(struct flow_table));
    table->dp = dp;
    table->miss_flag = 0;  

    table->stats = xmalloc(sizeof(struct ofl_table_stats));
    table->stats->table_id      = table_id;

    table->stats->active_count  = 0;
    table->stats->lookup_count  = 0;
    table->stats->matched_count = 0;

    /* Init Table features */
    table->features = xmalloc(sizeof(struct ofl_table_features));
    table->features->table_id = table_id;
    table->features->name          = ds_cstr(&string);
    table->features->metadata_match = 0xffffffffffffffff;
    table->features->metadata_write = 0xffffffffffffffff;
    table->features->config        = 0;
    table->features->max_entries   = dp->flow_table_max_entries;
    table->features->properties_num = TABLE_FEATURES_NUM;

    list_init(&table->match_entries);
//	list_init(&table->hard_entries);
//	list_init(&table->idle_entries);

    return table;
}

static bool miss_entry_overlaps(struct flow_entry *entry, struct ofl_msg_flow_mod *mod)
{
        return (entry->stats->priority == mod->priority &&
            (mod->out_port == OFPP_ANY || flow_entry_has_out_port(entry, mod->out_port)) &&
            (mod->out_group == OFPG_ANY || flow_entry_has_out_group(entry, mod->out_group)));
}
#if 0
static struct flow_entry *miss_entry_create(struct datapath *dp,
                                            struct flow_table *table,
                                            struct ofl_msg_flow_mod *mod)
{
    /*int i;*/
    struct flow_entry *entry;
    unsigned long long int now;

    now = time_msec();

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

    if (entry->no_pkt_count)
        entry->stats->packet_count     = 0xffffffffffffffff;
    else
        entry->stats->packet_count     = 0;

    if (entry->no_byt_count)
        entry->stats->byte_count       = 0xffffffffffffffff;
    else
        entry->stats->byte_count       = 0;

    entry->stats->match            = mod->match;
    entry->stats->instructions_num = mod->instructions_num;
    entry->stats->instructions     = mod->instructions;

    //entry->instructions_num = mod->instructions_num;
    //entry->instructions = mod->instructions;
    entry->match = mod->match;

    entry->created      = now;
    entry->remove_at    = mod->hard_timeout == 0 ? 0
                                  : now + mod->hard_timeout * 1000;
    //entry->last_used    = now;

    entry->send_removed = ((mod->flags & OFPFF_SEND_FLOW_REM) != 0);

    list_init(&entry->match_node);
    return entry;
}
#endif

struct ofl_flow_stats*
miss_table_lookup_stats(struct flow_table *table)
{
    struct flow_entry *entry;
    struct flow_table *miss_table = table->dp->pipeline->miss_table;

     LIST_FOR_EACH(entry, struct flow_entry,match_node,&miss_table->match_entries)
     {
         if (entry->table->stats->table_id == table->stats->table_id)
         {
            return entry->stats;
         }
     }
     return NULL;
}

ofl_err miss_table_add(struct flow_table *table,
                       struct ofl_msg_flow_mod *mod,
                       bool *match_kept, bool *insts_kept)
{
    // Note: new entries will be placed behind those with equal priority
    struct flow_entry *entry, *new_entry;
    struct flow_table *miss_table = table->dp->pipeline->miss_table;
    bool check_overlap = ((mod->flags & OFPFF_CHECK_OVERLAP) != 0);

    if (miss_table->stats->active_count >= table->dp->flow_table_max_entries)
    {
        return ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_TABLE_FULL);
    }
    LIST_FOR_EACH(entry, struct flow_entry,match_node,&miss_table->match_entries)
    {
        if (check_overlap && miss_entry_overlaps(entry, mod))
        {
            return ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_OVERLAP);
        }

        /* if the entry equals, replace the old one */
        if (entry->table->stats->table_id == table->stats->table_id)
        {
            new_entry = flow_entry_create(table->dp, table, mod);
            *match_kept = true;
            *insts_kept = true;

            /* NOTE: no flow removed message should be generated according to spec. */
            list_replace(&entry->match_node, &new_entry->match_node);
            return 0;
        }

        if (mod->priority > entry->stats->priority)
        {
            break;
        }
    }


    miss_table->stats->active_count++;

    new_entry = flow_entry_create(table->dp, table, mod);
    *match_kept = true;
    *insts_kept = true;

    //list_add_tail(&new_entry->match_node, &entry->match_node);
    list_insert(&entry->match_node, &new_entry->match_node);

    table->miss_flag = 1;

    VLOG_DBG(LOG_MODULE, "add miss table count:%d\n",miss_table->stats->active_count);
    return 0;
}

ofl_err miss_table_modify(struct flow_table *table,
                          struct ofl_msg_flow_mod *mod,
                          bool strict, bool *insts_kept)
{
    /*ofl_err error;*/
    struct flow_entry *entry, *next;/*, *new_entry*/
    struct flow_table *miss_table = table->dp->pipeline->miss_table;

    list_for_each_entry_safe(entry, next, &miss_table->match_entries, match_node)
    {
        if (entry->table->stats->table_id == table->stats->table_id)
        {
            flow_entry_replace_instructions(entry, mod->instructions_num, mod->instructions);
            //list_replace(&entry->match_node, &new_entry->match_node);
            *insts_kept = true;
        }
    }

    (void)strict;

    return 0;
}

ofl_err miss_table_delete(struct flow_table *table,
                          struct ofl_msg_flow_mod *mod, bool strict)
{
    struct flow_entry *entry, *next;
    struct flow_table *miss_table = table->dp->pipeline->miss_table;
    (void)strict;
    list_for_each_entry_safe(entry, next, &miss_table->match_entries, match_node)
    {
        if (flow_entry_match_outport(entry, mod)
            && entry->table->stats->table_id == table->stats->table_id)
        {
            if (entry->send_removed)
            {
                flow_entry_update(entry);
                {
                    struct ofl_msg_flow_removed msg =
                            {{.type = OFPT_FLOW_REMOVED},
                             .reason = OFPRR_DELETE,
                             .stats  = entry->stats};

        		    dp_send_message(entry->dp, (struct ofl_msg_header *)&msg,NULL);
                }
            }
            list_del(&entry->match_node);
            //list_remove(&entry->match_node);
            //list_remove(&entry->hard_node);
            //list_remove(&entry->idle_node);
            miss_table->stats->active_count--;

            table->miss_flag = 0;
            VLOG_DBG(LOG_MODULE, "delete miss table count:%d\n",miss_table->stats->active_count);
        }
    }

    return 0;
}
