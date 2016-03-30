
#include <stdbool.h>
#include <stdlib.h>
#include "datapath.h"
#include "dp_actions.h"
#include "flow_table.h"
#include "flow_entry.h"
#include "flow_entry_exact.h"
#include "group_table.h"
#include "group_entry.h"
#include "meter_table.h"
#include "meter_entry.h"
#include "oflib/ofl-messages.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl-actions.h"
#include "oflib/ofl-utils.h"
#include "oflib/oxm-match.h"
#include "packets.h"
#include "timeval.h"
#include "util.h"
#include "pipeline.h"
#include <assert.h>


#include "timer_wheel.h"

#include "vlog.h"
#define LOG_MODULE VLM_flow_e_exact



bool exact_flow_entry_overlaps(struct flow_table *table, struct ofl_msg_flow_mod *mod)
{
    struct flow_entry *entry = NULL;

    entry = exact_flow_entry_lookup(table, (struct ofl_match *)mod->match);
    if (entry != NULL)
    {
        return (entry->stats->priority == mod->priority
                && (mod->out_port == OFPP_ANY || flow_entry_has_out_port(entry, mod->out_port))
                && (mod->out_group == OFPG_ANY || flow_entry_has_out_group(entry, mod->out_group)));
    }

    return false;
}

unsigned char *malloc_flow_key(int len)
{
    unsigned char *ptr;
    ptr = xmalloc(len);
    memset(ptr,0,len);
    return ptr;
}

void free_flow_key(unsigned char *ptr)
{
    if(ptr!=NULL)
        free(ptr);
}

struct hlist_head *exact_flow_entry_pos(unsigned int hash,
                                            struct flow_table *table)
{
    struct hlist_head *head = NULL;

    hash = jhash_1word(hash, table->hash_seed[table->cur_index]);
    head = &table->buckets[table->cur_index][hash % EXACT_FLOW_TABLE_MAX_ENTRIES_MODE];

    VLOG_DBG(LOG_MODULE, "flow position hash:0x%x,index:%d \n",hash,(hash % EXACT_FLOW_TABLE_MAX_ENTRIES));
    return head;
}

unsigned int exact_flow_entry_hash(unsigned char *dst,unsigned long long int tbl_match,
                               struct ofl_match *match,int *key_len)
{
    int data_len;
    unsigned int hash;
    data_len = flow_entry_extract(dst,tbl_match,match);
    *key_len = ROUND_UP(data_len,sizeof(unsigned int));
      //¼ÆËãhashÖµ
    hash = jhash2((unsigned int *)dst,
                      DIV_ROUND_UP(data_len, sizeof(unsigned int)), 0);
    VLOG_DBG(LOG_MODULE, "flow hash:0x%x\n",hash);
    return hash;
}

void exact_flow_entry_timeout(struct flow_entry *entry)
{
    hlist_del(&entry->hash_node);
}

struct flow_entry *exact_flow_entry_lookup(struct flow_table *table,struct ofl_match  *match)
{
    unsigned char hash_index = 0;
    struct flow_entry *entry = NULL;
    unsigned int hash;
    struct hlist_head *head = NULL;
    struct hlist_node *n;
    unsigned char *flow_key;
    int key_len;

    hash_index = table->cur_index;
    if (match->header.length > 0 && table->hash_match[hash_index] > 0)
    {
        flow_key = malloc_flow_key(ROUND_UP(match->header.length, sizeof(unsigned int)));

        hash = exact_flow_entry_hash(flow_key, table->hash_match[hash_index],
                               (struct ofl_match *)match, &key_len);

        head = exact_flow_entry_pos(hash, table);
        assert(head);

        if ( VLOG_IS_DBG_ENABLED(ALTA_LOG_MODULE)) {
            VLOG_DBG(LOG_MODULE, "tid:%d,h_index:%d,flow mod key: \n", table->stats->table_id, hash_index);
            ofp_hex_dump(stdout, flow_key, key_len, 0, false);
        }

        hlist_for_each_entry(entry, n, head, hash_node)
        {
            if ((entry->hash == hash)
                && (entry->key_len == key_len)
                && !memcmp(entry->key, flow_key, key_len))
            {
                VLOG_DBG(LOG_MODULE, "exact table found a entry!\n");
                break;
            }
            else
            {
                entry = NULL;
            }
        }

        free_flow_key(flow_key);
    }

    return entry;
}

struct flow_entry *exact_flow_entry_create(struct datapath *dp,
                                                 struct flow_table *table,
                                                 struct ofl_msg_flow_mod *mod,
                                                 unsigned int hash,
                                                 unsigned char *key,
                                                 int  key_len)
{
    struct flow_entry *entry = NULL;
    entry = flow_entry_create(dp,table,mod);
    entry->hash = hash;
    entry->key = xmalloc(key_len);
    memcpy(entry->key,key,key_len);
    entry->key_len = key_len;
    return entry;
}


