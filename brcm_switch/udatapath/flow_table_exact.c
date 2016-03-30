
#include <stdbool.h>
#include <string.h>
#include "dynamic-string.h"
#include "datapath.h"
#include "flow_table.h"
#include "flow_table_exact.h"
#include "flow_entry.h"
#include "flow_entry_exact.h"
#include "oflib/ofl.h"
#include "oflib/oxm-match.h"
#include "time.h"
#include "table_miss.h"
#include "dp_capabilities.h"
#include "timer_wheel.h"
#include "hash.h"
#include "vlog.h"
#define LOG_MODULE VLM_flow_t_exact

static void fill_out16(unsigned char *dst,int pos,unsigned short int value,enum change_order change)
{
    unsigned short int data;
    if (change == HOST_TO_NET)
    {
        data = htons(value);
    }
    else
    {
        data = value;
    }

    memcpy(dst + pos, (unsigned char *)&data, sizeof(unsigned short int));
}

static void fill_out32(unsigned char *dst,int pos,unsigned int value,enum change_order change)
{
    unsigned int data;

    if (change == HOST_TO_NET)
    {
        data = htonl(value);
    }
    else
    {
        data = value;
    }

    memcpy(dst + pos, (unsigned char *)&data, sizeof(unsigned int));
}

static void field_extract(unsigned char *dst,int pos,unsigned char len,
                        unsigned char *src,enum change_order change)
{
     //根据匹配字段值的字节数作不同处理
     switch(len)
     {
           case 1:
           case 6:
           case 8:
           case 16:
                memcpy(dst + pos,src,len);
                break;
           case 2:
                fill_out16(dst,pos,*((unsigned short int *)(src)),change);
                break;
           case 4:
                fill_out32(dst,pos,*((unsigned int *)(src)),change);
                break;
    }
}


static void oxm_field_extract(unsigned char *dst,int pos,unsigned char len,unsigned char *src,unsigned char type)
{
    //根据匹配字段值的字节数作不同处理
    switch (len)
    {
    case 1:
    case 6:
    case 8:
    case 16:
        memcpy(dst + pos, src, len);
        break;
    case 2:
        fill_out16(dst, pos, *((unsigned short int *)(src)), HOST_TO_NET);
        break;
    case 4:
        if ( (type == OFPXMT_OFB_MPLS_LABEL) || (type == OFPXMT_OFB_IN_PORT))
        {
            fill_out32(dst, pos, *((unsigned int *)(src)), HOST_TO_NET);
        }
        else
        {
            fill_out32(dst, pos, *((unsigned int *)(src)), NO_CHANGE);
        }

        break;
    }
}

static int flow_field_extract(unsigned char *dst,int pos,int oxm_field,
                struct ofl_match *flow_match)
{

   unsigned char len;
   struct ofl_match_tlv *tlv;

   HMAP_FOR_EACH_WITH_HASH(tlv, struct ofl_match_tlv,
            hmap_node, DP_FIELD_HASH(oxm_field), &flow_match->match_fields)
   {
       len = OXM_LENGTH(tlv->header);

        if ( oxm_field == OXM_OF_METADATA_W)
       {
            len  = len /2;
       }

       //ofl_oxm_field_print(stdout,OXM_TYPE(tlv->header));

       oxm_field_extract(dst,pos,len,tlv->value,OXM_TYPE(tlv->header));

       pos += len;
   }
   return pos;
}

static int packet_field_extract(unsigned char *dst,int pos,int oxm_field,
                struct packet *pkt)
{

   unsigned char len;
   unsigned int hash;
   bool  found = false;
   struct packet_fields *packet_f;

   hash = DP_FIELD_HASH(oxm_field);
   HMAP_FOR_EACH_WITH_HASH(packet_f, struct packet_fields,
            hmap_node, hash, &pkt->handle_std->match.match_fields)
   {
       len = OXM_LENGTH(packet_f->header);
       //ofl_oxm_field_print(stdout,OXM_TYPE(packet_f->header));
       //网络包本来就是网络序，不需要转换字节序
       field_extract(dst,pos,len,packet_f->value,NO_CHANGE);
       pos += len;
       found = true;
   }
   //要求的匹配域在包中没有找到，就直接返回，例如:需要匹配udp src和upd dst,如果
   //是一个tcp包就一定不能匹配此流表项。
   if (!found && oxm_field != OXM_OF_VLAN_VID)
       return -1;


   //用于VLAN ID 为none时匹配没有带vlan tag的数据包
   if (!found && oxm_field == OXM_OF_VLAN_VID)
   {
        pos += OXM_LENGTH(oxm_field);
        pos += OXM_LENGTH(OXM_OF_VLAN_PCP);
   }

   return pos;
}

int flow_entry_extract(unsigned char *dst,unsigned long long int tbl_match,struct ofl_match *match)
{
    unsigned char i;
    int pos = 0;

    for(i=0;i< (OFPXMT_OFB_MPLS_TC + 1);i++)
    {
        if(tbl_match & ((1ULL) << i))
        {
            //ofl_oxm_field_print(stdout,OXM_TYPE(g_oxm_fields[i]));

            pos = flow_field_extract(dst,pos,g_oxm_fields[i],match);
            if (g_oxm_fields[i] == OXM_OF_METADATA )
            {
                 pos = flow_field_extract(dst,pos,OXM_OF_METADATA_W,match);
            }
        }
    }
    return pos;
}


static int packet_extract(unsigned char *dst,unsigned long long int tbl_match,struct packet *pkt)
{
    unsigned char i;
    int pos = 0;

    for(i=0;i< (OFPXMT_OFB_MPLS_TC + 1);i++)
    {
        if(tbl_match & ((1ULL) << i))
        {
            pos = packet_field_extract(dst,pos,g_oxm_fields[i],
                              pkt);
            if (pos == -1 )
                return -1;
        }
    }
    return pos;
}

static unsigned int packet_head_hash(unsigned char *dst,unsigned long long int tbl_match,
                                struct packet *pkt,int *key_len, bool *found)
{

    unsigned int data_len;

    data_len = packet_extract(dst,tbl_match,pkt);
    if (data_len == -1) {
        *found = false;
        return 0;
     }

    *found = true;
    *key_len = ROUND_UP(data_len,sizeof(unsigned int));

    //进行hash计算
    return jhash2((unsigned int *)dst,
                    DIV_ROUND_UP(data_len, sizeof(unsigned int)), 0);
}


static void exact_flow_table_delete_all(struct flow_table *table,struct ofl_msg_flow_mod *mod)
{
    int i,j;
    struct hlist_head *head = NULL;
    struct flow_entry *entry = NULL;
    struct flow_entry *entry_next = NULL;
    struct hlist_node *n;
    for (j = 0; j < MAX_HASH_BUCKETS_NUM; j++) {
        if (table->hash_match[j] == 0)
            break;
        for (i = 0; i < EXACT_FLOW_TABLE_MAX_ENTRIES; i++) {
            head = &table->buckets[j][i];
            hlist_for_each_entry_safe(entry, n, entry_next, head, hash_node) {
                if (flow_entry_match_outport(entry, mod)) {
                    free(entry->key);
                    hlist_del(&entry->hash_node);
                    alta_logic_entry_remove(entry,FLOW_DELETE);
                    flow_entry_remove(entry,OFPRR_DELETE);
                }
            }
        }
    }

}

void exact_flow_table_timeout(struct flow_table *table)
{
     int i,j;
     struct flow_entry *entry = NULL;
     struct hlist_head *head = NULL;
     struct hlist_node *n;

     for (j = 0; j < MAX_HASH_BUCKETS_NUM; j++ ) {
        if (table->hash_match[j] == 0)
            break;

        for (i = 0; i < EXACT_FLOW_TABLE_MAX_ENTRIES; i++) {
            head = &table->buckets[j][i];

            hlist_for_each_entry(entry, n, head, hash_node) {
                alta_logic_entry_count(entry);
                if (!flow_entry_hard_timeout(entry))
                     flow_entry_idle_timeout(entry);
            }
        }

     }
}

ofl_err exact_flow_table_delete(struct flow_table *table,
                                            struct ofl_msg_flow_mod *mod,bool strict)
{
    /*ofl_err error;*/
    int i,j;
    struct hlist_head *head = NULL;
    struct flow_entry *entry = NULL;
    struct flow_entry *entry_next = NULL;
    struct hlist_node *n;
    unsigned int hash;
    unsigned char *flow_key = NULL;
    int key_len = 0;
    int count = 0;

    if (VLOG_IS_DBG_ENABLED(ALTA_LOG_MODULE))
    {
        VLOG_DBG(ALTA_LOG_MODULE, "exact_flow_table_delete match len:%d\n",mod->match->length);
    }

     //没有匹配域时，删除流表中所有流表项
    if(mod->match->length == 0)
    {
        exact_flow_table_delete_all(table,mod);
    }
    else
    {
        if (strict &&
            is_exact_flow_entry(table, (struct ofl_match *)mod->match, OFPFC_DELETE_STRICT))
        {
            flow_key = malloc_flow_key(ROUND_UP(mod->match->length,sizeof(unsigned int)));
            hash = exact_flow_entry_hash(flow_key,table->hash_match[table->cur_index],
             (struct ofl_match *)mod->match,&key_len);

            head = exact_flow_entry_pos(hash, table);
            hlist_for_each_entry_safe(entry, n, entry_next, head, hash_node) {
                if (flow_entry_match_outport(entry, mod)
                     && entry->stats->priority == mod->priority
                     &&  entry->hash == hash
                     && entry->key_len == key_len
                     && !memcmp(entry->key, flow_key, key_len)) {
                    free(entry->key);
                    hlist_del(&entry->hash_node);
                    alta_logic_entry_remove(entry,FLOW_DELETE);
                    flow_entry_remove(entry,OFPRR_DELETE);
                }
            }
            free(flow_key);
        }
        else {
            for (j = 0; j < MAX_HASH_BUCKETS_NUM; j++) {
                if (table->hash_match[j] == 0)
                    break;

                for (i = 0; i < EXACT_FLOW_TABLE_MAX_ENTRIES; i++)
                {
                    head = &table->buckets[j][i];
                    hlist_for_each_entry_safe(entry, n, entry_next, head, hash_node)
                    {
                        if (flow_entry_match_outport(entry, mod)
                            && flow_entry_matches(entry, mod, strict, false))
                        {
                            free(entry->key);
                            hlist_del(&entry->hash_node);
                            alta_logic_entry_remove(entry,FLOW_DELETE);
                            flow_entry_remove(entry,OFPRR_DELETE);
                        }
                    }
                }
            }
        }
    }

    return 0;
}

ofl_err exact_match_fields_validate(struct flow_table *table,
                                struct ofl_msg_flow_mod *mod)
{
    int flow_match_count = 0;
    /*unsigned char len;*/
    unsigned char  type;
    struct ofl_match_tlv *tlv;

    HMAP_FOR_EACH(tlv, struct ofl_match_tlv,
                hmap_node, &((struct ofl_match *)mod->match)->match_fields)
    {
        flow_match_count ++;
        type = OXM_TYPE(tlv->header);
        /*if ( !(table->match & (1ULL << type)))
        {
            return ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_UNKNOWN);
        }*/
        if ( !(table->hash_match[table->cur_index] & (1ULL << type)))
        {
            return ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_UNKNOWN);
        }
    }

    if (flow_match_count != g_table_match_count[table->features->table_id])
    {
        VLOG_DBG(LOG_MODULE, "flow mod match fields count:%d, expected count:%d \n",
            flow_match_count, g_table_match_count[table->features->table_id]);
        return ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_UNKNOWN);
    }

    return 0;
}

ofl_err exact_flow_table_modify(struct flow_table *table,
                                     struct ofl_msg_flow_mod *mod, bool strict,
                                     bool *insts_kept)
{
    ofl_err error = 0;
    struct flow_entry *entry;

    entry = exact_flow_entry_lookup(table, (struct ofl_match *)(mod->match));
    if ( entry != NULL)
    {
        if (((entry->stats->cookie & mod->cookie_mask) != (mod->cookie & mod->cookie_mask)))
            return error;

        if (strict && (entry->stats->priority != mod->priority))
            return ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_UNKNOWN);

        flow_entry_replace_instructions(entry, mod->instructions_num, mod->instructions);
        entry->last_used = time_now_msec();
        alta_logic_entry_remove(entry,FLOW_MODIFY);
        list_remove(&entry->idle_node);
        list_init(&entry->idle_node);
        *insts_kept = true;
    }

    return error;
}
//根据精确表类型提取匹配字段域,用字段的网络序计算hash值
ofl_err exact_flow_table_add(struct flow_table *table,
                                struct ofl_msg_flow_mod *mod,  bool *match_kept,
                                bool *insts_kept)
{
    unsigned int hash;
    /*int i = 0;*/
    ofl_err error = 0;
    struct hlist_head *head = NULL;
    struct flow_entry *entry = NULL;
    struct flow_entry *old_entry = NULL;
    unsigned char *flow_key = NULL;
    int key_len = 0;
    int count = 0;
    bool check_overlap = ((mod->flags & OFPFF_CHECK_OVERLAP) != 0);

    if (mod->match->length == 0)
    {
        error = ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_UNKNOWN);
        goto fail;
    }

    if (table->stats->active_count >= table->dp->flow_table_max_entries)
    {
        error = ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_TABLE_FULL);
        goto fail;
    }

    if (check_overlap && exact_flow_entry_overlaps(table, mod))
    {
        error = ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_OVERLAP);
        goto fail;
    }

    flow_key = malloc_flow_key(ROUND_UP(mod->match->length,sizeof(unsigned int)));

    //按照spec中字段掩码位置顺序提取flow match fields的字段
    hash = exact_flow_entry_hash(flow_key,table->hash_match[table->cur_index],
           (struct ofl_match *)mod->match,&key_len);

    if (VLOG_IS_DBG_ENABLED(ALTA_LOG_MODULE))
    {
        VLOG_DBG(ALTA_LOG_MODULE, "flow mod match fields key, len=%d \n",key_len);
        ofp_hex_dump(stdout, flow_key, key_len, 0, false);
    }

    head = exact_flow_entry_pos(hash, table);
    old_entry = exact_flow_entry_lookup(table, (struct ofl_match *)mod->match);
    if (old_entry != NULL)
    {
        entry = exact_flow_entry_create(table->dp, table, mod,hash,flow_key,key_len);
        if (entry == NULL)
        {
            return 0;
        }

        *match_kept = true;
        *insts_kept = true;

        if (flow_entry_instruction_equal(entry,old_entry))
        {
            free_flow_key(flow_key);
            flow_entry_destroy(entry);
            return 0;
        }

        hlist_del(&old_entry->hash_node);
        hlist_add_head(&entry->hash_node, head);

        list_remove(&old_entry->hard_node);
        list_remove(&old_entry->idle_node);

        free_flow_key(flow_key);
        flow_entry_destroy(old_entry);
        return 0;
    }
    else
    {
        entry = exact_flow_entry_create(table->dp, table, mod,hash,flow_key,key_len);
        if (entry != NULL)
        {
            if (count >= EXACT_TABLE_CLASH_COUNT)
            {
                VLOG_DBG(LOG_MODULE, "hash clash\n");
                free_flow_key(flow_key);
                error = ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_UNKNOWN);
                goto fail;
            }

            hlist_add_head(&entry->hash_node, head);
            if (table->stats->active_count == EXACT_FLOW_TABLE_MAX_ENTRIES)
            {
                free_flow_key(flow_key);
                error = ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_TABLE_FULL);
                goto fail;
            }
            table->stats->active_count++;
            *match_kept = true;
            *insts_kept = true;
            add_to_timeout_lists(table, entry);
        }
    }

    free_flow_key(flow_key);

    return 0;

fail:
    *match_kept = false;
    *insts_kept = false;
    return error;
}

static void update_flow_entry_count(struct flow_table *table,
                                    struct packet *pkt,
                                    struct flow_entry *entry)
{

    if (!entry->no_byt_count)
       entry->stats->ofp_byte_count += pkt->buffer->size;
    if (!entry->no_pkt_count)
       entry->stats->ofp_packet_count++;

    entry->last_used = time_now_msec();
    table->ofp_matched_count++;
    table->ofp_lookup_count ++;
}

// 用匹配字段的网络序计算hash值
struct flow_entry *exact_flow_table_lookup(struct flow_table *table,
                                                  struct packet *pkt)
{
    int i;
    unsigned int hash;
    unsigned short int priority = 0;
    struct flow_entry *entry = NULL;
    struct flow_entry *ret_entry = NULL;
    struct hlist_node *n;
    struct hlist_head *head;
    unsigned char *pkt_key = NULL;
    int key_len;
    bool found;

    table->ofp_lookup_count++;

    if (pkt->handle_std->match.header.length == 0 )
        return entry;

    pkt_key = malloc_flow_key(ROUND_UP(pkt->handle_std->match.header.length,sizeof(unsigned int)));
    //根据精确表提取匹配域
    if (pkt_key == NULL)
        return entry;

    for ( i = 0; i < MAX_HASH_BUCKETS_NUM; i++ ) {
        if (table->hash_match[i] == 0)
            break;

        hash = packet_head_hash(pkt_key, table->hash_match[i], pkt, &key_len, &found);
        if (!found) {
            memset(pkt_key, 0, ROUND_UP(pkt->handle_std->match.header.length,sizeof(unsigned int)));
            continue;
        }

        if (VLOG_IS_DBG_ENABLED(ALTA_LOG_MODULE)) {
            VLOG_DBG(ALTA_LOG_MODULE, "packet_extract_fields ,len:%d\n", key_len);
            ofp_hex_dump(stdout, pkt_key, key_len, 0, false);
        }

        table->cur_index = i;
        head = exact_flow_entry_pos(hash, table);

        hlist_for_each_entry(entry, n, head, hash_node)
        {
            if ((entry->hash == hash)
                && (entry->key_len == key_len)
                && !memcmp(entry->key, pkt_key, key_len))
            {
                if (entry->stats->priority > priority)
                {
                    ret_entry = entry;
                }
                priority = entry->stats->priority;
                break;
            }
        }

        memset(pkt_key,0,key_len);
    }

    if (ret_entry )
        update_flow_entry_count(table,pkt,ret_entry);

    free_flow_key(pkt_key);

    return ret_entry;
}

static void exact_flow_table_stats_all(struct flow_table *table,
                                     struct ofl_flow_stats ***stats,
                                     size_t *stats_size,
                                     size_t *stats_num)
{
    int i,j;
    struct flow_entry *entry = NULL;
    struct hlist_head *head = NULL;
    struct hlist_node *n;
    struct ofl_flow_stats * flow_stats;

    for ( j = 0; j < MAX_HASH_BUCKETS_NUM; j++ )
    {
        if (table->hash_match[j] == 0)
            break;

        for ( i = 0; i < EXACT_FLOW_TABLE_MAX_ENTRIES; i++)
        {
            head = &table->buckets[j][i];
            hlist_for_each_entry(entry, n, head, hash_node)
            {
                flow_entry_update(entry);

                alta_logic_entry_count(entry);

                if ((*stats_size) == (*stats_num))
                {
                   (*stats) = xrealloc(*stats,
                           (sizeof(struct ofl_flow_stats *)) * (*stats_size) * 2);
                   *stats_size *= 2;
                }

                (*stats)[(*stats_num)] = entry->stats;
                (*stats_num)++;
            }
        }
    }
}

void exact_flow_table_stats(struct flow_table *table,
                                 struct ofl_msg_multipart_request_flow *msg,
                                 struct ofl_flow_stats ***stats,
                                 size_t *stats_size,
                                 size_t *stats_num)
{
    struct flow_entry *entry;

    //没有匹配域时，上传表中所有流表项
    if(msg->match->length == 0)
    {
        exact_flow_table_stats_all(table,stats,stats_size,stats_num);
    }
    else
    {
        entry = exact_flow_entry_lookup(table, (struct ofl_match *)(msg->match));
        if (entry != NULL &&
            (msg->out_port == OFPP_ANY || flow_entry_has_out_port(entry, msg->out_port)) &&
            (msg->out_group == OFPG_ANY || flow_entry_has_out_group(entry, msg->out_group)))
        {
            flow_entry_update(entry);

            alta_logic_entry_count(entry);
            if (entry->no_pkt_count == true)
            {
                entry->stats->packet_count = 0xffffffffffffffff;
            }
            if (entry->no_byt_count == true)
            {
                entry->stats->byte_count = 0xffffffffffffffff;
            }
            if ((*stats_size) == (*stats_num)) {
                (*stats) = xrealloc(*stats, (sizeof(struct ofl_flow_stats *)) * (*stats_size) * 2);
                *stats_size *= 2;
            }

            (*stats)[(*stats_num)] = entry->stats;
            (*stats_num)++;
        }
    }
}

static int packet_field_extract_pi(unsigned char *dst,int *pos,int oxm_field,
                struct packet *pkt,unsigned int match_len)
{

   unsigned char len;
   struct packet_fields *packet_f;

   HMAP_FOR_EACH_WITH_HASH(packet_f, struct packet_fields,
            hmap_node, DP_FIELD_HASH(oxm_field), &pkt->handle_std->match.match_fields)
   {
       len = OXM_LENGTH(packet_f->header);
       //ofl_oxm_field_print(stdout,OXM_TYPE(packet_f->header));
       //网络包本来就是网络序，不需要转换字节序
       if(*pos + len <= match_len)
       {
           memcpy(dst + *pos,packet_f->value,len);
           *pos += len;
       }
       else
       {
           return 0;
       }
   }

   return 1;
}

static int packet_extract_pi(unsigned char *dst,struct packet *pkt,unsigned int match_len)
{
    unsigned char i;
    int pos = 0;

    for(i=0;i< (OFPXMT_OFB_MPLS_TC + 1);i++)
    {
        if(0 == packet_field_extract_pi(dst,&pos,g_oxm_fields[i],pkt,match_len))
        {
            break;
        }
    }
    return pos;
}

unsigned int packet_hash_pi(unsigned char *dst ,
                                struct packet *pkt,unsigned int match_len)
{

    unsigned int data_len;

    if(dst == NULL)
    {
        return 0;
    }

    data_len = packet_extract_pi(dst,pkt,match_len);

    //进行hash计算
    return jhash2((unsigned int *)dst,
                    DIV_ROUND_UP(data_len, sizeof(unsigned int)), 0);
}

