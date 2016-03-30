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

#include <sys/types.h>
#include <stdbool.h>
#include <stdlib.h>

#include "action_set.h"
#include "compiler.h"
#include "dp_actions.h"
#include "dp_buffers.h"
#include "dp_exp.h"
#include "dp_ports.h"
#include "utilities/dpctl.h"
#include "dp_capabilities.h"
#include "datapath.h"
#include "packet.h"
#include "pipeline.h"
#include "flow_table.h"
#include "flow_entry.h"
#include "meter_table.h"
#include "oflib/ofl.h"
#include "oflib/ofl-structs.h"
#include "jhash.h"
#include "util.h"
#include "hash.h"
#include "oflib/oxm-match.h"
#include "vlog.h"

#include "oflib/ofl-utils.h"
#include "dpal_pub.h"

#define LOG_MODULE VLM_pipeline

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

static void
execute_entry(struct pipeline *pl, struct flow_entry *entry,
              struct flow_table **table, struct packet **pkt);

struct pipeline *
pipeline_create(struct datapath *dp) {
    struct pipeline *pl;
    int i;

    pl = xmalloc(sizeof(struct pipeline));
    for (i=0; i<PIPELINE_TABLES; i++) {
        pl->tables[i] = flow_table_create(dp, i);
    }
    pl->dp = dp;

    pl->miss_table = miss_table_create(dp, PIPELINE_TABLES);

    return pl;
}


void send_packet_to_controller(struct pipeline *pl, struct packet *pkt, unsigned char table_id, unsigned char reason)
{

    struct ofl_msg_packet_in msg;
    struct ofl_match *m;
    struct sw_port *p;
    size_t data_length;
    unsigned short int  copy_len = 0;

    msg.header.type = OFPT_PACKET_IN;
    //msg.total_len   = pkt->buffer->size;
    msg.reason      = reason;
    msg.table_id    = table_id;
    msg.cookie      = 0xffffffffffffffff;
    msg.data = pkt->buffer->data;

    data_length = pkt->buffer->size;

    VLOG_DBG(LOG_MODULE, "openflow:send packet in size:%lu reason:%d,max_len:0x%x \r\n",data_length,
            reason,pkt->out_port_max_len);

    p = dp_ports_lookup(pl->dp, pkt->in_port);
    if( p == NULL)
        return;


    if ((p->conf->config & OFPPC_NO_PACKET_IN) != 0)
    {
        VLOG_DBG(LOG_MODULE, "Packet-in disabled on port (%u)", p->stats->port_no);
        return;
    }

    meter_table_apply(pl->dp->meters, &pkt , OFPM_CONTROLLER);
    if( pkt == NULL)
    {
        return;
    }

    if (reason == OFPR_ACTION || reason == OFPR_NO_MATCH)
    {
        copy_len = pkt->out_port_max_len;
        if (copy_len == OFPCML_NO_BUFFER)
        {
           copy_len = data_length;
        }
        else
        {
            copy_len = MIN(data_length,copy_len);
        }
    }
    else
    {
        copy_len = MIN(pl->dp->config.miss_send_len,data_length);
    }

    msg.buffer_id = OFP_NO_BUFFER;
    if (msg.buffer_id == OFP_NO_BUFFER)
    {
        copy_len = data_length;
        msg.buffer_id = OFP_NO_BUFFER;
    }

    msg.data_length = copy_len;
    msg.total_len   = copy_len;

    m = xmalloc (sizeof(struct ofl_match));
    ofl_structs_match_init(m);
    ofl_structs_match_convert_pktf2oflm(&pkt->handle_std->match.match_fields, m);
    msg.match = (struct ofl_match_header*)m;

    dp_send_message(pl->dp, (struct ofl_msg_header *)&msg, NULL);

    ofl_structs_free_match((struct ofl_match_header* ) m, NULL);
}


int pi_pkt2ofp_send2controller(struct pipeline *pl, struct packet *pkt_in, unsigned char table_id, unsigned char reason)
{
    struct packet *pkt = pkt_in;
    struct ofp_packet_in *packet_in;
    unsigned short int total_len = 0;
    unsigned int buf_len = 0;
    unsigned int match_len = 0;
    struct sw_port *p = NULL;
    size_t data_length = 0;
    struct ofpbuf  *ofpbuf = NULL;
    int error = 0;
    unsigned char *ptr = NULL;

    p = dp_ports_lookup(pl->dp, pkt->in_port);
    if( p == NULL)
    {
        return -1;
    }

    if ((p->conf->config & OFPPC_NO_PACKET_IN) != 0)
    {
        VLOG_ERR(LOG_MODULE, "(p->conf->config & OFPPC_NO_PACKET_IN) is %u\n",
            (p->conf->config & OFPPC_NO_PACKET_IN));
        pkt->buffer_id = OFP_NO_BUFFER;
        packet_destroy(pkt);
        VLOG_ERR(LOG_MODULE, "Packet-in disabled on port (%u)", p->stats->port_no);
        return -1;
    }

    meter_table_apply(pl->dp->meters, &pkt , OFPM_CONTROLLER);
    if( pkt == NULL)
    {
        return -1;
    }

    if( (0 == pkt->handle_std->match.header.length) && (0 != pkt->handle_std->match_num) )
    {
        VLOG_ERR(LOG_MODULE, "****before  pkt->handle_std->match.header.length is equal to 0 *****\n");
        packet_destroy(pkt);
        return -1;
    }

    data_length = pkt->buffer->size;

    VLOG_DBG(LOG_MODULE, "After same pi process: send packet in size:%lu reason:%s,max_len:0x%x \r\n",
               data_length,reason_name[reason].name,pkt->out_port_max_len);

    if ( (pl->dp->config.miss_send_len != OFPCML_NO_BUFFER)&& (pkt->out_port_max_len < data_length) )
    {
        dp_buffers_save(pkt->dp->buffers, pkt);
    }
    else
    {
        pkt->buffer_id = OFP_NO_BUFFER;
    }

    if (reason == OFPR_ACTION || reason == OFPR_NO_MATCH)
    {
        total_len = pkt->out_port_max_len;
        if (total_len == OFPCML_NO_BUFFER)
        {
           total_len = data_length;
        }
        else
        {
            total_len = MIN(data_length,total_len);
        }
    }
    else
    {
        total_len = MIN(pl->dp->config.miss_send_len,data_length);
    }

    if (pkt->buffer_id == OFP_NO_BUFFER)
    {
        total_len = data_length;
    }

    //上送长度必须比miss_send_len小
    total_len = MIN(pl->dp->config.miss_send_len,total_len);

    match_len = (pkt->handle_std->match_num)*4 + pkt->handle_std->match.header.length;
    buf_len = sizeof(struct ofp_packet_in)-sizeof(struct ofp_match) + ROUND_UP(match_len+4 ,8) + total_len + 2;
    packet_in = (struct ofp_packet_in *)malloc(buf_len);
    packet_in->match.length = htons(match_len+4);

    packet_in->header.type = OFPT_PACKET_IN;
    packet_in->header.version = OFP_VERSION;
    packet_in->header.length  = htons(buf_len);
    packet_in->header.xid     = 0; //need modify
    packet_in->buffer_id   = htonl(pkt->buffer_id);
    packet_in->total_len   = htons(total_len);
    packet_in->reason      = reason;
    packet_in->table_id    = table_id;
    packet_in->cookie      = hton64(pkt->cookie);

    ptr = (unsigned char *)(packet_in) + (sizeof(struct ofp_packet_in)-4);//point to the start of the oxm_field

    packet_in->match.type = htons(OFPMT_OXM);

    ofp_structs_match_convert_pkt2ofp(&pkt->handle_std->match.match_fields, \
                                      &(packet_in->match),ptr, NULL);

    ptr = (unsigned char *)(packet_in)+(sizeof(struct ofp_packet_in)-sizeof(struct ofp_match))+ROUND_UP(match_len+4,8);

    memset(ptr,0,2);
    if ( total_len > 0 ) {
        memcpy(ptr + 2 , pkt->buffer->data, total_len);
    }

    ofpbuf = ofpbuf_new(0);
    ofpbuf_use(ofpbuf, (unsigned char *)packet_in, buf_len);
    ofpbuf_put_uninit(ofpbuf, buf_len);

    error = send_openflow_buffer(pl->dp, ofpbuf, NULL);

    if (error) {
        VLOG_WARN_RL(LOG_MODULE, &rl, "There was an error sending the message!");
        return error;
    }

    return 0;
}


static void ofp_path_dump(struct ofp_path *ofp_path,struct path *path)
{
    int i;
    char * str = NULL;
    struct path_entry *path_entry;

    if (!VLOG_IS_DBG_ENABLED(LOG_MODULE))
    {
        return;
    }

    if ( ofp_path != NULL)
    {
        VLOG_DBG(LOG_MODULE, "display exist path \n");
        for ( i = 0; i < PIPELINE_TABLES ; i++)
        {
            if (ofp_path->path_entry[i]->entry != NULL)
            {
                str = flow_entry_to_string((struct flow_entry *)(ofp_path->path_entry[i]->entry));
                if (str != NULL)
                {
                    VLOG_DBG(LOG_MODULE, "%s", str);
                    free(str);
                    str = NULL;
                }
            }
        }
    }

    if ( path != NULL )
    {
        VLOG_DBG(LOG_MODULE, "display new path \n");
        LIST_FOR_EACH(path_entry, struct path_entry, node, &path->head)
        {
            str = flow_entry_to_string((struct flow_entry *)path_entry->entry);
            if (str != NULL)
            {
                VLOG_DBG(LOG_MODULE, "%s", str);
                free(str);
                str = NULL;
            }
        }
    }
}

static void dp_path_dump(struct datapath *dp)
{
    struct ofp_path *path_item;
    int i = 0;

    if (!VLOG_IS_DBG_ENABLED(LOG_MODULE))
    {
        return;
    }

    VLOG_DBG(LOG_MODULE, "\n star dump path num:%lu \n", list_size(&dp->ofp_path));
    LIST_FOR_EACH(path_item, struct ofp_path, node, &dp->ofp_path)
    {
       ofp_path_dump(path_item, NULL);
       i++;
    }

    VLOG_DBG(LOG_MODULE, "\n end dump path num:%d\n", i);
}

static void pipeline_logic_path_init(struct packet *pkt,
                                  struct path *path,
                                  struct path_contex *context)
{
    int index;
    memset(context, 0, sizeof(struct path_contex));
    context->ivlan = INV_VLAN_ID;
    context->ipri = INV_VLAN_PCP;
    context->impls = 0xffffffff;
    context->impls_cnt = 0;

    if(pkt->handle_std->proto->mpls)
    {
        context->impls = ntohl(pkt->handle_std->proto->mpls->fields);
    }

    if (pkt->handle_std->proto->vlan)
    {
       context->ivlan = ntohs(pkt->handle_std->proto->vlan->vlan_tci) & VLAN_VID_MASK;
       context->ipri = (ntohs(pkt->handle_std->proto->vlan->vlan_tci) & VLAN_PCP_MASK) >> VLAN_PCP_SHIFT;
    }

    context->evlan = context->ivlan;
    context->epri = context->ipri;
    context->exist = true;

    for (index = 0; index < 4; index++)
    {
        context->empls[index] = 0xffffffff;
        context->mpls_pop_ethtype[index] = 0xffffffff;
    }
     context->loopback = false;
     context->l2_push  = false;

    memset(path, 0, sizeof(struct path));
    list_init(&path->head);

}


static void pipeline_write_path_info(struct packet *pkt,
                                  struct path *path,
                                  struct path_contex *context,
                                  struct path_entry *path_entry,
                                  struct flow_entry *entry)
{
    int mcast_group = 0;
    context->mcast_flag = action_is_multi_entry(pkt->action_set,pkt,(void*)context->usr_data, &mcast_group);
    context->mcast_group = mcast_group;
    context->mcast_ecmp_group = 0;
    path_entry->entry = entry;

    path_entry->table_class_id = TABLE_CLASS_ID(0, entry->table->features->table_id);

    path->meter.meter_entry = pkt->dp->m_entry;
    list_push_back(&path->head, &path_entry->node);
}

void
pipeline_process_packet(struct pipeline *pl, struct packet *pkt)
{
    struct flow_table *table, *next_table;
    struct path path;
    struct path_entry path_entry[PIPELINE_TABLES];
    struct path_contex context;
    unsigned int uiRet;
    DPAL_MESSAGE_DATA_S stMSGData = {0};

    g_send_to_ctl_count ++;

    memset(path_entry, 0, sizeof(path_entry));
    pipeline_logic_path_init(pkt,&path,&context);

    if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
        char *pkt_str = packet_to_string(pkt);
        VLOG_DBG_RL(LOG_MODULE, &rl, "processing packet: %s", pkt_str);
        free(pkt_str);
    }

    if (!packet_handle_std_is_ttl_valid(pkt->handle_std))
    {
        VLOG_DBG_RL(LOG_MODULE, &rl, "Packet has invalid TTL, sending to controller.");
        pi_pkt2ofp_send2controller(pl, pkt, 0/*table_id*/, OFPR_INVALID_TTL);
        packet_destroy(pkt);
        return;
    }

    pl->dp->m_entry = NULL;
    next_table = pl->tables[0];
    while (next_table != NULL)
    {
        struct flow_entry *entry;

        VLOG_DBG_RL(LOG_MODULE, &rl, "trying table %u.", next_table->stats->table_id);
        FAILOVER_PRINT("trying table %u.", next_table->stats->table_id);
        pkt->table_id = next_table->stats->table_id;
        table         = next_table;
        next_table    = NULL;

        pkt->mis_match_entry_hited = false;

        entry = flow_table_lookup(table, pkt);
        if (entry != NULL)
        {
            if (VLOG_IS_DBG_ENABLED(ALTA_LOG_MODULE))
            {
                char *m = ofl_structs_flow_stats_to_string(entry->stats, pkt->dp->exp);
                VLOG_DBG(ALTA_LOG_MODULE, "found matching entry: %s.", m);
                FAILOVER_PRINT("found matching entry: %s.", m);
                free(m);
            }

            if(entry->stats->priority == 0 && entry->match->length == 0)
            {
                pkt->mis_match_entry_hited = true;
            }

            execute_entry(pl, entry, &next_table, &pkt);
            if (!pkt)
            {
                return;
            }

            if ( !pl->dp->soft_switch )
            {
                pipeline_write_path_info(pkt,&path,&context,
                                 &path_entry[entry->stats->table_id],entry);
            }

            if (next_table == NULL)
            {
                if ((!pl->dp->soft_switch) && (!pkt->mis_match_entry_hited))
                {
                    ofp_path_dump(NULL, &path);

                    context.path = &path;
                    context.pkt = pkt;
                    if ((ntohs(pkt->handle_std->proto->eth->eth_type) != ETH_TYPE_ARP)
                          && (true == dp_hw_download(pl->dp->data_buffers, pkt, &context)))
                    {
                        uiRet = DPAL_TranslatePkt(DPAL_MSG_TYPE_FLOWTABLE_ADD, &context, &stMSGData);
                        if (0 == uiRet)
                        {
                            //发送报文
                            uiRet = Hybrid_Chatwith_V8_new(&stMSGData);
                            free(stMSGData.pData);
                            if (uiRet)
                            {
                                VLOG_ERR_RL(LOG_MODULE, &rl, "alta logic get entry count, send to v8 failed!\n");
                            }
                        }
                        else
                        {
                            VLOG_ERR_RL(LOG_MODULE, &rl, "DPAL_TranslatePkt flow table add failed!\n");
                        }
                    }
                }

                if (0 == pkt->reason)
                    action_set_execute(pkt->action_set, pkt, 0xffffffffffffffff);


                packet_destroy(pkt);

                return;
            }

        }
        else
        {
            if (next_table == NULL) {
                packet_destroy(pkt);
                return;
            }
        }
    }
}

static
int inst_compare(const void *inst1, const void *inst2){
    struct ofl_instruction_header * i1 = *(struct ofl_instruction_header **) inst1;
    struct ofl_instruction_header * i2 = *(struct ofl_instruction_header **) inst2;
    if ((i1->type == OFPIT_APPLY_ACTIONS && i2->type == OFPIT_CLEAR_ACTIONS) ||
        (i1->type == OFPIT_CLEAR_ACTIONS && i2->type == OFPIT_APPLY_ACTIONS))
        return i1->type > i2->type;

    return i1->type < i2->type;
}

ofl_err
pipeline_handle_flow_mod(struct pipeline *pl, struct ofl_msg_flow_mod *msg,
                                                const struct sender *sender) {
    ofl_err error;
    size_t i;
    bool match_kept,insts_kept;

    if (VLOG_IS_DBG_ENABLED(ALTA_LOG_MODULE))
    {
        char *msg_str = ofl_msg_to_string((struct ofl_msg_header*)msg, NULL);
        VLOG_DBG(ALTA_LOG_MODULE, "flow mod: %s", msg_str);
        free(msg_str);
    }

    if(sender->remote->role == OFPCR_ROLE_SLAVE)
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_IS_SLAVE);

    match_kept = false;
    insts_kept = false;

    qsort(msg->instructions, msg->instructions_num,
        sizeof(struct ofl_instruction_header *), inst_compare);

    for (i=0; i< msg->instructions_num; i++)
    {
        if (msg->instructions[i]->type == OFPIT_APPLY_ACTIONS ||
            msg->instructions[i]->type == OFPIT_WRITE_ACTIONS)
        {
            struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)msg->instructions[i];

            error = dp_actions_validate(pl->dp, ia->actions_num, ia->actions);
            if (error) {
                return error;
            }
        }
    }

    if (msg->table_id == 0xff) {
        if (msg->command == OFPFC_DELETE || msg->command == OFPFC_DELETE_STRICT) {
            size_t i;

            error = 0;
            for (i=0; i < PIPELINE_TABLES; i++) {
                error = flow_table_flow_mod(pl->tables[i], msg, &match_kept, &insts_kept);
                if (error) {
                    break;
                }
            }
            if (error) {
                return error;
            } else {
                ofl_msg_free_flow_mod(msg, !match_kept, !insts_kept, pl->dp->exp);
                return 0;
            }
        } else {
            return ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_TABLE_ID);
        }
    } else {
        error = flow_table_flow_mod(pl->tables[msg->table_id], msg, &match_kept, &insts_kept);
        if (error) {
            return error;
        }
        if ((msg->command == OFPFC_ADD || msg->command == OFPFC_MODIFY || msg->command == OFPFC_MODIFY_STRICT) &&
                            msg->buffer_id != OFP_NO_BUFFER)
        {
            struct packet *pkt;
            pkt = dp_buffers_retrieve(pl->dp->buffers, msg->buffer_id);
            if (pkt != NULL) {
                pipeline_process_packet(pl, pkt);
            } else {
                VLOG_WARN_RL(LOG_MODULE, &rl, "The buffer flow_mod referred to was empty (%u).", msg->buffer_id);
            }
        }

        ofl_msg_free_flow_mod(msg, !match_kept, !insts_kept, pl->dp->exp);
        return 0;
    }

}

ofl_err
pipeline_handle_table_mod(struct pipeline *pl,
                          struct ofl_msg_table_mod *msg,
                          const struct sender *sender) {

    if(sender->remote->role == OFPCR_ROLE_SLAVE)
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_IS_SLAVE);

    if (VLOG_IS_DBG_ENABLED(ALTA_LOG_MODULE))
    {
        char *msg_str = ofl_msg_to_string((struct ofl_msg_header*)msg, NULL);
        VLOG_DBG(ALTA_LOG_MODULE, "table mod: %s", msg_str);
        free(msg_str);
    }

    if (msg->table_id == 0xff) {
        size_t i;

        for (i=0; i<PIPELINE_TABLES; i++) {
            pl->tables[i]->features->config = msg->config;
        }
    } else {
        pl->tables[msg->table_id]->features->config = msg->config;
    }

    ofl_msg_free((struct ofl_msg_header *)msg, pl->dp->exp);
    return 0;
}

#define FLOW_STATS_REPLY_PEER 100

ofl_err
pipeline_handle_stats_request_flow(struct pipeline *pl,
                                   struct ofl_msg_multipart_request_flow *msg,
                                   const struct sender *sender)
{

    struct ofl_flow_stats **stats = xmalloc(sizeof(struct ofl_flow_stats *));
    size_t stats_size = 1;
    size_t stats_num = 0;
    size_t num = 0;
    size_t i;
    struct ofl_flow_stats **ptr;

    if (msg->table_id == 0xff)
    {
        for ( i = 0; i < PIPELINE_TABLES; i++ )
        {
            flow_table_stats(pl->tables[i], msg, &stats, &stats_size, &stats_num);
        }
    }
    else
    {
        flow_table_stats(pl->tables[msg->table_id], msg, &stats, &stats_size, &stats_num);
    }

    if(stats_num == 0)
    {
        struct ofl_msg_multipart_reply_flow reply =
                {{{.type = OFPT_MULTIPART_REPLY},
                  .type = OFPMP_FLOW, .flags = 0x0000},
                 .stats     = stats,
                 .stats_num = stats_num
                };

        dp_send_message(pl->dp, (struct ofl_msg_header *)&reply, sender);
    }
    else
    {
        while (stats_num != 0)
        {
            ptr = stats + FLOW_STATS_REPLY_PEER * num;
            if (stats_num > FLOW_STATS_REPLY_PEER)
            {
                struct ofl_msg_multipart_reply_flow reply =
                    {{{.type = OFPT_MULTIPART_REPLY},
                      .type = OFPMP_FLOW, .flags = OFPMPF_REPLY_MORE},
                     .stats     = ptr,
                     .stats_num = FLOW_STATS_REPLY_PEER
                    };

                dp_send_message(pl->dp, (struct ofl_msg_header *)&reply, sender);

                stats_num -= FLOW_STATS_REPLY_PEER;
                num++;
            }
            else
            {
                struct ofl_msg_multipart_reply_flow reply =
                    {{{.type = OFPT_MULTIPART_REPLY},
                      .type = OFPMP_FLOW, .flags = 0x0000},
                     .stats     = ptr,
                     .stats_num = stats_num
                    };

                dp_send_message(pl->dp, (struct ofl_msg_header *)&reply, sender);

                stats_num = 0;
            }
        }
    }

    free(stats);
    ofl_msg_free((struct ofl_msg_header *)msg, pl->dp->exp);
    return 0;
}

ofl_err
pipeline_handle_stats_request_table(struct pipeline *pl,
                                    struct ofl_msg_multipart_request_header *msg UNUSED,
                                    const struct sender *sender) {
    struct ofl_table_stats **stats;
    struct flow_entry *entry;
    size_t i;

    stats = xmalloc(sizeof(struct ofl_table_stats *) * PIPELINE_TABLES);

    for (i=0; i<PIPELINE_TABLES; i++)
    {
        LIST_FOR_EACH(entry, struct flow_entry, match_node, &pl->tables[i]->match_entries)
        {
            alta_logic_entry_count(entry);
        }
        stats[i] = pl->tables[i]->stats;
    }

    {
        struct ofl_msg_multipart_reply_table reply =
                {{{.type = OFPT_MULTIPART_REPLY},
                  .type = OFPMP_TABLE, .flags = 0x0000},
                 .stats     = stats,
                 .stats_num = PIPELINE_TABLES};

        dp_send_message(pl->dp, (struct ofl_msg_header *)&reply, sender);
    }

    free(stats);
    ofl_msg_free((struct ofl_msg_header *)msg, pl->dp->exp);
    return 0;
}

#define TABLES_PER_TIME 8

ofl_err
pipeline_handle_stats_request_table_features_request(struct pipeline *pl,
                                    struct ofl_msg_multipart_request_header *msg,
                                    const struct sender *sender) {
    size_t i, j = 0 ;
    struct ofl_table_features **features;
    struct ofl_msg_multipart_request_table_features *feat = (struct ofl_msg_multipart_request_table_features *) msg;
    unsigned int table_num =0;

    if(feat->table_features == NULL)
    {
       loop:
           features = (struct ofl_table_features**) xmalloc(sizeof(struct ofl_table_features  ) * 8);
           for (i = 0; i < TABLES_PER_TIME && j < PIPELINE_TABLES; i++)
           {
                features[i] = pl->tables[j]->features;
                j++;
           }

           {
             table_num = (j % TABLES_PER_TIME) == 0 ? TABLES_PER_TIME : (j % TABLES_PER_TIME);

              struct ofl_msg_multipart_reply_table_features reply =
                    {{{.type = OFPT_MULTIPART_REPLY},
                      .type = OFPMP_TABLE_FEATURES, .flags = (j == PIPELINE_TABLES) ? 0x00000000:OFPMPF_REPLY_MORE},
                     .table_features     = features,
                     .tables_num = table_num};

             dp_send_message(pl->dp, (struct ofl_msg_header *)&reply, sender);
             free(features);
           }

       if (j < PIPELINE_TABLES){
           goto loop;
       }
    }
    else{

    }
    ofl_msg_free((struct ofl_msg_header *)msg, pl->dp->exp);
    return 0;
}

ofl_err
pipeline_handle_stats_request_aggregate(struct pipeline *pl,
                                  struct ofl_msg_multipart_request_flow *msg,
                                  const struct sender *sender) {
    struct ofl_msg_multipart_reply_aggregate reply =
            {{{.type = OFPT_MULTIPART_REPLY},
              .type = OFPMP_AGGREGATE, .flags = 0x0000},
              .packet_count = 0,
              .byte_count   = 0,
              .flow_count   = 0};

    if (msg->table_id == 0xff) {
        size_t i;

        for (i=0; i<PIPELINE_TABLES; i++) {
            flow_table_aggregate_stats(pl->tables[i], msg,
                                       &reply.packet_count, &reply.byte_count, &reply.flow_count);
        }

    } else {
        flow_table_aggregate_stats(pl->tables[msg->table_id], msg,
                                   &reply.packet_count, &reply.byte_count, &reply.flow_count);
    }

    dp_send_message(pl->dp, (struct ofl_msg_header *)&reply, sender);

    ofl_msg_free((struct ofl_msg_header *)msg, pl->dp->exp);
    return 0;
}


void
pipeline_destroy(struct pipeline *pl) {
    struct flow_table *table;
    int i;

    for (i=0; i<PIPELINE_TABLES; i++) {
        table = pl->tables[i];
        if (table != NULL) {
            flow_table_destroy(table);
        }
    }
    free(pl);
}


void
pipeline_timeout(struct pipeline *pl) {
    int i;

    pthread_rwlock_rdlock(&pl->dp->rw_lock);
    for(i = 0; i < PIPELINE_TABLES; i++)
    {
        if(pl->tables[i]->timeout_entries.need_timeout == false)
        {
            /* 跳过已经遍历完成的table */
            continue;
        }
        flow_table_timeout(pl->tables[i]);
        if(pl->tables[i]->timeout_entries.need_timeout == true)
        {
            /* 已经遍历满500条entry，等待下一次遍历 */
            pthread_rwlock_unlock(&pl->dp->rw_lock);
            return;
        }
    }

    for(i = 0; i < PIPELINE_TABLES; i++)
    {
        /* 全部遍历完成后，将所有table重新标记为需要遍历 */
        pl->tables[i]->timeout_entries.need_timeout = true;
    }

    pthread_rwlock_unlock(&pl->dp->rw_lock);
    return;
}

static void
execute_entry(struct pipeline *pl, struct flow_entry *entry,
              struct flow_table **next_table, struct packet **pkt) {
    size_t i;
    struct ofl_instruction_header *inst;

    for (i=0; i < entry->stats->instructions_num; i++) {
        if(!(*pkt)){
            return;
        }
        inst = entry->stats->instructions[i];

        switch (inst->type) {
            case OFPIT_GOTO_TABLE: {
                struct ofl_instruction_goto_table *gi = (struct ofl_instruction_goto_table *)inst;

                *next_table = pl->tables[gi->table_id];
                break;
            }
            case OFPIT_WRITE_METADATA: {
                struct ofl_instruction_write_metadata *wi = (struct ofl_instruction_write_metadata *)inst;
                struct  packet_fields *f;
                packet_handle_std_validate((*pkt)->handle_std);

                HMAP_FOR_EACH_WITH_HASH(f,struct packet_fields, hmap_node, DP_FIELD_HASH(OXM_OF_METADATA), &(*pkt)->handle_std->match.match_fields)
                {
                    unsigned long long int *metadata = (unsigned long long int*) f->value;
                    unsigned long long int abc;
                    abc = ((*metadata & ~wi->metadata_mask) | (wi->metadata & wi->metadata_mask));
                    memcpy(f->value, &abc, sizeof(unsigned long long int));
                }
                break;
            }
            case OFPIT_WRITE_ACTIONS:
            {
                struct ofl_instruction_actions *wa = (struct ofl_instruction_actions *)inst;
                action_set_write_actions((*pkt)->action_set, wa->actions_num, wa->actions);

                break;
            }
            case OFPIT_APPLY_ACTIONS:
            {
                struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)inst;
                dp_execute_action_list((*pkt), ia->actions_num, ia->actions, entry->stats->cookie);

                packet_match_reset( *pkt);

                break;
            }
            case OFPIT_CLEAR_ACTIONS: {
                action_set_clear_actions((*pkt)->action_set);
                break;
            }
            case OFPIT_METER: {
                struct ofl_instruction_meter *im = (struct ofl_instruction_meter *)inst;
                meter_table_apply(pl->dp->meters, pkt , im->meter_id);
                break;
            }
            case OFPIT_EXPERIMENTER: {
                dp_exp_inst((*pkt), (struct ofl_instruction_experimenter *)inst);
                break;
            }
        }
    }
}

