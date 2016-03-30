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
 * Author: Zolt谩n Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <config.h>
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include "dpctl.h"
#include "oflib/ofl-messages.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl-actions.h"
#include "oflib/ofl-print.h"
#include "oflib/ofl.h"
#include "oflib/ofl-utils.h"
#include "oflib-exp/ofl-exp.h"
#include "oflib-exp/ofl-exp-openflow.h"
#include "oflib/oxm-match.h"

#include "command-line.h"
#include "compiler.h"
#include "dpif.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow-ext.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "random.h"
#include "socket-util.h"
#include "timeval.h"
#include "util.h"
#include "vconn-ssl.h"
#include "vconn.h"
#include "ipv6_util.h"

#include "ofpstat.h"
#include "openflow/private-ext.h"

#include "vlog.h"

#define LOG_MODULE VLM_dpctl

#define DPCTL_MAX_QUEUE_RATE    1000

// NOTE: the request and the barrier is sent with the same xid,
//       so a vconn_receive_block will return with either the
//       response, barrier resp., or the error
#define XID   0xf0ff00f0


struct command {
    char *name;
    int min_args;
    int max_args;
    void (*handler)(struct vconn *vconn, int argc, char *argv[]);
};

static struct command all_commands[];

static void
usage(void) NO_RETURN;

static void
parse_options(int argc, char *argv[]);

static unsigned char mask_all[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static void
parse_flow_mod_args(char *str, struct ofl_msg_flow_mod *req);

static void
parse_port_conf_args(char *str, struct ofl_exp_openflow_mod_port_conf *req);

static void
parse_qos_group_args(char *str, struct ofl_exp_openflow_mod_qos_group *req);

static void
parse_map_queue_args(char *str, struct ofl_exp_openflow_map_queue*req);

static void
parse_packet_out_args(char *str, struct ofl_msg_packet_out*req);

static void
parse_role_args(char *str, struct ofl_msg_role_request*req);

static void
parse_set_async_args(char * str, struct ofl_async_config * req);

static void
parse_group_mod_args(char *str, struct ofl_msg_group_mod *req);

static void
parse_meter_mod_args(char *str, struct ofl_msg_meter_mod *req);

static void
parse_bucket(char *str, struct ofl_bucket *b);

static void
parse_flow_stat_args(char *str, struct ofl_msg_multipart_request_flow *req);

static void
parse_match(char *str, struct ofl_match_header **match);

static void
parse_inst(char *str, struct ofl_instruction_header **inst);

static void
parse_actions(char *str, size_t *acts_num, struct ofl_action_header ***acts);

static void
parse_config(char *str, struct ofl_config *config);

static void
parse_port_mod(char *str, struct ofl_msg_port_mod *msg);

static void
parse_table_mod(char *str, struct ofl_msg_table_mod *msg);

static void
parse_band(char *str, struct ofl_msg_meter_mod *m, struct ofl_meter_band_header **b);

static void
parse_set_network_args(char *str, struct ofl_exp_openflow_network_conf *req);

static void
make_all_match(struct ofl_match_header **match);


static int
parse_hw_config(char *str, unsigned int *conf);


static int
parse_port(char *str, unsigned int *port);

static int
parse_queue(char *str, unsigned int *port);

static int
parse_group(char *str, unsigned int *group);

static int
parse_meter(char *str, unsigned int *meter);

static int
parse_table(char *str, unsigned char *table);

static int
parse_dl_addr(char *str, unsigned char *addr, unsigned char **mask);

static int
parse_nw_addr(char *str, unsigned int *addr, unsigned int **mask);

static int
parse_vlan_vid(char *str, unsigned short int *vid);

static int
parse_ext_hdr(char *str, unsigned short int *ext_hdr);

static int
parse8(char *str, struct names8 *names, size_t names_num, unsigned char max, unsigned char *val);

static int
parse16(char *str, struct names16 *names, size_t names_num, unsigned short int max, unsigned short int *val);

static int
parse32(char *str, struct names32 *names, size_t names_num, unsigned int max, unsigned int *val);


static struct ofl_exp_msg dpctl_exp_msg =
        {.pack      = ofl_exp_msg_pack,
         .unpack    = ofl_exp_msg_unpack,
         .free      = ofl_exp_msg_free,
         .to_string = ofl_exp_msg_to_string};

static struct ofl_exp dpctl_exp =
        {.act   = NULL,
         .inst  = NULL,
         .match = NULL,
         .stats = NULL,
         .msg   = &dpctl_exp_msg};


static void
dpctl_transact(struct vconn *vconn, struct ofl_msg_header *req,
                              struct ofl_msg_header **repl) {
    struct ofpbuf *ofpbufreq, *ofpbufrepl;
    unsigned char *bufreq;
    size_t bufreq_size;
    int error;

    error = ofl_msg_pack(req, XID, &bufreq, &bufreq_size, &dpctl_exp);
    if (error) {
        ofp_fatal(0, "Error packing request.");
    }

    ofpbufreq = ofpbuf_new(0);
    ofpbuf_use(ofpbufreq, bufreq, bufreq_size);
    ofpbuf_put_uninit(ofpbufreq, bufreq_size);
    error = vconn_transact(vconn, ofpbufreq, &ofpbufrepl);
    if (error) {
        ofp_fatal(0, "Error during transaction.");
    }
    error = ofl_msg_unpack(ofpbufrepl->data, ofpbufrepl->size, repl, NULL /*xid_ptr*/, &dpctl_exp);

    if (error) {
        ofp_fatal(0, "Error unpacking reply.");
    }

    /* NOTE: if unpack was successful, message takes over ownership of buffer's
     *       data. Rconn and vconn does not allocate headroom, so the ofpbuf
     *       wrapper can simply be deleted, keeping the data for the message. */
    ofpbufrepl->base = NULL;
    ofpbufrepl->data = NULL;
    ofpbuf_delete(ofpbufrepl);
}

static void
dpctl_transact_and_print(struct vconn *vconn, struct ofl_msg_header *req,
                                        struct ofl_msg_header **repl) {
    struct ofl_msg_header *reply;
    char *str;

    str = ofl_msg_to_string(req, &dpctl_exp);
    printf("\nSENDING:\n%s\n\n", str);
    free(str);
    dpctl_transact(vconn, req, &reply);
    str = ofl_msg_to_string(reply, &dpctl_exp);
    printf("\nRECEIVED:\n%s\n\n", str);
    free(str);

    if (repl != NULL) {
        (*repl) = reply;
    } else {
        ofl_msg_free(reply, &dpctl_exp);
    }
}

static void
dpctl_barrier(struct vconn *vconn) {
    struct ofl_msg_header *reply;
    char *str;

    struct ofl_msg_header req =
            {.type = OFPT_BARRIER_REQUEST};

    dpctl_transact(vconn, &req, &reply);

    if (reply->type == OFPT_BARRIER_REPLY) {
        str = ofl_msg_to_string(reply, &dpctl_exp);
        printf("\nOK.\n\n");
        free(str);
    } else {
        str = ofl_msg_to_string(reply, &dpctl_exp);
        printf("\nRECEIVED:\n%s\n\n", str);
        free(str);
    }

}

static void
dpctl_send(struct vconn *vconn, struct ofl_msg_header *msg) {
    struct ofpbuf *ofpbuf;
    unsigned char *buf;
    size_t buf_size;
    int error;

    error = ofl_msg_pack(msg, XID, &buf, &buf_size, &dpctl_exp);
    if (error) {
        ofp_fatal(0, "Error packing request.");
    }

    ofpbuf = ofpbuf_new(0);
    ofpbuf_use(ofpbuf, buf, buf_size);
    ofpbuf_put_uninit(ofpbuf, buf_size);
    //ofp_hex_dump(stdout, ofpbuf->data, ofpbuf->size, 0, 1);

    error = vconn_send_block(vconn, ofpbuf);
    if (error) {
        ofp_fatal(0, "Error during transaction.");
    }

    dpctl_barrier(vconn);
}

static void
dpctl_send_and_print(struct vconn *vconn, struct ofl_msg_header *msg) {
    char *str;
    str = ofl_msg_to_string(msg, &dpctl_exp);
    printf("\nSENDING:\n%s\n\n", str);
    free(str);

    dpctl_send(vconn, msg);
}

static void
ping(struct vconn *vconn, int argc, char *argv[]) {
    unsigned short int payload_size = 0;
    size_t times = 0, i;
    struct ofl_msg_echo *reply;

    struct ofl_msg_echo req =
            {{.type = OFPT_ECHO_REQUEST},
             .data_length = 0,
             .data = NULL};

    if (argc > 0) {
        times = atoi(argv[0]);
    }
    if (times == 0) {
        times = 4;
    }
    if (argc > 1) {
        payload_size = atoi(argv[1]);
    } else {
        payload_size = 1024;
    }
    if (payload_size > UINT16_MAX - sizeof(struct ofp_header)) {
        ofp_fatal(0, "payload must be between 0 and %zu bytes.", UINT16_MAX - sizeof(struct ofp_header));
    }

    req.data_length = payload_size;
    req.data     = xmalloc(payload_size);

    for (i=0; i<times; i++) {
        struct timeval start, end;

        random_bytes(req.data, payload_size);

        gettimeofday(&start, NULL);
        dpctl_transact(vconn, (struct ofl_msg_header *)&req, (struct ofl_msg_header **)&reply);
        gettimeofday(&end, NULL);

        if ((req.data_length != reply->data_length) ||
                     (memcmp(req.data, reply->data, req.data_length) != 0)) {
            ofp_fatal(0, "Reply does not match request.");
        }

        printf("%zu bytes from %s: time=%.1f ms\n",
               (reply->data_length - sizeof(struct ofp_header)),
               vconn_get_name(vconn),
               (1000*(double)(end.tv_sec - start.tv_sec)) + (.001*(end.tv_usec - start.tv_usec)));

    }

    free(req.data);
    ofl_msg_free((struct ofl_msg_header *)reply, &dpctl_exp);
}

static void
monitor(struct vconn *vconn, int argc UNUSED, char *argv[] UNUSED) {
    struct ofpbuf *buf;
    struct ofl_msg_header *msg;
    char *str;
    int error;

    printf("MONITORING %s...\n\n", vconn_get_name(vconn));

    for (;;) {
        if (vconn_recv_block(vconn, &buf) == 0) {
            if (buf) {
                error = ofl_msg_unpack(buf->data, buf->size, &msg, NULL /*xid_ptr*/, &dpctl_exp);
                if (error) {
                    ofp_fatal(0, "Error unpacking reply.");
                }

                /* NOTE: if unpack was successful, message takes over ownership of buffer's
                 *       data. Rconn and vconn does not allocate headroom, so the ofpbuf
                 *       wrapper can simply be deleted, keeping the data for the message. */
                buf->base = NULL;
                buf->data = NULL;
                ofpbuf_delete(buf);

                str = ofl_msg_to_string(msg, &dpctl_exp);
                printf("\nRECEIVED:\n%s\n\n", str);
                free(str);

                ofl_msg_free(msg, &dpctl_exp);
            }
        }
    }
}

static void
table_features(struct vconn *vconn, int argc UNUSED, char *argv[] UNUSED) {
    struct ofl_msg_multipart_request_table_features req =
        {{{.type = OFPT_MULTIPART_REQUEST},
              .type = OFPMP_TABLE_FEATURES, .flags = 0x0000},
             .tables_num = 0,
             .table_features = NULL,
          };

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}


static void
features(struct vconn *vconn, int argc UNUSED, char *argv[] UNUSED) {
    struct ofl_msg_header req =
            {.type = OFPT_FEATURES_REQUEST};

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}

static void
get_config(struct vconn *vconn, int argc UNUSED, char *argv[] UNUSED) {
    struct ofl_msg_header req =
            {.type = OFPT_GET_CONFIG_REQUEST};

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}



static void
stats_group_features(struct vconn *vconn, int argc UNUSED, char *argv[] UNUSED) {

    struct ofl_msg_multipart_request_header req =
            {{.type = OFPT_MULTIPART_REQUEST},
             .type = OFPMP_GROUP_FEATURES, .flags = 0x0000};

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}

static void
stats_meter_feature(struct vconn *vconn, int argc UNUSED, char *argv[] UNUSED) {

    struct ofl_msg_multipart_request_header req =
            {{.type = OFPT_MULTIPART_REQUEST},
             .type = OFPMP_METER_FEATURES, .flags = 0x0000};

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);

}

static void
stats_desc(struct vconn *vconn, int argc UNUSED, char *argv[] UNUSED) {
    struct ofl_msg_multipart_request_header req =
            {{.type = OFPT_MULTIPART_REQUEST},
             .type = OFPMP_DESC, .flags = 0x0000};

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}

static void
port_desc(struct vconn *vconn, int argc UNUSED, char *argv[] UNUSED) {
    struct ofl_msg_multipart_request_header req =
            {{.type = OFPT_MULTIPART_REQUEST},
             .type = OFPMP_PORT_DESC, .flags = 0x0000};

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}

static void
stats_flow(struct vconn *vconn, int argc, char *argv[]) {
    struct ofl_msg_multipart_request_flow req =
            {{{.type = OFPT_MULTIPART_REQUEST},
              .type = OFPMP_FLOW, .flags = 0x0000},
             .cookie = 0x0000000000000000ULL,
             .cookie_mask = 0x0000000000000000ULL,
             .table_id = 0xff,
             .out_port = OFPP_ANY,
             .out_group = OFPG_ANY,
             .match = NULL};
    if (argc > 0) {
        parse_flow_stat_args(argv[0], &req);
    }
    if (argc > 1) {
        parse_match(argv[1], &(req.match));
    } else {
        make_all_match(&(req.match));
    }

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}

static void
stats_aggr(struct vconn *vconn, int argc, char *argv[]) {
    struct ofl_msg_multipart_request_flow req =
            {{{.type = OFPT_MULTIPART_REQUEST},
              .type = OFPMP_AGGREGATE, .flags = 0x0000},
             .cookie = 0x0000000000000000ULL,
             .cookie_mask = 0x0000000000000000ULL,
             .table_id = 0xff,
             .out_port = OFPP_ANY,
             .out_group = OFPG_ANY,
             .match = NULL};

    if (argc > 0) {
        parse_flow_stat_args(argv[0], &req);
    }
    if (argc > 1) {
        parse_match(argv[1], &(req.match));
    } else {
        make_all_match(&(req.match));
    }

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}

static void
stats_table(struct vconn *vconn, int argc UNUSED, char *argv[] UNUSED) {
    struct ofl_msg_multipart_request_header req =
            {{.type = OFPT_MULTIPART_REQUEST},
             .type = OFPMP_TABLE, .flags = 0x0000};

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}



static void
stats_port(struct vconn *vconn, int argc, char *argv[]) {
    struct ofl_msg_multipart_request_port req =
            {{{.type = OFPT_MULTIPART_REQUEST},
              .type = OFPMP_PORT_STATS, .flags = 0x0000},
             .port_no = OFPP_ANY};

    if (argc > 0 && parse_port(argv[0], &req.port_no)) {
        ofp_fatal(0, "Error parsing port: %s.", argv[0]);
    }

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}



static void
stats_queue(struct vconn *vconn, int argc, char *argv[]) {
    struct ofl_msg_multipart_request_queue req =
            {{{.type = OFPT_MULTIPART_REQUEST},
              .type = OFPMP_QUEUE, .flags = 0x0000},
             .port_no = OFPP_ANY,
             .queue_id = OFPQ_ALL};

    if (argc > 0 && parse_port(argv[0], &req.port_no)) {
        ofp_fatal(0, "Error parsing port: %s.", argv[0]);
    }
    if (argc > 1 && parse_queue(argv[1], &req.queue_id)) {
        ofp_fatal(0, "Error parsing queue: %s.", argv[1]);
    }

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}



static void
stats_group(struct vconn *vconn, int argc, char *argv[]) {
    struct ofl_msg_multipart_request_group req =
            {{{.type = OFPT_MULTIPART_REQUEST},
              .type = OFPMP_GROUP, .flags = 0x0000},
             .group_id = OFPG_ALL};

    if (argc > 0 && parse_group(argv[0], &req.group_id)) {
        ofp_fatal(0, "Error parsing group: %s.", argv[0]);
    }

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}



static void
stats_group_desc(struct vconn *vconn, int argc, char *argv[]) {
    struct ofl_msg_multipart_request_group req =
            {{{.type = OFPT_MULTIPART_REQUEST},
              .type = OFPMP_GROUP_DESC, .flags = 0x0000},
             .group_id = OFPG_ALL};

    if (argc > 0 && parse_group(argv[0], &req.group_id)) {
        ofp_fatal(0, "Error parsing group: %s.", argv[0]);
    }

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}

static void
set_config(struct vconn *vconn, int argc UNUSED, char *argv[]) {
    struct ofl_msg_set_config msg =
            {{.type = OFPT_SET_CONFIG},
             .config = NULL};

    msg.config = xmalloc(sizeof(struct ofl_config));
    msg.config->flags = OFPC_FRAG_NORMAL;
    msg.config->miss_send_len = OFP_DEFAULT_MISS_SEND_LEN;

    parse_config(argv[0], msg.config);

    dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);
}

static void
packet_out(struct vconn *vconn, int argc, char *argv[]){
    struct ofl_msg_packet_out msg =
            {{.type = OFPT_PACKET_OUT},
             .buffer_id = OFP_NO_BUFFER,
             .in_port = OFPP_CONTROLLER,
             .actions_num = 0,
             .actions = NULL,
             .data_length= 0,
             .data = NULL};

    parse_packet_out_args(argv[0], &msg);

    if (argc > 1) {
        parse_actions(argv[1], &(msg.actions_num), &(msg.actions));
    }

    if (0 != msg.data_length){
        size_t i;
        size_t data_len = msg.data_length;

       msg.data = xmalloc(data_len);

       if (NULL != msg.data){

          for(i=0; i<data_len; i++){
              *(msg.data+i) = 0x00+i;
          }
       }
       else{

           ofp_fatal(0, "Error packet_out fail to xmalloc data buffer");
       }

    }
    ofp_hex_dump(stdout, &msg, sizeof(struct ofl_msg_packet_out), 0, 1);
    dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);

}

unsigned char hex2val(unsigned char hex)
{
   unsigned char val;
   if( hex>= '0' && hex<='9')
   {
      val = hex - '0';
   }
   else if( hex>= 'a' && hex<='f')
   {
      val = hex - 'a' + 10;
   }
   else if( hex>= 'A' && hex<='F')
   {
      val = hex - 'A' + 10;
   }
   return val;
}
static void
raw_send(struct vconn *vconn, int argc, char *argv[]){
    struct ofpbuf *ofpbuf;
    unsigned char *buf;
    size_t buf_size;
    int error;
    int i;
    struct ofp_header *oh;
    if( argc == 0)
        return;
    buf_size = argc;
    buf = malloc(buf_size);
    for( i=0; i<buf_size; i++)
    {
        buf[i] = hex2val( (*argv)[0]) * 16 + hex2val( (*argv)[1]);
        argv += 1;
    }
    oh = (struct ofp_header *)buf;
    oh->xid = htonl(XID);
    ofpbuf = ofpbuf_new(0);
    ofpbuf_use(ofpbuf, buf, buf_size);
    ofpbuf_put_uninit(ofpbuf, buf_size);
    ofp_hex_dump(stdout, ofpbuf->data, ofpbuf->size, 0, 1);
    error = vconn_send_block(vconn, ofpbuf);
    if (error) {
        ofp_fatal(0, "Error during transaction.");
    }
    dpctl_barrier(vconn);
}
static void
flow_mod(struct vconn *vconn, int argc, char *argv[]) {
    struct ofl_msg_flow_mod msg =
            {{.type = OFPT_FLOW_MOD},
             .cookie = 0x0000000000000000ULL,
             .cookie_mask = 0x0000000000000000ULL,
             .table_id = 0xff,
             .command = OFPFC_ADD,
             .idle_timeout = OFP_FLOW_PERMANENT,
             .hard_timeout = OFP_FLOW_PERMANENT,
             .priority = OFP_DEFAULT_PRIORITY,
             .buffer_id = OFP_NO_BUFFER,
             .out_port = OFPP_ANY,
             .out_group = OFPG_ANY,
             .flags = 0x0000,
             .match = NULL,
             .instructions_num = 0,
             .instructions = NULL};

    parse_flow_mod_args(argv[0], &msg);

    if (argc > 1) {
        size_t i;
        size_t inst_num = argc - 2;
        parse_match(argv[1], &(msg.match));

         msg.instructions_num = inst_num;
         msg.instructions = xmalloc(sizeof(struct ofl_instruction_header *) * inst_num);

         if(0 == msg.match->length)
         {
            inst_num=argc - 1;
            msg.instructions_num = inst_num;
            msg.instructions = xmalloc(sizeof(struct ofl_instruction_header *) * inst_num);

            for (i=0; i < inst_num; i++) {
                 parse_inst(argv[1+i], &(msg.instructions[i]));
            }
         }
         else
         {
            for (i=0; i < inst_num; i++) {
                 parse_inst(argv[2+i], &(msg.instructions[i]));
            }
         }

    } else {
        make_all_match(&(msg.match));
    }

    dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);
}


static void
group_mod(struct vconn *vconn, int argc, char *argv[]) {
    struct ofl_msg_group_mod msg =
            {{.type = OFPT_GROUP_MOD},
             .command  = OFPGC_ADD,
             .type     = OFPGT_ALL,
             .group_id = OFPG_ALL,
             .buckets_num = 0,
             .buckets = NULL};

    parse_group_mod_args(argv[0], &msg);

    if (argc > 1) {
        size_t i;
        size_t buckets_num = (argc - 1) / 2;

        msg.buckets_num = buckets_num;
        msg.buckets = xmalloc(sizeof(struct ofl_bucket *) * buckets_num);

        for (i=0; i < buckets_num; i++) {
            msg.buckets[i] = xmalloc(sizeof(struct ofl_bucket));
            msg.buckets[i]->weight = 0;
            msg.buckets[i]->watch_port = OFPP_ANY;
            msg.buckets[i]->watch_group = OFPG_ANY;
            msg.buckets[i]->actions_num = 0;
            msg.buckets[i]->actions = NULL;

            parse_bucket(argv[i*2+1], msg.buckets[i]);
            parse_actions(argv[i*2+2], &(msg.buckets[i]->actions_num), &(msg.buckets[i]->actions));
        }
    }

    dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);
}

static void meter_mod(struct vconn *vconn, int argc, char *argv[]){

    struct ofl_msg_meter_mod msg =
                {{.type = OFPT_METER_MOD},
                 .command = OFPMC_ADD,
                 .flags   = OFPMF_KBPS,
                 .meter_id = 0,
                 .meter_bands_num = 0,
                 .bands = NULL};

   parse_meter_mod_args(argv[0], &msg);

   if (argc > 1){
        size_t i;
        size_t bands_num = argc - 1;
        msg.meter_bands_num = bands_num;
        msg.bands = xmalloc(sizeof(struct ofl_meter_band_header *) * bands_num);
        for (i=0; i < bands_num; i++) {
            parse_band(argv[i+1], &msg, &msg.bands[i]);
        }
   }
   dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);

}

static void
stats_meter(struct vconn *vconn, int argc UNUSED, char *argv[]){

    struct ofl_msg_multipart_meter_request req =
            {{{.type = OFPT_MULTIPART_REQUEST},
              .type = OFPMP_METER, .flags = 0x0000},
             .meter_id = OFPM_ALL};

    if (argc > 0 && parse_meter(argv[0], &req.meter_id)) {
        ofp_fatal(0, "Error parsing meter: %s.", argv[0]);
    }

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);

}

static void
meter_config(struct vconn *vconn, int argc UNUSED, char *argv[]){

    struct ofl_msg_multipart_meter_request req =
            {{{.type = OFPT_MULTIPART_REQUEST},
              .type = OFPMP_METER_CONFIG, .flags = 0x0000},
             .meter_id = OFPM_ALL};

    if (argc > 0 && parse_meter(argv[0], &req.meter_id)) {
        ofp_fatal(0, "Error parsing meter: %s.", argv[0]);
    }

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&req, NULL);
}

static void
port_mod(struct vconn *vconn, int argc UNUSED, char *argv[]) {
    struct ofl_msg_port_mod msg =
            {{.type = OFPT_PORT_MOD},
             .port_no = OFPP_ANY,
             .config = 0x00000000,
             .mask = 0x00000000,
             .advertise = 0x00000000
            };
            memcpy(msg.hw_addr, mask_all, OFP_ETH_ALEN);

    parse_port_mod(argv[0], &msg);

    dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);
}



static void
table_mod(struct vconn *vconn, int argc UNUSED, char *argv[]) {
    struct ofl_msg_table_mod msg =
            {{.type = OFPT_TABLE_MOD},
             .table_id = 0xff,
             .config = 0x00};

    parse_table_mod(argv[0], &msg);

    dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);
}



static void
queue_get_config(struct vconn *vconn, int argc UNUSED, char *argv[]) {
    struct ofl_msg_queue_get_config_request msg =
            {{.type = OFPT_QUEUE_GET_CONFIG_REQUEST},
             .port = OFPP_ALL};

    if (parse_port(argv[0], &msg.port)) {
        ofp_fatal(0, "Error parsing queue_get_config port: %s.", argv[0]);
    }

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&msg, NULL);
}



static void
set_desc(struct vconn *vconn, int argc UNUSED, char *argv[]) {
    struct ofl_exp_openflow_msg_set_dp_desc msg =
            {{{{.type = OFPT_EXPERIMENTER},
               .experimenter_id = OPENFLOW_VENDOR_ID},
              .type = OFP_EXT_SET_DESC},
             .dp_desc = argv[0]};

    dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);
}


/*
static void
queue_mod(struct vconn *vconn, int argc UNUSED, char *argv[]) {
    struct ofl_packet_queue *pq;
    struct ofl_queue_prop_min_rate *p;

    struct ofl_exp_openflow_msg_queue msg =
            {{{{.type = OFPT_EXPERIMENTER},
               .experimenter_id = OPENFLOW_VENDOR_ID},
              .type = OFP_EXT_QUEUE_MODIFY},
             .port_id = OFPP_ANY,
             .queue = NULL};

    if (parse_port(argv[0], &msg.port_id)) {
        ofp_fatal(0, "Error parsing queue_mod port: %s.", argv[0]);
    }

    pq = xmalloc(sizeof(struct ofl_packet_queue));
    msg.queue = pq;
    if (parse_queue(argv[1], &pq->queue_id)) {
        ofp_fatal(0, "Error parsing queue_mod queue: %s.", argv[1]);
    }

    pq->properties_num = 1;
    pq->properties = xmalloc(sizeof(struct ofl_queue_prop_header *));

    p = xmalloc(sizeof(struct ofl_queue_prop_min_rate));
    pq->properties[0] = (struct ofl_queue_prop_header *)p;
    p->header.type = OFPQT_MIN_RATE;

    if (parse16(argv[2], NULL,0, UINT16_MAX, &p->rate)) {
        ofp_fatal(0, "Error parsing queue_mod bw: %s.", argv[2]);
    }


    dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);
}
*/

static void queue_mod(struct vconn *vconn, int argc UNUSED, char *argv[]) {
    struct ofl_packet_queue *pq;
    struct ofl_queue_prop_min_rate *p;
    struct ofl_queue_prop_max_rate *q;

    struct ofl_exp_openflow_msg_queue msg =
            {{{{.type = OFPT_EXPERIMENTER},
               .experimenter_id = OPENFLOW_VENDOR_ID},
              .type = OFP_EXT_QUEUE_MODIFY},
             .port_id = OFPP_ANY,
             .queue = NULL};

    if (strncmp(argv[0], PORT_MOD_PORT KEY_VAL, strlen(PORT_MOD_PORT KEY_VAL)) == 0) {
        if (parse_port(argv[0]+strlen(PORT_MOD_PORT KEY_VAL), &msg.port_id)) {
            ofp_fatal(0, "Error parsing queue_mod port: %s.", argv[0]);
        }
    }

    pq = xmalloc(sizeof(struct ofl_packet_queue));
    msg.queue = pq;

    if (strncmp(argv[1], QUEUE_MOD_ID KEY_VAL, strlen(QUEUE_MOD_ID KEY_VAL)) == 0) {
        if (parse_queue(argv[1]+strlen(QUEUE_MOD_ID KEY_VAL), &pq->queue_id)) {
            ofp_fatal(0, "Error parsing queue_mod queue: %s.", argv[1]);
        }
    }

    pq->properties_num = 2;
    pq->properties = xmalloc(2 * sizeof(struct ofl_queue_prop_header *));

    p = xmalloc(sizeof(struct ofl_queue_prop_min_rate));
    pq->properties[0] = (struct ofl_queue_prop_header *)p;
    p->header.type = OFPQT_MIN_RATE;

    if (strncmp(argv[2], QUEUE_MOD_RATE_MIN KEY_VAL, strlen(QUEUE_MOD_RATE_MIN KEY_VAL)) == 0) {
        if (parse16(argv[2]+strlen(QUEUE_MOD_RATE_MIN KEY_VAL), NULL,0, UINT16_MAX, &p->rate)) {
            ofp_fatal(0, "Error parsing queue_mod min rate: %s.", argv[2]);
        }
    }

    if (DPCTL_MAX_QUEUE_RATE < p->rate) {
        ofp_fatal(0, "Rate can't larger than %d", DPCTL_MAX_QUEUE_RATE);
    }

    q = xmalloc(sizeof(struct ofl_queue_prop_max_rate));
    pq->properties[1] = (struct ofl_queue_prop_header *)q;
    q->header.type = OFPQT_MAX_RATE;

    if (strncmp(argv[3], QUEUE_MOD_RATE_MAX KEY_VAL, strlen(QUEUE_MOD_RATE_MAX KEY_VAL)) == 0) {
        if (parse16(argv[3]+strlen(QUEUE_MOD_RATE_MAX KEY_VAL), NULL,0, UINT16_MAX, &q->rate)) {
            ofp_fatal(0, "Error parsing queue_mod max rate: %s.", argv[3]);
        }
    }

    if (DPCTL_MAX_QUEUE_RATE < q->rate) {
        ofp_fatal(0, "Rate can't larger than %d", DPCTL_MAX_QUEUE_RATE);
    }

    dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);
}



static void
queue_del(struct vconn *vconn, int argc UNUSED, char *argv[]) {
    struct ofl_packet_queue *pq;

    struct ofl_exp_openflow_msg_queue msg =
            {{{{.type = OFPT_EXPERIMENTER},
               .experimenter_id = OPENFLOW_VENDOR_ID},
              .type = OFP_EXT_QUEUE_DELETE},
             .port_id = OFPP_ANY,
             .queue = NULL};

    if (parse_port(argv[0], &msg.port_id)) {
        ofp_fatal(0, "Error parsing queue_mod port: %s.", argv[0]);
    }

    pq = xmalloc(sizeof(struct ofl_packet_queue));
    msg.queue = pq;
    if (parse_queue(argv[1], &pq->queue_id)) {
        ofp_fatal(0, "Error parsing queue_mod queue: %s.", argv[1]);
    }

    pq->properties_num = 0;
    pq->properties = NULL;

    dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);
}

static void show_perf(struct vconn *vconn, int argc UNUSED, char *argv[])
{
    printf("show function performance\r\n");
    struct ofl_exp_openflow_msg_show_perf msg =
        {{{{.type = OFPT_EXPERIMENTER},
               .experimenter_id = OPENFLOW_VENDOR_ID},
              .type = OFP_EXT_COUNT},
              .command = 1
        };

     dpctl_send(vconn, (struct ofl_msg_header *)&msg);
}

static void set_network(struct vconn *vconn, int argc UNUSED, char *argv[])
{
    printf("set up network parameter\n");
    struct ofl_exp_openflow_network_conf msg =
    {{{{.type = OFPT_EXPERIMENTER},
           .experimenter_id = OPENFLOW_VENDOR_ID},
          .type = OFP_EXT_SET_NETWORK}
    };

    msg.ipv4 = 0;
    msg.mask = 0;
    msg.gw = 0;
    parse_set_network_args(argv[0], &msg);

    dpctl_send(vconn, (struct ofl_msg_header *)&msg);
}

static void mod_alta_port_conf(struct vconn *vconn, int argc UNUSED, char *argv[])
{
    struct ofl_exp_openflow_mod_port_conf msg =
    {{{{.type = OFPT_EXPERIMENTER},
           .experimenter_id = OPENFLOW_VENDOR_ID},
          .type = OFP_EXT_MOD_PORT_CONF}
    };

    parse_port_conf_args(argv[0], &msg);

    dpctl_send(vconn, (struct ofl_msg_header *)&msg);
}

static void qos_group(struct vconn *vconn, int argc UNUSED, char *argv[])
{
    struct ofl_exp_openflow_mod_qos_group msg =
        {{{{.type = OFPT_EXPERIMENTER},
               .experimenter_id = OPENFLOW_VENDOR_ID},
              .type = OFP_EXT_MOD_QOS_GROUP}
        };

     parse_qos_group_args(argv[0], &msg);

     dpctl_send(vconn, (struct ofl_msg_header *)&msg);
}


static void map_queue(struct vconn *vconn, int argc UNUSED, char *argv[])
{
    int i;
    struct ofl_exp_openflow_map_queue msg =
        {{{{.type = OFPT_EXPERIMENTER},
               .experimenter_id = OPENFLOW_VENDOR_ID},
              .type = OFP_EXT_MAP_QUEUE},
              .command =1,
        };

    for( i=0; i<8; i++)
    {
        msg.queue_array[i] = 0xff;
    }

    parse_map_queue_args(argv[0], &msg);

    dpctl_send(vconn, (struct ofl_msg_header *)&msg);
}

static void set_hw_config(struct vconn *vconn, int argc UNUSED, char *argv[])
{

   struct ofl_exp_openflow_msg_hw_config msg =
        {{{{.type = OFPT_EXPERIMENTER},
               .experimenter_id = OPENFLOW_VENDOR_ID},
              .type = OFP_EXT_HW_CONFIG},
              .config = 1
        };

     parse_hw_config(argv[0],&msg.config);

     dpctl_send(vconn, (struct ofl_msg_header *)&msg);
}

static void
get_async(struct vconn *vconn, int argc UNUSED, char *argv[] UNUSED){

    struct ofl_msg_async_config msg =
             {{.type = OFPT_GET_ASYNC_REQUEST},
             .config = NULL};

    dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&msg, NULL);
}

static void
set_async(struct vconn *vconn, int argc UNUSED, char *argv[] UNUSED){

    struct ofl_msg_async_config msg =
             {{.type = OFPT_SET_ASYNC},
              .config = NULL};

    msg.config = xmalloc(sizeof(struct ofl_async_config));
    parse_set_async_args(argv[0], msg.config);

    dpctl_send_and_print(vconn, (struct ofl_msg_header *)&msg);

}

//zhaoxiuchu 20130319
static void
get_role(struct vconn *vconn, int argc UNUSED, char *argv[] UNUSED){

    struct ofl_msg_role_request msg =
        {{.type = OFPT_ROLE_REQUEST},
        .role = OFPCR_ROLE_NOCHANGE,
        .generation_id=0};
    if(argc>0){
        parse_role_args(argv[0], &msg);
    }

   dpctl_transact_and_print(vconn, (struct ofl_msg_header *)&msg, NULL);
}

static struct command all_commands[] = {
    {"ping", 0, 2, ping},
    {"monitor", 0, 0, monitor},

    {"features", 0, 0, features },
    {"get-config", 0, 0, get_config},
    {"table-features", 0, 0, table_features},
    {"stats-desc", 0, 0, stats_desc },
    {"stats-flow", 0, 2, stats_flow},
    {"stats-aggr", 0, 2, stats_aggr},
    {"stats-table", 0, 0, stats_table },
    {"stats-port", 0, 1, stats_port },
    {"stats-queue", 0, 2, stats_queue },
    {"stats-group", 0, 1, stats_group },
    {"stats-group-desc", 0, 1, stats_group_desc },
    {"stats-group-features", 0, 0, stats_group_features },
    {"stats-meter", 0, 1, stats_meter},
    {"meter-config", 0, 1, meter_config},
    {"stats-meter-features", 0, 0, stats_meter_feature},
    {"port-desc", 0, 0, port_desc},
    {"set-config", 1, 1, set_config},
    {"flow-mod", 1, 8/*+1 for each inst type*/, flow_mod },
    {"group-mod", 1, UINT8_MAX, group_mod },
    {"meter-mod", 1, UINT8_MAX, meter_mod},
    {"get-async",0,0, get_async},
    {"port-mod", 1, 1, port_mod },
    {"table-mod", 1, 1, table_mod },
    {"queue-get-config", 1, 1, queue_get_config},
    {"set-desc", 1, 1, set_desc},

    {"queue-mod", 4, 4, queue_mod},
    {"queue-del", 2, 2, queue_del},
    {"show-perf",0,0,show_perf},
    {"qos-group",1,1,qos_group},
    {"map-queue",1,1,map_queue},
    {"hw-config",0,2,set_hw_config},
    {"port-attr",1,1,mod_alta_port_conf},
    {"set-network",1,3,set_network},
    {"get-role", 0, 2, get_role},
    {"set-async", 1, 6, set_async},
    {"packet-out", 1, 5, packet_out},
    {"raw", 1, 200, raw_send}
};


int main(int argc, char *argv[])
{
    struct command *p;
    struct vconn *vconn;
    size_t i;
    int error;

    set_program_name(argv[0]);
    time_init();
    vlog_init();
    oxm_match_init();
    parse_options(argc, argv);
    signal(SIGPIPE, SIG_IGN);

    argc -= optind;
    argv += optind;
    if (argc < 1)
        ofp_fatal(0, "missing SWITCH; use --help for help");
    if (argc < 2)
        ofp_fatal(0, "missing COMMAND; use --help for help");

    error = vconn_open_block(argv[0], OFP_VERSION, &vconn);
    if (error) {
        ofp_fatal(error, "Error connecting to switch %s.", argv[0]);
    }
    argc -= 1;
    argv += 1;

    for (i=0; i<NUM_ELEMS(all_commands); i++) {
        p = &all_commands[i];
        if (strcmp(p->name, argv[0]) == 0) {
            argc -= 1;
            argv += 1;
            if (argc < p->min_args)
                ofp_fatal(0, "'%s' command requires at least %d arguments",
                          p->name, p->min_args);
            else if (argc > p->max_args)
                ofp_fatal(0, "'%s' command takes at most %d arguments",
                          p->name, p->max_args);
            else {
                p->handler(vconn, argc, argv);
                if (ferror(stdout)) {
                    ofp_fatal(0, "write to stdout failed");
                }
                if (ferror(stderr)) {
                    ofp_fatal(0, "write to stderr failed");
                }
                vconn_close(vconn);
                exit(0);
            }
        }
    }
    ofp_fatal(0, "unknown command '%s'; use --help for help", argv[0]);
    vconn_close(vconn);
    return 0;
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_STRICT = UCHAR_MAX + 1
    };
    static struct option long_options[] = {
        {"timeout", required_argument, 0, 't'},
        {"verbose", optional_argument, 0, 'v'},
        {"strict", no_argument, 0, OPT_STRICT},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        VCONN_SSL_LONG_OPTIONS
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        unsigned long int timeout;
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 't':
            timeout = strtoul(optarg, NULL, 10);
            if (timeout <= 0) {
                ofp_fatal(0, "value %s on -t or --timeout is not at least 1",
                          optarg);
            } else {
                time_alarm(timeout);
            }
            break;

        case 'h':
            usage();

        case 'V':
            printf("%s %s compiled "__DATE__" "__TIME__"\n",
                   program_name, VERSION BUILDNR);
            exit(EXIT_SUCCESS);

        case 'v':
            vlog_set_verbosity(optarg);
            break;

        VCONN_SSL_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);
}



static void
usage(void)
{
    printf("%s: OpenFlow switch management utility\n"
           "usage: %s [OPTIONS] SWITCH COMMAND [ARG...]\n"
           "  SWITCH ping [N] [B]                    latency of B-byte echos N times\n"
           "  SWITCH monitor                         monitors packets from the switch\n"
           "\n"
           "  SWITCH features                        show basic information\n"
           "  SWITCH get-config                      get switch configuration\n"
           "  SWITCH meter-config [METER]            get meter configuration\n"
           "  SWITCH stats-desc                      print switch description\n"
           "  SWITCH stats-flow [ARG [MATCH]]        print flow stats\n"
           "  SWITCH stats-aggr [ARG [MATCH]]        print flow aggregate stats\n"
           "  SWITCH stats-table                     print table stats\n"
           "  SWITCH stats-port [PORT]               print port statistics\n"
           "  SWITCH stats-queue [PORT [QUEUE]]      print queue statistics\n"
           "  SWITCH stats-group [GROUP]             print group statistics\n"
           "  SWITCH stats-group-desc [GROUP]        print group desc statistics\n"
           "  SWITCH stats-group-features             print group features\n"
           "  SWITCH stats-meter [METER]             print meter statistics\n"
           "  SWITCH meter-config [METER]            print meter config\n"
           "  SWITCH stats-meter-features            print meter features\n"
           "  SWITCH port-desc                             print port description\n"
           "  SWITCH queue-get-config PORT          send queue_get_config message\n"
           "  SWITCH get-role                               print role message\n"
           "  SWITCH get-async                            print async message\n"
           "\n"
           "  SWITCH set-config ARG                  set switch configuration\n"
           "  SWITCH packet-out ARG                 packet out\n"
           "  SWITCH flow-mod ARG [MATCH [INST...]]  send flow_mod message\n"
           "  SWITCH group-mod ARG [BUCARG ACT...]   send group_mod message\n"
           "  SWITCH meter-mod ARG [BANDARG ...]     send meter_mod message\n"
           "  SWITCH port-mod ARG                    send port_mod message\n"
           "  SWITCH table-mod ARG                   send table_mod message\n"
           "  SWITCH set-async ARG                   set async message\n"
           "\n"
           "OpenFlow extensions\n"
           "  SWITCH set-desc DESC                   sets the DP description\n"
           "  SWITCH queue-mod PORT QUEUE BW         adds/modifies queue\n"
           "  SWITCH queue-del PORT QUEUE            deletes queue\n"
           "  SWITCH show-perf                 show performace record\n"
           "  SWITCH port-attr                 set Alta port attribute\n"
           "  SWITCH set-network device=eth0,ip=192.168.0.2,mask=255.255.255.0,gw=192.168.0.1 \n"
           "  SWITCH map-queue map_command=add,map_port=1,map_group=0,map_type=drr,map_queue=0/1/2/        map queue\n"
           "  SWITCH qos-group qos_command=mod,qos_port=1,qos_group=2,qos_type=sp,qos_value=1       config qos\n"
           "\n",
           program_name, program_name);
    vconn_usage(true, false, false);
    vlog_usage();
    printf("\nOther options:\n"
           "  --strict                    use strict match for flow commands\n"
           "  -t, --timeout=SECS          give up after SECS seconds\n"
           "  -h, --help                  display this help message\n"
           "  -V, --version               display version information\n");
    exit(EXIT_SUCCESS);
}

static void
parse_match(char *str, struct ofl_match_header **match) {
    // TODO parse masks
    char *token, *saveptr = NULL;
    struct ofl_match *m = xmalloc(sizeof(struct ofl_match));
    ofl_structs_match_init(m);

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
         if (strncmp(token, "apply", strlen("apply")) == 0 ||  strncmp(token, "write", strlen("write")) == 0 \
             ||  strncmp(token, "goto", strlen("goto")) == 0 ||  strncmp(token, "meta", strlen("meta")) == 0\
             ||  strncmp(token, "clear", strlen("clear")) == 0 ||  strncmp(token, "meter", strlen("meter")) == 0) {
                break;
         }
        /* In_port */
         if (strncmp(token, MATCH_IN_PORT KEY_VAL, strlen(MATCH_IN_PORT KEY_VAL)) == 0) {
            unsigned int in_port;
            if (parse_port(token + strlen(MATCH_IN_PORT KEY_VAL), &in_port)) {
                ofp_fatal(0, "Error parsing port: %s.", token);
            }
            else ofl_structs_match_put32(m,OXM_OF_IN_PORT,in_port);
            continue;
        }

        /* Ethernet Address*/
        if (strncmp(token, MATCH_DL_SRC KEY_VAL, strlen(MATCH_DL_SRC KEY_VAL)) == 0) {
            unsigned char eth_src[6];
            unsigned char *mask;
            if (parse_dl_addr(token + strlen(MATCH_DL_SRC KEY_VAL), eth_src, &mask)) {
                ofp_fatal(0, "Error parsing dl_src: %s.", token);
            }
            else {
                if (mask == NULL)
                    ofl_structs_match_put_eth(m,OXM_OF_ETH_SRC,eth_src);
                else
                    ofl_structs_match_put_eth_m(m,OXM_OF_ETH_SRC_W,eth_src,mask);
            }
            continue;
        }
        if (strncmp(token, MATCH_DL_DST KEY_VAL, strlen(MATCH_DL_DST KEY_VAL)) == 0) {
            unsigned char eth_dst[6];
            unsigned char *mask;
            if (parse_dl_addr(token + strlen(MATCH_DL_DST KEY_VAL), eth_dst, &mask)) {
                ofp_fatal(0, "Error parsing dl_dst: %s.", token);
            }
            else {
                 if (mask == NULL)
                    ofl_structs_match_put_eth(m,OXM_OF_ETH_DST,eth_dst);
                 else
                    ofl_structs_match_put_eth_m(m,OXM_OF_ETH_DST_W,eth_dst, mask);
            }
            continue;
        }
        /* ARP */
        if (strncmp(token, MATCH_ARP_SHA KEY_VAL, strlen(MATCH_ARP_SHA KEY_VAL)) == 0) {
            unsigned char arp_sha[6];
            unsigned char *mask;
            if (parse_dl_addr(token + strlen(MATCH_DL_SRC KEY_VAL), arp_sha, &mask)) {
                ofp_fatal(0, "Error parsing arp_sha: %s.", token);
            }
            else {
                if (mask == NULL)
                    ofl_structs_match_put_eth(m, OXM_OF_ARP_SHA, arp_sha);
                else
                    ofl_structs_match_put_eth_m(m, OXM_OF_ARP_SHA_W, arp_sha, mask);
            }
            continue;
        }
        if (strncmp(token, MATCH_ARP_THA KEY_VAL, strlen(MATCH_ARP_THA KEY_VAL)) == 0) {
            unsigned char arp_tha[6];
            unsigned char *mask;
            if (parse_dl_addr(token + strlen(MATCH_ARP_THA KEY_VAL), arp_tha, &mask)) {
                ofp_fatal(0, "Error parsing arp_tha %s.", token);
            }
            else {
                if (mask == NULL)
                    ofl_structs_match_put_eth(m,OXM_OF_ARP_THA, arp_tha);
                else
                    ofl_structs_match_put_eth_m(m,OXM_OF_ARP_THA_W, arp_tha, mask);
            }
            continue;
        }
        if (strncmp(token, MATCH_ARP_OP KEY_VAL, strlen(MATCH_ARP_OP KEY_VAL)) == 0) {
            unsigned char arp_op;
            if (parse8(token + strlen(MATCH_DL_VLAN_PCP KEY_VAL), NULL, 0, 0x7, &arp_op)){
                ofp_fatal(0, "Error parsing arp_op: %s.", token);
            } else {
                ofl_structs_match_put8(m, OXM_OF_ARP_OP, arp_op);
            }
            continue;
        }
        /*ARP ip*/
        if (strncmp(token, MATCH_ARP_SPA KEY_VAL, strlen(MATCH_ARP_SPA KEY_VAL)) == 0) {
            unsigned int nw_src;
            unsigned int *mask;
            if (parse_nw_addr(token + strlen(MATCH_ARP_SPA KEY_VAL), &(nw_src), &mask)) {
                /* 释放mask的内存*/
                free(mask);
                ofp_fatal(0, "Error parsing ip_src: %s.", token);
            }
            else {
                if (mask == NULL)
                    ofl_structs_match_put32(m, OXM_OF_ARP_SPA,nw_src);
                else
                    ofl_structs_match_put32m(m, OXM_OF_ARP_SPA_W, nw_src, *mask);
            }

            /* 释放mask的内存*/
            free(mask);
            continue;
        }
        if (strncmp(token, MATCH_ARP_TPA KEY_VAL, strlen(MATCH_ARP_TPA KEY_VAL)) == 0) {
            unsigned int nw_dst;
            unsigned int *mask;
            if (parse_nw_addr(token + strlen(MATCH_ARP_TPA KEY_VAL), &nw_dst, &mask)) {
                /* 释放mask的内存*/
                free(mask);
                ofp_fatal(0, "Error parsing ip_dst: %s.", token);
            }
            else {
                if (mask == NULL)
                    ofl_structs_match_put32(m, OXM_OF_ARP_TPA,nw_dst);
                else
                    ofl_structs_match_put32m(m, OXM_OF_ARP_TPA_W,nw_dst, *mask);
            }

            /* 释放mask的内存*/
            free(mask);
            continue;
        }

        /* VLAN */
        if (strncmp(token, MATCH_DL_VLAN KEY_VAL, strlen(MATCH_DL_VLAN KEY_VAL)) == 0) {
            unsigned short int dl_vlan;
            unsigned short int vlan_vid_mask;
            char *saveptr_in = NULL;

            //vlan_id
            if (parse_vlan_vid(token + strlen(MATCH_DL_VLAN KEY_VAL), &dl_vlan)) {
                ofp_fatal(0, "Error parsing vlan label: %s.", token);
            }

            strtok_r(token+strlen(MATCH_DL_VLAN KEY_VAL), MASK_SEP, &saveptr_in);

            //==0:without mask
            if(strcmp(saveptr_in,"") == 0){
                 ofl_structs_match_put16(m,OXM_OF_VLAN_VID, dl_vlan);
            }
            else{
                //vlan_vid_mask value
                   if (sscanf(saveptr_in, "%"SCNu16"", (&vlan_vid_mask)) !=1) {
                        ofp_fatal(0, "Error parsing %s: %s.", MATCH_VLAN_VID_MASK, token);
                }
                   else{
                          ofl_structs_match_put16m(m,OXM_OF_VLAN_VID_W, dl_vlan, vlan_vid_mask);
                   }
            }

            continue;
        }
        if (strncmp(token, MATCH_DL_VLAN_PCP KEY_VAL, strlen(MATCH_DL_VLAN_PCP KEY_VAL)) == 0) {
            unsigned char pcp;
            if (parse8(token + strlen(MATCH_DL_VLAN_PCP KEY_VAL), NULL, 0, 0x7, &pcp)) {
                ofp_fatal(0, "Error parsing vlan pcp: %s.", token);
            } else
                ofl_structs_match_put8(m, OXM_OF_VLAN_PCP, pcp);
            continue;
        }

        /* Eth Type */
        if (strncmp(token, MATCH_DL_TYPE KEY_VAL, strlen(MATCH_DL_TYPE KEY_VAL)) == 0) {
            unsigned short int dl_type;
            if (parse16(token + strlen(MATCH_DL_TYPE KEY_VAL), NULL, 0, 0xffff, &dl_type)) {
                ofp_fatal(0, "Error parsing eth_type: %s.", token);
            }
            else
                ofl_structs_match_put16(m, OXM_OF_ETH_TYPE,dl_type);
            continue;
        }

        /* IP */
        if (strncmp(token, MATCH_IP_ECN KEY_VAL, strlen(MATCH_IP_ECN KEY_VAL)) == 0) {
            unsigned char ip_ecn;
            if (parse8(token + strlen(MATCH_IP_ECN KEY_VAL), NULL, 0, 0x3f, &ip_ecn)) {
                ofp_fatal(0, "Error parsing nw_tos: %s.", token);
            }
            else
                 ofl_structs_match_put8(m, OXM_OF_IP_ECN, ip_ecn);
            continue;
        }
        if (strncmp(token, MATCH_IP_DSCP KEY_VAL, strlen(MATCH_IP_DSCP KEY_VAL)) == 0) {
            unsigned char ip_dscp;
            if (parse8(token + strlen(MATCH_IP_DSCP KEY_VAL), NULL, 0, 0x3f, &ip_dscp)) {
                ofp_fatal(0, "Error parsing nw_tos: %s.", token);
            }
            else
            {
                 ofl_structs_match_put8(m, OXM_OF_IP_DSCP, ip_dscp);
             }
            continue;
        }
        if (strncmp(token, MATCH_NW_PROTO KEY_VAL, strlen(MATCH_NW_PROTO KEY_VAL)) == 0) {
            unsigned char nw_proto;
            if (parse8(token + strlen(MATCH_NW_PROTO KEY_VAL), NULL, 0, 0xff, &nw_proto)) {
                ofp_fatal(0, "Error parsing ip_proto: %s.", token);
            }
            else ofl_structs_match_put8(m,OXM_OF_IP_PROTO, nw_proto);
            continue;
        }
        if (strncmp(token, MATCH_NW_SRC KEY_VAL, strlen(MATCH_NW_SRC KEY_VAL)) == 0) {
            unsigned int nw_src;
            unsigned int *mask;
            if (parse_nw_addr(token + strlen(MATCH_NW_SRC KEY_VAL), &(nw_src), &mask)) {
                ofp_fatal(0, "Error parsing ip_src: %s.", token);
            }
            else {
                if (mask == NULL)
                    ofl_structs_match_put32(m, OXM_OF_IPV4_SRC,nw_src);
                else
                    ofl_structs_match_put32m(m, OXM_OF_IPV4_SRC_W, nw_src, *mask);
            }
            continue;
        }
        if (strncmp(token, MATCH_NW_DST KEY_VAL, strlen(MATCH_NW_DST KEY_VAL)) == 0) {
            unsigned int nw_dst;
            unsigned int *mask;
            if (parse_nw_addr(token + strlen(MATCH_NW_DST KEY_VAL), &nw_dst, &mask)) {
                ofp_fatal(0, "Error parsing ip_dst: %s.", token);
            }
            else {
                if (mask == NULL)
                    ofl_structs_match_put32(m, OXM_OF_IPV4_DST,nw_dst);
                else
                    ofl_structs_match_put32m(m, OXM_OF_IPV4_DST_W,nw_dst, *mask);
            }
            continue;
        }

        /* ICMP */
        if (strncmp(token, MATCH_ICMPV4_CODE KEY_VAL, strlen(MATCH_ICMPV4_CODE KEY_VAL)) == 0) {
            unsigned char icmpv4_code;
            if (parse8(token + strlen(MATCH_ICMPV4_CODE KEY_VAL), NULL, 0, 0x3f, &icmpv4_code)) {
                ofp_fatal(0, "Error parsing icmpv4_code: %s.", token);
            }
            else
                 ofl_structs_match_put8(m, OXM_OF_ICMPV4_CODE, icmpv4_code);
            continue;
        }
        if (strncmp(token, MATCH_ICMPV4_TYPE KEY_VAL, strlen(MATCH_ICMPV4_TYPE KEY_VAL)) == 0) {
            unsigned char icmpv4_type;
            if (parse8(token + strlen(MATCH_ICMPV4_TYPE KEY_VAL), NULL, 0, 0x3f, &icmpv4_type)) {
                ofp_fatal(0, "Error parsing icmpv4_type: %s.", token);
            }
            else
                 ofl_structs_match_put8(m, OXM_OF_ICMPV4_TYPE, icmpv4_type);
            continue;
        }

        /* TCP */
        if (strncmp(token, MATCH_TP_SRC KEY_VAL, strlen(MATCH_TP_SRC KEY_VAL)) == 0) {
            unsigned short int tp_src;
            if (parse16(token + strlen(MATCH_TP_SRC KEY_VAL), NULL, 0, 0xffff, &tp_src)) {
                ofp_fatal(0, "Error parsing tcp_src: %s.", token);
            }
            else ofl_structs_match_put16(m, OXM_OF_TCP_SRC,tp_src);
            continue;
        }
        if (strncmp(token, MATCH_TP_DST KEY_VAL, strlen(MATCH_TP_DST KEY_VAL)) == 0) {
            unsigned short int tp_dst;
            if (parse16(token + strlen(MATCH_TP_DST KEY_VAL), NULL, 0, 0xffff, &tp_dst)) {
                ofp_fatal(0, "Error parsing tcp_dst: %s.", token);
            }
            else ofl_structs_match_put16(m, OXM_OF_TCP_DST,tp_dst);
            continue;
        }

        /*UDP */
        if (strncmp(token, MATCH_UDP_SRC KEY_VAL, strlen(MATCH_UDP_SRC KEY_VAL)) == 0) {
            unsigned short int udp_src;
            if (parse16(token + strlen(MATCH_UDP_SRC KEY_VAL), NULL, 0, 0xffff, &udp_src)) {
                ofp_fatal(0, "Error parsing udp_src: %s.", token);
            }
            else ofl_structs_match_put16(m, OXM_OF_UDP_SRC,udp_src);
            continue;
        }
        if (strncmp(token, MATCH_UDP_DST KEY_VAL, strlen(MATCH_UDP_DST KEY_VAL)) == 0) {
            unsigned short int udp_dst;
            if (parse16(token + strlen(MATCH_UDP_DST KEY_VAL), NULL, 0, 0xffff, &udp_dst)) {
                ofp_fatal(0, "Error parsing udp_dst: %s.", token);
            }
            else ofl_structs_match_put16(m, OXM_OF_UDP_DST,udp_dst);
            continue;
        }

        /*SCTP*/
        if (strncmp(token, MATCH_SCTP_SRC KEY_VAL, strlen(MATCH_SCTP_SRC KEY_VAL)) == 0) {
            unsigned short int sctp_src;
            if (parse16(token + strlen(MATCH_SCTP_SRC KEY_VAL), NULL, 0, 0xffff, &sctp_src)) {
                ofp_fatal(0, "Error parsing sctp_src: %s.", token);
            }
            else ofl_structs_match_put16(m, OXM_OF_SCTP_SRC,sctp_src);
            continue;
        }
        if (strncmp(token, MATCH_SCTP_DST KEY_VAL, strlen(MATCH_SCTP_DST KEY_VAL)) == 0) {
            unsigned short int sctp_dst;
            if (parse16(token + strlen(MATCH_SCTP_DST KEY_VAL), NULL, 0, 0xffff, &sctp_dst)) {
                ofp_fatal(0, "Error parsing sctp_dst: %s.", token);
            }
            else ofl_structs_match_put16(m, OXM_OF_SCTP_DST,sctp_dst);
            continue;
        }

        /* MPLS */
        if (strncmp(token, MATCH_MPLS_LABEL KEY_VAL, strlen(MATCH_MPLS_LABEL KEY_VAL)) == 0) {
            unsigned int mpls_label;
            if (parse32(token + strlen(MATCH_MPLS_LABEL KEY_VAL), NULL, 0, 0xfffff, &mpls_label)) {
                ofp_fatal(0, "Error parsing mpls_label: %s.", token);
            }
            else ofl_structs_match_put32(m,OXM_OF_MPLS_LABEL,mpls_label);
            continue;
        }
        if (strncmp(token, MATCH_MPLS_TC KEY_VAL, strlen(MATCH_MPLS_TC KEY_VAL)) == 0) {
            unsigned char mpls_tc;
        if (parse8(token + strlen(MATCH_MPLS_TC KEY_VAL), NULL, 0, 0x07, &mpls_tc)) {
                ofp_fatal(0, "Error parsing mpls_tc: %s.", token);
            }
        else
            ofl_structs_match_put8(m, OXM_OF_MPLS_TC, mpls_tc);
            continue;
        }

        /* IPv6 */
        if (strncmp(token, MATCH_NW_SRC_IPV6 KEY_VAL , strlen(MATCH_NW_SRC_IPV6 KEY_VAL)) == 0) {
            struct in6_addr addr, mask;
            struct in6_addr in6addr_zero = IN6ADDR_ZERO_INIT;
            if (str_to_ipv6(token + strlen(MATCH_NW_DST_IPV6)+1, &addr, &mask) < 0) {
                ofp_fatal(0, "Error parsing nw_src_ipv6: %s.", token);
            }
            else {
                if(ipv6_addr_equals(&mask, &in6addr_zero)){
                    ofl_structs_match_put_ipv6(m, OXM_OF_IPV6_SRC, addr.s6_addr);
                }
                else {
                    ofl_structs_match_put_ipv6m(m, OXM_OF_IPV6_SRC_W,addr.s6_addr, mask.s6_addr);
                }
            }
            continue;
        }
        if (strncmp(token, MATCH_NW_DST_IPV6 KEY_VAL , strlen(MATCH_NW_DST_IPV6 KEY_VAL)) == 0) {
            struct in6_addr addr, mask;
            struct in6_addr in6addr_zero = IN6ADDR_ZERO_INIT;
            if (str_to_ipv6(token + strlen(MATCH_NW_DST_IPV6)+1, &addr, &mask) < 0) {
                ofp_fatal(0, "Error parsing nw_src_ipv6: %s.", token);
            }
            else {
                if(ipv6_addr_equals(&mask, &in6addr_zero)){
                    ofl_structs_match_put_ipv6(m, OXM_OF_IPV6_DST, addr.s6_addr);
                }
                else {
                    ofl_structs_match_put_ipv6m(m, OXM_OF_IPV6_DST_W, addr.s6_addr, mask.s6_addr);
                }
            }
            continue;
        }
         if (strncmp(token, MATCH_IPV6_FLABEL KEY_VAL, strlen(MATCH_IPV6_FLABEL KEY_VAL)) == 0) {
            unsigned int ipv6_label;
            unsigned int ipv6_label_mask;
            char *saveptr_in = NULL;

            //ipv6_flabel
            if (parse32(token + strlen(MATCH_IPV6_FLABEL KEY_VAL), NULL, 0, 0xfffff, &ipv6_label)) {
                ofp_fatal(0, "Error parsing ipv6_label: %s.", token);
            }

            strtok_r(token+strlen(MATCH_IPV6_FLABEL KEY_VAL), MASK_SEP, &saveptr_in);

            //==0:without mask
            if(strcmp(saveptr_in,"") == 0){
                ofl_structs_match_put32(m,OXM_OF_IPV6_FLABEL, ipv6_label);
            }
            else{
                //ipv6_flabel_mask value
                   if (sscanf(saveptr_in, "%"SCNu32"", (&ipv6_label_mask)) !=1) {
                        ofp_fatal(0, "Error parsing %s: %s.", MATCH_IPV6_FLABEL_MASK, token);
                }
                   else{
                          ofl_structs_match_put32m(m,OXM_OF_IPV6_FLABEL_W, ipv6_label, ipv6_label_mask);
                   }
            }

            continue;
        }

        /* ICMPv6 */
        if (strncmp(token, MATCH_ICMPV6_CODE KEY_VAL, strlen(MATCH_ICMPV6_CODE KEY_VAL)) == 0) {
            unsigned char icmpv6_code;
            if (parse8(token + strlen(MATCH_ICMPV6_CODE KEY_VAL), NULL, 0, 0x3f, &icmpv6_code)) {
                ofp_fatal(0, "Error parsing icmpv6_code: %s.", token);
            }
            else
                 ofl_structs_match_put8(m, OXM_OF_ICMPV6_CODE, icmpv6_code);
            continue;
        }
        if (strncmp(token, MATCH_ICMPV6_TYPE KEY_VAL, strlen(MATCH_ICMPV6_TYPE KEY_VAL)) == 0) {
            unsigned char icmpv6_type;
            if (parse8(token + strlen(MATCH_ICMPV6_TYPE KEY_VAL), NULL, 0, 0x3f, &icmpv6_type)) {
                ofp_fatal(0, "Error parsing icmpv6_type: %s.", token);
            }
            else
                 ofl_structs_match_put8(m, OXM_OF_ICMPV6_CODE, icmpv6_type);
            continue;
        }

        /* IPv6 ND */
        if (strncmp(token, MATCH_IPV6_ND_TARGET KEY_VAL , strlen(MATCH_IPV6_ND_TARGET KEY_VAL)) == 0) {
            struct in6_addr addr, mask;
            if (str_to_ipv6(token + strlen(MATCH_IPV6_ND_TARGET)+1, &addr, &mask) < 0) {
                ofp_fatal(0, "Error parsing ipv6_nd_target %s.", token);
            }
            else {
                ofl_structs_match_put_ipv6(m, OXM_OF_IPV6_ND_TARGET, addr.s6_addr);
            }
            continue;
        }
        if (strncmp(token, MATCH_IPV6_ND_SLL KEY_VAL, strlen(MATCH_IPV6_ND_SLL KEY_VAL)) == 0) {
            unsigned char eth_src[6];
            unsigned char *mask;
            if (parse_dl_addr(token + strlen(MATCH_IPV6_ND_SLL KEY_VAL), eth_src, &mask)) {
                ofp_fatal(0, "Error parsing ipv6_nd_sll: %s.", token);
            }
            else {
                 ofl_structs_match_put_eth(m,OXM_OF_IPV6_ND_SLL, eth_src);
            }
            continue;
        }
        if (strncmp(token, MATCH_IPV6_ND_TLL KEY_VAL, strlen(MATCH_IPV6_ND_TLL KEY_VAL)) == 0) {
            unsigned char eth_dst[6];
            unsigned char *mask;
            if (parse_dl_addr(token + strlen(MATCH_IPV6_ND_TLL KEY_VAL), eth_dst, &mask)) {
                ofp_fatal(0, "Error parsing ipv_nd_tll: %s.", token);
            }
            else {
                ofl_structs_match_put_eth(m, OXM_OF_IPV6_ND_TLL,eth_dst);
            }
            continue;
        }

        /* Metadata */
        if (strncmp(token, MATCH_METADATA KEY_VAL, strlen(MATCH_METADATA KEY_VAL)) == 0) {
            unsigned long long int metadata;
            unsigned long long int metadata_mask;
            char *saveptr_in = NULL;

            //metadata value
            if (sscanf(token, MATCH_METADATA KEY_VAL "0x%"SCNx64"", (&metadata)) !=1) {
                ofp_fatal(0, "Error parsing %s: %s.", MATCH_METADATA, token);
            }

            strtok_r(token+strlen(MATCH_METADATA KEY_VAL), MASK_SEP, &saveptr_in);

            //==0:without mask
            if(strcmp(saveptr_in,"") == 0){
                ofl_structs_match_put64(m, OXM_OF_METADATA, hton64(metadata));
            }
            else{
                //metadata_mask value
                   if (sscanf(saveptr_in, "0x%"SCNx64"", (&metadata_mask)) !=1) {
                        ofp_fatal(0, "Error parsing %s: %s.", MATCH_METADATA_MASK, token);
                }
                   else{
                          ofl_structs_match_put64m(m, OXM_OF_METADATA_W, hton64(metadata),hton64(metadata_mask));
                   }
            }

            continue;
        }
        /*PBB ISID*/
        if (strncmp(token, MATCH_PBB_ISID KEY_VAL, strlen(MATCH_PBB_ISID KEY_VAL)) == 0) {
            unsigned int pbb_isid;
            unsigned int pbb_isid_mask;
            char *saveptr_in = NULL;

            //pbb_isid vlaue
            if (parse32(token + strlen(MATCH_PBB_ISID KEY_VAL), NULL, 0, 0x1000000, &pbb_isid)) {
                ofp_fatal(0, "Error parsing pbb_isid: %s.", token);
            }

            strtok_r(token+strlen(MATCH_PBB_ISID KEY_VAL), MASK_SEP, &saveptr_in);

            //==0:without mask
            if(strcmp(saveptr_in,"") == 0){
                ofl_structs_match_put32(m, OXM_OF_PBB_ISID, pbb_isid);
            }
            else{
                //metadata_mask value
                   if (sscanf(saveptr_in, "%"SCNu32"", (&pbb_isid_mask)) !=1) {
                        ofp_fatal(0, "Error parsing %s: %s.", MATCH_PBB_ISID_MASK, token);
                }
                   else{
                          ofl_structs_match_put32m(m, OXM_OF_PBB_ISID_W, pbb_isid,pbb_isid_mask);
                   }
            }
            continue;
        }
        /* Tunnel ID */
        if (strncmp(token, MATCH_TUNNEL_ID KEY_VAL, strlen(MATCH_TUNNEL_ID KEY_VAL)) == 0) {
            unsigned long long int tunn_id;
            unsigned long long int tunn_id_mask;
            char * saveptr_in = NULL;

            //tunnel_id value
            if (sscanf(token, MATCH_TUNNEL_ID KEY_VAL "0x%"SCNx64"", (&tunn_id)) != 1) {
                ofp_fatal(0, "Error parsing %s: %s.", MATCH_TUNNEL_ID, token);
            }

            strtok_r(token+strlen(MATCH_TUNNEL_ID KEY_VAL), MASK_SEP, &saveptr_in);

            //==0:without mask
            if(strcmp(saveptr_in,"") == 0){
                ofl_structs_match_put64(m, OXM_OF_TUNNEL_ID, tunn_id);
            }
            else{
                //metadata_mask value
                   if (sscanf(saveptr_in, "0x%"SCNx64"", (&tunn_id_mask)) !=1) {
                        ofp_fatal(0, "Error parsing %s: %s.", MATCH_TUNNEL_ID_MASK, token);
                }
                   else{
                          ofl_structs_match_put64m(m, OXM_OF_TUNNEL_ID_W, tunn_id,tunn_id_mask);
                   }
            }

            continue;
        }
        /*Extension Headers */
        if (strncmp(token, MATCH_EXT_HDR KEY_VAL, strlen(MATCH_EXT_HDR KEY_VAL)) == 0) {
            unsigned short int ext_hdr;
            unsigned short int ext_hdr_mask;
            char *saveptr_in = NULL;
            char *token_in = NULL;

            token_in = strtok_r(token+strlen(MATCH_EXT_HDR KEY_VAL), MASK_SEP, &saveptr_in);
            //ext_hdr
            if (parse_ext_hdr(token_in, &ext_hdr)) {
                ofp_fatal(0, "Error parsing ext_hdr %s.", token);
            }


            //==0:without mask
            if(strcmp(saveptr_in,"") == 0){
                ofl_structs_match_put16(m, OXM_OF_IPV6_EXTHDR, ext_hdr);
            }
            else{
                //metadata_mask value
                   if (sscanf(saveptr_in, "0x%"SCNx16"", (&ext_hdr_mask)) !=1) {
                        ofp_fatal(0, "Error parsing %s: %s.", MATCH_IPV6_EXTHDR_MASK, token);
                }
                   else{
                          ofl_structs_match_put16m(m, OXM_OF_IPV6_EXTHDR_W, ext_hdr,ext_hdr_mask);
                   }
            }

            continue;
        }
        ofp_fatal(0, "Error parsing match arg: %s.", token);
    }

    (*match) = (struct ofl_match_header *)m;
}

static int
parse_set_field(char *token, struct ofl_action_set_field *act) {


    if (strncmp(token, MATCH_DL_SRC KEY_VAL, strlen(MATCH_DL_SRC KEY_VAL)) == 0) {
        unsigned char* dl_src = xmalloc(6);
        unsigned char *mask = NULL;
        if (parse_dl_addr(token + strlen(MATCH_DL_SRC KEY_VAL), dl_src, &mask)) {
                ofp_fatal(0, "Error parsing dl_src: %s.", token);
        }else{
                act->field = (struct ofl_match_tlv*) malloc(sizeof(struct ofl_match_tlv));
                act->field->header = OXM_OF_ETH_SRC;
                act->field->value = (unsigned char*) dl_src;
            }
        return 0;
    }
    if (strncmp(token, MATCH_DL_DST KEY_VAL, strlen(MATCH_DL_DST KEY_VAL)) == 0) {
        unsigned char* dl_dst = xmalloc(6);
        unsigned char *mask = NULL;
        if (parse_dl_addr(token + strlen(MATCH_DL_DST KEY_VAL), dl_dst, &mask)) {
                ofp_fatal(0, "Error parsing dl_src: %s.", token);
        }else{
                act->field = (struct ofl_match_tlv*) malloc(sizeof(struct ofl_match_tlv));
                act->field->header = OXM_OF_ETH_DST;
                act->field->value = (unsigned char*) dl_dst;
            }
        return 0;
    }
    if (strncmp(token, MATCH_DL_TYPE KEY_VAL, strlen(MATCH_DL_TYPE KEY_VAL)) == 0) {
        unsigned short int* dl_type = xmalloc(sizeof(unsigned short int));
        if (parse16(token + strlen(MATCH_DL_TYPE KEY_VAL), NULL, 0, 0xffff, dl_type)) {
            ofp_fatal(0, "Error parsing dl_type: %s.", token);
        }
        else {
            act->field = (struct ofl_match_tlv*) malloc(sizeof(struct ofl_match_tlv));
            act->field->header = OXM_OF_ETH_TYPE;
            act->field->value = (unsigned char*) dl_type;
        }
        return 0;
    }
    if (strncmp(token, MATCH_DL_VLAN KEY_VAL, strlen(MATCH_DL_VLAN KEY_VAL)) == 0) {
            unsigned short int *dl_vlan = malloc(sizeof(unsigned short int));
            if (parse_vlan_vid(token + strlen(MATCH_DL_VLAN KEY_VAL), dl_vlan)) {
                ofp_fatal(0, "Error parsing vlan label: %s.", token);
            }
            else {
                act->field = (struct ofl_match_tlv*) malloc(sizeof(struct ofl_match_tlv));
                act->field->header = OXM_OF_VLAN_VID;
                act->field->value = (unsigned char*) dl_vlan;
            }
        return 0;
    }
    if (strncmp(token, MATCH_PBB_ISID KEY_VAL, strlen(MATCH_PBB_ISID KEY_VAL)) == 0) {
            unsigned int *pbb_isid = malloc(sizeof(unsigned int));
            if (parse32(token + strlen(MATCH_PBB_ISID KEY_VAL), NULL, 0, 0x1000000, pbb_isid)) {
                ofp_fatal(0, "Error parsing pbb service id: %s.", token);
            }
            else {
                act->field = (struct ofl_match_tlv*) malloc(sizeof(struct ofl_match_tlv));
                act->field->header = OXM_OF_PBB_ISID;
                act->field->value = (unsigned char*) pbb_isid;
            }
        return 0;
    }
    if (strncmp(token, MATCH_MPLS_LABEL KEY_VAL, strlen(MATCH_MPLS_LABEL KEY_VAL)) == 0) {
            unsigned int *mpls_label = malloc(sizeof(unsigned int));
            if (parse32(token + strlen(MATCH_MPLS_LABEL KEY_VAL), NULL, 0, 0x1000000, mpls_label)) {
                ofp_fatal(0, "Error parsing mpls label id: %s.", token);
            }
            else {
                act->field = (struct ofl_match_tlv*) malloc(sizeof(struct ofl_match_tlv));
                act->field->header = OXM_OF_MPLS_LABEL;
                act->field->value = (unsigned char*) mpls_label;
            }
        return 0;
    }
    if (strncmp(token, MATCH_MPLS_TC KEY_VAL, strlen(MATCH_MPLS_TC KEY_VAL)) == 0) {
            unsigned char *mpls_tc = malloc(sizeof(unsigned char));
            if (parse8(token + strlen(MATCH_MPLS_TC KEY_VAL), NULL, 0, 0x07, mpls_tc)) {
                ofp_fatal(0, "Error parsing mpls_tc: %s.", token);
            }
            else {
                act->field = (struct ofl_match_tlv*) malloc(sizeof(struct ofl_match_tlv));
                act->field->header = OXM_OF_MPLS_TC;
                act->field->value = (unsigned char*)mpls_tc;
            }
            return 0;
    }

    if (strncmp(token, MATCH_DL_VLAN_PCP KEY_VAL, strlen(MATCH_DL_VLAN_PCP KEY_VAL)) == 0) {
        unsigned char* vlan_pcp = malloc(sizeof(unsigned char));
        if (parse8(token + strlen(MATCH_DL_VLAN_PCP KEY_VAL), NULL, 0, 0x7, vlan_pcp)) {
            ofp_fatal(0, "Error parsing vlan pcp: %s.", token);
        }
        else{
                act->field = (struct ofl_match_tlv*) malloc(sizeof(struct ofl_match_tlv));
                act->field->header = OXM_OF_VLAN_PCP;
                act->field->value =  (unsigned char*) vlan_pcp;
        }
        return 0;
    }
    if (strncmp(token, MATCH_NW_SRC KEY_VAL, strlen(MATCH_NW_SRC KEY_VAL)) == 0) {
        unsigned int* nw_src = malloc(sizeof(unsigned int));
        unsigned int *mask;

        if (parse_nw_addr(token + strlen(MATCH_NW_SRC KEY_VAL), nw_src, &mask)) {
            /* 释放内存*/
            free(mask);
            free(nw_src);
            ofp_fatal(0, "Error parsing ip_src: %s.", token);
        }
        else {
            act->field = (struct ofl_match_tlv*) malloc(sizeof(struct ofl_match_tlv));
            act->field->header = OXM_OF_IPV4_SRC;
            act->field->value =  (unsigned char*) nw_src;
        }

        /* 释放内存*/
        free(mask);
        free(nw_src);
        return 0;
    }
    if (strncmp(token, MATCH_NW_DST KEY_VAL, strlen(MATCH_NW_DST KEY_VAL)) == 0) {
        unsigned int * nw_dst =   malloc(sizeof(unsigned int));
        unsigned int *mask;

        if (parse_nw_addr(token + strlen(MATCH_NW_DST KEY_VAL), nw_dst, &mask)) {
                ofp_fatal(0, "Error parsing ip_dst: %s.", token);
            }
        else {
            act->field = (struct ofl_match_tlv*) malloc(sizeof(struct ofl_match_tlv));
            act->field->header = OXM_OF_IPV4_DST;
            act->field->value =  (unsigned char*) nw_dst;
        }
        return 0;
    }
    if (strncmp(token, MATCH_TP_SRC KEY_VAL, strlen(MATCH_TP_SRC KEY_VAL)) == 0) {
        unsigned short int* tp_src = xmalloc(2);
        if (parse16(token+ strlen(MATCH_TP_SRC KEY_VAL), NULL, 0, 0xffff, tp_src)) {
            ofp_fatal(0, "Error parsing tcp_src: %s.", token);
        }else{
            act->field = (struct ofl_match_tlv*) malloc(sizeof(struct ofl_match_tlv));
            act->field->header = OXM_OF_TCP_SRC;
            act->field->value = (unsigned char*) tp_src;
        }
        return 0;
    }
    if (strncmp(token, MATCH_TP_DST KEY_VAL, strlen(MATCH_TP_DST KEY_VAL)) == 0) {
        unsigned short int* tp_dst = xmalloc(2);
        if (parse16(token + strlen(MATCH_TP_SRC KEY_VAL), NULL, 0, 0xffff, tp_dst)) {
            ofp_fatal(0, "Error parsing tcp_src: %s.", token);
        }else{
            act->field = (struct ofl_match_tlv*) malloc(sizeof(struct ofl_match_tlv));
            act->field->header = OXM_OF_TCP_DST;
            act->field->value = (unsigned char*) tp_dst;
        }
        return 0;
    }
    ofp_fatal(0, "Error parsing set_field arg: %s.", token);
}

static void
make_all_match(struct ofl_match_header **match) {
    struct ofl_match *m = xmalloc(sizeof(struct ofl_match));

    ofl_structs_match_init(m);

    (*match) = (struct ofl_match_header *)m;
}


static void
parse_action(unsigned short int type, char *str, struct ofl_action_header **act) {
    switch (type) {
        case (OFPAT_OUTPUT): {
            char *token, *saveptr = NULL;
            struct ofl_action_output *a = xmalloc(sizeof(struct ofl_action_output));

            token = strtok_r(str, KEY_VAL2, &saveptr);
            if (parse_port(token, &(a->port))) {
                ofp_fatal(0, "Error parsing port in output action: %s.", str);
            }
            token = strtok_r(NULL, KEY_VAL2, &saveptr);
            if (token == NULL) {
                a->max_len = 0;
            } else {
                if (parse16(token, NULL, 0, 0xffff - sizeof(struct ofp_header), &(a->max_len))) {
                    ofp_fatal(0, "Error parsing max_len in output action: %s.", str);
                }
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_SET_FIELD):{
            struct ofl_action_set_field *a = xmalloc(sizeof (struct ofl_action_set_field));
            if (parse_set_field(str, a)) {
                ofp_fatal(0, "Error parsing field in set_field action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_COPY_TTL_OUT):
        case (OFPAT_COPY_TTL_IN): {
            struct ofl_action_header *a = xmalloc(sizeof(struct ofl_action_header));
            (*act) = a;
            break;
        }
        case (OFPAT_SET_MPLS_TTL): {
            struct ofl_action_mpls_ttl *a = xmalloc(sizeof(struct ofl_action_mpls_ttl));
            if (parse8(str, NULL, 0, 255, &(a->mpls_ttl))) {
                ofp_fatal(0, "Error parsing ttl in mpls_ttl action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_DEC_MPLS_TTL): {
            struct ofl_action_header *a = xmalloc(sizeof(struct ofl_action_header));
            (*act) = a;
            break;
        }
        case (OFPAT_PUSH_VLAN):
        case (OFPAT_PUSH_PBB):
        case (OFPAT_PUSH_MPLS): {
            struct ofl_action_push *a = xmalloc(sizeof(struct ofl_action_push));
            if (sscanf(str, "0x%"SCNx16"", &(a->ethertype)) != 1) {
                ofp_fatal(0, "Error parsing ethertype in push_mpls/vlan/pbb action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_POP_VLAN):
        case (OFPAT_POP_PBB): {
            struct ofl_action_header *a = xmalloc(sizeof(struct ofl_action_header));
            (*act) = a;
            break;
        }
        case (OFPAT_POP_MPLS): {
            struct ofl_action_pop_mpls *a = xmalloc(sizeof(struct ofl_action_pop_mpls));
            if (sscanf(str, "0x%"SCNx16"", &(a->ethertype)) != 1) {
                ofp_fatal(0, "Error parsing ethertype in pop_mpls action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_SET_QUEUE): {
            struct ofl_action_set_queue *a = xmalloc(sizeof(struct ofl_action_set_queue));
            if (parse32(str, NULL, 0, 0xffffffff, &(a->queue_id))) {
                ofp_fatal(0, "Error parsing queue in queue action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_GROUP): {
            struct ofl_action_group *a = xmalloc(sizeof(struct ofl_action_group));
            if (parse_group(str, &(a->group_id))) {
                ofp_fatal(0, "Error parsing group in group action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_SET_NW_TTL): {
            struct ofl_action_set_nw_ttl *a = xmalloc(sizeof(struct ofl_action_set_nw_ttl));
            if (parse8(str, NULL, 0, 255, &(a->nw_ttl))) {
                ofp_fatal(0, "Error parsing ttl in mpls_ttl action: %s.", str);
            }
            (*act) = (struct ofl_action_header *)a;
            break;
        }
        case (OFPAT_DEC_NW_TTL): {
            struct ofl_action_header *a = xmalloc(sizeof(struct ofl_action_header));
            (*act) = a;
            break;
        }
        default: {
            ofp_fatal(0, "Error parsing action: %s.", str);
        }
    }
    (*act)->type = type;
}

static void
parse_actions(char *str, size_t *acts_num, struct ofl_action_header ***acts) {
    char *token, *saveptr = NULL;
    char *s;
    size_t i;
    bool found;
    struct ofl_action_header *act = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        found = false;
        for (i=0; i<NUM_ELEMS(action_names); i++) {
            if (strncmp(token, action_names[i].name, strlen(action_names[i].name)) == 0) {
                s = token + strlen(action_names[i].name);

                if (strncmp(s, KEY_VAL, strlen(KEY_VAL)) == 0) {
                    s+= strlen(KEY_VAL);
                }
                parse_action(action_names[i].code, s, &act);
                (*acts_num)++;
                (*acts) = xrealloc((*acts), sizeof(struct ofl_action_header *) * (*acts_num));
                (*acts)[(*acts_num)-1] = act;
                found = true;
                break;
            }
        }
        if (!found) {
            ofp_fatal(0, "Error parsing action: %s.", token);
        }
    }

}



static void
parse_inst(char *str, struct ofl_instruction_header **inst) {
    size_t i;
    char *s;

    for (i=0; i<NUM_ELEMS(inst_names); i++) {
        if (strncmp(str, inst_names[i].name, strlen(inst_names[i].name)) == 0) {

            s = str + strlen(inst_names[i].name);

            if (strncmp(s, KEY_VAL2, strlen(KEY_VAL2)) != 0) {
                ofp_fatal(0, "Error parsing instruction: %s.", str);
            }
            s+= strlen(KEY_VAL2);
            switch (inst_names[i].code) {
                case (OFPIT_GOTO_TABLE): {
                    struct ofl_instruction_goto_table *i = xmalloc(sizeof(struct ofl_instruction_goto_table));
                    i->header.type = OFPIT_GOTO_TABLE;
                    if (parse_table(s, &(i->table_id))) {
                        ofp_fatal(0, "Error parsing table in goto instruction: %s.", s);
                    }
                    (*inst) = (struct ofl_instruction_header *)i;
                    return;
                }
                case (OFPIT_WRITE_METADATA): {
                    char *token, *saveptr = NULL;
                    struct ofl_instruction_write_metadata *i = xmalloc(sizeof(struct ofl_instruction_write_metadata));
                    i->header.type = OFPIT_WRITE_METADATA;
                    token = strtok_r(s, KEY_SEP, &saveptr);
                    if (sscanf(token, "0x%"SCNx64"", &(i->metadata)) != 1) {
                        ofp_fatal(0, "Error parsing metadata in write metadata instruction: %s.", s);
                    }
                    token = strtok_r(NULL, KEY_SEP, &saveptr);
                    if (token == NULL) {
                        i->metadata_mask = 0xffffffffffffffffULL;
                    } else {
                        if (sscanf(token, "0x%"SCNx64"", &(i->metadata_mask)) != 1) {
                            ofp_fatal(0, "Error parsing metadata_mask in write metadata instruction: %s.", s);
                        }
                    }
                    (*inst) = (struct ofl_instruction_header *)i;
                    return;
                }
                case (OFPIT_WRITE_ACTIONS): {
                    struct ofl_instruction_actions *i = xmalloc(sizeof(struct ofl_instruction_actions));
                    i->header.type = OFPIT_WRITE_ACTIONS;
                    i->actions = NULL;
                    i->actions_num = 0;
                    parse_actions(s, &(i->actions_num), &(i->actions));
                    (*inst) = (struct ofl_instruction_header *)i;
                    return;
                }
                case (OFPIT_APPLY_ACTIONS): {
                    struct ofl_instruction_actions *i = xmalloc(sizeof(struct ofl_instruction_actions));
                    i->header.type = OFPIT_APPLY_ACTIONS;
                    i->actions = NULL;
                    i->actions_num = 0;
                    parse_actions(s, &(i->actions_num), &(i->actions));
                    (*inst) = (struct ofl_instruction_header *)i;
                    return;
                }
                case (OFPIT_METER): {
                    struct ofl_instruction_meter *i = xmalloc(sizeof(struct ofl_instruction_meter));
                    i->header.type = OFPIT_METER;
                    if(parse32(s, NULL, 0, OFPM_MAX ,&i->meter_id)){
                        ofp_fatal(0, "Error parsing meter instruction: %s.", s);
                    }
                    (*inst) = (struct ofl_instruction_header *)i;
                    return;
                }
                case (OFPIT_CLEAR_ACTIONS): {
                    struct ofl_instruction_header *i = xmalloc(sizeof(struct ofl_instruction_header));
                    i->type = OFPIT_CLEAR_ACTIONS;
                    (*inst) = (struct ofl_instruction_header *)i;
                    return;
                }
            }
        }
    }
    ofp_fatal(0, "Error parsing instruction: %s.", str);
}


static void
parse_flow_stat_args(char *str, struct ofl_msg_multipart_request_flow *req) {
    char *token, *saveptr = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        if (strncmp(token, FLOW_MOD_COOKIE KEY_VAL, strlen(FLOW_MOD_COOKIE KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_COOKIE KEY_VAL "0x%"SCNx64"", &(req->cookie)) != 1) {
                ofp_fatal(0, "Error parsing flow_stat cookie: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_COOKIE_MASK KEY_VAL, strlen(FLOW_MOD_COOKIE_MASK KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_COOKIE_MASK KEY_VAL "0x%"SCNx64"", &(req->cookie_mask)) != 1) {
                ofp_fatal(0, "Error parsing flow_stat cookie mask: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_TABLE_ID KEY_VAL, strlen(FLOW_MOD_TABLE_ID KEY_VAL)) == 0) {
            if (parse8(token + strlen(FLOW_MOD_TABLE_ID KEY_VAL), table_names, NUM_ELEMS(table_names), 254,  &req->table_id)) {
                ofp_fatal(0, "Error parsing flow_stat table: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_OUT_PORT KEY_VAL, strlen(FLOW_MOD_OUT_PORT KEY_VAL)) == 0) {
            if (parse_port(token + strlen(FLOW_MOD_OUT_PORT KEY_VAL), &req->out_port)) {
                ofp_fatal(0, "Error parsing flow_stat port: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_OUT_GROUP KEY_VAL, strlen(FLOW_MOD_OUT_GROUP KEY_VAL)) == 0) {
            if (parse_group(token + strlen(FLOW_MOD_OUT_GROUP KEY_VAL), &req->out_group)) {
                ofp_fatal(0, "Error parsing flow_stat group: %s.", token);
            }
            continue;
        }
        ofp_fatal(0, "Error parsing flow_stat arg: %s.", token);
    }
}

static void
parse_set_async_args(char *str, struct ofl_async_config *req){

    char *token, *saveptr = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
         if (strncmp(token, PACKET_IN_MASK0 KEY_VAL, strlen(PACKET_IN_MASK0 KEY_VAL)) == 0) {
            if (sscanf(token, PACKET_IN_MASK0 KEY_VAL "%"SCNu32"", &(req->packet_in_mask[0])) != 1) {
                ofp_fatal(0, "Error parsing %s: %s.", PACKET_IN_MASK0, token);
            }
            continue;
        }
        if (strncmp(token, PACKET_IN_MASK1 KEY_VAL, strlen(PACKET_IN_MASK1 KEY_VAL)) == 0) {
            if (sscanf(token, PACKET_IN_MASK1 KEY_VAL "%"SCNu32"", &(req->packet_in_mask[1])) != 1) {
                ofp_fatal(0, "Error parsing %s: %s.", PACKET_IN_MASK1, token);
            }
            continue;
        }
        if (strncmp(token, PORT_STATUS_MASK0 KEY_VAL, strlen(PORT_STATUS_MASK0 KEY_VAL)) == 0) {
            if (sscanf(token, PORT_STATUS_MASK0 KEY_VAL "%"SCNu32"", &(req->port_status_mask[0])) != 1) {
                ofp_fatal(0, "Error parsing %s: %s.", PORT_STATUS_MASK0, token);
            }
            continue;
        }
        if (strncmp(token, PORT_STATUS_MASK1 KEY_VAL, strlen(PORT_STATUS_MASK1 KEY_VAL)) == 0) {
            if (sscanf(token, PORT_STATUS_MASK1 KEY_VAL "%"SCNu32"", &(req->port_status_mask[1])) != 1) {
                ofp_fatal(0, "Error parsing %s: %s.", PORT_STATUS_MASK1, token);
            }
            continue;
        }
        if (strncmp(token, FLOW_STATUS_MASK0 KEY_VAL, strlen(FLOW_STATUS_MASK0 KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_STATUS_MASK0 KEY_VAL "%"SCNu32"", &(req->flow_removed_mask[0])) != 1) {
                ofp_fatal(0, "Error parsing %s: %s.", FLOW_STATUS_MASK0, token);
            }
            continue;
        }
        if (strncmp(token, FLOW_STATUS_MASK1 KEY_VAL, strlen(FLOW_STATUS_MASK1 KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_STATUS_MASK1 KEY_VAL "%"SCNu32"", &(req->flow_removed_mask[1])) != 1) {
                ofp_fatal(0, "Error parsing %s: %s.", FLOW_STATUS_MASK1, token);
            }
            continue;
        }
        ofp_fatal(0, "Error parsing set async arg: %s.", token);
    }

}

static void
parse_role_args(char *str, struct ofl_msg_role_request *req){
    char *token, *saveptr = NULL;
    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
         if (strncmp(token, ROLE_ROLE KEY_VAL, strlen(ROLE_ROLE KEY_VAL)) == 0) {
            if (sscanf(token, ROLE_ROLE KEY_VAL "%"SCNu32"", &(req->role)) != 1) {
                ofp_fatal(0, "Error parsing %s: %s.", ROLE_ROLE, token);
            }
            continue;
        }
        if (strncmp(token, ROLE_GENERATION_ID KEY_VAL, strlen(ROLE_GENERATION_ID KEY_VAL)) == 0) {
            if (sscanf(token, ROLE_GENERATION_ID KEY_VAL "0x%"SCNx64"", &(req->generation_id)) != 1) {
                ofp_fatal(0, "Error parsing role generation id: %s.", token);
            }
            continue;
        }
        ofp_fatal(0, "Error parsing role arg: %s.", token);
    }
}

static void
parse_packet_out_args(char *str, struct ofl_msg_packet_out *req)
{
    char *token, *saveptr = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        if (strncmp(token, PACKET_OUT_BUFFER KEY_VAL, strlen(PACKET_OUT_BUFFER KEY_VAL)) == 0) {
            if (parse32(token + strlen(PACKET_OUT_BUFFER KEY_VAL), buffer_names, NUM_ELEMS(buffer_names), UINT32_MAX,  &req->buffer_id)) {
                ofp_fatal(0, "Error parsing packet out buffer_id: %s.", token);
            }
            continue;
        }
        if (strncmp(token, PACKET_OUT_IN_PORT KEY_VAL, strlen(PACKET_OUT_IN_PORT KEY_VAL)) == 0) {
            if (parse_port(token + strlen(PACKET_OUT_IN_PORT KEY_VAL), &req->in_port)) {
                ofp_fatal(0, "Error parsing packet out in_port: %s.", token);
            }
            continue;
        }
        if (strncmp(token, PACKET_OUT_DATA_LEN KEY_VAL, strlen(PACKET_OUT_DATA_LEN KEY_VAL)) == 0) {
            if (sscanf(token, PACKET_OUT_DATA_LEN KEY_VAL "%"SCNu32"", &(req->data_length)) != 1) {
                ofp_fatal(0, "Error parsing %s: %s.", PACKET_OUT_DATA_LEN, token);
            }
            continue;
        }
        ofp_fatal(0, "Error parsing flow_mod arg: %s.", token);
    }

}

//wenbailin add
static void
parse_set_network_args(char *str, struct ofl_exp_openflow_network_conf *req)
{
    char *token, *saveptr = NULL;
    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr))
    {
         if (strncmp(token, IPV4 KEY_VAL, strlen(IPV4 KEY_VAL)) == 0) {
            unsigned int ipv4_src;
            unsigned int *mask;
            if (parse_nw_addr(token + strlen(IPV4 KEY_VAL), &(ipv4_src), &mask)) {
                ofp_fatal(0, "Error parsing ipv4: %s.", token);
            }
            else {
                if (mask == NULL)
                    req->ipv4 = ipv4_src;
                else {
                    req->mask = *mask;
                    free(mask);
                }

            }
            continue;
          }

          if (strncmp(token, GATE_WAY KEY_VAL, strlen(GATE_WAY KEY_VAL)) == 0) {
            unsigned int gate_way;
            unsigned int *mask;
            if (parse_nw_addr(token + strlen(GATE_WAY KEY_VAL), &(gate_way), &mask)) {
                ofp_fatal(0, "Error parsing gate way: %s.", token);
            }
            else {
                if (mask == NULL)
                    req->gw = gate_way;
                else {
                    req->mask = *mask;
                    free(mask);
                }

            }
            continue;
          }
          ofp_fatal(0, "Error parsing parse_set_network_args: %s.", token);
    }
}

static void
parse_port_conf_args(char *str, struct ofl_exp_openflow_mod_port_conf *req)
{
    char *token, *saveptr = NULL;
    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr))
    {
        if (strncmp(token, PORT_ID KEY_VAL, strlen(PORT_ID KEY_VAL)) == 0) {
            if (sscanf(token + strlen(PORT_ID KEY_VAL), "%"SCNu32"", &req->port_id) != 1) {
                ofp_fatal(0, "Error parsing PORT_ID: %s.", token);
            }
            continue;
        }

        if (strncmp(token, PORT_ATTR KEY_VAL, strlen(PORT_ATTR KEY_VAL)) == 0) {
            if (parse32(token + strlen(PORT_ATTR KEY_VAL), port_attr, NUM_ELEMS(port_attr),
                 UINT32_MAX,&req->attr)) {
                ofp_fatal(0, "Error parsing PORT_ATTR: %s.", token);
            }
            continue;
        }
        if (strncmp(token, PORT_BOOL KEY_VAL, strlen(PORT_BOOL KEY_VAL)) == 0) {
            if (parse8(token + strlen(PORT_BOOL KEY_VAL), port_is_bool,  NUM_ELEMS(port_is_bool), UINT8_MAX,  &req->is_bool)) {
                ofp_fatal(0, "Error parsing PORT_BOOL: %s.", token);
            }
            continue;
        }

        if (strncmp(token, PORT_VALUE KEY_VAL, strlen(PORT_VALUE KEY_VAL)) == 0) {
            if (sscanf(token + strlen(PORT_VALUE KEY_VAL), "%"SCNu32"", &(req->value)) != 1) {
                ofp_fatal(0, "Error parsing PORT_VALUE: %s.", token);
            }
            continue;
        }
        ofp_fatal(0, "Error parsing parse_port_conf_args: %s.", token);
    }
}


static void
parse_qos_group_args(char *str, struct ofl_exp_openflow_mod_qos_group *req) {
    char *token, *saveptr = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {

        if (strncmp(token, QOS_COMMAND KEY_VAL, strlen(QOS_COMMAND KEY_VAL)) == 0) {
            if (parse32(token + strlen(QOS_COMMAND KEY_VAL), qos_command_names, NUM_ELEMS(qos_command_names), \
                        UINT32_MAX,  &req->command)) {
                ofp_fatal(0, "Error parsing MOD_QOS_GROUP_ID: %s.", token);
            }
            continue;
        }

        if (strncmp(token, QOS_PORT_ID KEY_VAL, strlen(QOS_PORT_ID KEY_VAL)) == 0) {
            if (sscanf(token + strlen(QOS_PORT_ID KEY_VAL), "%"SCNu32"", &req->port_id) != 1) {
                ofp_fatal(0, "Error parsing QOS_PORT_IDf: %s.", token);
            }
            continue;
        }
        if (strncmp(token, QOS_GROU_ID KEY_VAL, strlen(QOS_GROU_ID KEY_VAL)) == 0) {
            if (sscanf(token + strlen(QOS_GROU_ID KEY_VAL), "%"SCNu32"", &req->qos_group_id) != 1) {
                ofp_fatal(0, "Error parsing QOS_GROU_ID: %s.", token);
            }
            continue;
        }
        if (strncmp(token, QOS_TYPE KEY_VAL, strlen(QOS_TYPE KEY_VAL)) == 0) {
            if (parse32(token + strlen(QOS_TYPE KEY_VAL), qos_type_names, NUM_ELEMS(qos_type_names), UINT32_MAX,  &req->type)) {
                ofp_fatal(0, "Error parsing QOS_TYPE: %s.", token);
            }
            continue;
        }
        if (strncmp(token, QOS_VALUE KEY_VAL, strlen(QOS_VALUE KEY_VAL)) == 0) {
            if (sscanf(token + strlen(QOS_VALUE KEY_VAL), "%"SCNu64"", &(req->value)) != 1) {
                ofp_fatal(0, "Error parsing QOS_VALUE: %s.", token);
            }
            continue;
        }
        ofp_fatal(0, "Error parsing qos_group_args: %s.", token);
    }
}


static void
parse_map_queue_args(char *str, struct ofl_exp_openflow_map_queue*req) {
    char *token, *saveptr = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        if (strncmp(token, MAP_COMMAND KEY_VAL, strlen(MAP_COMMAND KEY_VAL)) == 0) {
            if (parse32(token + strlen(MAP_COMMAND KEY_VAL), qos_command_names, NUM_ELEMS(qos_command_names), \
                        UINT32_MAX,  &req->command)) {
                ofp_fatal(0, "Error parsing MAP_QOS_GROUP_ID: %s.", token);
            }

            if(qos_command_apply ==req->command)
            {
                req->port_id = 0;
                req->qos_group_id = 0;
                req->type = 0;

                break;
            }
            continue;
        }
        if (strncmp(token, MAP_PORT_ID KEY_VAL, strlen(MAP_PORT_ID KEY_VAL)) == 0) {
            if (sscanf(token + strlen(MAP_PORT_ID KEY_VAL), "%"SCNu32"", &req->port_id) != 1) {
                ofp_fatal(0, "Error parsing MAP_PORT_ID: %s.", token);
            }
            continue;
        }
        if (strncmp(token, MAP_TYPE KEY_VAL, strlen(MAP_TYPE KEY_VAL)) == 0) {
            if (parse32(token + strlen(MAP_TYPE KEY_VAL), qos_type_names, NUM_ELEMS(qos_type_names), \
                        UINT32_MAX,  &req->type)) {
                ofp_fatal(0, "Error parsing MAP_TYPE: %s.", token);
            }
            continue;
        }
        if (strncmp(token, MAP_QOS_GROUP_ID KEY_VAL, strlen(MAP_QOS_GROUP_ID KEY_VAL)) == 0) {
            if (sscanf(token + strlen(MAP_QOS_GROUP_ID KEY_VAL), "%"SCNu32"", &req->qos_group_id) != 1) {
                ofp_fatal(0, "Error parsing MAP_QOS_GROUP_ID: %s.", token);
            }
            continue;
        }
        if (strncmp(token, MAP_QUEUE_ARRAY KEY_VAL, strlen(MAP_QUEUE_ARRAY KEY_VAL)) == 0) {

            //parse "/"
            char *token_in, *saveptr_in = NULL;
            int i = 0;

            token_in = strtok_r(token, KEY_VAL, &saveptr_in);

            for (token_in = strtok_r(saveptr_in, MASK_SEP, &saveptr_in); token_in != NULL; token_in = strtok_r(NULL, MASK_SEP, &saveptr_in))
            {
                if (sscanf(token_in, "%"SCNu32"",&(req->queue_array[i])) != 1){
                ofp_fatal(0, "Error parsing MAP_QUEUE_ARRAY: %s.", token);
                }
                else{
                    i++;
                }
            }
            continue;
        }
        ofp_fatal(0, "Error parsing qos_group_args: %s.", token);
    }
}

static void
parse_flow_mod_args(char *str, struct ofl_msg_flow_mod *req) {
    char *token, *saveptr = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        if (strncmp(token, FLOW_MOD_COMMAND KEY_VAL, strlen(FLOW_MOD_COMMAND KEY_VAL)) == 0) {
            unsigned char command;
            if (parse8(token + strlen(FLOW_MOD_COMMAND KEY_VAL), flow_mod_cmd_names, NUM_ELEMS(flow_mod_cmd_names),0,  &command)) {
                ofp_fatal(0, "Error parsing flow_mod command: %s.", token);
            }
            req->command = command;
            continue;
        }
        if (strncmp(token, FLOW_MOD_COOKIE KEY_VAL, strlen(FLOW_MOD_COOKIE KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_COOKIE KEY_VAL "0x%"SCNx64"", &(req->cookie)) != 1) {
                ofp_fatal(0, "Error parsing flow_mod cookie: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_COOKIE_MASK KEY_VAL, strlen(FLOW_MOD_COOKIE_MASK KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_COOKIE_MASK KEY_VAL "0x%"SCNx64"", &(req->cookie_mask)) != 1) {
                ofp_fatal(0, "Error parsing flow_mod cookie mask: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_TABLE_ID KEY_VAL, strlen(FLOW_MOD_TABLE_ID KEY_VAL)) == 0) {
            if (parse8(token + strlen(FLOW_MOD_TABLE_ID KEY_VAL), table_names, NUM_ELEMS(table_names), 254,  &req->table_id)) {
                ofp_fatal(0, "Error parsing flow_mod table: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_IDLE KEY_VAL, strlen(FLOW_MOD_IDLE KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_IDLE KEY_VAL "%"SCNu16"", &(req->idle_timeout)) != 1) {
                ofp_fatal(0, "Error parsing %s: %s.", FLOW_MOD_IDLE, token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_HARD KEY_VAL, strlen(FLOW_MOD_HARD KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_HARD KEY_VAL "%"SCNu16"", &(req->hard_timeout)) != 1) {
                ofp_fatal(0, "Error parsing %s: %s.", FLOW_MOD_HARD, token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_PRIO KEY_VAL, strlen(FLOW_MOD_PRIO KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_PRIO KEY_VAL "%"SCNu16"", &(req->priority)) != 1) {
                ofp_fatal(0, "Error parsing %s: %s.", FLOW_MOD_PRIO, token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_BUFFER KEY_VAL, strlen(FLOW_MOD_BUFFER KEY_VAL)) == 0) {
            if (parse32(token + strlen(FLOW_MOD_BUFFER KEY_VAL), buffer_names, NUM_ELEMS(buffer_names), UINT32_MAX,  &req->buffer_id)) {
                ofp_fatal(0, "Error parsing flow_mod buffer: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_OUT_PORT KEY_VAL, strlen(FLOW_MOD_OUT_PORT KEY_VAL)) == 0) {
            if (parse_port(token + strlen(FLOW_MOD_OUT_PORT KEY_VAL), &req->out_port)) {
                ofp_fatal(0, "Error parsing flow_mod port: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_OUT_GROUP KEY_VAL, strlen(FLOW_MOD_OUT_GROUP KEY_VAL)) == 0) {
            if (parse_group(token + strlen(FLOW_MOD_OUT_GROUP KEY_VAL), &req->out_port)) {
                ofp_fatal(0, "Error parsing flow_mod group: %s.", token);
            }
            continue;
        }
        if (strncmp(token, FLOW_MOD_FLAGS KEY_VAL, strlen(FLOW_MOD_FLAGS KEY_VAL)) == 0) {
            if (sscanf(token, FLOW_MOD_FLAGS KEY_VAL "0x%"SCNx16"", &(req->flags)) != 1) {
                ofp_fatal(0, "Error parsing %s: %s.", FLOW_MOD_FLAGS, token);
            }
            continue;
        }
        ofp_fatal(0, "Error parsing flow_mod arg: %s.", token);
    }
}

static void
parse_group_mod_args(char *str, struct ofl_msg_group_mod *req) {
    char *token, *saveptr = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        if (strncmp(token, GROUP_MOD_COMMAND KEY_VAL, strlen(GROUP_MOD_COMMAND KEY_VAL)) == 0) {
            unsigned short int command;
            if (parse16(token + strlen(GROUP_MOD_COMMAND KEY_VAL), group_mod_cmd_names, NUM_ELEMS(group_mod_cmd_names),0,  &command)) {
                ofp_fatal(0, "Error parsing group_mod command: %s.", token);
            }
            req->command = command;
            continue;
        }
        if (strncmp(token, GROUP_MOD_GROUP KEY_VAL, strlen(GROUP_MOD_GROUP KEY_VAL)) == 0) {
            if (parse_group(token + strlen(GROUP_MOD_GROUP KEY_VAL), &req->group_id)) {
                ofp_fatal(0, "Error parsing group_mod group: %s.", token);
            }
            continue;
        }
        if (strncmp(token, GROUP_MOD_TYPE KEY_VAL, strlen(GROUP_MOD_TYPE KEY_VAL)) == 0) {
            unsigned char type;
            if (parse8(token + strlen(GROUP_MOD_TYPE KEY_VAL), group_type_names, NUM_ELEMS(group_type_names), UINT8_MAX,  &type)) {
                ofp_fatal(0, "Error parsing group_mod type: %s.", token);
            }
            req->type = type;
            continue;
        }
        ofp_fatal(0, "Error parsing group_mod arg: %s.", token);
    }
}

static void
parse_bucket(char *str, struct ofl_bucket *b) {
    char *token, *saveptr = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        if (strncmp(token, BUCKET_WEIGHT KEY_VAL, strlen(BUCKET_WEIGHT KEY_VAL)) == 0) {
            if (parse16(token + strlen(BUCKET_WEIGHT KEY_VAL), NULL, 0, UINT16_MAX, &b->weight)) {
                ofp_fatal(0, "Error parsing bucket_weight: %s.", token);
            }
            continue;
        }
        if (strncmp(token, BUCKET_WATCH_PORT KEY_VAL, strlen(BUCKET_WATCH_PORT KEY_VAL)) == 0) {
            if (parse_port(token + strlen(BUCKET_WATCH_PORT KEY_VAL), &b->watch_port)) {
                ofp_fatal(0, "Error parsing bucket watch port: %s.", token);
            }
            continue;
        }
        if (strncmp(token, BUCKET_WATCH_GROUP KEY_VAL, strlen(BUCKET_WATCH_GROUP KEY_VAL)) == 0) {
            if (parse_group(token + strlen(BUCKET_WATCH_GROUP KEY_VAL), &b->watch_group)) {
                ofp_fatal(0, "Error parsing bucket watch group: %s.", token);
            }
            continue;
        }
        ofp_fatal(0, "Error parsing bucket arg: %s.", token);
    }
}

static void
parse_meter_mod_args(char *str, struct ofl_msg_meter_mod *req){
    char *token, *saveptr = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        if (strncmp(token, METER_MOD_COMMAND KEY_VAL, strlen(METER_MOD_COMMAND KEY_VAL)) == 0) {
            unsigned short int command;
            if (parse16(token + strlen(GROUP_MOD_COMMAND KEY_VAL), meter_mod_cmd_names, NUM_ELEMS(meter_mod_cmd_names),0,  &command)) {
                ofp_fatal(0, "Error parsing meter_mod command: %s.", token);
            }
            req->command = command;
            continue;
        }
        if (strncmp(token, METER_MOD_FLAGS KEY_VAL, strlen(METER_MOD_FLAGS KEY_VAL)) == 0) {
            if (parse16(token + strlen(METER_MOD_FLAGS KEY_VAL), NULL, 0, 0xffff,  &req->flags)) {
                ofp_fatal(0, "Error parsing meter_mod flags: %s.", token);
            }
            continue;
        }
        if (strncmp(token, METER_MOD_METER KEY_VAL, strlen(METER_MOD_METER KEY_VAL)) == 0) {
            unsigned int meter_id;
            if (parse32(token + strlen(METER_MOD_METER KEY_VAL), NULL, 0, 1024,  &meter_id)) {
                ofp_fatal(0, "Error parsing meter_mod id: %s.", token);
            }
            req->meter_id = meter_id;
            continue;
        }
        ofp_fatal(0, "Error parsing group_mod arg: %s.", token);
    }

}

static void
parse_band_args(char *str, struct ofl_msg_meter_mod *m, struct ofl_meter_band_header *b){
    char *token, *saveptr = NULL;
    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        if (strncmp(token, BAND_RATE KEY_VAL, strlen(BAND_RATE KEY_VAL)) == 0) {
            if (parse32(token + strlen(BAND_RATE KEY_VAL), NULL, 0, UINT32_MAX, &b->rate)) {
                ofp_fatal(0, "Error parsing band rate: %s.", token);
            }
            continue;
        }
        if (strncmp(token, BAND_BURST_SIZE KEY_VAL, strlen(BAND_BURST_SIZE KEY_VAL)) == 0) {
            if(m->flags & OFPMF_BURST){
                if (parse32(token + strlen(BAND_BURST_SIZE KEY_VAL), NULL, 0, UINT32_MAX, &b->burst_size)) {
                    ofp_fatal(0, "Error parsing band rate: %s.", token);
                }
                continue;
            }
            else ofp_fatal(0, "Error parsing burst size. Meter flags should contain %x.", OFPMF_BURST);
        }
        if (strncmp(token, BAND_PREC_LEVEL KEY_VAL, strlen(BAND_PREC_LEVEL KEY_VAL)) == 0) {
            if (parse8(token + strlen(BAND_PREC_LEVEL KEY_VAL), NULL, 0, UINT8_MAX, \
                &((struct ofl_meter_band_dscp_remark*)b)->prec_level)) {
                   ofp_fatal(0, "Error parsing prec_level: %s.", token);
                }
                continue;
        }
    }
}

static void
parse_band(char *str, struct ofl_msg_meter_mod *m, struct ofl_meter_band_header **b){
    char *s;
    size_t i;
    for (i=0; i<NUM_ELEMS(band_names); i++) {

        if (strncmp(str, band_names[i].name, strlen(band_names[i].name)) == 0) {
            s = str + strlen(band_names[i].name);

            if (strncmp(s, KEY_VAL2, strlen(KEY_VAL2)) != 0) {
                ofp_fatal(0, "Error parsing meter band: %s.", str);
            }

            s+= strlen(KEY_VAL2);
            switch(band_names[i].code){
                case(OFPMBT_DROP):{
                    struct ofl_meter_band_drop *d = (struct ofl_meter_band_drop*) xmalloc(sizeof(struct ofl_meter_band_drop));
                    d->type = OFPMBT_DROP;
                    d->rate = 0;
                    d->burst_size = 0;
                    parse_band_args(s, m, (struct ofl_meter_band_header*)d);
                    *b = (struct ofl_meter_band_header*) d;
                    break;
                }
                case(OFPMBT_DSCP_REMARK):{
                    struct ofl_meter_band_dscp_remark *d = (struct ofl_meter_band_dscp_remark*) xmalloc(sizeof(struct ofl_meter_band_dscp_remark));
                    d->type = OFPMBT_DSCP_REMARK;
                    d->rate = 0;
                    d->burst_size = 0;
                    d->prec_level = 0;
                    parse_band_args(s, m, (struct ofl_meter_band_header*)d);
                    *b = (struct ofl_meter_band_header*) d;
                    break;
                }
            }
         }
    }
}


static void
parse_config(char *str, struct ofl_config *c) {
    char *token, *saveptr = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        if (strncmp(token, CONFIG_FLAGS KEY_VAL, strlen(CONFIG_FLAGS KEY_VAL)) == 0) {
            if (sscanf(token + strlen(CONFIG_FLAGS KEY_VAL), "0x%"SCNx16"", &c->flags) != 1) {
                ofp_fatal(0, "Error parsing config flags: %s.", token);
            }
            continue;
        }
        if (strncmp(token, CONFIG_MISS KEY_VAL, strlen(CONFIG_MISS KEY_VAL)) == 0) {
            if (parse16(token + strlen(CONFIG_MISS KEY_VAL), NULL, 0, UINT16_MAX - sizeof(struct ofp_packet_in), &c->miss_send_len)) {
                ofp_fatal(0, "Error parsing config miss send len: %s.", token);
            }
            continue;
        }
        ofp_fatal(0, "Error parsing config arg: %s.", token);
    }
}

static void
parse_port_mod(char *str, struct ofl_msg_port_mod *msg) {
    char *token, *saveptr = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        if (strncmp(token, PORT_MOD_PORT KEY_VAL, strlen(PORT_MOD_PORT KEY_VAL)) == 0) {
            if (parse_port(token + strlen(PORT_MOD_PORT KEY_VAL), &msg->port_no)) {
                ofp_fatal(0, "Error parsing port_mod port: %s.", token);
            }
            continue;
        }
        if (strncmp(token, PORT_MOD_HW_ADDR KEY_VAL, strlen(PORT_MOD_HW_ADDR KEY_VAL)) == 0) {
            unsigned char *mask = NULL;
            if (parse_dl_addr(token + strlen(PORT_MOD_HW_ADDR KEY_VAL), msg->hw_addr, &mask)) {
                ofp_fatal(0, "Error parsing port_mod hw_addr: %s.", token);
            }
            continue;
        }
        if (strncmp(token, PORT_MOD_HW_CONFIG KEY_VAL, strlen(PORT_MOD_HW_CONFIG KEY_VAL)) == 0) {
            if (sscanf(token + strlen(PORT_MOD_HW_CONFIG KEY_VAL), "0x%"SCNx32"", &msg->config) != 1) {
                ofp_fatal(0, "Error parsing port_mod conf: %s.", token);
            }
            continue;
        }
        if (strncmp(token, PORT_MOD_MASK KEY_VAL, strlen(PORT_MOD_MASK KEY_VAL)) == 0) {
            if (sscanf(token + strlen(PORT_MOD_MASK KEY_VAL), "0x%"SCNx32"", &msg->mask) != 1) {
                ofp_fatal(0, "Error parsing port_mod mask: %s.", token);
            }
            continue;
        }
        if (strncmp(token, PORT_MOD_ADVERTISE KEY_VAL, strlen(PORT_MOD_ADVERTISE KEY_VAL)) == 0) {
            if (sscanf(token + strlen(PORT_MOD_ADVERTISE KEY_VAL), "0x%"SCNx32"", &msg->advertise) != 1) {
                ofp_fatal(0, "Error parsing port_mod advertise: %s.", token);
            }
            continue;
        }
        ofp_fatal(0, "Error parsing port_mod arg: %s.", token);
    }
}


static void
parse_table_mod(char *str, struct ofl_msg_table_mod *msg) {
    char *token, *saveptr = NULL;

    for (token = strtok_r(str, KEY_SEP, &saveptr); token != NULL; token = strtok_r(NULL, KEY_SEP, &saveptr)) {
        if (strncmp(token, TABLE_MOD_TABLE KEY_VAL, strlen(TABLE_MOD_TABLE KEY_VAL)) == 0) {
            if (parse_table(token + strlen(TABLE_MOD_TABLE KEY_VAL), &msg->table_id)) {
                ofp_fatal(0, "Error parsing table_mod table: %s.", token);
            }
            continue;
        }
        if (strncmp(token, TABLE_MOD_CONFIG KEY_VAL, strlen(TABLE_MOD_CONFIG KEY_VAL)) == 0) {
            if (sscanf(token + strlen(TABLE_MOD_CONFIG KEY_VAL), "0x%"SCNx32"", &msg->config) != 1) {
                ofp_fatal(0, "Error parsing table_mod conf: %s.", token);
            }
            continue;
        }
        ofp_fatal(0, "Error parsing table_mod arg: %s.", token);
    }
}


static int
parse_port(char *str, unsigned int *port) {
    return parse32(str, port_names, NUM_ELEMS(port_names), OFPP_MAX, port);
}

static int
parse_hw_config(char *str, unsigned int *conf)
{
    return parse32(str + strlen(HW_CONFIG KEY_VAL), NULL, 0, OFPP_MAX, conf);
}

static int
parse_queue(char *str, unsigned int *port) {
    return parse32(str, queue_names, NUM_ELEMS(queue_names), 0xfffffffe, port);
}

static int
parse_group(char *str, unsigned int *group) {
    return parse32(str, group_names, NUM_ELEMS(group_names), OFPG_MAX, group);
}

static int
parse_meter(char *str, unsigned int *meter) {
    return parse32(str, NULL, 0, OFPM_MAX, meter);
}

static int
parse_table(char *str, unsigned char *table) {
    return parse8(str, table_names, NUM_ELEMS(table_names), 0xfe, table);
}

static int
parse_dl_addr(char *str, unsigned char *addr, unsigned char **mask) {
    char *saveptr = NULL;
    if (sscanf(str, "%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8,
            addr, addr+1, addr+2, addr+3, addr+4, addr+5) != 6){
        return -1;
    }
    strtok_r(str, MASK_SEP, &saveptr);

    if(strcmp(saveptr,"") == 0){
        *mask = NULL;
        return 0;
    }
    else {
        *mask = (unsigned char*) malloc (sizeof(OFP_ETH_ALEN));
        if (sscanf(saveptr, "%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8,
            *mask, *mask+1, *mask+2, *mask+3, *mask+4, *mask+5) != 6){
            return -1;
         }
    }
    return 0;
}

static int
parse_nw_addr(char *str, unsigned int *addr, unsigned int **mask) {
    // TODO Zoltan: DNS lookup ?
    unsigned char a[4],b[4];
    unsigned int netmask;
    char *saveptr = NULL;

    if (sscanf(str, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8,
               &a[0], &a[1], &a[2], &a[3]) == 4) {
        if (htonl(1) == 1)
            *addr = (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
        else
            *addr = (a[3] << 24) | (a[2] << 16) | (a[1] << 8) | a[0];
    }
    else {
        return -1;
    }
    strtok_r(str, MASK_SEP, &saveptr);
    if(strcmp(saveptr,"") == 0){
        *mask = NULL;
        return 0;
    }
    *mask = (unsigned int*) malloc(sizeof(unsigned int));
    netmask = 0xffffffff;
    if(strlen(saveptr) <= 2){
        /* Subnet mask*/
        unsigned char subnet_mask;
        sscanf(saveptr, "%"SCNu8"",
               &subnet_mask);
        if (subnet_mask > 32)
            return -1;
        if (subnet_mask == 0)
            netmask = 0x00000000;
        else netmask = netmask << (32 - subnet_mask);
        **mask = htonl(netmask);
    }
    else {
        /*Arbitrary mask*/
        if (sscanf(saveptr, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8,
               &b[0], &b[1], &b[2], &b[3]) == 4) {
            if (htonl(1) == 1)
                **mask = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
            else
                **mask = (b[3] << 24) | (b[2] << 16) | (b[1] << 8) | b[0];
        }
        else {
            return -1;
        }
    }

    return 0;
}

static int
parse_vlan_vid(char *str, unsigned short int *vid) {
    return parse16(str, vlan_vid_names, NUM_ELEMS(vlan_vid_names), 0x1001, vid);
}

static int
parse_ext_hdr(char *str, unsigned short int *ext_hdr){
    char *token, *saveptr = NULL;
    size_t i;
    memset(ext_hdr, 0x0, sizeof(unsigned short int));
    for (token = strtok_r(str, ADD, &saveptr); token != NULL; token = strtok_r(NULL, ADD, &saveptr)) {
        for (i=0; i < 9; i++) {
            if (strcmp(token, ext_header_names[i].name) == 0) {
                *ext_hdr = *ext_hdr ^ ext_header_names[i].code;
                break;
            }
        }
        if(i == 9)
            return -1;
    }
    return 0;
}

static int
parse8(char *str, struct names8 *names, size_t names_num, unsigned char max, unsigned char *val) {
    size_t i;

    for (i=0; i<names_num; i++) {
        if (strcmp(str, names[i].name) == 0) {
            *val = names[i].code;
            return 0;
        }
    }

    if ((max > 0) && (sscanf(str, "%"SCNu8"", val)) == 1 && ((*val) <= max)) {
        return 0;
    }
    return -1;
}

static int
parse16(char *str, struct names16 *names, size_t names_num, unsigned short int max, unsigned short int *val) {
    size_t i;

    for (i=0; i<names_num; i++) {
        if (strcmp(str, names[i].name) == 0) {
            *val = names[i].code;
            return 0;
        }
    }

    /* Checks if the passed value is hexadecimal. */
    if( str[1] == 'x'){
        if ((max > 0) && (sscanf(str, "%"SCNx16"", val))  == 1 && (*val <= max)) {
            return 0;
        }
    }
    else {
         if ((max > 0) && (sscanf(str, "%"SCNu16"", val))  == 1 && (*val <= max)) {
            return 0;
         }
    }
    return -1;
}


static int
parse32(char *str, struct names32 *names, size_t names_num, unsigned int max, unsigned int *val) {
    size_t i;

    for (i=0; i<names_num; i++) {
        if (strcmp(str, names[i].name) == 0) {
            *val = names[i].code;
            return 0;
        }
    }

    if ((max > 0) && (sscanf(str, "%"SCNu32"", val)) == 1 && ((*val) <= max)) {
        return 0;
    }
    return -1;
}

