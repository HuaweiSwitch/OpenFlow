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

#ifndef OFL_EXP_OPENFLOW_H
#define OFL_EXP_OPENFLOW_H 1


#include "../oflib/ofl-structs.h"
#include "../oflib/ofl-messages.h"


struct ofl_exp_openflow_msg_header {
    struct ofl_msg_experimenter   header; /* OPENFLOW_VENDOR_ID */

    unsigned int   type;
};

struct ofl_exp_openflow_msg_queue {
    struct ofl_exp_openflow_msg_header   header; /* OFP_EXT_QUEUE_MODIFY|DELETE */

    unsigned int                  port_id;
    struct ofl_packet_queue  *queue;
};


struct ofl_exp_openflow_msg_set_dp_desc {
    struct ofl_exp_openflow_msg_header   header; /* OFP_EXT_SET_DESC */

    char  *dp_desc;
};

struct ofl_exp_openflow_msg_show_perf {
    struct ofl_exp_openflow_msg_header   header; /* OFP_EXT_SET_DESC */

    unsigned int command;
};




struct ofl_exp_openflow_msg_hw_config {
    struct ofl_exp_openflow_msg_header   header; /* OFP_EXT_SET_DESC */

    unsigned int config;
};

struct ofl_exp_openflow_mod_port_conf{
    struct ofl_exp_openflow_msg_header   header;

    unsigned int port_id;
    unsigned int attr;
    unsigned char  is_bool;
    unsigned int value;
};

struct ofl_exp_openflow_network_conf{
    struct ofl_exp_openflow_msg_header   header;

    unsigned int ipv4;
    unsigned int mask;
    unsigned int gw;
};

struct ofl_exp_openflow_mod_qos_group{
    struct ofl_exp_openflow_msg_header   header; /* OFP_EXT_ADD/DELET SHAPING GROUP */

    unsigned int command; 
    unsigned int port_id;
    unsigned int qos_group_id;
    unsigned int type;    
    unsigned long long int value;
};

struct ofl_exp_openflow_map_queue{
    struct ofl_exp_openflow_msg_header   header; /* queue bind to shaping group */

    unsigned int command;  //
    unsigned int port_id;
    unsigned int qos_group_id;
    unsigned int type;
    unsigned int queue_array[16];
};


int
ofl_exp_openflow_msg_pack(struct ofl_msg_experimenter *msg, unsigned char **buf, size_t *buf_len);

ofl_err
ofl_exp_openflow_msg_unpack(struct ofp_header *oh, size_t *len, struct ofl_msg_experimenter **msg);

int
ofl_exp_openflow_msg_free(struct ofl_msg_experimenter *msg);

char *
ofl_exp_openflow_msg_to_string(struct ofl_msg_experimenter *msg);


#endif /* OFL_EXP_OPENFLOW_H */
