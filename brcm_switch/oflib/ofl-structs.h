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
 *
 */

#ifndef OFL_STRUCTS_H
#define OFL_STRUCTS_H 1

#include <sys/types.h>
#include <stdio.h>
#include <pthread.h>

#include <netinet/icmp6.h>
#include "../include/openflow/openflow.h"
#include "ofl.h"
#include "ofl-actions.h"
#include "ofl-packets.h"
#include "../lib/hmap.h"
#include "../lib/byte-order.h"
#include "ofl-messages.h"


struct ofl_exp;

/****************************************************************************
 * Supplementary structure definitions.
 ****************************************************************************/

struct ofl_packet_queue {
    unsigned int   queue_id; /* id for the specific queue. */
    size_t                         properties_num;
    struct ofl_queue_prop_header **properties;
};


struct ofl_queue_prop_header {
    enum ofp_queue_properties   type; /* One of OFPQT_. */
};

struct ofl_queue_prop_min_rate {
    struct ofl_queue_prop_header   header; /* OFPQT_MIN_RATE */

    unsigned short int   rate; /* In 1/10 of a percent; >1000 -> disabled. */
};

struct ofl_queue_prop_max_rate {
    struct ofl_queue_prop_header   header; /* OFPQT_MAX_RATE */

    unsigned short int   rate; /* In 1/10 of a percent; >1000 -> disabled. */
};

struct ofl_queue_prop_experimenter {
    struct ofl_queue_prop_header prop_header; /* prop: OFPQT_EXPERIMENTER, len: 16. */
    unsigned int experimenter;
    unsigned char *data; /* Experimenter defined data. */
};


struct ofl_instruction_header {
    enum ofp_instruction_type   type; /* Instruction type */
};

struct ofl_instruction_goto_table {
    struct ofl_instruction_header   header; /* OFPIT_GOTO_TABLE */

    unsigned char   table_id; /* Set next table in the lookup pipeline */
};



struct ofl_instruction_write_metadata {
    struct ofl_instruction_header   header; /* OFPIT_WRITE_METADATA */

    unsigned long long int   metadata;      /* Metadata value to write */
    unsigned long long int   metadata_mask; /* Metadata write bitmask */
};


struct ofl_instruction_actions {
    struct ofl_instruction_header   header; /* OFPIT_WRITE|APPLY_ACTIONS */

    size_t                     actions_num;
    struct ofl_action_header **actions;
};

struct ofl_instruction_meter {
    struct ofl_instruction_header   header; /* OFPIT_METER */
    unsigned int meter_id;

};

/* Instruction structure for experimental instructions */
struct ofl_instruction_experimenter {
    struct ofl_instruction_header   header; /* OFPIT_EXPERIMENTER */

    unsigned int   experimenter_id; /* Experimenter ID */
};

struct ofl_config {
    unsigned short int   flags;         /* OFPC_* flags. */
    unsigned short int   miss_send_len; /* Max bytes of new flow that datapath should
                                send to the controller. */
};

struct ofl_async_config {
    unsigned int packet_in_mask[2]; /* Bitmasks of OFPR_* values. */
    unsigned int port_status_mask[2]; /* Bitmasks of OFPPR_* values. */
    unsigned int flow_removed_mask[2];/* Bitmasks of OFPRR_* values. */
};

struct ofl_bucket {
    unsigned short int   weight;      /* Relative weight of bucket. Only
                              defined for select groups. */
    unsigned int   watch_port;  /* Port whose state affects whether this
                              bucket is live. Only required for fast
                              failover groups. */
    unsigned int   watch_group; /* Group whose state affects whether this
                              bucket is live. Only required for fast
                              failover groups. */
    size_t                     actions_num;
    struct ofl_action_header **actions;
};

struct ofl_flow_stats {
    unsigned char                         table_id;      /* ID of table flow came from. */
    unsigned int                        duration_sec;  /* Time flow has been alive in secs. */
    unsigned int                        duration_nsec; /* Time flow has been alive in nsecs
                                                     beyond duration_sec. */
    unsigned short int                        priority;      /* Priority of the entry. Only meaningful
                                                     when this is not an exact-match entry. */
    unsigned short int                        idle_timeout;  /* Number of seconds idle before
                                                     expiration. */
    unsigned short int                        hard_timeout;  /* Number of seconds before expiration. */
    unsigned short int                        flags; /* One of OFPFF_*. */
    unsigned long long int                        cookie;        /* Opaque controller-issued identifier. */
    unsigned long long int                        packet_count;  /* Number of packets in flow. */
    unsigned long long int                        byte_count;    /* Number of bytes in flow. */
    unsigned long long int                        ofp_packet_count;
    unsigned long long int                        ofp_byte_count;
    struct ofl_match_header        *match;         /* Description of fields. */
    size_t                          instructions_num;
    struct ofl_instruction_header **instructions; /* Instruction set. */
};



struct ofl_table_stats {
    unsigned char    table_id;      /* Identifier of table. Lower numbered tables
                                are consulted first. */
    unsigned char    pad[3];
    unsigned int   active_count;  /* Number of active entries. */
    unsigned long long int   lookup_count;  /* Number of packets looked up in table. */
    unsigned long long int   matched_count; /* Number of packets that hit table. */
};

struct ofl_table_feature_prop_header {
    unsigned short int type;                /* Table feature type */
    unsigned short int length;              /* Property length */
};
// Is this needed ? Jean II
OFP_ASSERT(sizeof(struct ofl_table_feature_prop_header) == 4);

/* Instructions property */
struct ofl_table_feature_prop_instructions {
    struct ofl_table_feature_prop_header header;
    size_t ids_num;
    struct ofl_instruction_header *instruction_ids; /* List of instructions */
};

struct ofl_table_feature_prop_next_tables {
    struct ofl_table_feature_prop_header header;
    size_t table_num;
    unsigned char *next_table_ids;
};

/* Actions property */
struct ofl_table_feature_prop_actions {
    struct ofl_table_feature_prop_header header;
    size_t actions_num;
    struct ofl_action_header *action_ids; /*Actions list*/
};

struct ofl_table_feature_prop_oxm {
    struct ofl_table_feature_prop_header header;
    size_t oxm_num;
    unsigned int *oxm_ids; /* Array of OXM headers */
};


/* Body for ofp_multipart_request of type OFPMP_TABLE_FEATURES./
* Body of reply to OFPMP_TABLE_FEATURES request. */
struct ofl_table_features {
    unsigned short int length;  /* Length is padded to 64 bits. */
    unsigned char table_id; /* Identifier of table. Lower numbered tables
                         are consulted first. */
    unsigned char pad[5];   /* Align to 64-bits. */
    char *name;
    unsigned long long int metadata_match; /* Bits of metadata table can match. */
    unsigned long long int metadata_write; /* Bits of metadata table can write. */
    unsigned int config;         /* Bitmap of OFPTC_* values */
    unsigned int max_entries;    /* Max number of entries supported. */
    size_t properties_num;  /* Number of properties*/
    /* Table Feature Property list */
    struct ofl_table_feature_prop_header **properties;
};

struct ofl_match_header {
    unsigned short int   type;             /* One of OFPMT_* */
    unsigned short int   length;           /* Match length */
};

struct ofl_match {
    struct ofl_match_header   header; /* Match header */
    struct hmap match_fields;         /* Match fields. Contain OXM TLV's  */
};

struct ofl_match_tlv{

    struct hmap_node hmap_node;
    unsigned int header;    /* TLV header */
    unsigned char *value;     /* TLV value */
};


/* Common header for all meter bands */
struct ofl_meter_band_header {
    unsigned short int type;                   /* One of OFPMBT_*. */
    unsigned int rate;                   /* Rate for this band. */
    unsigned int burst_size;             /* Size of bursts. */
};


/* OFPMBT_DROP band - drop packets */
struct ofl_meter_band_drop {
    unsigned short int type;                  /* OFPMBT_DROP. */
    unsigned int rate;                  /* Rate for dropping packets. */
    unsigned int burst_size;            /* Size of bursts. */
};

/* OFPMBT_DSCP_REMARK band - Remark DSCP in the IP header */
struct ofl_meter_band_dscp_remark {
    unsigned short int type;                      /* OFPMBT_DSCP_REMARK. */
    unsigned int rate;                      /* Rate for remarking packets. */
    unsigned int burst_size;                 /* Size of bursts. */
    unsigned char prec_level;                  /* Number of precendence level to substract. */
};

/* OFPMBT_EXPERIMENTER band - Write actions in action set */
struct ofl_meter_band_experimenter {
    unsigned short int type;                              /* One of OFPMBT_*. */
    unsigned int rate;                              /* Rate for this band. */
    unsigned int burst_size;                         /* Size of bursts. */
    unsigned int experimenter;                          /* Experimenter ID which takes the same
                                                     form as in struct
                                                   ofp_experimenter_header. */
};

struct ofl_port_stats {
    unsigned int   port_no;
    unsigned long long int   rx_packets;   /* Number of received packets. */
    unsigned long long int   tx_packets;   /* Number of transmitted packets. */
    unsigned long long int   rx_bytes;     /* Number of received bytes. */
    unsigned long long int   tx_bytes;     /* Number of transmitted bytes. */
    unsigned long long int   rx_dropped;   /* Number of packets dropped by RX. */
    unsigned long long int   tx_dropped;   /* Number of packets dropped by TX. */
    unsigned long long int   rx_errors;    /* Number of receive errors. This is a super-set
                               of more specific receive errors and should be
                               greater than or equal to the sum of all
                               rx_*_err values. */
    unsigned long long int   tx_errors;    /* Number of transmit errors. This is a super-set
                               of more specific transmit errors and should be
                               greater than or equal to the sum of all
                               tx_*_err values (none currently defined.) */
    unsigned long long int   rx_frame_err; /* Number of frame alignment errors. */
    unsigned long long int   rx_over_err;  /* Number of packets with RX overrun. */
    unsigned long long int   rx_crc_err;   /* Number of CRC errors. */
    unsigned long long int   collisions;   /* Number of collisions. */
    unsigned int   duration_sec; /* Time port has been alive in seconds */
    unsigned int   duration_nsec; /* Time port has been alive in nanoseconds
                                 beyond duration_sec */
};

struct ofl_bucket_counter {
    unsigned long long int   packet_count; /* Number of packets processed by bucket. */
    unsigned long long int   byte_count;   /* Number of bytes processed by bucket. */
};

struct ofl_group_stats {
    unsigned int   group_id;
    unsigned int   ref_count;
    unsigned long long int   packet_count;
    unsigned long long int   byte_count;
    size_t                      counters_num;
    unsigned int   duration_sec; /* Time group has been alive in seconds */
    unsigned int   duration_nsec; /* Time group has been alive in nanoseconds
                                 beyond duration_sec */
    struct ofl_bucket_counter **counters;
};


struct ofl_port {
    unsigned int   port_no;
    unsigned char    hw_addr[OFP_ETH_ALEN];
    char      *name;

    unsigned int   config;        /* Bitmap of OFPPC_* flags. */
    unsigned int   state;         /* Bitmap of OFPPS_* flags. */

    unsigned int   curr;          /* Current features. */
    unsigned int   advertised;    /* Features being advertised by the port. */
    unsigned int   supported;     /* Features supported by the port. */
    unsigned int   peer;          /* Features advertised by peer. */

    unsigned int   curr_speed;    /* Current port bitrate in kbps. */
    unsigned int   max_speed;     /* Max port bitrate in kbps */
};



struct ofl_queue_stats {
    unsigned int   port_no;
    unsigned int   queue_id;   /* Queue i.d */
    unsigned long long int   tx_bytes;   /* Number of transmitted bytes. */
    unsigned long long int   tx_packets; /* Number of transmitted packets. */
    unsigned long long int   tx_errors;  /* Number of packets dropped due to overrun. */
    unsigned int   duration_sec; /* Time queue has been alive in seconds */
    unsigned int   duration_nsec; /* Time queue has been alive in nanoseconds
                                 beyond duration_sec */
};

struct ofl_group_desc_stats {
    unsigned char             type;        /* One of OFPGT_*. */
    unsigned int            group_id;    /* Group identifier. */

    size_t              buckets_num;
    struct ofl_bucket **buckets;
};


/* Statistics for each meter band */
struct ofl_meter_band_stats {
    unsigned long long int packet_band_count;         /* Number of packets in band. */
    unsigned long long int byte_band_count;           /* Number of bytes in band. */
    unsigned long long int last_fill;             /* Token bucket */
    unsigned long long int tokens;
    pthread_spinlock_t spinlock;         
};

/* Body of reply to OFPMP_METER request. Meter statistics. */
struct ofl_meter_stats {
    unsigned int meter_id;                                /* Meter instance. */
    unsigned short int len;                                   /* Length in bytes of this stats. */
    unsigned int flow_count;                            /* Number of flows bound to meter. */
    unsigned long long int packet_in_count;                       /* Number of packets in input. */
    unsigned long long int byte_in_count;                         /* Number of bytes in input. */
    unsigned int duration_sec;                           /* Time meter has been alive in seconds. */
    unsigned int duration_nsec;                         /* Time meter has been alive in nanoseconds beyond
                                                 duration_sec. */
    size_t meter_bands_num;
    struct ofl_meter_band_stats **band_stats; /* The band_stats length is
                                                  inferred from the length field. */
};

/* Body of reply to OFPMP_METER_CONFIG request. Meter configuration. */
struct ofl_meter_config {
    unsigned short int length;                        /* Length of this entry. */
    unsigned short int flags;                          /* All OFPMC_* that apply. */
    unsigned int meter_id;                      /* Meter instance. */
    size_t meter_bands_num;
    struct ofl_meter_band_header **bands; /* The bands length is
                                              inferred from the length field. */
};

struct ofl_meter_features {
    unsigned int max_meter;            /* Maximum number of meters. */
    unsigned int band_types;            /* Bitmaps of OFPMBT_* values supported. */
    unsigned int capabilities;           /* Bitmaps of "ofp_meter_flags". */
    unsigned char max_bands;              /* Maximum bands per meters */
    unsigned char max_color;              /* Maximum color value */
};

/****************************************************************************
 * Utility functions to match structure
 ****************************************************************************/
void
ofl_structs_match_init(struct ofl_match *match);

void
ofl_structs_match_put8(struct ofl_match *match, unsigned int header, unsigned char value);

void
ofl_structs_match_put8m(struct ofl_match *match, unsigned int header, unsigned char value, unsigned char mask);

void
ofl_structs_match_put16(struct ofl_match *match, unsigned int header, unsigned short int value);

void
ofl_structs_match_put16m(struct ofl_match *match, unsigned int header, unsigned short int value, unsigned short int mask);

void
ofl_structs_match_put32(struct ofl_match *match, unsigned int header, unsigned int value);

void
ofl_structs_match_put32m(struct ofl_match *match, unsigned int header, unsigned int value, unsigned int mask);

void
ofl_structs_match_put64(struct ofl_match *match, unsigned int header, unsigned long long int value);

void
ofl_structs_match_put64m(struct ofl_match *match, unsigned int header, unsigned long long int value, unsigned long long int mask);

void
ofl_structs_match_put_eth(struct ofl_match *match, unsigned int header, unsigned char value[ETH_ADDR_LEN]);

void
ofl_structs_match_put_eth_m(struct ofl_match *match, unsigned int header, unsigned char value[ETH_ADDR_LEN], unsigned char mask[ETH_ADDR_LEN]);

void
ofl_structs_match_put_ipv6(struct ofl_match *match, unsigned int header, unsigned char value[IPv6_ADDR_LEN] );

void
ofl_structs_match_put_ipv6m(struct ofl_match *match, unsigned int header, unsigned char value[IPv6_ADDR_LEN], unsigned char mask[IPv6_ADDR_LEN]);

int
ofl_structs_match_ofp_total_len(struct ofl_match *match);

void
ofl_structs_match_convert_pktf2oflm(struct hmap * hmap_packet_fields, struct ofl_match * match);

void
ofp_structs_match_convert_pkt2ofp(struct hmap * hmap_packet_fields, struct ofp_match * match,
                                  unsigned char* oxm_fields, struct ofl_exp *exp);

/****************************************************************************
 * Functions for (un)packing structures
 ****************************************************************************/

size_t
ofl_structs_instructions_pack(struct ofl_instruction_header *src, struct ofp_instruction *dst, struct ofl_exp *exp);

size_t
ofl_structs_meter_band_pack(struct ofl_meter_band_header *src, struct ofp_meter_band_header *dst);

size_t
ofl_structs_meter_conf_pack(struct ofl_meter_config *src, struct ofp_meter_config *dst, unsigned char* data);

size_t
ofl_structs_meter_stats_pack(struct ofl_meter_stats *src, struct ofp_meter_stats *dst);

size_t
ofl_structs_table_properties_pack(struct ofl_table_feature_prop_header * src, struct ofp_table_feature_prop_header *dst, unsigned char *data, struct ofl_exp *exp);

size_t
ofl_structs_table_features_pack(struct ofl_table_features *src, struct ofp_table_features *dst, unsigned char* data, struct ofl_exp *exp);

size_t
ofl_structs_bucket_pack(struct ofl_bucket *src, struct ofp_bucket *dst, struct ofl_exp *exp);

size_t
ofl_structs_flow_stats_pack(struct ofl_flow_stats *src, unsigned char *dst, struct ofl_exp *exp);

size_t
ofl_structs_group_stats_pack(struct ofl_group_stats *src, struct ofp_group_stats *dst);

size_t
ofl_structs_queue_prop_pack(struct ofl_queue_prop_header *src, struct ofp_queue_prop_header *dst);

size_t
ofl_structs_packet_queue_pack(struct ofl_packet_queue *src, struct ofp_packet_queue *dst);

size_t
ofl_structs_port_stats_pack(struct ofl_port_stats *src, struct ofp_port_stats *dst);


size_t
ofl_structs_port_pack(struct ofl_port *src, struct ofp_port *dst);

size_t
ofl_structs_table_stats_pack(struct ofl_table_stats *src, struct ofp_table_stats *dst);


size_t
ofl_structs_queue_stats_pack(struct ofl_queue_stats *src, struct ofp_queue_stats *dst);

size_t
ofl_structs_group_desc_stats_pack(struct ofl_group_desc_stats *src, struct ofp_group_desc_stats *dst, struct ofl_exp *exp);

size_t
ofl_structs_bucket_counter_pack(struct ofl_bucket_counter *src, struct ofp_bucket_counter *dst);

size_t
ofl_structs_match_pack(struct ofl_match_header *src, struct ofp_match *dst, unsigned char* oxm_fields, struct ofl_exp *exp);

ofl_err
ofl_structs_instructions_unpack(struct ofl_msg_flow_mod * dm,struct ofp_instruction *src, size_t *len, struct ofl_instruction_header **dst, struct ofl_exp *exp);

ofl_err
ofl_structs_table_features_unpack(struct ofp_table_features *src, size_t *len, struct ofl_table_features **dst, struct ofl_exp *exp);

ofl_err
ofl_structs_bucket_unpack(struct ofp_bucket *src, size_t *len, unsigned char gtype, struct ofl_bucket **dst, struct ofl_exp *exp);

ofl_err
ofl_structs_flow_stats_unpack(struct ofp_flow_stats *src,unsigned char *buf, size_t *len, struct ofl_flow_stats **dst, struct ofl_exp *exp);

ofl_err
ofl_structs_queue_prop_unpack(struct ofp_queue_prop_header *src, size_t *len, struct ofl_queue_prop_header **dst);

ofl_err
ofl_structs_packet_queue_unpack(struct ofp_packet_queue *src, size_t *len, struct ofl_packet_queue **dst);

ofl_err
ofl_structs_port_unpack(struct ofp_port *src, size_t *len, struct ofl_port **dst);

ofl_err
ofl_structs_table_stats_unpack(struct ofp_table_stats *src, size_t *len, struct ofl_table_stats **dst);

ofl_err
ofl_structs_port_stats_unpack(struct ofp_port_stats *src, size_t *len, struct ofl_port_stats **dst);

ofl_err
ofl_structs_group_stats_unpack(struct ofp_group_stats *src, size_t *len, struct ofl_group_stats **dst);

ofl_err
ofl_structs_queue_stats_unpack(struct ofp_queue_stats *src, size_t *len, struct ofl_queue_stats **dst);

ofl_err
ofl_structs_meter_band_unpack(struct ofp_meter_band_header *src, size_t *len, struct ofl_meter_band_header **dst);

ofl_err
ofl_structs_group_desc_stats_unpack(struct ofp_group_desc_stats *src, size_t *len, struct ofl_group_desc_stats **dst, struct ofl_exp *exp);

ofl_err
ofl_structs_bucket_counter_unpack(struct ofp_bucket_counter *src, size_t *len, struct ofl_bucket_counter **dst);


// reason for unpacket oxm messsage;
#define UNPK_REASON_PACKETIN    (1<<0)
#define UNPK_REASON_FLOW_ADD    (1<<1)
#define UNPK_REASON_FLOW_MOD    (1<<2)
#define UNPK_REASON_FLOW_MOD_STRIC    (1<<3)
#define UNPK_REASON_FLOW_DEL    (1<<4)
#define UNPK_REASON_FLOW_DEL_STRIC    (1<<5)
#define UNPK_REASON_FLOW_STA    (1<<6)
#define UNPK_REASON_FLOW_REMOV	(1<<7)
// unpack oxm field do not need prereq check;
#define UNPK_NEED_NOT_PREREQ_CHK (UNPK_REASON_PACKETIN|UNPK_REASON_FLOW_MOD|UNPK_REASON_FLOW_DEL|UNPK_REASON_FLOW_STA|UNPK_REASON_FLOW_REMOV)
// unpack oxm field need prereq check;
#define UNPK_NEED_PREREQ_CHK (UNPK_REASON_FLOW_ADD|UNPK_REASON_FLOW_MOD_STRIC|UNPK_REASON_FLOW_DEL_STRIC)

ofl_err
ofl_structs_match_unpack(struct ofp_match *src,unsigned char *buf, size_t *len, struct ofl_match_header **dst, struct ofl_exp *exp, unsigned char reason);

ofl_err
ofl_structs_meter_band_stats_unpack(struct ofp_meter_band_stats *src, size_t *len, struct ofl_meter_band_stats **dst);

ofl_err
ofl_structs_meter_stats_unpack(struct ofp_meter_stats *src, size_t *len, struct ofl_meter_stats **dst);

ofl_err
ofl_structs_meter_config_unpack(struct ofp_meter_config *src, size_t *len, struct ofl_meter_config **dst);

/****************************************************************************
 * Functions for freeing action structures
 ****************************************************************************/

void
ofl_structs_free_meter_bands(struct ofl_meter_band_header *meter_band);

void
ofl_structs_free_packet_queue(struct ofl_packet_queue *queue);

void
ofl_structs_free_instruction(struct ofl_instruction_header *inst, struct ofl_exp *exp);

void
ofl_structs_free_table_stats(struct ofl_table_stats *stats);

void
ofl_structs_free_bucket(struct ofl_bucket *bucket, struct ofl_exp *exp);

void
ofl_structs_free_flow_stats(struct ofl_flow_stats *stats, struct ofl_exp *exp);

void
ofl_structs_free_port(struct ofl_port *port);

void
ofl_structs_free_group_stats(struct ofl_group_stats *stats);

void
ofl_structs_free_group_desc_stats(struct ofl_group_desc_stats *stats, struct ofl_exp *exp);

void
ofl_structs_free_match(struct ofl_match_header *match, struct ofl_exp *exp);

void
ofl_structs_free_meter_band_stats(struct ofl_meter_band_stats* s);

void
ofl_structs_free_meter_stats(struct ofl_meter_stats *stats);

void
ofl_structs_free_meter_config(struct ofl_meter_config *conf);

void
ofl_structs_free_table_features(struct ofl_table_features* features, struct ofl_exp *exp);

void
ofl_structs_free_table_properties(struct ofl_table_feature_prop_header *prop, struct ofl_exp *exp);

/****************************************************************************
 * Utility functions
 ****************************************************************************/

/* Given a list of structures in OpenFlow wire format, these functions return
 * the count of those structures in the passed in byte array. The functions
 * return an ofl_err in case of an error, or 0 on succes. */
ofl_err
ofl_utils_count_ofp_instructions(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_buckets(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_meter_bands(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_ports(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_flow_stats(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_group_stats(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_table_stats(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_bucket_counters(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_port_stats(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_queue_stats(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_group_desc_stats(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_packet_queues(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_queue_props(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_table_features_properties(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_table_features(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_meter_stats(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_meter_band_stats(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_meter_config(void *data, size_t data_len, size_t *count);

size_t
ofl_structs_instructions_ofp_total_len(struct ofl_instruction_header **instructions, size_t instructions_num, struct ofl_exp *exp);

size_t
ofl_structs_instructions_ofp_len(struct ofl_instruction_header *instruction, struct ofl_exp *exp);

size_t
ofl_structs_meter_bands_ofp_total_len(struct ofl_meter_band_header **meter_bands, size_t meter_bands_num);

size_t
ofl_structs_meter_band_ofp_len(struct ofl_meter_band_header *meter_band);

size_t
ofl_structs_buckets_ofp_total_len(struct ofl_bucket ** buckets, size_t buckets_num, struct ofl_exp *exp);

size_t
ofl_structs_buckets_ofp_len(struct ofl_bucket *bucket, struct ofl_exp *exp);

size_t
ofl_structs_flow_stats_ofp_total_len(struct ofl_flow_stats ** stats, size_t stats_num, struct ofl_exp *exp);

size_t
ofl_structs_flow_stats_ofp_len(struct ofl_flow_stats *stats, struct ofl_exp *exp);

size_t
ofl_structs_group_stats_ofp_total_len(struct ofl_group_stats ** stats, size_t stats_num);

size_t
ofl_structs_group_stats_ofp_len(struct ofl_group_stats *stats);

size_t
ofl_structs_group_desc_stats_ofp_total_len(struct ofl_group_desc_stats ** stats, size_t stats_num, struct ofl_exp *exp);

size_t
ofl_structs_table_features_properties_ofp_len(struct ofl_table_feature_prop_header *prop, struct ofl_exp *exp);

size_t
ofl_structs_table_features_properties_ofp_total_len(struct ofl_table_feature_prop_header **props, size_t features_num, struct ofl_exp *exp);

size_t ofl_structs_table_features_ofp_total_len(struct ofl_table_features **feat, size_t tables_num, struct ofl_exp * exp);

size_t
ofl_structs_group_desc_stats_ofp_len(struct ofl_group_desc_stats *stats, struct ofl_exp *exp);

size_t
ofl_structs_queue_prop_ofp_total_len(struct ofl_queue_prop_header ** props, size_t props_num);

size_t
ofl_structs_queue_prop_ofp_len(struct ofl_queue_prop_header *prop);

size_t
ofl_structs_packet_queue_ofp_total_len(struct ofl_packet_queue ** queues, size_t queues_num);

size_t
ofl_structs_packet_queue_ofp_len(struct ofl_packet_queue *queue);

size_t
ofl_structs_match_ofp_len(struct ofl_match_header *match, struct ofl_exp *exp);

size_t
ofl_structs_meter_stats_ofp_total_len(struct ofl_meter_stats **stats, size_t stats_num);

size_t
ofl_structs_meter_stats_ofp_len(struct ofl_meter_stats * stats);

size_t
ofl_structs_pack_band_stats(struct ofl_meter_band_stats *src, struct ofp_meter_band_stats *dst);

size_t
ofl_structs_meter_conf_ofp_total_len(struct ofl_meter_config **meter_conf, size_t stats_num);

size_t
ofl_structs_meter_conf_ofp_len(struct ofl_meter_config * meter_conf);



/****************************************************************************
 * Functions for printing structures
 ****************************************************************************/

char *
ofl_structs_port_to_string(struct ofl_port *port);

void
ofl_structs_port_print(FILE *stream, struct ofl_port *port);

char *
ofl_structs_instruction_to_string(struct ofl_instruction_header *inst, struct ofl_exp *exp);

void
ofl_structs_instruction_print(FILE *stream, struct ofl_instruction_header *inst, struct ofl_exp *exp);

char *
ofl_structs_match_to_string(struct ofl_match_header *match, struct ofl_exp *exp);

void
ofl_structs_match_print(FILE *stream, struct ofl_match_header *match, struct ofl_exp *exp);

void
print_oxm_tlv(FILE *stream, struct ofl_match_tlv *f, size_t *size);

char *
ofl_structs_config_to_string(struct ofl_config *c);

void
ofl_structs_config_print(FILE *stream, struct ofl_config *c);

char *
ofl_structs_bucket_to_string(struct ofl_bucket *b, struct ofl_exp *exp);

void
ofl_structs_bucket_print(FILE *stream, struct ofl_bucket *b, struct ofl_exp *exp);

char *
ofl_structs_queue_to_string(struct ofl_packet_queue *q);

void
ofl_structs_queue_print(FILE *stream, struct ofl_packet_queue *q);

char *
ofl_structs_queue_prop_to_string(struct ofl_queue_prop_header *p);

void
ofl_structs_queue_prop_print(FILE *stream, struct ofl_queue_prop_header *p);

char *
ofl_structs_flow_stats_to_string(struct ofl_flow_stats *s, struct ofl_exp *exp);

void
ofl_structs_flow_stats_print(FILE *stream, struct ofl_flow_stats *s, struct ofl_exp *exp);

char *
ofl_structs_bucket_counter_to_string(struct ofl_bucket_counter *s);

void
ofl_structs_bucket_counter_print(FILE *stream, struct ofl_bucket_counter *c);

char *
ofl_structs_group_stats_to_string(struct ofl_group_stats *s);

void
ofl_structs_group_stats_print(FILE *stream, struct ofl_group_stats *s);

char *
ofl_structs_table_stats_to_string(struct ofl_table_stats *s);

void
ofl_structs_table_stats_print(FILE *stream, struct ofl_table_stats *s);

char *
ofl_structs_table_properties_to_string(struct ofl_table_feature_prop_header *s);

void
ofl_structs_table_properties_print(FILE * stream, struct ofl_table_feature_prop_header* s);

char *
ofl_structs_table_features_to_string(struct ofl_table_features *s);

void
ofl_structs_table_features_print(FILE *stream, struct ofl_table_features *s);

char *
ofl_structs_port_stats_to_string(struct ofl_port_stats *s);

void
ofl_structs_port_stats_print(FILE *stream, struct ofl_port_stats *s);

char *
ofl_structs_queue_stats_to_string(struct ofl_queue_stats *s);

void
ofl_structs_queue_stats_print(FILE *stream, struct ofl_queue_stats *s);

char *
ofl_structs_group_desc_stats_to_string(struct ofl_group_desc_stats *s, struct ofl_exp *exp);

void
ofl_structs_group_desc_stats_print(FILE *stream, struct ofl_group_desc_stats *s, struct ofl_exp *exp);

char*
ofl_structs_meter_band_to_string(struct ofl_meter_band_header* s);

void
ofl_structs_meter_band_print(FILE *stream, struct ofl_meter_band_header* s);

char*
ofl_structs_meter_band_stats_to_string(struct ofl_meter_band_stats* s);

void
ofl_structs_meter_band_stats_print(FILE *stream, struct ofl_meter_band_stats* s);

char*
ofl_structs_meter_features_to_string(struct ofl_meter_features* s);

void
ofl_structs_meter_features_print(FILE *stream, struct ofl_meter_features* s);

char *
ofl_structs_meter_stats_to_string(struct ofl_meter_stats *s);

void
ofl_structs_meter_stats_print(FILE *stream, struct ofl_meter_stats* s);

char*
ofl_structs_meter_config_to_string(struct ofl_meter_config* s);

void
ofl_structs_meter_config_print(FILE *stream, struct ofl_meter_config* s);

char *
ofl_structs_async_config_to_string(struct ofl_async_config *s);

void
ofl_structs_async_config_print(FILE * stream, struct ofl_async_config *s);

#endif /* OFL_STRUCTS_H */
