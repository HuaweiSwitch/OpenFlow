#ifndef FLOW_TABLE_EXACT_H
#define FLOW_TABLE_EXACT_H 1

#include "oflib/oxm-match.h"
#include "dp_capabilities.h"

enum change_order{
    NO_CHANGE = 0,
    NET_TO_HOST = 1,
    HOST_TO_NET = 2,
};

static unsigned int  g_oxm_fields[]={OXM_OF_IN_PORT,OXM_OF_IN_PHY_PORT,OXM_OF_METADATA,
                                  OXM_OF_ETH_DST,OXM_OF_ETH_SRC,    OXM_OF_ETH_TYPE,
                                  OXM_OF_VLAN_VID,OXM_OF_VLAN_PCP,  OXM_OF_IP_DSCP,
                                  OXM_OF_IP_ECN,  OXM_OF_IP_PROTO,  OXM_OF_IPV4_SRC,
                                  OXM_OF_IPV4_DST,OXM_OF_TCP_SRC,   OXM_OF_TCP_DST,
                                  OXM_OF_UDP_SRC, OXM_OF_UDP_DST,   OXM_OF_SCTP_SRC,
                                  OXM_OF_SCTP_DST,OXM_OF_ICMPV4_TYPE,OXM_OF_ICMPV4_CODE,
                                  OXM_OF_ARP_OP,  OXM_OF_ARP_SPA,   OXM_OF_ARP_TPA,
                                  OXM_OF_ARP_SHA, OXM_OF_ARP_THA,   OXM_OF_IPV6_SRC,
                                  OXM_OF_IPV6_DST,OXM_OF_IPV6_FLABEL,OXM_OF_ICMPV6_TYPE,
                                  OXM_OF_ICMPV6_CODE,OXM_OF_IPV6_ND_TARGET,OXM_OF_IPV6_ND_SLL,
                                  OXM_OF_IPV6_ND_TLL,OXM_OF_MPLS_LABEL,OXM_OF_MPLS_TC};

static unsigned long long int g_table_match[]={T0_SUPPORTED_MATCH_FIELDS,
                                  T1_SUPPORTED_MATCH_FIELDS,
                                  T2_SUPPORTED_MATCH_FIELDS,
                                  T3_SUPPORTED_MATCH_FIELDS,
                                  T4_SUPPORTED_MATCH_FIELDS,
                                  T5_SUPPORTED_MATCH_FIELDS,
                                  T6_SUPPORTED_MATCH_FIELDS,
                                  T7_SUPPORTED_MATCH_FIELDS,
                                  T8_SUPPORTED_MATCH_FIELDS
                                 };

static unsigned char  g_table_match_count[] = {0,
                                           0,
                                           T2_MATCH_FIELDS_COUNT,
                                           T3_MATCH_FIELDS_COUNT,
                                           T4_MATCH_FIELDS_COUNT,
                                           T5_MATCH_FIELDS_COUNT,
                                           0,
                                           T7_MATCH_FIELDS_COUNT,
                                           0
                                           };
// 流表类型,0:精确表，
static unsigned long long int g_table_type[] = { T0_SUPPORTED_MATCH_FIELDS,
                                  T1_SUPPORTED_MATCH_FIELDS,
                                  EXACT_TABLE,
                                  EXACT_TABLE,
                                  EXACT_TABLE,
                                  EXACT_TABLE,
                                  T6_SUPPORTED_MATCH_FIELDS,
                                  EXACT_TABLE,
                                  T8_SUPPORTED_MATCH_FIELDS
                                 };


static unsigned int global_table_match_fields[][40] = {
    /*{ OXM_OF_ETH_TYPE, OXM_OF_IPV4_SRC, OXM_OF_IPV4_DST, OXM_OF_IPV6_SRC,
      OXM_OF_IPV6_DST, OXM_OF_IP_PROTO, OXM_OF_SCTP_SRC, OXM_OF_SCTP_DST,
      OXM_OF_TCP_SRC,  OXM_OF_TCP_DST,  OXM_OF_UDP_SRC,  OXM_OF_UDP_DST},*/

    { OXM_OF_IN_PORT,  OXM_OF_METADATA, OXM_OF_ETH_DST,  OXM_OF_ETH_SRC,
      OXM_OF_ETH_TYPE, OXM_OF_VLAN_VID, OXM_OF_VLAN_PCP, OXM_OF_IP_DSCP,
      OXM_OF_IP_PROTO, OXM_OF_IPV4_SRC, OXM_OF_IPV4_DST, OXM_OF_TCP_SRC,
      OXM_OF_TCP_DST,  OXM_OF_UDP_SRC,  OXM_OF_UDP_DST,  OXM_OF_SCTP_SRC,
      OXM_OF_SCTP_DST, OXM_OF_IPV6_SRC, OXM_OF_IPV6_DST, OXM_OF_ICMPV4_CODE,
      OXM_OF_ICMPV4_TYPE, OXM_OF_ICMPV6_TYPE, OXM_OF_ICMPV6_CODE,
      OXM_OF_MPLS_LABEL,  OXM_OF_MPLS_TC},

    { OXM_OF_ETH_TYPE, OXM_OF_IP_DSCP,  OXM_OF_IN_PORT,
      OXM_OF_VLAN_VID, OXM_OF_ETH_DST,  OXM_OF_METADATA},

    { OXM_OF_ETH_SRC,  OXM_OF_ETH_DST,  OXM_OF_METADATA},

    { OXM_OF_VLAN_VID,  OXM_OF_VLAN_PCP,  OXM_OF_METADATA},

    { OXM_OF_ETH_TYPE, OXM_OF_MPLS_LABEL, OXM_OF_MPLS_TC, OXM_OF_METADATA},

    { OXM_OF_ETH_TYPE, OXM_OF_IPV4_SRC, OXM_OF_IPV4_DST,
	  OXM_OF_IPV6_SRC, OXM_OF_IPV6_DST, OXM_OF_METADATA},

    { OXM_OF_ETH_TYPE, OXM_OF_IPV4_SRC, OXM_OF_IPV4_DST,
      OXM_OF_IPV6_SRC, OXM_OF_IPV6_DST, OXM_OF_METADATA},

    { OXM_OF_ETH_TYPE, OXM_OF_IP_PROTO, OXM_OF_ICMPV4_TYPE, OXM_OF_ICMPV4_CODE,
	  OXM_OF_ICMPV6_TYPE, OXM_OF_ICMPV6_CODE, OXM_OF_METADATA},

    { OXM_OF_IN_PORT,  OXM_OF_METADATA, OXM_OF_ETH_DST,  OXM_OF_ETH_SRC,
      OXM_OF_ETH_TYPE, OXM_OF_VLAN_VID, OXM_OF_VLAN_PCP, OXM_OF_IP_DSCP,
      OXM_OF_IP_PROTO, OXM_OF_IPV4_SRC, OXM_OF_IPV4_DST, OXM_OF_TCP_SRC,
      OXM_OF_TCP_DST,  OXM_OF_UDP_SRC,  OXM_OF_UDP_DST,  OXM_OF_SCTP_SRC,
      OXM_OF_SCTP_DST, OXM_OF_IPV6_SRC, OXM_OF_IPV6_DST, OXM_OF_ICMPV4_CODE,
      OXM_OF_ICMPV4_TYPE, OXM_OF_ICMPV6_TYPE, OXM_OF_ICMPV6_CODE,
      OXM_OF_MPLS_LABEL,  OXM_OF_MPLS_TC}
};

static unsigned int global_table_wildcard_fields[][40] = {
        /*{ OXM_OF_ETH_TYPE, OXM_OF_IPV4_SRC, OXM_OF_IPV4_DST, OXM_OF_IPV6_SRC,
          OXM_OF_IPV6_DST, OXM_OF_IP_PROTO, OXM_OF_SCTP_SRC, OXM_OF_SCTP_DST,
          OXM_OF_TCP_SRC,  OXM_OF_TCP_DST,  OXM_OF_UDP_SRC,  OXM_OF_UDP_DST},*/

        {OXM_OF_IN_PORT,  OXM_OF_METADATA, OXM_OF_ETH_DST,  OXM_OF_ETH_SRC,
         OXM_OF_ETH_TYPE, OXM_OF_VLAN_VID, OXM_OF_VLAN_PCP, OXM_OF_IP_DSCP,
         OXM_OF_IP_PROTO, OXM_OF_IPV4_SRC, OXM_OF_IPV4_DST, OXM_OF_TCP_SRC,
         OXM_OF_TCP_DST,  OXM_OF_UDP_SRC,  OXM_OF_UDP_DST,  OXM_OF_SCTP_SRC,
         OXM_OF_SCTP_DST, OXM_OF_IPV6_SRC, OXM_OF_IPV6_DST, OXM_OF_ICMPV4_CODE,
         OXM_OF_ICMPV4_TYPE, OXM_OF_ICMPV6_TYPE, OXM_OF_ICMPV6_CODE,
         OXM_OF_MPLS_LABEL,  OXM_OF_MPLS_TC},

        {OXM_OF_ETH_TYPE, OXM_OF_IP_DSCP,  OXM_OF_IN_PORT,
         OXM_OF_VLAN_VID, OXM_OF_ETH_DST,  OXM_OF_METADATA},

        {0},

        {0},

        {0},

        {0},

        {OXM_OF_ETH_TYPE, OXM_OF_IPV4_SRC, OXM_OF_IPV4_DST,
         OXM_OF_IPV6_SRC, OXM_OF_IPV6_DST, OXM_OF_METADATA},

        {0},

        {OXM_OF_IN_PORT,  OXM_OF_METADATA, OXM_OF_ETH_DST,  OXM_OF_ETH_SRC,
         OXM_OF_ETH_TYPE, OXM_OF_VLAN_VID, OXM_OF_VLAN_PCP, OXM_OF_IP_DSCP,
         OXM_OF_IP_PROTO, OXM_OF_IPV4_SRC, OXM_OF_IPV4_DST, OXM_OF_TCP_SRC,
         OXM_OF_TCP_DST,  OXM_OF_UDP_SRC,  OXM_OF_UDP_DST,  OXM_OF_SCTP_SRC,
         OXM_OF_SCTP_DST, OXM_OF_IPV6_SRC, OXM_OF_IPV6_DST, OXM_OF_ICMPV4_CODE,
         OXM_OF_ICMPV4_TYPE, OXM_OF_ICMPV6_TYPE, OXM_OF_ICMPV6_CODE,
         OXM_OF_MPLS_LABEL,  OXM_OF_MPLS_TC}
};

#define T0_MATCH_COUNT 25
#define T1_MATCH_COUNT 6
#define T2_MATCH_COUNT 3
#define T3_MATCH_COUNT 3
#define T4_MATCH_COUNT 4
#define T5_MATCH_COUNT 6
#define T6_MATCH_COUNT 6
#define T7_MATCH_COUNT 7
#define T8_MATCH_COUNT 25

static unsigned char  global_table_match_count[] = { T0_MATCH_COUNT,
                                               T1_MATCH_COUNT,
                                               T2_MATCH_COUNT,
                                               T3_MATCH_COUNT,
                                               T4_MATCH_COUNT,
                                               T5_MATCH_COUNT,
                                               T6_MATCH_COUNT,
                                               T7_MATCH_COUNT,
                                               T8_MATCH_COUNT
                                             };

#define T0_WILDCARD_COUNT 25
#define T1_WILDCARD_COUNT 6
#define T6_WILDCARD_COUNT 6
#define T8_WILDCARD_COUNT 25

static unsigned char global_table_wildcard_count[] = { T0_WILDCARD_COUNT,
                                                 T1_WILDCARD_COUNT,
                                                 0,
                                                 0,
                                                 0,
                                                 0,
                                                 T6_WILDCARD_COUNT,
                                                 0,
                                                 T8_WILDCARD_COUNT
                                               };

ofl_err exact_flow_table_add(struct flow_table *table,
                                struct ofl_msg_flow_mod *mod,  bool *match_kept,
                                bool *insts_kept);

ofl_err exact_flow_table_modify(struct flow_table *table,
                                     struct ofl_msg_flow_mod *mod, bool strict,
                                     bool *insts_kept);

ofl_err exact_flow_table_delete(struct flow_table *table,
                                            struct ofl_msg_flow_mod *mod,bool strict);

struct flow_entry *exact_flow_table_lookup(struct flow_table *table,struct packet *pkt);

unsigned int packet_hash_pi(unsigned char *dst ,
                                struct packet *pkt,unsigned int match_len);

void exact_flow_table_stats(struct flow_table *table,
                                 struct ofl_msg_multipart_request_flow *msg,
                                 struct ofl_flow_stats ***stats,
                                 size_t *stats_size,
                                 size_t *stats_num);

int flow_entry_extract(unsigned char *dst,unsigned long long int tbl_match,struct ofl_match *match);

void exact_flow_table_timeout(struct flow_table *table);

#endif

