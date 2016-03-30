/* Copyright (c) 2012, CPqD, Brazil
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
/*
 *  * Copyright (c) 2010 Nicira Networks.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#include <config.h>

#include "oxm-match.h"
#include<netinet/in.h>
#include <netinet/icmp6.h>
#include "hmap.h"
#include "hash.h"
#include "ofp.h"
#include "ofpbuf.h"
#include "byte-order.h"
#include "packets.h"
#include "ofpbuf.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl-utils.h"
#include "unaligned.h"
#include "byte-order.h"
#include "../include/openflow/openflow.h"

#define LOG_MODULE VLM_oxm_match
#include "vlog.h"

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

/* Possible masks for TLV OXM_ETH_DST_W. */
static const unsigned char eth_all_0s[ETH_ADDR_LEN]
    = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const unsigned char eth_all_1s[ETH_ADDR_LEN]
    = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
static const unsigned char eth_mcast_1[ETH_ADDR_LEN]
    = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
static const unsigned char eth_mcast_0[ETH_ADDR_LEN]
    = {0xfe, 0xff, 0xff, 0xff, 0xff, 0xff};

/* For each OXM_* field, define OFI_OXM_* as consecutive integers starting from
 * zero. */
enum oxm_field_index {
#define DEFINE_FIELD(HEADER,DL_TYPES, NW_PROTO, MASKABLE) \
        OFI_OXM_##HEADER,
#include "oxm-match.def"
    N_OXM_FIELDS
};

struct oxm_field {
    struct hmap_node hmap_node;
    enum oxm_field_index index;       /* OFI_* value. */
    unsigned int header;                  /* OXM_* value. */
    unsigned short int dl_type[N_OXM_DL_TYPES]; /* dl_type prerequisites. */
    unsigned char nw_proto;                 /* nw_proto prerequisite, if nonzero. */
    bool maskable;                    /* Writable with OXAST_REG_{MOVE,LOAD}? */
};

/* All the known fields. */
static struct oxm_field oxm_fields[N_OXM_FIELDS] = {
#define DEFINE_FIELD(HEADER, DL_TYPES, NW_PROTO, MASKABLE)     \
    { HMAP_NODE_NULL_INITIALIZER, OFI_OXM_##HEADER, OXM_##HEADER, \
        DL_CONVERT DL_TYPES, NW_PROTO, MASKABLE },
//#define DL_CONVERT(T1, T2) { CONSTANT_HTONS(T1), CONSTANT_HTONS(T2) }
#define DL_CONVERT(T1, T2) { (T1), (T2) }
#include "oxm-match.def"
};

/* Hash table of 'oxm_fields'. */
static struct hmap all_oxm_fields = HMAP_INITIALIZER(&all_oxm_fields);

static void
oxm_init(void)
{
    if (hmap_is_empty(&all_oxm_fields)) {
        int i;

        for (i = 0; i < N_OXM_FIELDS; i++) {
            struct oxm_field *f = &oxm_fields[i];
            hmap_insert(&all_oxm_fields, &f->hmap_node,
                        DP_FIELD_HASH(f->header));
        }

        /* Verify that the header values are unique (duplicate "case" values
         * cause a compile error). */
        switch (0) {
#define DEFINE_FIELD(HEADER, DL_TYPE, NW_PROTO, MASKABLE)  \
        case OXM_##HEADER: break;
#include "oxm-match.def"
        }
    }
}

static const struct oxm_field *
oxm_field_lookup(unsigned int header)
{
    struct oxm_field *f;

    oxm_init();

    HMAP_FOR_EACH_WITH_HASH(f, struct oxm_field, hmap_node ,DP_FIELD_HASH(header),
                             &all_oxm_fields) {
        if (f->header == header) {
            return f;
        }
    }

    return NULL;
}

static bool
check_present_prereq(const struct ofl_match *match, unsigned int header){

    struct ofl_match_tlv *omt;

    /* Check for header */
    HMAP_FOR_EACH_WITH_HASH (omt, struct ofl_match_tlv, hmap_node, DP_FIELD_HASH(header),
          &match->match_fields) {
         return true;
    }
    return false;
}

bool action_check_present_prereq(struct ofl_msg_flow_mod * dm, unsigned int header){
    struct ofl_match *match;
    bool result;
    match = (struct ofl_match *)(dm->match);
    result = check_present_prereq(match, header);
    return result;
}
static bool
oxm_prereqs_ok(const struct oxm_field *field, const struct ofl_match *rule)
{

    struct ofl_match_tlv *omt = NULL;

    /*bool result = true;
    if (field->nw_proto)
    {
        result = false;
        HMAP_FOR_EACH_WITH_HASH (omt, struct ofl_match_tlv, hmap_node, DP_FIELD_HASH(OXM_OF_IP_PROTO),
                    &rule->match_fields) {
                    unsigned char ip_proto;
                    memcpy(&ip_proto,omt->value, sizeof(unsigned char));
                    result = true;
        }
    }
    if( false == result)
        return false;
    if( field->dl_type[0])
    {
        result = false;
        HMAP_FOR_EACH_WITH_HASH (omt, struct ofl_match_tlv, hmap_node, DP_FIELD_HASH(OXM_OF_ETH_TYPE),
              &rule->match_fields) {
                unsigned short int eth_type;
                memcpy(&eth_type, omt->value, sizeof(unsigned short int));
                result = true;
        }
    }
    if( false == result)
        return false;*/
    /*Check for IP_PROTO */
    if (field->nw_proto)
        HMAP_FOR_EACH_WITH_HASH (omt, struct ofl_match_tlv, hmap_node, DP_FIELD_HASH(OXM_OF_IP_PROTO),
            &rule->match_fields) {
            unsigned char ip_proto;
            memcpy(&ip_proto,omt->value, sizeof(unsigned char));
            if (field->nw_proto != ip_proto)
                return false;
    }

    /* Check for eth_type */
    if (!field->dl_type[0])
        return true;
    else {
        HMAP_FOR_EACH_WITH_HASH (omt, struct ofl_match_tlv, hmap_node, DP_FIELD_HASH(OXM_OF_ETH_TYPE),
              &rule->match_fields) {
            unsigned short int eth_type;
            memcpy(&eth_type, omt->value, sizeof(unsigned short int));
            if (field->dl_type[0] == ntohs(eth_type)) {
                return true;
            }
            else if (field->dl_type[1] && field->dl_type[1] ==  htons(eth_type)) {
                VLOG_INFO(LOG_MODULE, "add eth type =[%d]\r\n", eth_type);
                return true;
            }
        }
    }
    return false;
}

static bool
check_oxm_dup(struct ofl_match *match,const struct oxm_field *om){

    struct ofl_match_tlv *t;
    HMAP_FOR_EACH_WITH_HASH(t, struct ofl_match_tlv, hmap_node ,DP_FIELD_HASH(om->header),
                             &match->match_fields) {
        return true;
    }
    return false;

}

unsigned char* get_oxm_value(struct ofl_match *m, unsigned int header){

     struct ofl_match_tlv *t;
     HMAP_FOR_EACH_WITH_HASH (t, struct ofl_match_tlv, hmap_node, DP_FIELD_HASH(header),
          &m->match_fields) {
         return t->value;
     }

     return NULL;
}

static int
parse_oxm_entry(struct ofl_match *match, const struct oxm_field *f,
                const void *value, const void *mask, unsigned char reason){

    switch (f->index) {
        case OFI_OXM_OF_IN_PORT: {
            unsigned int* in_port = (unsigned int*) value;
            ofl_structs_match_put32(match, f->header, htonl(*in_port));
            return 0;
        }
        case OFI_OXM_OF_IN_PHY_PORT:{
            /* Check for inport presence */
            if (check_present_prereq(match,OXM_OF_IN_PORT)
                    || (reason & UNPK_NEED_NOT_PREREQ_CHK) )
                ofl_structs_match_put32(match, f->header, *((unsigned int*) value));
            else return ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_PREREQ);

        }
        case OFI_OXM_OF_METADATA:{
            ofl_structs_match_put64(match, f->header, *((unsigned long long int*) value));
            return 0;
        }
        case OFI_OXM_OF_METADATA_W:{
            ofl_structs_match_put64m(match, f->header,*((unsigned long long int*) value),*((unsigned long long int*) mask));
            return 0;
        }
        /* Ethernet header. */
        case OFI_OXM_OF_ETH_DST:
        case OFI_OXM_OF_ETH_SRC:{
            ofl_structs_match_put_eth(match, f->header,(unsigned char* )value);
            return 0;
        }
        case OFI_OXM_OF_ETH_DST_W:
        case OFI_OXM_OF_ETH_SRC_W:{
            ofl_structs_match_put_eth_m(match, f->header,(unsigned char* )value, (unsigned char* )mask );
            return 0;
        }
        case OFI_OXM_OF_ETH_TYPE:{
            unsigned short int* eth_type = (unsigned short int*) value;
            ofl_structs_match_put16(match, f->header, ntohs(*eth_type));
            return 0;
        }
        /* 802.1Q header. */
        case OFI_OXM_OF_VLAN_VID:{
            unsigned short int * vlan_vid = (unsigned short int*) value;
            unsigned short int vlan_id = ntohs(*vlan_vid);

            if (vlan_id != 0)
            {
                vlan_id |= OFPVID_PRESENT;
            }
            /*l00135737 reset vlan CFI bit*/
            //if(vlan_id != OFPVID_PRESENT)
            if( vlan_id - OFPVID_PRESENT >= OFPVID_PRESENT )
            {
                return ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_VALUE);
            }
            else if( (vlan_id < OFPVID_PRESENT) && (vlan_id != OFPVID_NONE) )
            {
                VLOG_INFO(LOG_MODULE, "error vlan_id < 0x1000 \r\n");
                return ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_VALUE);
            }
            else
            {
                *vlan_vid = htons(vlan_id);
                ofl_structs_match_put16(match, f->header, ntohs(*vlan_vid));
            }
            return 0;
        }
        case OFI_OXM_OF_VLAN_VID_W:{
            unsigned short int* vlan_vid = (unsigned short int*) value;
            unsigned short int* vlan_mask = (unsigned short int*) mask;
            if( ntohs(*vlan_vid) != OFPVID_PRESENT || ntohs(*vlan_mask) != OFPVID_PRESENT)
            {
                return ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_MASK);
            }
            else
                ofl_structs_match_put16m(match, f->header, ntohs(*vlan_vid),ntohs(*vlan_mask));
            return 0;
        }

        case OFI_OXM_OF_VLAN_PCP:
        {
            unsigned char  *p;
            /* Check for VLAN_VID presence */
            if( reason & UNPK_NEED_NOT_PREREQ_CHK)
            {
                unsigned char *v = (unsigned char*) value;
                if( *v > 7)  
                {
                    VLOG_INFO(LOG_MODULE, "vlan pcp err[%d]\n",*v);
                    return ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_VALUE);
                }
                else
                {
                    ofl_structs_match_put8(match, f->header, *v);
                }
                return 0;
            }
            else
            {
                if (check_present_prereq(match,OXM_OF_VLAN_VID)
                    || check_present_prereq(match,OXM_OF_VLAN_VID_W)) {
                    if(check_present_prereq(match,OXM_OF_VLAN_VID))
                        p = get_oxm_value(match,OXM_OF_VLAN_VID);
                    if(check_present_prereq(match,OXM_OF_VLAN_VID_W))
                        p = get_oxm_value(match,OXM_OF_VLAN_VID_W);

                    if (*(unsigned short int*) p != OFPVID_NONE ) {
                         unsigned char *v = (unsigned char*) value;
                        if( *v > 7)  
                        {
                            VLOG_INFO(LOG_MODULE, "vlan pcp error[%d]\n",*v);
                            return ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_VALUE);
                        }
                        else
                        {
                            ofl_structs_match_put8(match, f->header, *v);
                        }
                    }
                    else {
                        return ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_PREREQ);
                    }
                    return 0;
                }
                else
                    return ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_PREREQ);
            }
        }
            /* IP header. */
        case OFI_OXM_OF_IP_DSCP:{
            unsigned char *v = (unsigned char*) value;
            if (*v > 0x3F) 
            {
                VLOG_INFO(LOG_MODULE, "dscp error[%d]\n",*v);
                return ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_VALUE);
            }
            else
            {
                ofl_structs_match_put8(match, f->header, (*v));
                return 0;
            }
        }
        case OFI_OXM_OF_IP_ECN:
        case OFI_OXM_OF_IP_PROTO:{
            unsigned char *v = (unsigned char*) value;
            ofl_structs_match_put8(match, f->header, *v);
            return 0;
        }

        /* IP addresses in IP and ARP headers. */
        case OFI_OXM_OF_IPV4_SRC:
        case OFI_OXM_OF_IPV4_DST:
        case OFI_OXM_OF_ARP_TPA:
        case OFI_OXM_OF_ARP_SPA:
            ofl_structs_match_put32(match, f->header, *((unsigned int*) value));
            return 0;
        case OFI_OXM_OF_IPV4_DST_W:
        case OFI_OXM_OF_IPV4_SRC_W:
        case OFI_OXM_OF_ARP_SPA_W:
        case OFI_OXM_OF_ARP_TPA_W:
            ofl_structs_match_put32m(match, f->header, *((unsigned int*) value), *((unsigned int*) mask));
            return 0;
        case OFI_OXM_OF_ARP_SHA:
        case OFI_OXM_OF_ARP_THA:
            ofl_structs_match_put_eth(match, f->header,(unsigned char* )value);
            return 0;

        case OFI_OXM_OF_ARP_SHA_W:
        case OFI_OXM_OF_ARP_THA_W:
            ofl_structs_match_put_eth_m(match, f->header,(unsigned char* )value, (unsigned char* )mask );
            return 0;

            /* IPv6 addresses. */
        case OFI_OXM_OF_IPV6_SRC:
        case OFI_OXM_OF_IPV6_DST:{
            ofl_structs_match_put_ipv6(match, f->header,(unsigned char* ) value);
            return 0;
        }
        case OFI_OXM_OF_IPV6_SRC_W:
        case OFI_OXM_OF_IPV6_DST_W:{
            ofl_structs_match_put_ipv6m(match, f->header,(unsigned char* ) value,(unsigned char* ) mask);
            return 0;
        }
        case OFI_OXM_OF_IPV6_FLABEL:{
            ofl_structs_match_put32(match, f->header, ntohl(*((unsigned int*) value)));
            return 0;
        }
        case OFI_OXM_OF_IPV6_FLABEL_W:{
            ofl_structs_match_put32m(match, f->header, ntohl(*((unsigned int*) value)), ntohl(*((unsigned int*) mask)));
            return 0;
        }
        /* TCP header. */
        case OFI_OXM_OF_TCP_SRC:
        case OFI_OXM_OF_TCP_DST:
        /* UDP header. */
        case OFI_OXM_OF_UDP_SRC:
        case OFI_OXM_OF_UDP_DST:
            /* SCTP header. */
        case OFI_OXM_OF_SCTP_SRC:
        case OFI_OXM_OF_SCTP_DST:
            ofl_structs_match_put16(match, f->header, ntohs(*((unsigned short int*) value)));
            return 0;

            /* ICMP header. */
        case OFI_OXM_OF_ICMPV4_TYPE:
        case OFI_OXM_OF_ICMPV4_CODE:
            /* ICMPv6 header. */
        case OFI_OXM_OF_ICMPV6_TYPE:
        case OFI_OXM_OF_ICMPV6_CODE:{
            unsigned char *v = (unsigned char*) value;
            ofl_structs_match_put8(match, f->header, *v);
            return 0;
        }
            /* IPv6 Neighbor Discovery. */
        case OFI_OXM_OF_IPV6_ND_TARGET:
            ofl_structs_match_put_ipv6(match, f->header,(unsigned char* ) value);
            return 0;
        case OFI_OXM_OF_IPV6_ND_SLL:
        case OFI_OXM_OF_IPV6_ND_TLL:
            ofl_structs_match_put_eth(match, f->header,(unsigned char* )value);
            return 0;
            /* ARP header. */
        case OFI_OXM_OF_ARP_OP:{
            unsigned short int* arp_op = (unsigned short int*) value;
            ofl_structs_match_put16(match, f->header, ntohs(*arp_op));

         /* modify by linke,E版本协议理解有误,short */
         /* unsigned char *v = (unsigned char*) value;
            if (*v > 255)
                return ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_VALUE);
            else
                ofl_structs_match_put8(match, f->header, *v);*/
            return 0;
        }
        case OFI_OXM_OF_MPLS_LABEL:
        {
            //VLOG_INFO(LOG_MODULE, "*****OFI_OXM_OF_MPLS_LABEL %08x ", ntohl(*((unsigned int*) value)));
            if (ntohl(*((unsigned int*) value)) > 1048576) // 0x100000
            {
                VLOG_INFO(LOG_MODULE, "mpls label value err[%d]\n",ntohl(*((unsigned int*) value)));
                return ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_VALUE);
            }
            else
            {
                ofl_structs_match_put32(match, f->header, ntohl(*((unsigned int*) value)));
            }

          return 0;
        }
        case OFI_OXM_OF_MPLS_TC:
        {
            unsigned char *v = (unsigned char*) value;
            if(*v > 7 )
                return ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_VALUE);
            else
                ofl_structs_match_put8(match, f->header, *v);
            return 0;
        }
        case OFI_OXM_OF_MPLS_BOS:{
            unsigned char *v = (unsigned char*) value;
            ofl_structs_match_put8(match, f->header, *v);
            return 0;
        }
        case OFI_OXM_OF_PBB_ISID:
            ofl_structs_match_put32(match, f->header, ntohl(*((unsigned int*) value)));
            return 0;
        case OFI_OXM_OF_PBB_ISID_W:
            ofl_structs_match_put32m(match, f->header, ntohl(*((unsigned int*) value)), ntohl(*((unsigned int*) mask)));
            return 0;
        case OFI_OXM_OF_TUNNEL_ID:{
            ofl_structs_match_put64(match, f->header, *((unsigned long long int*) value));
            return 0;
        }
        case OFI_OXM_OF_TUNNEL_ID_W:{
            ofl_structs_match_put64m(match, f->header,*((unsigned long long int*) value),*((unsigned long long int*) mask));
            return 0;
        }
        case OFI_OXM_OF_IPV6_EXTHDR:
            ofl_structs_match_put16(match, f->header, ntohs(*((unsigned short int*) value)));
            return 0;
        case OFI_OXM_OF_IPV6_EXTHDR_W:
            ofl_structs_match_put16m(match, f->header, ntohs(*((unsigned short int*) value)),ntohs(*((unsigned short int*) mask)));
            return 0;
        default:
            NOT_REACHED();
    }
    NOT_REACHED();
}
bool check_mask_value_ok(unsigned int header, unsigned char* value, unsigned char * mask, unsigned char len)
{
    int i;
    if( OXM_HASMASK(header) )
    {
        for(i=0; i<len; i++)
        {
            if( ( (~mask[i]) & value[i] ) != 0)
                return false;
        }
    }
    return true;
}
 /*hmap_insert(match_dst, &f->hmap_node,
                hash_int(f->header, 0));               */

/* ox_pull_match() and helpers. */


/* Puts the match in a hash_map structure */
int
oxm_pull_match(struct ofpbuf *buf, struct ofl_match * match_dst, int match_len, unsigned char reason)
{

    unsigned int header;
    unsigned char *p;
    p = ofpbuf_try_pull(buf, match_len);

    if (!p) {
        VLOG_DBG_RL(LOG_MODULE,&rl, "oxm_match length %u, rounded up to a "
                    "multiple of 8, is longer than space in message (max "
                    "length %lu)", match_len, buf->size);

        return ofp_mkerr(OFPET_BAD_MATCH, OFPBRC_BAD_LEN);
    }
    ofl_structs_match_init(match_dst);
    while ((header = oxm_entry_ok(p, match_len)) != 0) {

        unsigned length = OXM_LENGTH(header);
        const struct oxm_field *f;
        int error;
        f = oxm_field_lookup(header);

        if (!f) {
            error = ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_FIELD);
        }
        else if (OXM_HASMASK(header) && !f->maskable){
            error = ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_MASK);
        }
        else if(!check_mask_value_ok(header, p+4, p+4+length/2, length/2) )
        {
            error = ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_WILDCARDS);
        }
        else if (!oxm_prereqs_ok(f, match_dst)
                        && (reason & UNPK_NEED_PREREQ_CHK )) {
            error = ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_PREREQ);
        }
        else if (check_oxm_dup(match_dst,f)){
            error = ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_DUP_FIELD);
        }
        else {
            /* 'hasmask' and 'length' are known to be correct at this point
             * because they are included in 'header' and oxm_field_lookup()
             * checked them already. */
            error = parse_oxm_entry(match_dst, f, p + 4, p + 4 + length / 2, reason);
        }
        if (error) {
            VLOG_DBG_RL(LOG_MODULE,&rl, "bad oxm_entry with vendor=%"PRIu32", "
                        "field=%"PRIu32", hasmask=%"PRIu32", type=%"PRIu32" "
                        "(error %x)",
                        OXM_VENDOR(header), OXM_FIELD(header),
                        OXM_HASMASK(header), OXM_TYPE(header),
                        error);
            return error;
        }
        p += 4 + length;
        match_len -= 4 + length;
    }
    return match_len ? ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_LEN) : 0;
}


unsigned int
oxm_entry_ok(const void *p, unsigned int match_len)
{
    unsigned int payload_len;
    unsigned int header;

    if (match_len <= 4) {
        if (match_len) {
            VLOG_DBG(LOG_MODULE,"oxm_match ends with partial oxm_header");
        }
        return 0;
    }

    memcpy(&header, p, 4);
    header = ntohl(header);
    payload_len = OXM_LENGTH(header);
    if (!payload_len) {
        VLOG_DBG(LOG_MODULE, "oxm_entry %08"PRIx32" has invalid payload "
                    "length 0", header);
        return 0;
    }
    if (match_len < payload_len + 4) {
        VLOG_DBG(LOG_MODULE, "%"PRIu32"-byte oxm_entry but only "
                    "%u bytes left in ox_match", payload_len + 4, match_len);
        VLOG_DBG(LOG_MODULE, "Header ==  %d"
                    ,  OXM_FIELD(header));
        return 0;
    }
    return header;
}

/* oxm_put_match() and helpers.
 *
 * 'put' functions whose names end in 'w' add a wildcarded field.
 * 'put' functions whose names end in 'm' add a field that might be wildcarded.
 * Other 'put' functions add exact-match fields.
 */

static void
oxm_put_header(struct ofpbuf *buf, unsigned int header)
{
    unsigned int n_header = htonl(header);
    ofpbuf_put(buf, &n_header, sizeof n_header);

}

static void
oxm_put_8(struct ofpbuf *buf, unsigned int header, unsigned char value)
{
    oxm_put_header(buf, header);
    ofpbuf_put(buf, &value, sizeof value);
}

static void
oxm_put_8w(struct ofpbuf *buf, unsigned int header, unsigned char value, unsigned short int mask){

    oxm_put_header(buf, header);
    ofpbuf_put(buf, &value, sizeof value);
    ofpbuf_put(buf, &mask, sizeof mask);

}

static void
oxm_put_16(struct ofpbuf *buf, unsigned int header, unsigned short int value)
{
    oxm_put_header(buf, header);
    ofpbuf_put(buf, &value, sizeof value);
}

static void
oxm_put_16w(struct ofpbuf *buf, unsigned int header, unsigned short int value, unsigned short int mask)
{
   oxm_put_header(buf, header);
   ofpbuf_put(buf, &value, sizeof value);
   ofpbuf_put(buf, &mask, sizeof mask);
}

static void
oxm_put_32(struct ofpbuf *buf, unsigned int header, unsigned int value)
{
    oxm_put_header(buf, header);
    ofpbuf_put(buf, &value, sizeof value);
}

static void
oxm_put_32w(struct ofpbuf *buf, unsigned int header, unsigned int value, unsigned int mask)
{
    oxm_put_header(buf, header);
    ofpbuf_put(buf, &value, sizeof value);
    ofpbuf_put(buf, &mask, sizeof mask);
}

static void
oxm_put_64(struct ofpbuf *buf, unsigned int header, unsigned long long int value)
{
    oxm_put_header(buf, header);
    ofpbuf_put(buf, &value, sizeof value);
}

static void
oxm_put_64w(struct ofpbuf *buf, unsigned int header, unsigned long long int value, unsigned long long int mask)
{
    oxm_put_header(buf, header);
    ofpbuf_put(buf, &value, sizeof value);
    ofpbuf_put(buf, &mask, sizeof mask);
}

static void
oxm_put_eth(struct ofpbuf *buf, unsigned int header,
            const unsigned char value[ETH_ADDR_LEN])
{
    oxm_put_header(buf, header);
    ofpbuf_put(buf, value, ETH_ADDR_LEN);

}

static void
oxm_put_ethm(struct ofpbuf *buf, unsigned int header,
            const unsigned char value[ETH_ADDR_LEN], const unsigned char mask[ETH_ADDR_LEN])
{
    oxm_put_header(buf, header);
    ofpbuf_put(buf, value, ETH_ADDR_LEN);
    ofpbuf_put(buf, mask, ETH_ADDR_LEN);
}

static void oxm_put_ipv6(struct ofpbuf *buf, unsigned int header,
                    unsigned char value[IPv6_ADDR_LEN]){
     oxm_put_header(buf, header);
     ofpbuf_put(buf, value, IPv6_ADDR_LEN);
}

static void oxm_put_ipv6m(struct ofpbuf *buf, unsigned int header,
                    unsigned char value[ETH_ADDR_LEN], unsigned char mask[ETH_ADDR_LEN]){
    oxm_put_header(buf, header);
    ofpbuf_put(buf, value, ETH_ADDR_LEN);
    ofpbuf_put(buf, mask, ETH_ADDR_LEN);
}

/* TODO: put the ethernet destiny address handling possible masks
static void
oxm_put_eth_dst(struct ofpbuf *b,
                unsigned int wc, const unsigned char value[ETH_ADDR_LEN])
{
    switch (wc & (bufWW_DL_DST | FWW_ETH_MCAST)) {
    case FWW_DL_DST | FWW_ETH_MCAST:
        break;
    case FWW_DL_DST:
        oxm_put_header(b, oxM_OF_ETH_DST_W);
        ofpbuf_put(b, value, ETH_ADDR_LEN);
        ofpbuf_put(b, eth_mcast_1, ETH_ADDR_LEN);
        break;
    case FWW_ETH_MCAST:
        oxm_put_header(b, oxM_OF_ETH_DST_W);
        ofpbuf_put(b, value, ETH_ADDR_LEN);
        ofpbuf_put(b, eth_mcast_0, ETH_ADDR_LEN);
        break;
    case 0:
        oxm_put_eth(b, oxM_OF_ETH_DST, value);
        break;
    }
}*/

static bool
is_requisite(unsigned int header){
    if(header == OXM_OF_IN_PORT || header == OXM_OF_ETH_TYPE
        || header == OXM_OF_VLAN_VID || header == OXM_OF_IP_PROTO) {
        return true;
    }
    return false;
}

/* Puts the match in the buffer */
int oxm_put_match(struct ofpbuf *buf, struct ofl_match *omt){

    struct ofl_match_tlv *oft;
    int start_len = buf->size;
    int match_len;


    /* We put all pre-requisites fields first */
    /* In port present */
    HMAP_FOR_EACH_WITH_HASH(oft, struct ofl_match_tlv, hmap_node, DP_FIELD_HASH(OXM_OF_IN_PORT),
          &omt->match_fields) {
        unsigned int value;
        memcpy(&value, oft->value,sizeof(unsigned int));
        oxm_put_32(buf,oft->header, htonl(value));
    }

    /* L2 Pre-requisites */

    /* Ethernet type */
    HMAP_FOR_EACH_WITH_HASH(oft, struct ofl_match_tlv, hmap_node, DP_FIELD_HASH(OXM_OF_ETH_TYPE),
          &omt->match_fields) {
        unsigned short int value;
        memcpy(&value, oft->value,sizeof(unsigned short int));
        oxm_put_16(buf,oft->header, htons(value));
    }

     /* VLAN ID */
    HMAP_FOR_EACH_WITH_HASH(oft, struct ofl_match_tlv, hmap_node, DP_FIELD_HASH(OXM_OF_VLAN_VID),
          &omt->match_fields) {
         unsigned short int value;
         memcpy(&value, oft->value,sizeof(unsigned short int));
         /*l00135737 set vlan CFI*/
         if(!(value & 0x1000))
         {
            value |= 0x1000;
         }
         oxm_put_16(buf,oft->header, htons(value));
    }

    /* L3 Pre-requisites */
     HMAP_FOR_EACH_WITH_HASH(oft, struct ofl_match_tlv, hmap_node, DP_FIELD_HASH(OXM_OF_IP_PROTO),
          &omt->match_fields) {
         unsigned char value;
         memcpy(&value, oft->value,sizeof(unsigned char));
         oxm_put_8(buf,oft->header, value);
    }

    /* Loop through the remaining fields */
    HMAP_FOR_EACH(oft, struct ofl_match_tlv, hmap_node, &omt->match_fields){

        if (is_requisite(oft->header))
            /*We already inserted  fields that are pre requisites to others */
             continue;
        else {
            unsigned char length = OXM_LENGTH(oft->header) ;
            bool has_mask =false;
            if (OXM_HASMASK(oft->header)){
               length = length / 2;
               has_mask = true;
            }
            switch (length){
                case (sizeof(unsigned char)):{
                    unsigned char value;
                    memcpy(&value, oft->value,sizeof(unsigned char));
                    if(!has_mask)
                    {
                        oxm_put_8(buf,oft->header, value);
                    }
                    else
                    {
                        unsigned char mask;
                        memcpy(&mask,oft->value + length ,sizeof(unsigned char));
                        oxm_put_8w(buf, oft->header,value,mask);
                    }
                    break;
                  }
                case (sizeof(unsigned short int)):{
                    unsigned short int value;
                    memcpy(&value, oft->value,sizeof(unsigned short int));
                    if(!has_mask)
                        oxm_put_16(buf,oft->header, htons(value));
                    else {
                        unsigned short int mask;
                        memcpy(&mask,oft->value + length ,sizeof(unsigned short int));
                        oxm_put_16w(buf, oft->header,htons(value),htons(mask));
                    }
                    break;
                }
                case (sizeof(unsigned int)):{
                    unsigned int value;
                    memcpy(&value, oft->value,sizeof(unsigned int));
                    if(!has_mask)
                        if (oft->header == OXM_OF_IPV4_DST || oft->header == OXM_OF_IPV4_SRC
                            ||oft->header == OXM_OF_ARP_SPA || oft->header == OXM_OF_ARP_TPA)
                            oxm_put_32(buf,oft->header, value);
                        else
                            oxm_put_32(buf,oft->header, htonl(value));
                    else {
                         unsigned int mask;
                         memcpy(&mask,oft->value + length ,sizeof(unsigned int));
                         if (oft->header == OXM_OF_IPV4_DST_W|| oft->header == OXM_OF_IPV4_SRC_W
                            ||oft->header == OXM_OF_ARP_SPA_W || oft->header == OXM_OF_ARP_TPA_W)
                            oxm_put_32w(buf, oft->header, value, mask);
                         else
                            oxm_put_32w(buf, oft->header, htonl(value),htonl(mask));
                    }
                      break;

                }
                case (sizeof(unsigned long long int)):{
                     unsigned long long int value;
                     memcpy(&value, oft->value,sizeof(unsigned long long int));
                     if(!has_mask)
                         oxm_put_64(buf,oft->header, value);
                     else {
                         unsigned long long int mask;
                         memcpy(&mask,oft->value + length ,sizeof(unsigned long long int));
                         oxm_put_64w(buf, oft->header,value,mask);
                     }
                     break;
                }
                case (ETH_ADDR_LEN):{
                     unsigned char value[ETH_ADDR_LEN];
                     memcpy(&value, oft->value,ETH_ADDR_LEN);
                     if(!has_mask)
                         oxm_put_eth(buf,oft->header, value);
                     else {
                         unsigned char mask[ETH_ADDR_LEN];
                         memcpy(&mask,oft->value + length ,ETH_ADDR_LEN);
                         oxm_put_ethm(buf, oft->header,value,mask);
                      }
                      break;
                   }
               case (IPv6_ADDR_LEN):{
                     unsigned char value[IPv6_ADDR_LEN];
                     memcpy(value, oft->value,IPv6_ADDR_LEN);
                     if(!has_mask)
                         oxm_put_ipv6(buf,oft->header, value);
                     else {
                         unsigned char mask[IPv6_ADDR_LEN];
                         memcpy(&mask,oft->value + length ,IPv6_ADDR_LEN);
                         oxm_put_ipv6m(buf, oft->header,value,mask);
                      }
                      break;
                   }
            }
        }
    }

    match_len = buf->size - start_len;
    ofpbuf_put_zeros(buf, ROUND_UP(match_len - 4, 8) - (match_len -4));
    return match_len;
}

/* Puts the match extracted from packets in the buffer
TODO: That function is the same as the above, except by the fact it
doesn't change the values byte order. It's necessaire because packet data
already comes in the network byte order, so if we use the other function, values
will not be in the desired format. */
int oxm_put_packet_match(struct ofpbuf *buf, struct ofl_match *omt){

    struct ofl_match_tlv *oft;
    int start_len = buf->size;
    int match_len;


    /* We put all pre-requisites fields first */
    /* In port present */
    HMAP_FOR_EACH_WITH_HASH(oft, struct ofl_match_tlv, hmap_node, DP_FIELD_HASH(OXM_OF_IN_PORT),
          &omt->match_fields) {
        unsigned int value;
        memcpy(&value, oft->value,sizeof(unsigned int));
        oxm_put_32(buf,oft->header, value);
    }

    /* L2 Pre-requisites */

    /* Ethernet type */
    HMAP_FOR_EACH_WITH_HASH(oft, struct ofl_match_tlv, hmap_node, DP_FIELD_HASH(OXM_OF_ETH_TYPE),
          &omt->match_fields) {
        unsigned short int value;
        memcpy(&value, oft->value,sizeof(unsigned short int));
        oxm_put_16(buf,oft->header, value);
    }

     /* VLAN ID */
    HMAP_FOR_EACH_WITH_HASH(oft, struct ofl_match_tlv, hmap_node, DP_FIELD_HASH(OXM_OF_VLAN_VID),
          &omt->match_fields) {
         unsigned short int value;
         memcpy(&value, oft->value,sizeof(unsigned short int));
         oxm_put_16(buf,oft->header, value);
    }

    /* L3 Pre-requisites */
     HMAP_FOR_EACH_WITH_HASH(oft, struct ofl_match_tlv, hmap_node, DP_FIELD_HASH(OXM_OF_IP_PROTO),
          &omt->match_fields) {
         unsigned char value;
         memcpy(&value, oft->value,sizeof(unsigned char));
         oxm_put_8(buf,oft->header, value);
    }

    /* Loop through the remaining fields */
    HMAP_FOR_EACH(oft, struct ofl_match_tlv, hmap_node, &omt->match_fields){

        if (is_requisite(oft->header))
            /*We already inserted  fields that are pre requisites to others */
             continue;
        else {
            unsigned char length = OXM_LENGTH(oft->header) ;
            bool has_mask =false;
            if (OXM_HASMASK(oft->header)){
               length = length / 2;
               has_mask = true;
            }
            switch (length){
                case (sizeof(unsigned char)):{
                    unsigned char value;
                    memcpy(&value, oft->value,sizeof(unsigned char));
                    if(!has_mask)
                        oxm_put_8(buf,oft->header, value);
                    else {
                        unsigned char mask;
                        memcpy(&mask,oft->value + length ,sizeof(unsigned char));
                        oxm_put_8w(buf, oft->header,value,mask);
                    }
                    break;
                  }
                case (sizeof(unsigned short int)):{
                    unsigned short int value;
                    memcpy(&value, oft->value,sizeof(unsigned short int));
                    if(!has_mask)
                        oxm_put_16(buf,oft->header, value);
                    else {
                        unsigned short int mask;
                        memcpy(&mask,oft->value + length ,sizeof(unsigned short int));
                        oxm_put_16w(buf, oft->header,value,mask);
                    }
                    break;
                }
                case (sizeof(unsigned int)):{
                    unsigned int value;
                    memcpy(&value, oft->value,sizeof(unsigned int));
                    if(!has_mask)
                         oxm_put_32(buf,oft->header, value);
                    else {
                         unsigned int mask;
                         memcpy(&mask,oft->value + length ,sizeof(unsigned int));
                         oxm_put_32w(buf, oft->header, value, mask);
                    }
                      break;

                }
                case (sizeof(unsigned long long int)):{
                     unsigned long long int value;
                     memcpy(&value, oft->value,sizeof(unsigned long long int));
                     if(!has_mask)
                         oxm_put_64(buf,oft->header, value);
                     else {
                         unsigned long long int mask;
                         memcpy(&mask,oft->value + length ,sizeof(unsigned long long int));
                         oxm_put_64w(buf, oft->header, value, mask);
                     }
                     break;
                }
                case (ETH_ADDR_LEN):{
                     unsigned char value[ETH_ADDR_LEN];
                     memcpy(&value, oft->value,ETH_ADDR_LEN);
                     if(!has_mask)
                         oxm_put_eth(buf,oft->header, value);
                     else {
                         unsigned char mask[ETH_ADDR_LEN];
                         memcpy(&mask,oft->value + length ,ETH_ADDR_LEN);
                         oxm_put_ethm(buf, oft->header,value,mask);
                      }
                      break;
                   }
               case (IPv6_ADDR_LEN):{
                     unsigned char value[IPv6_ADDR_LEN];
                     memcpy(value, oft->value,IPv6_ADDR_LEN);
                     if(!has_mask)
                         oxm_put_ipv6(buf,oft->header, value);
                     else {
                         unsigned char mask[IPv6_ADDR_LEN];
                         memcpy(&mask,oft->value + length ,IPv6_ADDR_LEN);
                         oxm_put_ipv6m(buf, oft->header,value,mask);
                      }
                      break;
                   }
            }
        }
    }

    match_len = buf->size - start_len;
    ofpbuf_put_zeros(buf, ROUND_UP(match_len - 4, 8) - (match_len -4));
    return match_len;
}

unsigned int field_hash[OFPXMT_MAX][2];

void oxm_match_init(void)
{
    int i;
    unsigned int field_header[OFPXMT_MAX] =   {OXM_OF_IN_PORT,
                                           OXM_OF_IN_PHY_PORT,
                                       OXM_OF_METADATA,
                                       OXM_OF_ETH_DST,
                                       OXM_OF_ETH_SRC,
                                       OXM_OF_ETH_TYPE,
                                       OXM_OF_VLAN_VID,
                                       OXM_OF_VLAN_PCP,
                                       OXM_OF_IP_DSCP,
                                       OXM_OF_IP_ECN,
                                       OXM_OF_IP_PROTO,
                                       OXM_OF_IPV4_SRC,
                                       OXM_OF_IPV4_DST,
                                       OXM_OF_TCP_SRC,
                                       OXM_OF_TCP_DST,
                                       OXM_OF_UDP_SRC,
                                       OXM_OF_UDP_DST,
                                       OXM_OF_SCTP_SRC,
                                       OXM_OF_SCTP_DST,
                                       OXM_OF_ICMPV4_TYPE,
                                       OXM_OF_ICMPV4_CODE,
                                       OXM_OF_ARP_OP,
                                       OXM_OF_ARP_SPA,
                                       OXM_OF_ARP_TPA,
                                       OXM_OF_ARP_SHA,
                                       OXM_OF_ARP_THA,
                                       OXM_OF_IPV6_SRC,
                                       OXM_OF_IPV6_DST,
                                       OXM_OF_IPV6_FLABEL,
                                       OXM_OF_ICMPV6_TYPE,
                                       OXM_OF_ICMPV6_CODE,
                                       OXM_OF_IPV6_ND_TARGET,
                                       OXM_OF_IPV6_ND_SLL,
                                       OXM_OF_IPV6_ND_TLL,
                                       OXM_OF_MPLS_LABEL,
                                       OXM_OF_MPLS_TC,
                                       OXM_OF_MPLS_BOS,
                                       OXM_OF_PBB_ISID,
                                       OXM_OF_TUNNEL_ID,
                                       OXM_OF_IPV6_EXTHDR};

    for (i = 0; i < OFPXMT_MAX; i++)
    {
        field_hash[i][0] = hash_int(field_header[i], 0);
        field_hash[i][1] = hash_int(OXM_MAKE_WILD_HEADER(field_header[i]), 0);
    }

    return;
}


