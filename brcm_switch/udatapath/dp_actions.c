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

#include <netinet/in.h>
#include "csum.h"
#include "dp_exp.h"
#include "dp_actions.h"
#include "dp_buffers.h"
#include "datapath.h"
#include "oflib/ofl.h"
#include "oflib/ofl-actions.h"
#include "oflib/ofl-log.h"
#include "packet.h"
#include "packets.h"
#include "pipeline.h"
#include "util.h"
#include "oflib/oxm-match.h"
#include "hash.h"
#include "pipeline.h"

#define LOG_MODULE VLM_dp_acts

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

static void
output(struct packet *pkt, struct ofl_action_output *action) {
    pkt->out_port = action->port;

    if (action->port == OFPP_CONTROLLER) {
        pkt->out_port_max_len = action->max_len;
    }
}

static void
set_ip_dscp(struct packet *pkt, unsigned char *value)
{
    if (pkt->handle_std->proto->ipv4 != NULL)
    {
        struct ip_header *ipv4 = pkt->handle_std->proto->ipv4;
        unsigned char new_value;
        new_value = (ipv4->ip_tos & IP_ECN_MASK) | (( *value << 2) & IP_DSCP_MASK);
        ipv4->ip_csum = recalc_csum16(ipv4->ip_csum, htons((unsigned short int)(ipv4->ip_tos)), htons((unsigned short int)new_value));
        ipv4->ip_tos = new_value;

        pkt->handle_std->valid = false;
    }
    else if( NULL != pkt->handle_std->proto->ipv6)
    {
        struct ipv6_header *ipv6 = pkt->handle_std->proto->ipv6;
        unsigned int tc_flow = ntohl(ipv6->ip6_flow);
        unsigned int new_value = *value;

        new_value = new_value << 22;
        tc_flow = (tc_flow & ~0x0fc00000) | new_value;

        ipv6->ip6_flow = ntohl(tc_flow);
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_IP_DSCP action on packet with no ip dscp.");
    }
}

static void set_ip_ecn(struct packet *pkt, unsigned char *value)
{
    if (pkt->handle_std->proto->ipv4 != NULL)
    {
        struct ip_header *ipv4 = pkt->handle_std->proto->ipv4;
        unsigned char new_value;

        new_value = (ipv4->ip_tos & IP_DSCP_MASK) | (*(value)  & IP_ECN_MASK);
        ipv4->ip_csum = recalc_csum16(ipv4->ip_csum, htons((unsigned short int)(ipv4->ip_tos)), htons((unsigned short int)new_value));
        ipv4->ip_tos = new_value;
        pkt->handle_std->valid = false;
    }
    else if( NULL != pkt->handle_std->proto->ipv6)
    {
        struct ipv6_header *ipv6 = pkt->handle_std->proto->ipv6;
        unsigned int tc_flow = ntohl(ipv6->ip6_flow);
        unsigned int new_value = *value;

        new_value = new_value << 20;
        tc_flow = (tc_flow & ~0x00300000) | new_value;

        ipv6->ip6_flow = ntohl(tc_flow);
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_IP_ECN action on packet with no ip_ecn.");
    }
}

static void set_vlan_vid(struct packet *pkt, unsigned char *value)
{
    if (pkt->handle_std->proto->vlan != NULL)
    {
        struct vlan_header *vlan = pkt->handle_std->proto->vlan;
        vlan->vlan_tci = htons((ntohs(vlan->vlan_tci) & ~VLAN_VID_MASK) |
                           (*((unsigned short int *)value) & VLAN_VID_MASK));
        pkt->handle_std->valid = false;

        if (pkt->dp)
        {
            pkt->dp->vlan = *((unsigned short int *)value) & VLAN_VID_MASK;
        }
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_VLAN_VID action on packet with no vlan.");
    }
}

static void set_vlan_pcp(struct packet *pkt, unsigned char *value)
{
    if (pkt->handle_std->proto->vlan != NULL)
    {
        struct vlan_header *vlan = pkt->handle_std->proto->vlan;

        vlan->vlan_tci = (vlan->vlan_tci & ~htons(VLAN_PCP_MASK))
            | htons( *((unsigned char *)value) << VLAN_PCP_SHIFT);
        pkt->handle_std->valid = false;
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_VLAN_PCP action on packet with no vlan.");
    }
}

static void set_mpls_label(struct packet *pkt, unsigned char *value)
{
    if (pkt->handle_std->proto->mpls != NULL)
    {
        struct mpls_header *mpls = pkt->handle_std->proto->mpls;
        mpls->fields = (mpls->fields & ~ntohl(MPLS_LABEL_MASK))
            | ntohl( ( *((unsigned int *)value) << MPLS_LABEL_SHIFT) & MPLS_LABEL_MASK);
        pkt->handle_std->valid = false;
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_MPLS_LABEL action on packet with no mpls.");
    }
}

static void
set_mpls_tc(struct packet *pkt, unsigned char *value)
{
    if (pkt->handle_std->proto->mpls != NULL)
    {
        struct mpls_header *mpls = pkt->handle_std->proto->mpls;
        mpls->fields = (mpls->fields & ~ntohl(MPLS_TC_MASK))
            | ntohl((*((unsigned char *)value) << MPLS_TC_SHIFT) & MPLS_TC_MASK);
        pkt->handle_std->valid = false;
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_MPLS_TC action on packet with no mpls.");
    }
}

static void
set_mpls_bos(struct packet *pkt, unsigned char *value)
{
    if (pkt->handle_std->proto->mpls != NULL)
    {
        struct mpls_header *mpls = pkt->handle_std->proto->mpls;
        mpls->fields = (mpls->fields & ~ntohl(MPLS_S_MASK))
            | ntohl((*((unsigned int *)value) << MPLS_S_SHIFT) & MPLS_S_MASK);
        pkt->handle_std->valid = false;
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute set_mpls_bos action on packet with no mpls.");
    }
}

static void set_eth_src(struct packet *pkt, unsigned char *value,unsigned char len)
{
    if (pkt->handle_std->proto->eth != NULL)
    {
        struct eth_header *eth = pkt->handle_std->proto->eth;
        memcpy(eth->eth_src, value, len);
        pkt->handle_std->valid = false;
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_ETH_SRC action on packet with no eth.");
    }
}

static void set_eth_dst(struct packet *pkt, unsigned char *value,unsigned char len)
{
    if (pkt->handle_std->proto->eth != NULL)
    {
        struct eth_header *eth = pkt->handle_std->proto->eth;
        memcpy(eth->eth_dst, value, len);
        pkt->handle_std->valid = false;
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_ETH_SRC action on packet with no eth.");
    }
}

static void set_ipv4_addr(struct packet *pkt,unsigned char *val,unsigned int type)
{
    unsigned int value;
    unsigned int  *field;
    struct ip_header *ipv4;

    if (pkt->handle_std->proto->ipv4 != NULL)
    {
        ipv4 = pkt->handle_std->proto->ipv4;
        value =  (*((unsigned int*) val));
        field = type == OXM_OF_IPV4_SRC ? &ipv4->ip_src : &ipv4->ip_dst;

        if (pkt->handle_std->proto->tcp != NULL) {
            struct tcp_header *tcp = pkt->handle_std->proto->tcp;

            tcp->tcp_csum = recalc_csum32(tcp->tcp_csum, *field,value);
        } else if (pkt->handle_std->proto->udp != NULL) {
            struct udp_header *udp = pkt->handle_std->proto->udp;
            udp->udp_csum = recalc_csum32(udp->udp_csum, *field, value);

        }

        ipv4->ip_csum = recalc_csum32(ipv4->ip_csum, *field, value);

        *field = value;
        pkt->handle_std->valid = false;
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_IPV4 action on packet with no ipv4.");
    }

}

static void set_ipv6_src(struct packet *pkt, unsigned char *value,unsigned char len)
{
   int i;

    if (pkt->handle_std->proto->ipv6 != NULL)
    {
        struct ipv6_header *ipv6 = pkt->handle_std->proto->ipv6;

        unsigned short int * old_field = ipv6->ip6_src;
        unsigned short int * new_field = value;

        if (pkt->handle_std->proto->tcp != NULL)
        {
            struct tcp_header *tcp = pkt->handle_std->proto->tcp;

            for(i=0; i<8; i++)
            {
                tcp->tcp_csum = recalc_csum16(tcp->tcp_csum, *(old_field+i),*(new_field+i));
            }
        }
        else if (pkt->handle_std->proto->udp != NULL)
        {
            struct udp_header *udp = pkt->handle_std->proto->udp;

            for(i=0; i<8; i++)
            {
                udp->udp_csum = recalc_csum16(udp->udp_csum, *(old_field+i),*(new_field+i));
            }
        }
        memcpy(ipv6->ip6_src,value,len);
        pkt->handle_std->valid = false;
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_IPV6_SRC action on packet with no ipv6.");
    }
}

static void set_ipv6_dst(struct packet *pkt, unsigned char *value,unsigned char len)
{
    int i;

    if (pkt->handle_std->proto->ipv6 != NULL)
    {
        struct ipv6_header *ipv6 = pkt->handle_std->proto->ipv6;
        unsigned short int * old_field = ipv6->ip6_dst;
        unsigned short int * new_field = value;

        if (pkt->handle_std->proto->tcp != NULL)
        {
            struct tcp_header *tcp = pkt->handle_std->proto->tcp;

            for(i=0; i<8; i++)
            {
                tcp->tcp_csum = recalc_csum16(tcp->tcp_csum, *(old_field+i),*(new_field+i));
            }
        }
        else if (pkt->handle_std->proto->udp != NULL)
        {
            struct udp_header *udp = pkt->handle_std->proto->udp;

            for(i=0; i<8; i++)
            {
                udp->udp_csum = recalc_csum16(udp->udp_csum, *(old_field+i),*(new_field+i));
            }
        }

        memcpy(ipv6->ip6_dst,value,len);
        pkt->handle_std->valid = false;
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_IPV6_SRC action on packet with no ipv6.");
    }
}

static void set_tp_src(struct packet *pkt, unsigned char *value)
{
    unsigned short int port = 0;
    if (pkt->handle_std->proto->tcp != NULL)
    {
        struct tcp_header *tcp = pkt->handle_std->proto->tcp;
        port = *((unsigned short int *)value);
        tcp->tcp_csum = recalc_csum16(tcp->tcp_csum, tcp->tcp_src, htons(port));
        tcp->tcp_src = htons(port);
        pkt->handle_std->valid = false;
    }
    else if (pkt->handle_std->proto->udp != NULL)
    {
        struct udp_header *udp = pkt->handle_std->proto->udp;

        port = *((unsigned short int *)value);
        udp->udp_csum = recalc_csum16(udp->udp_csum, udp->udp_src, htons(port));
        udp->udp_src = htons(port);
        pkt->handle_std->valid = false;
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_TP_SRC action on packet with no tp.");
    }
}

static void set_tp_dst(struct packet *pkt, unsigned char *value)
{
    unsigned short int port = 0;

    if (pkt->handle_std->proto->tcp != NULL)
    {
        struct tcp_header *tcp = pkt->handle_std->proto->tcp;
        port = *((unsigned short int *)value);

        tcp->tcp_csum = recalc_csum16(tcp->tcp_csum, tcp->tcp_dst, htons(port));
        tcp->tcp_dst = htons(port);
        pkt->handle_std->valid = false;

    }
    else if (pkt->handle_std->proto->udp != NULL)
    {
        struct udp_header *udp = pkt->handle_std->proto->udp;

        port = *((unsigned short int *)value);
        udp->udp_csum = recalc_csum16(udp->udp_csum, udp->udp_dst, htons(port));
        udp->udp_dst = htons(port);
        pkt->handle_std->valid = false;
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_TP_DST action on packet with no tp.");
    }
}

static void set_eth_type(struct packet *pkt, unsigned char *value)
{
    unsigned short int eth_type =0;

    if (pkt->handle_std->proto->eth != NULL)
    {
        struct eth_header *eth = pkt->handle_std->proto->eth;
        eth_type = *((unsigned short int *)value);

        eth->eth_type =htons(eth_type);

        pkt->handle_std->valid = false;
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_ETH_TYPE action on packet with no tp.");
    }
}

static void set_ipv6_flable(struct packet *pkt, unsigned char *value)
{
    unsigned int flow_lable;

    if( NULL != pkt->handle_std->proto->ipv6)
    {
        flow_lable = ntohl(pkt->handle_std->proto->ipv6->ip6_flow);
        flow_lable = flow_lable & ~0x000fffff | *( (unsigned int*)(value) );
        pkt->handle_std->proto->ipv6->ip6_flow = ntohl(flow_lable);
        pkt->handle_std->valid = false;
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute set_ipv6_flable action on packet with no tp.");
    }
}

static void set_icmpv6_type(struct packet *pkt, unsigned char *value)
{
    unsigned char type;
    unsigned short int old_value;
    unsigned short int new_value;
    struct icmp_header *icmp;

    if( NULL != pkt->handle_std->proto->icmp)
    {
        icmp = pkt->handle_std->proto->icmp;
        old_value = (icmp->icmp_type << 8) + icmp->icmp_code;
        new_value = (*value << 8) + icmp->icmp_code;

        icmp->icmp_csum = recalc_csum16(icmp->icmp_csum, htons(old_value), htons(new_value));
        icmp->icmp_type = *value;
        pkt->handle_std->valid = false;
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute set_icmpv6_type action on packet with no tp.");
    }
}

static void set_ipv6_nd_target(struct packet *pkt, unsigned char *value)
{
    unsigned short int *old_value;
    unsigned short int *new_value;
    struct icmpv6_nd_header *icmp;
    int i;

    if( NULL != pkt->handle_std->proto->icmp)
    {
        icmp = pkt->handle_std->proto->icmp;

        old_value = (unsigned char *)icmp + 4 +4;
        new_value = value;
        for( i=0; i<8; i++)
        {
            icmp->icmp_csum = recalc_csum16(icmp->icmp_csum, *(old_value+i), *(new_value+i));
        }
        memcpy(icmp->target,value,16);
        pkt->handle_std->valid = false;
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute set_ipv6_nd_target action on packet with no tp.");
    }
}

static void set_ipv6_nd_sll(struct packet *pkt, unsigned char *value)
{
    unsigned short int *old_value;
    unsigned short int *new_value;
    struct icmpv6_nd_header *icmp;
    int i;

    if( NULL != pkt->handle_std->proto->icmp)
    {
        icmp = pkt->handle_std->proto->icmp;

        old_value = icmp->option.mac;
        new_value = value;
        for( i=0; i<3; i++)
        {
            icmp->icmp_csum = recalc_csum16(icmp->icmp_csum, *(old_value+i), *(new_value+i));
        }
        memcpy(icmp->option.mac,value,6);
        pkt->handle_std->valid = false;
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute set_ipv6_nd_sll action on packet with no tp.");
    }
}


static void set_icmp_code(struct packet *pkt, unsigned char *value)
{
    unsigned char type;
    unsigned short int old_value;
    unsigned short int new_value;
    struct icmp_header *icmp;

    if( NULL != pkt->handle_std->proto->icmp)
    {
        icmp = pkt->handle_std->proto->icmp;
        old_value = (icmp->icmp_type << 8) + icmp->icmp_code;
        new_value = (icmp->icmp_type << 8) + *value;

        icmp->icmp_csum = recalc_csum16(icmp->icmp_csum, htons(old_value), htons(new_value));
        icmp->icmp_code = *value;
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute set_icmpv6_type action on packet with no tp.");
    }
}

static void set_arp_op(struct packet *pkt, unsigned char *value)
{
    struct arp_eth_header  * arp;

    arp = pkt->handle_std->proto->arp;
    arp->ar_op = htons( *((unsigned short int*)value) );
}

static void set_arp_spa(struct packet *pkt, unsigned char *value)
{
    struct arp_eth_header  * arp;

    arp = pkt->handle_std->proto->arp;
    arp->ar_spa = (*((unsigned int*) value));
}

static void set_arp_tpa(struct packet *pkt, unsigned char *value)
{
    struct arp_eth_header  * arp;

    arp = pkt->handle_std->proto->arp;
    arp->ar_tpa = (*((unsigned int*) value));
}

static void set_arp_sha(struct packet *pkt, unsigned char *value)
{
    struct arp_eth_header  * arp;

    arp = pkt->handle_std->proto->arp;
    memcpy(arp->ar_sha,value,6);
}

static void set_arp_tha(struct packet *pkt, unsigned char *value)
{
    struct arp_eth_header  * arp;

    arp = pkt->handle_std->proto->arp;
    memcpy(arp->ar_tha,value,6);
}

generate_crc32c(unsigned char *buffer, unsigned int length);
static void set_sctp_src(struct packet *pkt, unsigned char *value)
{
    struct sctp_header  * sctp;
    unsigned char *buff;
    unsigned int len;

    sctp = pkt->handle_std->proto->sctp;

    sctp->sctp_csum = 0;
    sctp->sctp_src = htons(*((unsigned short int*) value));

    buff =  (unsigned char*)sctp;
}

static void set_sctp_dst(struct packet *pkt, unsigned char *value)
{
    struct sctp_header  * sctp;

    sctp = pkt->handle_std->proto->sctp;
    sctp->sctp_dst = htons(*((unsigned short int*) value));
}
#if 1
static void set_field(struct packet *pkt, struct ofl_action_set_field *act )
{
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->valid)
    {
        struct ofl_match_tlv *field = act->field;
        switch(field->header)
        {
            case OXM_OF_VLAN_VID:
            {
                set_vlan_vid(pkt,field->value);
                break;
            }
            case OXM_OF_VLAN_PCP:
            {
                set_vlan_pcp(pkt,field->value);
                break;
            }
            case OXM_OF_ETH_SRC:
            {
                set_eth_src(pkt,field->value,OXM_LENGTH(field->header));
                break;
            }
            case OXM_OF_ETH_DST:
            {
                set_eth_dst(pkt,field->value,OXM_LENGTH(field->header));
                break;
            }
             case OXM_OF_MPLS_LABEL:
            {
                set_mpls_label(pkt, field->value);
                break;
            }
            case OXM_OF_MPLS_TC:
            {
                set_mpls_tc(pkt, field->value);
                break;
            }
            case OXM_OF_IPV6_SRC:
            {
                set_ipv6_src(pkt,field->value,OXM_LENGTH(field->header));
                break;
            }
            case OXM_OF_IPV6_DST:
            {
                set_ipv6_dst(pkt,field->value,OXM_LENGTH(field->header));
                break;
            }
            case OXM_OF_IPV4_SRC:
            {
                set_ipv4_addr(pkt,field->value,field->header);
                break;
            }
            case OXM_OF_IPV4_DST:
            {
                set_ipv4_addr(pkt,field->value,field->header);
                break;
            }
            case OXM_OF_IP_DSCP:
            {
                set_ip_dscp(pkt,field->value);
                break;
            }
            case OXM_OF_IP_ECN:
            {
                set_ip_ecn(pkt,field->value);
                break;
            }
            case OXM_OF_TCP_SRC:
            case OXM_OF_UDP_SRC:
            {
                set_tp_src(pkt,field->value);
                break;
            }
            case OXM_OF_TCP_DST:
            case OXM_OF_UDP_DST:
            {
                set_tp_dst(pkt,field->value);
                break;
            }
            case OXM_OF_ETH_TYPE:
            {
                set_eth_type(pkt,field->value);
                break;
            }
            case OXM_OF_IPV6_FLABEL:
            {
                set_ipv6_flable(pkt,field->value);
                break;
            }
            case OXM_OF_ICMPV6_TYPE:
            case OXM_OF_ICMPV4_TYPE:
            {
                set_icmpv6_type(pkt,field->value);
                break;
            }
            case OXM_OF_ICMPV6_CODE:
            case OXM_OF_ICMPV4_CODE:
            {
                set_icmp_code(pkt,field->value);
                break;
            }
            case OXM_OF_MPLS_BOS:
            {
                set_mpls_bos(pkt,field->value);
                break;
            }
            case OXM_OF_IPV6_ND_TARGET:
            {
                set_ipv6_nd_target(pkt,field->value);
                break;
            }
            case OXM_OF_IPV6_ND_SLL:
            {
                set_ipv6_nd_sll(pkt,field->value);
                break;
            }
            case OXM_OF_IPV6_ND_TLL:
            {
                set_ipv6_nd_sll(pkt,field->value);
                break;
            }
            case OXM_OF_ARP_OP:
            {
                set_arp_op(pkt,field->value);
                break;
            }
            case OXM_OF_ARP_SPA:
            {
                set_arp_spa(pkt,field->value);
                break;
            }
            case OXM_OF_ARP_TPA:
            {
                set_arp_tpa(pkt,field->value);
                break;
            }
            case OXM_OF_ARP_SHA:
            {
                set_arp_sha(pkt,field->value);
                break;
            }
            case OXM_OF_ARP_THA:
            {
                set_arp_tha(pkt,field->value);
                break;
            }
            case OXM_OF_SCTP_SRC:
            {
                set_sctp_src(pkt,field->value);
                break;
            }
            case OXM_OF_SCTP_DST:
            {
                set_sctp_dst(pkt,field->value);
                break;
            }
            // <==
            default:
            {
                VLOG_WARN_RL(LOG_MODULE, &rl,
                    "Trying to execute SET_FIELD :%u action on packet with no corresponding field.",field->header);
                break;
            }
        }
        packet_handle_std_validate(pkt->handle_std);
    }
    else
    {
         VLOG_WARN_RL(LOG_MODULE, &rl, "standard packet invalid.");
    }
}

#endif

static void
copy_ttl_out(struct packet *pkt, struct ofl_action_header *act UNUSED) {
    struct ip_header   *ipv4 = NULL;
    struct ipv6_header *ipv6 = NULL;

    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->mpls != NULL)
    {
        ipv4 = pkt->handle_std->proto->ipv4;
        ipv6 = pkt->handle_std->proto->ipv6;

        struct mpls_header *mpls = pkt->handle_std->proto->mpls;

        if ((ntohl(mpls->fields) & MPLS_S_MASK) == 0)
        {
            struct mpls_header *in_mpls = (struct mpls_header *)((unsigned char *)mpls + MPLS_HEADER_LEN);

            mpls->fields = (mpls->fields & ~htonl(MPLS_TTL_MASK)) | (in_mpls->fields & htonl(MPLS_TTL_MASK));
            if (ipv4)
            {
                mpls->fields = (mpls->fields & ~htonl(MPLS_TTL_MASK)) | htonl((unsigned int)ipv4->ip_ttl & MPLS_TTL_MASK);
            }
            else if (ipv6)
            {
                mpls->fields = (mpls->fields & ~htonl(MPLS_TTL_MASK)) | htonl((unsigned int)ipv6->ip6_hlim & MPLS_TTL_MASK);
            }
            pkt->handle_std->valid = false;
        }
        else if (pkt->buffer->size >= ETH_HEADER_LEN + MPLS_HEADER_LEN + IP_HEADER_LEN)
        {
            if (ipv4)
            {
                mpls->fields = (mpls->fields & ~htonl(MPLS_TTL_MASK)) | htonl((unsigned int)ipv4->ip_ttl & MPLS_TTL_MASK);
            }
            else if (ipv6)
            {
                mpls->fields = (mpls->fields & ~htonl(MPLS_TTL_MASK)) | htonl((unsigned int)ipv6->ip6_hlim & MPLS_TTL_MASK);
            }

            pkt->handle_std->valid = false;
        }
        else
        {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute copy ttl in action on packet with only one mpls.");
        }
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute COPY_TTL_OUT action on packet with no mpls.");
    }
}

static void
copy_ttl_in(struct packet *pkt, struct ofl_action_header *act UNUSED) {
    struct ip_header   *ipv4 = NULL;
    struct ipv6_header *ipv6 = NULL;

    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->mpls != NULL) {
        struct mpls_header *mpls = pkt->handle_std->proto->mpls;

        ipv4 = pkt->handle_std->proto->ipv4;
        ipv6 = pkt->handle_std->proto->ipv6;

        if ((ntohl(mpls->fields) & MPLS_S_MASK) == 0)
        {
            struct mpls_header *in_mpls = (struct mpls_header *)((unsigned char *)mpls + MPLS_HEADER_LEN);

            in_mpls->fields = (in_mpls->fields & ~htonl(MPLS_TTL_MASK)) | (mpls->fields & htonl(MPLS_TTL_MASK));
            pkt->handle_std->valid = false;

        } else if (pkt->buffer->size >= ETH_HEADER_LEN + MPLS_HEADER_LEN + IP_HEADER_LEN) {
            if (ipv4) {
                unsigned char new_ttl = (ntohl(mpls->fields) & MPLS_TTL_MASK) >> MPLS_TTL_SHIFT;
                unsigned short int old_val = htons((ipv4->ip_proto) + (ipv4->ip_ttl<<8));
                unsigned short int new_val = htons((ipv4->ip_proto) + (new_ttl<<8));
                ipv4->ip_csum = recalc_csum16(ipv4->ip_csum, old_val, new_val);
                ipv4->ip_ttl = new_ttl;
            } else if (ipv6) {
                ipv6->ip6_hlim = (ntohl(mpls->fields) & MPLS_TTL_MASK) >> MPLS_TTL_SHIFT;
            }
            pkt->handle_std->valid = false;

        } else {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute copy ttl in action on packet with only one mpls.");
        }
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute COPY_TTL_IN action on packet with no mpls.");
    }
}

static void
push_vlan(struct packet *pkt, struct ofl_action_push *act) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->eth != NULL) {
        struct eth_header  *eth,  *new_eth;
        struct snap_header *snap, *new_snap;
        struct vlan_header *vlan, *new_vlan, *push_vlan;
        size_t eth_size;

        eth = pkt->handle_std->proto->eth;
        snap = pkt->handle_std->proto->eth_snap;
        vlan = pkt->handle_std->proto->vlan;

        eth_size = snap == NULL
                   ? ETH_HEADER_LEN
                   : ETH_HEADER_LEN + LLC_HEADER_LEN + SNAP_HEADER_LEN;

        if (ofpbuf_headroom(pkt->buffer) >= VLAN_HEADER_LEN) {
            pkt->buffer->data = (unsigned char *)(pkt->buffer->data) - VLAN_HEADER_LEN;
            pkt->buffer->size += VLAN_HEADER_LEN;

            memmove(pkt->buffer->data, eth, eth_size);

            new_eth = (struct eth_header *)(pkt->buffer->data);
            new_snap = snap == NULL ? NULL
                                   : (struct snap_header *)((unsigned char *)new_eth
                                        + ETH_HEADER_LEN + LLC_HEADER_LEN);
            push_vlan = (struct vlan_header *)((unsigned char *)new_eth + eth_size);
            new_vlan = vlan;
        } else {
            ofpbuf_put_uninit(pkt->buffer, VLAN_HEADER_LEN);

            new_eth = (struct eth_header *)(pkt->buffer->data);
            new_snap = snap == NULL ? NULL
                                   : (struct snap_header *)((unsigned char *)new_eth
                                        + ETH_HEADER_LEN + LLC_HEADER_LEN);
            push_vlan = (struct vlan_header *)((unsigned char *)new_eth + eth_size);

            memmove((unsigned char *)push_vlan + VLAN_HEADER_LEN, push_vlan,
                    pkt->buffer->size - eth_size);

            new_vlan = vlan == NULL ? NULL
              : (struct vlan_header *)((unsigned char *)push_vlan + VLAN_HEADER_LEN);
        }

        push_vlan->vlan_tci = new_vlan == NULL ? 0x0000 : new_vlan->vlan_tci;

        if (new_snap != NULL) {
            push_vlan->vlan_next_type = new_snap->snap_type;
            new_snap->snap_type = ntohs(act->ethertype);
            new_eth->eth_type = htons(ntohs(new_eth->eth_type) + VLAN_HEADER_LEN);
        } else {
            push_vlan->vlan_next_type = new_eth->eth_type;
            new_eth->eth_type = ntohs(act->ethertype);
        }

        pkt->handle_std->valid = false;

    }
    else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute push vlan action on packet with no eth.");
    }
}

void insert_vlan(unsigned short int vlan, unsigned short int pcp, unsigned short int eth_type, struct ofpbuf *buffer)
{
    struct packet pkt;
    struct ofl_action_push act;

    if(VLOG_IS_DBG_ENABLED(ALTA_LOG_MODULE))
    {
        VLOG_DBG(LOG_MODULE, "insert vlan tag to packet.vlan:%d,pcp:%d\n", vlan, pcp);
    }

    memset(&pkt, 0, sizeof(pkt));
    memset(&act, 0, sizeof(act));

    act.ethertype = eth_type;

    pkt.buffer = buffer;
    pkt.handle_std = packet_handle_std_create(&pkt);

    push_vlan(&pkt, &act);
    packet_handle_std_validate(pkt.handle_std);

    set_vlan_vid(&pkt, (unsigned char *)&vlan);
    set_vlan_pcp(&pkt, (unsigned char *)&pcp);

    packet_handle_std_destroy(pkt.handle_std);
    return;
}

static void
pop_vlan(struct packet *pkt, struct ofl_action_header *act UNUSED) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->eth != NULL && pkt->handle_std->proto->vlan != NULL) {
        struct eth_header *eth = pkt->handle_std->proto->eth;
        struct snap_header *eth_snap = pkt->handle_std->proto->eth_snap;
        struct vlan_header *vlan = pkt->handle_std->proto->vlan;
        size_t move_size;

        if (eth_snap != NULL) {
            eth_snap->snap_type = vlan->vlan_next_type;
            eth->eth_type = htons(ntohs(eth->eth_type) - VLAN_HEADER_LEN);
        } else {
            eth->eth_type = vlan->vlan_next_type;
        }

        move_size = (unsigned char *)vlan - (unsigned char *)eth;

        pkt->buffer->data = (unsigned char *)pkt->buffer->data + VLAN_HEADER_LEN;
        pkt->buffer->size -= VLAN_HEADER_LEN;

        memmove(pkt->buffer->data, eth, move_size);

        pkt->handle_std->valid = false;
    }
    else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute POP_VLAN action on packet with no eth/vlan.");
    }
}

void delete_vlan(struct ofpbuf *buffer)
{
    struct packet pkt;

    if(VLOG_IS_DBG_ENABLED(ALTA_LOG_MODULE))
    {
        VLOG_DBG(LOG_MODULE, "delete vlan tag from packet.\n");
    }

    memset(&pkt, 0, sizeof(pkt));
    pkt.buffer = buffer;
    pkt.handle_std = packet_handle_std_create(&pkt);
    pop_vlan(&pkt, NULL);
    packet_handle_std_destroy(pkt.handle_std);
}

static void
set_mpls_ttl(struct packet *pkt, struct ofl_action_mpls_ttl *act) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->mpls != NULL) {
        struct mpls_header *mpls = pkt->handle_std->proto->mpls;

        mpls->fields = (mpls->fields & ~ntohl(MPLS_TTL_MASK)) | ntohl((act->mpls_ttl << MPLS_TTL_SHIFT) & MPLS_TTL_MASK);

    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_MPLS_TTL action on packet with no mpls.");
    }
}

static void
dec_mpls_ttl(struct packet *pkt, struct ofl_action_header *act UNUSED) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->mpls != NULL) {
        struct mpls_header *mpls = pkt->handle_std->proto->mpls;

        unsigned int ttl = ntohl(mpls->fields) & MPLS_TTL_MASK;

        if (ttl > 0) { ttl--; }
        mpls->fields = (mpls->fields & ~ntohl(MPLS_TTL_MASK)) | htonl(ttl);

    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute DEC_MPLS_TTL action on packet with no mpls.");
    }
}

static void
push_mpls(struct packet *pkt, struct ofl_action_push *act) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->eth != NULL) {
        struct eth_header  *eth,  *new_eth;
        struct snap_header *snap, *new_snap;
        struct vlan_header *vlan, *new_vlan;
        struct mpls_header *mpls, *new_mpls, *push_mpls;
        struct ip_header   *ipv4;
        struct ipv6_header *ipv6;
        size_t eth_size, head_offset;
        unsigned int ipv4_ttl = 0;
        unsigned int ipv6_ttl = 0;

        eth = pkt->handle_std->proto->eth;
        snap = pkt->handle_std->proto->eth_snap;
        vlan = pkt->handle_std->proto->vlan_last;
        mpls = pkt->handle_std->proto->mpls;
        ipv4 = pkt->handle_std->proto->ipv4;
        ipv6 = pkt->handle_std->proto->ipv6;

        if (ipv4)
        {
            ipv4_ttl = ipv4->ip_ttl;
        }
        else if (ipv6)
        {
            ipv6_ttl = ipv6->ip6_hops;
        }

        eth_size = snap == NULL
                   ? ETH_HEADER_LEN
                   : ETH_HEADER_LEN + LLC_HEADER_LEN + SNAP_HEADER_LEN;

        head_offset = vlan == NULL ? eth_size
              : (unsigned char *)vlan - (unsigned char *)eth + VLAN_HEADER_LEN;

        if (ofpbuf_headroom(pkt->buffer) >= MPLS_HEADER_LEN)
        {
            pkt->buffer->data = (unsigned char *)(pkt->buffer->data) - MPLS_HEADER_LEN;
            pkt->buffer->size += MPLS_HEADER_LEN;

            memmove(pkt->buffer->data, eth, eth_size);

            new_eth = (struct eth_header *)(pkt->buffer->data);
            new_snap = snap == NULL ? NULL
                                   : (struct snap_header *)((unsigned char *)new_eth
                                        + ETH_HEADER_LEN + MPLS_HEADER_LEN + LLC_HEADER_LEN);
            push_mpls = (struct mpls_header *)((unsigned char *)new_eth + eth_size);
            new_vlan = vlan == NULL ? NULL
                    : (struct vlan_header *)((unsigned char *)vlan - MPLS_HEADER_LEN);
            new_mpls = mpls;

        }
        else
        {
            ofpbuf_put_uninit(pkt->buffer, MPLS_HEADER_LEN);

            new_eth = (struct eth_header *)(pkt->buffer->data);
            new_snap = snap == NULL ? NULL
                                   : (struct snap_header *)((unsigned char *)new_eth
                                        + ETH_HEADER_LEN + MPLS_HEADER_LEN + LLC_HEADER_LEN);
            push_mpls = (struct mpls_header *)((unsigned char *)new_eth + ETH_HEADER_LEN);

            memmove((unsigned char *)push_mpls + MPLS_HEADER_LEN, push_mpls,
                    pkt->buffer->size - ETH_HEADER_LEN);

           new_mpls = mpls == NULL ? NULL
              : (struct mpls_header *)((unsigned char *)push_mpls + MPLS_HEADER_LEN);
        }

        if (new_mpls != NULL) {
            push_mpls->fields = new_mpls->fields & ~htonl(MPLS_S_MASK);
        } else if (ipv4 != NULL) {
            push_mpls->fields = htonl(ipv4_ttl & MPLS_TTL_MASK) | htonl(MPLS_S_MASK);
        } else if (ipv6 != NULL) {
            push_mpls->fields = htonl(ipv6_ttl & MPLS_TTL_MASK) | htonl(MPLS_S_MASK);
        }
        else {
            push_mpls->fields = htonl(MPLS_S_MASK);
        }

        if (new_snap != NULL) {
            new_snap->snap_type = ntohs(act->ethertype);
        } else {
            new_eth->eth_type = ntohs(act->ethertype);
        }

        pkt->handle_std->valid = false;

    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute PUSH_MPLS action on packet with no eth.");
    }
}

static void
pop_mpls(struct packet *pkt, struct ofl_action_pop_mpls *act) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->eth != NULL && pkt->handle_std->proto->mpls != NULL) {
        struct eth_header *eth = pkt->handle_std->proto->eth;
        struct snap_header *snap = pkt->handle_std->proto->eth_snap;
        struct vlan_header *vlan_last = pkt->handle_std->proto->vlan_last;
        struct mpls_header *mpls = pkt->handle_std->proto->mpls;
        size_t move_size;

        if (vlan_last != NULL) {
            vlan_last->vlan_next_type = htons(act->ethertype);
        } else if (snap != NULL) {
            snap->snap_type = htons(act->ethertype);
        } else {
            eth->eth_type = htons(act->ethertype);
        }

        move_size = (unsigned char *)mpls - (unsigned char *)eth;

        pkt->buffer->data = (unsigned char *)pkt->buffer->data + MPLS_HEADER_LEN;
        pkt->buffer->size -= MPLS_HEADER_LEN;

        memmove(pkt->buffer->data, eth, move_size);

        if (snap != NULL) {
            struct eth_header *new_eth = (struct eth_header *)(pkt->buffer->data);
            new_eth->eth_type = htons(ntohs(new_eth->eth_type) + MPLS_HEADER_LEN);
        }

        pkt->handle_std->valid = false;
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute POP_MPLS action on packet with no eth/mpls.");
    }
}

static void
push_pbb(struct packet *pkt, struct ofl_action_push *act) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->eth != NULL) {
        struct eth_header  *eth,  *new_eth;
        struct snap_header *snap, *new_snap;
        struct pbb_header *pbb, *new_pbb, *push_pbb;
        struct vlan_header * vlan;
        size_t eth_size;

        eth = pkt->handle_std->proto->eth;
        snap = pkt->handle_std->proto->eth_snap;
        pbb = pkt->handle_std->proto->pbb;
        vlan = pkt->handle_std->proto->vlan;

        eth_size = snap == NULL
                   ? ETH_HEADER_LEN
                   : ETH_HEADER_LEN + LLC_HEADER_LEN + SNAP_HEADER_LEN;

        if (ofpbuf_headroom(pkt->buffer) >= PBB_HEADER_LEN) {
            pkt->buffer->data = (unsigned char *)(pkt->buffer->data) - PBB_HEADER_LEN;
            pkt->buffer->size += PBB_HEADER_LEN;

            memmove(pkt->buffer->data, eth, eth_size);

            new_eth = (struct eth_header *)(pkt->buffer->data);
            new_snap = snap == NULL ? NULL
                                   : (struct snap_header *)((unsigned char *)new_eth
                                        + ETH_HEADER_LEN + PBB_HEADER_LEN + LLC_HEADER_LEN);
            push_pbb = (struct pbb_header *)((unsigned char *)new_eth + eth_size);
            new_pbb = pbb;

        } else {
            ofpbuf_put_uninit(pkt->buffer, PBB_HEADER_LEN);

            new_eth = (struct eth_header *)(pkt->buffer->data);
            new_snap = snap == NULL ? NULL
                                   : (struct snap_header *)((unsigned char *)new_eth
                                        + ETH_HEADER_LEN + PBB_HEADER_LEN + LLC_HEADER_LEN);
            push_pbb = (struct pbb_header *)((unsigned char *)new_eth + ETH_HEADER_LEN);

            memmove((unsigned char *)push_pbb + PBB_HEADER_LEN, push_pbb,
                    pkt->buffer->size - ETH_HEADER_LEN);

           new_pbb = pbb == NULL ? NULL
              : (struct pbb_header *)((unsigned char *)push_pbb + PBB_HEADER_LEN);
        }

        push_pbb->id = new_pbb == NULL ? 0x0000 : new_pbb->id;
        push_pbb->id = vlan == NULL
                       ? push_pbb->id
                       : push_pbb->id & (((unsigned int) (vlan->vlan_tci & ~htonl(VLAN_PCP_MASK)) )<< 16);
        memcpy(push_pbb->c_eth_dst,eth,ETH_ADDR_LEN);

        if (new_snap != NULL) {

            push_pbb->pbb_next_type = new_snap->snap_type;
            new_snap->snap_type = ntohs(act->ethertype);
            new_eth->eth_type = htons(ntohs(new_eth->eth_type) + PBB_HEADER_LEN);
        } else {
            push_pbb->pbb_next_type = new_eth->eth_type;
            new_eth->eth_type = ntohs(act->ethertype);
        }

        pkt->handle_std->valid = false;

    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute push pbb action on packet with no eth.");
    }
}


static void
pop_pbb(struct packet *pkt, struct ofl_action_header *act UNUSED) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->eth != NULL && pkt->handle_std->proto->pbb != NULL) {
        struct eth_header *eth = pkt->handle_std->proto->eth;
        struct pbb_header *pbb = pkt->handle_std->proto->pbb;
        size_t move_size;

        move_size = (unsigned char *) pbb->c_eth_dst - (unsigned char *)eth;

        memmove(pkt->buffer->data, pbb->c_eth_dst, (pkt->buffer->size - move_size));
        pkt->buffer->size -= move_size;

        pkt->handle_std->valid = false;
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute POP_PBB action on packet with no PBB header.");
    }
}


static void
set_queue(struct packet *pkt, struct ofl_action_set_queue *act)
{
    pkt->out_queue = act->queue_id;
}

static void
group(struct packet *pkt, struct ofl_action_group *act) {
    pkt->out_group = act->group_id;
}

static void
set_nw_ttl(struct packet *pkt, struct ofl_action_set_nw_ttl *act) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->ipv4 != NULL)
    {
        struct ip_header *ipv4 = pkt->handle_std->proto->ipv4;

        unsigned short int old_val = htons((ipv4->ip_proto) + (ipv4->ip_ttl<<8));
        unsigned short int new_val = htons((ipv4->ip_proto) + (act->nw_ttl<<8));
        ipv4->ip_csum = recalc_csum16(ipv4->ip_csum, old_val, new_val);
        ipv4->ip_ttl = act->nw_ttl;
        pkt->handle_std->valid = false;
    }
    else if(pkt->handle_std->proto->ipv6 != NULL)
    {
        struct ipv6_header *ipv6 = pkt->handle_std->proto->ipv6;
        ipv6->ip6_hlim = act->nw_ttl;
        pkt->handle_std->valid = false;
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_NW_TTL action on packet with no ipv4.");
    }
}

static void
dec_nw_ttl(struct packet *pkt, struct ofl_action_header *act UNUSED) {
    packet_handle_std_validate(pkt->handle_std);
    if (pkt->handle_std->proto->ipv4 != NULL)
    {
        struct ip_header *ipv4 = pkt->handle_std->proto->ipv4;

        if (ipv4->ip_ttl > 0)
        {
            unsigned char new_ttl = ipv4->ip_ttl - 1;
            unsigned short int old_val = htons((ipv4->ip_proto) + (ipv4->ip_ttl << 8));
            unsigned short int new_val = htons((ipv4->ip_proto) + (new_ttl << 8));
            ipv4->ip_csum = recalc_csum16(ipv4->ip_csum, old_val, new_val);
            ipv4->ip_ttl = new_ttl;

            pkt->handle_std->valid = false;
        }
    }
    else if(pkt->handle_std->proto->ipv6 != NULL)
    {
        struct ipv6_header *ipv6 = pkt->handle_std->proto->ipv6;
        ipv6->ip6_hlim--;
        pkt->handle_std->valid = false;
    }
    else
    {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute DEC_NW_TTL action on packet with no ipv4.");
    }
}


void
dp_execute_action(struct packet *pkt,
               struct ofl_action_header *action) {

    if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
        char *a = ofl_action_to_string(action, pkt->dp->exp);
        VLOG_DBG_RL(LOG_MODULE, &rl, "executing action %s.", a);
        free(a);
    }

    switch (action->type) {
        case (OFPAT_SET_FIELD): {
            set_field(pkt,(struct ofl_action_set_field*) action);
            break;
        }
         case (OFPAT_OUTPUT): {
            output(pkt, (struct ofl_action_output *)action);
            break;
        }
        case (OFPAT_COPY_TTL_OUT): {
            copy_ttl_out(pkt, action);
            break;
        }
        case (OFPAT_COPY_TTL_IN): {
            copy_ttl_in(pkt, action);
            break;
        }
        case (OFPAT_SET_MPLS_TTL): {
            set_mpls_ttl(pkt, (struct ofl_action_mpls_ttl *)action);
            break;
        }
        case (OFPAT_DEC_MPLS_TTL): {
            dec_mpls_ttl(pkt, action);
            break;
        }
        case (OFPAT_PUSH_VLAN): {
            push_vlan(pkt, (struct ofl_action_push *)action);
            break;
        }
        case (OFPAT_POP_VLAN): {
            pop_vlan(pkt, action);
            break;
        }
        case (OFPAT_PUSH_MPLS): {
            push_mpls(pkt, (struct ofl_action_push *)action);
            break;
        }
        case (OFPAT_POP_MPLS): {
            pop_mpls(pkt, (struct ofl_action_pop_mpls *)action);
            break;
        }
        case (OFPAT_SET_QUEUE): {
            set_queue(pkt, (struct ofl_action_set_queue *)action);
            break;
        }
        case (OFPAT_GROUP): {
            group(pkt, (struct ofl_action_group *)action);
            break;
        }
        case (OFPAT_SET_NW_TTL): {
            set_nw_ttl(pkt, (struct ofl_action_set_nw_ttl *)action);
            break;
        }
        case (OFPAT_DEC_NW_TTL): {
            dec_nw_ttl(pkt, action);
            break;
        }
        case (OFPAT_PUSH_PBB):{
            push_pbb(pkt, (struct ofl_action_push*)action);
            break;
        }
        case (OFPAT_POP_PBB):{
            pop_pbb(pkt, action);
            break;
        }
        case (OFPAT_EXPERIMENTER): {
            dp_exp_action(pkt, (struct ofl_action_experimenter *)action);
            break;
        }

        case (OFPAT_PUSH_FHID):{
            break;
        }

        default: {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute unknown action type (%u).", action->type);
        }
    }
    if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
        char *p = packet_to_string(pkt);
        VLOG_DBG_RL(LOG_MODULE, &rl, "action result: %s", p);
        free(p);
    }

}

int
dp_execute_action_list(struct packet *pkt,
                size_t actions_num, struct ofl_action_header **actions, unsigned long long int cookie) {
    size_t i;
    int ret_val = 0;

    VLOG_DBG_RL(LOG_MODULE, &rl, "Executing action list.");

    for (i=0; i < actions_num; i++) {
        dp_execute_action(pkt, actions[i]);

        if (pkt->out_group != OFPG_ANY) {
            unsigned int group = pkt->out_group;
            pkt->out_group = OFPG_ANY;
            VLOG_DBG_RL(LOG_MODULE, &rl, "Group action; executing group (%u).", group);
            group_table_execute(pkt->dp->groups, pkt, group);
        } 
        else if (pkt->out_port != OFPP_ANY) {
            unsigned int port = pkt->out_port;
            unsigned int queue = pkt->out_queue;
            unsigned short int max_len = pkt->out_port_max_len;
            pkt->out_port = OFPP_ANY;
            if (pkt->handle_std->proto->vlan != NULL)
                queue = (pkt->handle_std->proto->vlan->vlan_tci >> VLAN_PCP_SHIFT) & VLAN_PCP_BITMASK;

            VLOG_DBG_RL(LOG_MODULE, &rl, "Port action; sending to port (%u).", port);
            ret_val = dp_actions_output_port(pkt, port, queue, max_len, cookie);

        }

    }

    return ret_val;
}


int
dp_actions_output_port(struct packet *pkt, unsigned int out_port, unsigned int out_queue, unsigned short int max_len, unsigned long long int cookie) {
    int ret_val = 0;
    (void)max_len;

    switch (out_port)
    {
        case (OFPP_TABLE):
        {
            if (pkt->packet_out)
            {
                pipeline_process_packet(pkt->dp->pipeline, pkt);
                ret_val = 1;
            }
            break;
        }
        case (OFPP_IN_PORT):
        {
            dp_ports_output(pkt->dp, pkt->buffer, pkt->in_port, out_queue);
            break;
        }
        case (OFPP_CONTROLLER):
        {
            unsigned char reason = 0;

            meter_table_apply(pkt->dp->meters, &pkt , OFPM_CONTROLLER);
            if( pkt == NULL )
                break;
            reason = pkt->mis_match_entry_hited == true ? OFPR_NO_MATCH : OFPR_ACTION;

            dp_flow_set_flag(pkt->dp->data_buffers, pkt->hash,true);
            pkt->cookie = cookie;
            pi_pkt2ofp_send2controller(pkt->dp->pipeline,pkt,pkt->table_id,reason);
            break;
        }
        case (OFPP_FLOOD):
        case (OFPP_ALL): {
            dp_ports_output_all(pkt->dp, pkt->buffer, pkt->in_port, out_port == OFPP_FLOOD, out_queue);
            break;
        }
        case (OFPP_NORMAL):
        case (OFPP_LOCAL):
        default: {
            if (pkt->in_port == out_port) {
            } 
            else {
                dp_flow_set_flag(pkt->dp->data_buffers, pkt->hash,false);
                dp_ports_output(pkt->dp, pkt->buffer, out_port, out_queue);
            }
        }
    }
    return ret_val;
}

bool
dp_actions_list_has_out_port(size_t actions_num, struct ofl_action_header **actions, unsigned int port) {
    size_t i;

    for (i=0; i < actions_num; i++) {
        if (actions[i]->type == OFPAT_OUTPUT) {
            struct ofl_action_output *ao = (struct ofl_action_output *)actions[i];
            if (ao->port == port) {
                return true;
            }
        }
    }
    return false;
}

bool
dp_actions_list_has_out_group(size_t actions_num, struct ofl_action_header **actions, unsigned int group) {
    size_t i;

    for (i=0; i < actions_num; i++) {
        if (actions[i]->type == OFPAT_GROUP) {
            struct ofl_action_group *ag = (struct ofl_action_group *)actions[i];
            if (ag->group_id == group) {
                return true;
            }
        }
    }
    return false;
}

ofl_err
dp_actions_validate(struct datapath *dp, size_t actions_num, struct ofl_action_header **actions) {
    size_t i;

    for (i=0; i < actions_num; i++) {
        if (actions[i]->type == OFPAT_OUTPUT) {
            struct ofl_action_output *ao = (struct ofl_action_output *)actions[i];

            if (ao->port <= OFPP_MAX && dp_ports_lookup(dp, ao->port) == NULL) {
                VLOG_WARN_RL(LOG_MODULE, &rl, "Output action for invalid port (%u).", ao->port);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT);
            }
        }
        if (actions[i]->type == OFPAT_GROUP) {
            struct ofl_action_group *ag = (struct ofl_action_group *)actions[i];

            if (ag->group_id <= OFPG_MAX && group_table_find(dp->groups, ag->group_id) == NULL) {
                VLOG_WARN_RL(LOG_MODULE, &rl, "Group action for invalid group (%u).", ag->group_id);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_GROUP);
            }
        }
    }

    return 0;
}
