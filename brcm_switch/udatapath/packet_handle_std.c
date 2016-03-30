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

#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>


#include "packet_handle_std.h"
#include "packet.h"
#include "packets.h"
#include "oflib/ofl-structs.h"
#include "openflow/openflow.h"
#include "compiler.h"

#include "lib/hash.h"
#include "oflib/oxm-match.h"

#include "lib/vlog.h"

#define   IPV4  0x40
#define   IPV6  0x60
#define   MPLS_LAST_ENTRY  0x1

void insert_field(struct packet_handle_std *handle,
                    unsigned int field_header,unsigned char *ptr);

static void replace_eth_type(struct packet_handle_std *handle, unsigned short int eth_type)
{
    struct packet_fields *iter;

    HMAP_FOR_EACH_WITH_HASH(iter, struct packet_fields, hmap_node,
                            DP_FIELD_HASH(OXM_OF_ETH_TYPE), &handle->match.match_fields)
    {
        memcpy(iter->value, &eth_type, OXM_LENGTH(OXM_OF_ETH_TYPE));
    }
}

static bool parse_tcp(struct packet_handle_std *handle,struct protocols_std *proto,size_t offset)
{
    if (handle->pkt->buffer->size < offset + sizeof(struct tcp_header)) 
    {
       return false;
    }
    
    proto->tcp = (struct tcp_header *)((unsigned char *)handle->pkt->buffer->data + offset);
    insert_field(handle, OXM_OF_TCP_SRC, (unsigned char *)(&proto->tcp->tcp_src));
    insert_field(handle, OXM_OF_TCP_DST, (unsigned char *)(&proto->tcp->tcp_dst));

    return true;
}

static bool parse_udp(struct packet_handle_std *handle,
                           struct protocols_std *proto,
                            size_t offset)
{
     if (handle->pkt->buffer->size < offset + sizeof(struct udp_header))
     {
        return false;
     }
     proto->udp = (struct udp_header *)((unsigned char *)handle->pkt->buffer->data + 
                        offset);
    insert_field(handle, OXM_OF_UDP_SRC, (unsigned char *)(&proto->udp->udp_src));
    insert_field(handle, OXM_OF_UDP_DST, (unsigned char *)(&proto->udp->udp_dst));

    return true;
}

static bool parse_icmpv4(struct packet_handle_std *handle,
                                struct protocols_std *proto,
                                    size_t offset)
{
     if (handle->pkt->buffer->size < offset + sizeof(struct icmp_header)) 
     {
       return false;
     }
     proto->icmp = (struct icmp_header *)((unsigned char *)handle->pkt->buffer->data 
                                   + offset);
     insert_field(handle, OXM_OF_ICMPV4_CODE, &proto->icmp->icmp_code);
     insert_field(handle, OXM_OF_ICMPV4_TYPE, &proto->icmp->icmp_type);
     
     return true;
}

static bool parse_sctp(struct packet_handle_std *handle,
                            struct protocols_std *proto,
                                size_t offset)
{

    if (handle->pkt->buffer->size < offset + sizeof(struct sctp_header)) 
    {
       return false;
    }
    proto->sctp = (struct sctp_header *)((unsigned char *)handle->pkt->buffer->data
                                        + offset);
    insert_field(handle, OXM_OF_SCTP_SRC, (unsigned char *)(&proto->sctp->sctp_src));
    insert_field(handle, OXM_OF_SCTP_DST, (unsigned char *)(&proto->sctp->sctp_dst));
 
    return true;
}

static bool parse_icmpv6(struct packet_handle_std *handle,struct protocols_std *proto,
                              size_t offset)
{
     unsigned char arp_sha[ETH_ADDR_LEN] ={0};
     unsigned char arp_tha[ETH_ADDR_LEN] ={0};
     const struct icmp6_hdr *icmp;
     const struct in6_addr *nd_target;
     const struct nd_opt_hdr *nd_opt;
     int opt_len;
     
     struct packet *pkt = handle->pkt;
     (void)proto;
     if (pkt->buffer->size < offset + sizeof(struct icmp6_hdr)) 
     {
        return false;
     }

     proto->icmp = (struct icmp_header *)((unsigned char *)pkt->buffer->data + offset);
     icmp = (struct icmp6_hdr *) ((unsigned char *)pkt->buffer->data + offset);
     offset += sizeof(struct icmp6_hdr);

     insert_field(handle, OXM_OF_ICMPV6_TYPE, (unsigned char  *)(&icmp->icmp6_type));
     insert_field(handle, OXM_OF_ICMPV6_CODE, (unsigned char *)(&icmp->icmp6_code));

     if (icmp->icmp6_code == 0 &&
        (icmp->icmp6_type == ND_NEIGHBOR_SOLICIT ||
         icmp->icmp6_type == ND_NEIGHBOR_ADVERT))
     {
        if (pkt->buffer->size < offset + sizeof(struct in6_addr)) 
        {
            return false;
        }
        
        nd_target=(struct in6_addr *)((unsigned char *)pkt->buffer->data + offset);
        offset += sizeof(struct in6_addr);
        insert_field(handle, OXM_OF_IPV6_ND_TARGET, (unsigned char *)nd_target);

        while((pkt->buffer->size - offset) >= 8)
        {
            nd_opt = (struct nd_opt_hdr *)((unsigned char *)pkt->buffer->data + offset);
            opt_len = nd_opt->nd_opt_len * 8;

            if (!opt_len || opt_len > (pkt->buffer->size - offset)) {
                goto invalid;
            }

            if (nd_opt->nd_opt_type == ND_OPT_SOURCE_LINKADDR
                    && opt_len == 8) {
                if (eth_addr_is_zero(arp_sha)) 
                {
                    memcpy(arp_sha, nd_opt + 1, ETH_ADDR_LEN);
                    insert_field(handle, OXM_OF_IPV6_ND_SLL, (unsigned char *)(nd_opt + 1));
                } 
                else 
                {
                    goto invalid;
                }
            } 
            else if (nd_opt->nd_opt_type == ND_OPT_TARGET_LINKADDR
                    && opt_len == 8) 
            {
                if (eth_addr_is_zero(arp_tha)) 
                {
                    memcpy(arp_tha, nd_opt + 1, ETH_ADDR_LEN);
                    insert_field(handle, OXM_OF_IPV6_ND_TLL, (unsigned char *)(nd_opt + 1));
                }
                else
                {
                    goto invalid;
                }
            }

            offset += opt_len;
            
        }
     }
     
invalid:
    memset(arp_sha, 0, sizeof(arp_sha));
    memset(arp_tha, 0, sizeof(arp_tha));

    return true;
}
     
static void parse_ethernet_II(struct packet_handle_std *handle,
                           struct protocols_std *proto,unsigned short int *eth_type)
{
     insert_field(handle, OXM_OF_ETH_SRC, (unsigned char *)(proto->eth->eth_src));
     insert_field(handle, OXM_OF_ETH_DST, (unsigned char *)(proto->eth->eth_dst));
     insert_field(handle, OXM_OF_ETH_TYPE,(unsigned char *)(&proto->eth->eth_type));
     *eth_type = ntohs(proto->eth->eth_type);
}

static bool parse_ethernet_802_3(struct packet_handle_std *handle,
                                struct protocols_std *proto,size_t offset,
                                unsigned short int *eth_type)
{
    struct llc_header *llc;
    struct packet *pkt = handle->pkt;
       
    if (pkt->buffer->size < offset + sizeof(struct llc_header)) 
    {
        return false;
    }

    llc = (struct llc_header *)((unsigned char *)pkt->buffer->data + offset);
    offset += sizeof(struct llc_header);

    if (!(llc->llc_dsap == LLC_DSAP_SNAP &&
          llc->llc_ssap == LLC_SSAP_SNAP &&
          llc->llc_cntl == LLC_CNTL_SNAP)) 
    {
        return false;
    }

    if (pkt->buffer->size < offset + sizeof(struct snap_header)) 
    {
        return false;
    }

    proto->eth_snap = (struct snap_header *)((unsigned char *)pkt->buffer->data + offset);
    offset += sizeof(struct snap_header);

    if (memcmp(proto->eth_snap->snap_org, SNAP_ORG_ETHERNET, sizeof(SNAP_ORG_ETHERNET)) != 0) {
        return false;
    }

    insert_field(handle, OXM_OF_ETH_SRC, proto->eth->eth_src);
    insert_field(handle, OXM_OF_ETH_DST, proto->eth->eth_dst);
    insert_field(handle, OXM_OF_ETH_TYPE, (unsigned char *)(&proto->eth_snap->snap_type)); 
    *eth_type = ntohs(proto->eth_snap->snap_type);

    return true;
}

static size_t  parse_vlan(struct packet_handle_std *handle,
               struct protocols_std *proto,
               size_t offset,
               unsigned short int *eth_type)
{
    unsigned short int vlan_vid;
    unsigned char  vlan_pcp;
    
    struct packet *pkt = handle->pkt;
   
    
    proto->vlan = (struct vlan_header *)((unsigned char *)pkt->buffer->data + offset);
    proto->vlan_last = proto->vlan;
    offset += sizeof(struct vlan_header);

    vlan_vid = ntohs(proto->vlan->vlan_tci) & VLAN_VID_MASK;
    vlan_vid = vlan_vid | 0x1000;
    vlan_pcp = (ntohs(proto->vlan->vlan_tci) & VLAN_PCP_MASK) >> VLAN_PCP_SHIFT;

    vlan_vid = htons(vlan_vid);
    
    insert_field(handle,OXM_OF_VLAN_VID,(unsigned char *)&vlan_vid);
    insert_field(handle,OXM_OF_VLAN_PCP,&vlan_pcp);
    
    *eth_type = ntohs(proto->vlan->vlan_next_type);

    return offset;
}

static bool  parse_mpls(struct packet_handle_std *handle,
                 struct protocols_std *proto, size_t *offset)
{
    unsigned int mpls_label;
    unsigned char mpls_tc;
    unsigned char mpls_end;
    struct packet *pkt = handle->pkt;

    struct mpls_header *mpls_ptr;

    proto->mpls = (struct mpls_header *)((unsigned char *)pkt->buffer->data + *offset);
    *offset += sizeof(struct mpls_header);

    mpls_label = (ntohl(proto->mpls->fields) & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT;
    mpls_tc  = (ntohl(proto->mpls->fields) & MPLS_TC_MASK) >> MPLS_TC_SHIFT;
    mpls_end = (ntohl(proto->mpls->fields) & MPLS_S_MASK) >> MPLS_S_SHIFT;

    mpls_label = htonl(mpls_label);

    insert_field(handle,OXM_OF_MPLS_LABEL,(unsigned char *)&mpls_label);
    insert_field(handle,OXM_OF_MPLS_TC,&mpls_tc);
    insert_field(handle,OXM_OF_MPLS_BOS,&mpls_end);

    mpls_ptr = proto->mpls;
    /* skip through rest of MPLS tags */
    while (mpls_end != MPLS_LAST_ENTRY)
    {

        if (pkt->buffer->size < *offset + sizeof(struct mpls_header))
        {
            return false;
        }
        mpls_ptr =  (struct mpls_header *)((unsigned char *)pkt->buffer->data + *offset);
        //proto->mpls = (struct mpls_header *)((unsigned char *)pkt->buffer->data + *offset);
        *offset += sizeof(struct mpls_header);
        mpls_end = (ntohl(mpls_ptr->fields) & MPLS_S_MASK) >> MPLS_S_SHIFT;
        //mpls_end = (ntohl(proto->mpls->fields) & MPLS_S_MASK) >> MPLS_S_SHIFT;
    }

    return true;
}

static bool parse_arp(struct packet_handle_std *handle,
                    struct protocols_std *proto,
                        size_t offset)
{
    unsigned short int ip_proto = 0x0;
    struct packet *pkt = handle->pkt;
    
    if (pkt->buffer->size < offset + sizeof(struct arp_eth_header)) 
    {
        return false;
    }
    
    proto->arp = (struct arp_eth_header *)((unsigned char *)pkt->buffer->data + offset);
    offset += sizeof(struct arp_eth_header);

    if (ntohs(proto->arp->ar_hrd) == 1 &&
        ntohs(proto->arp->ar_pro) == ETH_TYPE_IP &&
        proto->arp->ar_hln == ETH_ADDR_LEN &&
        proto->arp->ar_pln == 4) {

        if (ntohs(proto->arp->ar_op) <= 0xff) {
            ip_proto = ntohs(proto->arp->ar_op);
            insert_field(handle,OXM_OF_ARP_OP,(unsigned char *)&(proto->arp->ar_op));
        }
        
        if (ip_proto == ARP_OP_REQUEST || ip_proto == ARP_OP_REPLY) 
        {

            //结构体发生变化，为了编译通过注释下面代码
            insert_field(handle, OXM_OF_ARP_SHA, proto->arp->ar_sha);
            insert_field(handle, OXM_OF_ARP_THA, proto->arp->ar_tha);
            insert_field(handle, OXM_OF_ARP_SPA, (unsigned char *)&(proto->arp->ar_spa));
            insert_field(handle, OXM_OF_ARP_TPA, (unsigned char *)&(proto->arp->ar_tpa));
        }
    }
    return true;
}

static bool parse_ipv4(struct packet_handle_std *handle,struct protocols_std *proto, size_t offset)
{
    unsigned char ip_dscp;
    unsigned char ip_ecn;
    unsigned char ip_proto;

    struct packet *pkt = handle->pkt;

    proto->ipv4 = (struct ip_header *)((unsigned char *)pkt->buffer->data + offset);
    offset += sizeof(struct ip_header);

    insert_field(handle, OXM_OF_IPV4_SRC, (unsigned char *)&(proto->ipv4->ip_src));
    insert_field(handle, OXM_OF_IPV4_DST, (unsigned char *)&(proto->ipv4->ip_dst));

    ip_dscp  = (proto->ipv4->ip_tos & IP_DSCP_MASK) >> 2;
    ip_proto = proto->ipv4->ip_proto;
    ip_ecn   = proto->ipv4->ip_tos & IP_ECN_MASK;
    
    insert_field(handle, OXM_OF_IP_DSCP, &ip_dscp);
    insert_field(handle, OXM_OF_IP_ECN, &ip_ecn);
    insert_field(handle, OXM_OF_IP_PROTO, &ip_proto);
    if( (proto->ipv4->ip_ihl_ver & 0x0f) > 5) 
    {
        pkt->l3_options |= L3_OPTION_IP_OPTION ;
    }
    if( ntohs(proto->ipv4->ip_tot_len) > ALTA_L3_DEFAULT_MTU)
    {
        pkt->l3_options |= L3_OPTION_MTU ;
    }

    if (IP_IS_FRAGMENT(proto->ipv4->ip_frag_off)) 
    {
        pkt->l3_options |= L3_OPTION_FRAGMENT ;
        return false;
    }

    if (ip_proto == IP_TYPE_TCP) 
    {
        return parse_tcp(handle,proto,offset);
    }
    else if (ip_proto == IP_TYPE_UDP) 
    {
        return parse_udp(handle,proto,offset);    
    } 
    else if (ip_proto == IP_TYPE_ICMP) 
    {
        return parse_icmpv4(handle,proto,offset);        
    }
    else if (ip_proto == IP_TYPE_SCTP) 
    {
        return parse_sctp(handle,proto,offset);       
    }

    return true;
}

static bool parse_ipv6(struct packet_handle_std *handle,struct protocols_std *proto,size_t offset)
{
    int nexthdr;
    unsigned char ip_dscp;
    unsigned char    ip_ttl;
    unsigned char ip_ecn;
    unsigned int   ipv6_label;
    unsigned int tc_flow;
    unsigned char    ip_proto;
    struct packet *pkt = handle->pkt;
    const struct ip6_ext *ext_hdr;
    const struct ip6_frag *frag_hdr;

    proto->ipv6 = (struct ipv6_header *)((unsigned char *)pkt->buffer->data + offset);
    offset += sizeof(struct ipv6_header);

    nexthdr = proto->ipv6->ip6_nxt;

    insert_field(handle, OXM_OF_IPV6_SRC, proto->ipv6->ip6_src);
    insert_field(handle, OXM_OF_IPV6_DST, proto->ipv6->ip6_dst);

    tc_flow = ntohl(proto->ipv6->ip6_flow);
    ip_dscp = (tc_flow >> 22) & 0x3f;
    ip_ecn  = (tc_flow >> 20) & 0x03;

    ipv6_label = ntohl( tc_flow & IPV6_LABEL_MASK);
    ip_ttl   = proto->ipv6->ip6_hlim;
    ip_proto = IPPROTO_NONE;


    insert_field(handle,OXM_OF_IP_DSCP,&ip_dscp);
    insert_field(handle,OXM_OF_IP_ECN,&ip_ecn);
    insert_field(handle,OXM_OF_IPV6_FLABEL,(unsigned char *)&ipv6_label);

    while(1)
    {
        if ((nexthdr != IPPROTO_HOPOPTS)
            && (nexthdr != IPPROTO_ROUTING)
            && (nexthdr != IPPROTO_DSTOPTS)
            && (nexthdr != IPPROTO_AH)
            && (nexthdr != IPPROTO_FRAGMENT)) {
        /* It's either a terminal header (e.g., TCP, UDP) or one we
         * don't understand.  In either case, we're done with the
         * packet, so use it to fill in 'nw_proto'. */
        break;
        }

        /* We only verify that at least 8 bytes of the next header are
        * available, but many of these headers are longer.  Ensure that
        * accesses within the extension header are within those first 8
        * bytes. All extension headers are required to be at least 8
        * bytes. */
        if ((pkt->buffer->size - offset) < 8)
        {
             return false;
        }

        if ((nexthdr == IPPROTO_HOPOPTS)
            || (nexthdr == IPPROTO_ROUTING)
            || (nexthdr == IPPROTO_DSTOPTS)) {
            /* These headers, while different, have the fields we care about
             * in the same location and with the same interpretation. */
            const struct ip6_ext *ext_hdr = (struct ip6_ext *)((unsigned char *)pkt->buffer->data + offset);
            nexthdr = ext_hdr->ip6e_nxt;
            offset += (ext_hdr->ip6e_len + 1) * 8;

        } 
        else if (nexthdr == IPPROTO_AH) 
        {
            /* A standard AH definition isn't available, but the fields
             * we care about are in the same location as the generic
             * option header--only the header length is calculated
             * differently. */
            if (pkt->buffer->size < offset + sizeof(struct ip6_ext)) 
            {
                return false;
            }
            ext_hdr = (struct ip6_ext *)((unsigned char *)pkt->buffer->data + offset);
            nexthdr = ext_hdr->ip6e_nxt;
            offset += (ext_hdr->ip6e_len + 2) * 4;

        } 
        else if (nexthdr == IPPROTO_FRAGMENT) 
        {
            pkt->l3_options |= L3_OPTION_FRAGMENT ;
            
            if (pkt->buffer->size < offset + sizeof(struct ip6_frag)) 
            {
                return false;
            }
         
            frag_hdr = (struct ip6_frag *)((unsigned char *)pkt->buffer->data + offset);

            nexthdr = frag_hdr->ip6f_nxt;
            offset += sizeof(struct ip6_frag);


        /* We only process the first fragment. */
        //                      if (frag_hdr->ip6f_offlg != htons(0)) 
        //                      {
        //                          if ((frag_hdr->ip6f_offlg & IP6F_OFF_MASK) == htons(0)) 
        //                          {
        //                              flow->nw_frag = FLOW_NW_FRAG_ANY;
        //                          } 
        //                          else 
        //                          {
        //                              flow->nw_frag |= FLOW_NW_FRAG_LATER;
        //                              nexthdr = IPPROTO_FRAGMENT;
        //                              break;
        //                          }
        //                      }
        }
    }
    ip_proto = nexthdr;
    insert_field(handle,OXM_OF_IP_PROTO,&ip_proto);

    /* Transport */
    if (ip_proto == IP_TYPE_TCP) 
    {
        return parse_tcp(handle,proto,offset);
    }
    else if (ip_proto == IP_TYPE_UDP) 
    {
       return parse_udp(handle,proto,offset);
    } 
    else if (ip_proto == IP_TYPE_ICMPV6) 
    {
        return parse_icmpv6(handle,proto,offset);
    }
    else if (ip_proto == IP_TYPE_SCTP)
    {
        return parse_sctp(handle,proto,offset);
    }
    return true;
}

static bool packet_head_extract(struct packet_handle_std *handle) 
{
    unsigned short int eth_type;
    bool bRet;
    size_t offset = 0;
    unsigned char version;
    struct packet *pkt = handle->pkt;
    struct protocols_std *proto = handle->proto;

    if (handle->valid)
    {
        return false;
    }

    handle->valid = true;
    protocol_reset(handle->proto);
       
    /* Ethernet */
    if (pkt->buffer->size < offset + sizeof(struct eth_header))
    {
        return false;
    }

    proto->eth = (struct eth_header *)((unsigned char *)pkt->buffer->data + offset);
    offset += sizeof(struct eth_header);

    if (ntohs(proto->eth->eth_type) >= ETH_TYPE_II_START)
    {
        /* Ethernet II */
        parse_ethernet_II(handle, proto, &eth_type);
    }
    else
    {
        /* Ethernet 802.3 */
        parse_ethernet_802_3(handle, proto, offset, &eth_type);
    }

    /* VLAN */
    if (eth_type == ETH_TYPE_VLAN ||
        eth_type == ETH_TYPE_VLAN_PBB)
    {
        if (pkt->buffer->size < offset + sizeof(struct vlan_header))
        {
            return false;
        }
         
        offset = parse_vlan(handle,proto,offset,&eth_type);          
     
        /* skip through rest of VLAN tags */
        while ((eth_type == ETH_TYPE_VLAN)
           || (eth_type == ETH_TYPE_VLAN_PBB))
        {
            if (pkt->buffer->size < offset + sizeof(struct vlan_header))
            {
                return false;
            }

            proto->vlan_last = (struct vlan_header *)((unsigned char *)pkt->buffer->data + offset);
            offset += sizeof(struct vlan_header);

            eth_type = ntohs(proto->vlan_last->vlan_next_type);
        }
        replace_eth_type(handle, htons(eth_type));
    }

    /* MPLS */
    if ((eth_type == ETH_TYPE_MPLS)
        || (eth_type == ETH_TYPE_MPLS_MCAST))
    {
        if (pkt->buffer->size < offset + sizeof(struct mpls_header))
        {
            return false;
        }

        bRet = parse_mpls(handle, proto, &offset);
        if (!bRet)
        {
            return false;
        }

        version = (*((unsigned char *)pkt->buffer->data + offset)) & 0xF0;

        if (version == IPV4)
        {
            eth_type = ETH_TYPE_IP;
        }

        if (version == IPV6)
        {
            eth_type = ETH_TYPE_IPV6;
        }
    }

    //proto->eth->eth_type = htons(eth_type);
    //insert_field(handle, OXM_OF_ETH_TYPE, &proto->eth->eth_type);

    /* ARP */
    if (eth_type == ETH_TYPE_ARP) 
    {
        return parse_arp(handle,proto,offset);        
    }

    /* Network Layer */
    else if (eth_type == ETH_TYPE_IP) 
    {
        if (pkt->buffer->size < offset + sizeof(struct ip_header))
        {
            return false;
        }

        return parse_ipv4(handle,proto,offset);
    }
    else if(eth_type == ETH_TYPE_IPV6)
    {
        if (pkt->buffer->size < offset + sizeof(struct ipv6_header))
        {
            return false;
        }

        return parse_ipv6(handle,proto,offset);
    }
    

    return true;
}


//ptr的内容以网络序存放
void insert_field(struct packet_handle_std *handle,
                    unsigned int field_header,unsigned char *ptr)
{
    struct packet_fields *pktout;
    unsigned char len;

    len = OXM_LENGTH(field_header);
    pktout = (struct packet_fields*) malloc(sizeof(struct packet_fields));  
    pktout->header = field_header;
    pktout->value = (unsigned char*) malloc(len);
    memset(pktout->value,0x0,len);
    memcpy(pktout->value,ptr,len);
    hmap_insert(&handle->match.match_fields, &pktout->hmap_node,
                DP_FIELD_HASH(field_header));
#if 0
    if(VLOG_IS_DBG_ENABLED(ALTA_LOG_MODULE))
    {
      extract_fields_debug(pktout);
    }
#endif
}
//add end


void packet_handle_std_validate(struct packet_handle_std *handle) 
{
    /*struct packet_fields *pktout_inport, *pktout_metadata;*/
    struct packet_fields *pkt_f;
    unsigned int in_port;
    unsigned long long int metadata;
    struct packet_fields * iter, *next;
    
    if(handle->valid)
    {
        return;
    }

    HMAP_FOR_EACH_SAFE(iter, next, struct packet_fields, hmap_node, &handle->match.match_fields)
    {
        free(iter->value);
        free(iter);
    }
    
    hmap_destroy(&handle->match.match_fields);
    hmap_init(&handle->match.match_fields); 
    handle->match.header.length = 0;


    packet_head_extract(handle);
    
    handle->valid = true;
    
    /* Add in_port value to the hash_map */
    in_port = htonl(handle->pkt->in_port);
    insert_field(handle, OXM_OF_IN_PORT, (unsigned char *)&in_port);

    /*Add metadata value to the hash_map */
    //metadata = 0xffffffffffffffff;
    metadata = 0x0;
    insert_field(handle, OXM_OF_METADATA, (unsigned char *)&metadata);

    //packet_match_field_print(&handle->match);
    //获取网络包中匹配字段域的数据长度
    handle->match_num = 0;

    HMAP_FOR_EACH(pkt_f, struct packet_fields, hmap_node, &handle->match.match_fields)
    {
        handle->match.header.length +=  OXM_LENGTH(pkt_f->header);

        if( 0 != OXM_LENGTH(pkt_f->header))
        {
            handle->match_num++;
        }
    }
    //add end
    return;
}

 
struct packet_handle_std *
packet_handle_std_create(struct packet *pkt) {
    struct packet_handle_std *handle = xmalloc(sizeof(struct packet_handle_std));
    handle->proto = xmalloc(sizeof(struct protocols_std));
    handle->pkt = pkt;
    
    hmap_init(&handle->match.match_fields);
    
    handle->valid = false;
    packet_handle_std_validate(handle);
        
    return handle;
}

struct packet_handle_std *
packet_handle_std_clone(struct packet *pkt, struct packet_handle_std *handle UNUSED) {
    struct packet_handle_std *clone = xmalloc(sizeof(struct packet_handle_std));

    clone->pkt = pkt;
    clone->proto = xmalloc(sizeof(struct protocols_std));
    hmap_init(&clone->match.match_fields);
    clone->valid = false;
    // TODO Zoltan: if handle->valid, then match could be memcpy'd, and protocol
    //              could be offset
    packet_handle_std_validate(clone);

    return clone;
}

void
packet_handle_std_destroy(struct packet_handle_std *handle) 
{
    struct packet_fields * iter, *next;
    
    HMAP_FOR_EACH_SAFE(iter, next, struct packet_fields, hmap_node, &handle->match.match_fields)
    {
        free(iter->value);
        free(iter);
    }
    free(handle->proto);
    
    hmap_destroy(&handle->match.match_fields);
    free(handle);
    handle = NULL;
}

bool packet_handle_std_is_ttl_valid(struct packet_handle_std *handle) 
{
    packet_handle_std_validate(handle);

    if (handle->proto->mpls != NULL) 
    {
        unsigned int ttl = ntohl(handle->proto->mpls->fields) & MPLS_TTL_MASK;
        if (ttl <= 1) 
        {
            return false;
        }
    }
    
    if (handle->proto->ipv4 != NULL) 
    {
        if (handle->proto->ipv4->ip_ttl < 1)
        {
            return false;
        }
    }
    
    if (handle->proto->ipv6 != NULL) 
    {
        if (handle->proto->ipv6->ip6_hlim < 1)
        {
            return false;
        }
    }
    return true;
}

bool
packet_handle_std_is_fragment(struct packet_handle_std *handle) {
    packet_handle_std_validate(handle);

    return false;
    /*return ((handle->proto->ipv4 != NULL) &&
            IP_IS_FRAGMENT(handle->proto->ipv4->ip_frag_off));*/
}


bool
packet_handle_std_match(struct packet_handle_std *handle, struct ofl_match *match){
    
    if (!handle->valid){
        packet_handle_std_validate(handle);
        if (!handle->valid){
            return false;
        }
    }

    return packet_match(match ,&handle->match );
}


/* TODO Denicol: From this point on, work to be done */

/* If pointer is not null, returns str; otherwise returns an empty string. 
static inline const char *
pstr(void *ptr, const char *str) {
    return (ptr == NULL) ? "" : str;
}

 Prints the names of protocols that are available in the given protocol stack. 

static void
proto_print(FILE *stream, struct protocols_std *p) {
    fprintf(stream, "{%s%s%s%s%s%s%s%s%s}",
            pstr(p->eth, "eth"), pstr(p->vlan, ",vlan"), pstr(p->mpls, ",mpls"), pstr(p->ipv4, ",ipv4"),
            pstr(p->arp, ",arp"), pstr(p->tcp, ",tcp"), pstr(p->udp, ",udp"), pstr(p->sctp, ",sctp"),
            pstr(p->icmp, ",icmp"));
}

char *
packet_handle_std_to_string(struct packet_handle_std *handle) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    packet_handle_std_print(stream, handle);

    fclose(stream);
    return str;
}

void
packet_handle_std_print(FILE *stream, struct packet_handle_std *handle) {
    packet_handle_std_validate(handle);

    fprintf(stream, "{proto=");
    proto_print(stream, handle->proto);

    fprintf(stream, ", match=");
    ofl_structs_match_print(stream, (struct ofl_match_header *)(handle->match), handle->pkt->dp->exp);
    fprintf(stream, "\"}");
}
*/
