/* Copyright (c) 2011, CPqD, Brazil
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

#include "ofl-structs.h"
#include "lib/hash.h"
#include "oxm-match.h"
#include "../nbee_link/nbee_link.h"

void
ofl_structs_match_init(struct ofl_match *match){

    match->header.type = OFPMT_OXM;
    match->header.length = 0;
    match->match_fields = (struct hmap) HMAP_INITIALIZER(&match->match_fields);
}


void
ofl_structs_match_put8(struct ofl_match *match, unsigned int header, unsigned char value){
    struct ofl_match_tlv *m = malloc(sizeof (struct ofl_match_tlv));
    int len = sizeof(unsigned char);

    m->header = header;
    m->value = malloc(len);
    memcpy(m->value, &value, len);
    hmap_insert(&match->match_fields,&m->hmap_node,DP_FIELD_HASH(header));
    match->header.length += len + 4;
}

void
ofl_structs_match_put8m(struct ofl_match *match, unsigned int header, unsigned char value, unsigned char mask){
    struct ofl_match_tlv *m = malloc(sizeof (struct ofl_match_tlv));
    int len = sizeof(unsigned char);

    if(mask == 0x00)
        return;

    m->header = header;
    m->value = malloc(len*2);
    memcpy(m->value, &value, len);
    memcpy(m->value + len, &mask, len);
    hmap_insert(&match->match_fields,&m->hmap_node,DP_FIELD_HASH(header));
    match->header.length += len*2 + 4;
}

void
ofl_structs_match_put16(struct ofl_match *match, unsigned int header, unsigned short int value){
    struct ofl_match_tlv *m = malloc(sizeof (struct ofl_match_tlv));
    int len = sizeof(unsigned short int);

    m->header = header;
    m->value = malloc(len);
    memcpy(m->value, &value, len);
    hmap_insert(&match->match_fields,&m->hmap_node,DP_FIELD_HASH(header));
    match->header.length += len + 4;
}


void
ofl_structs_match_put16m(struct ofl_match *match, unsigned int header, unsigned short int value, unsigned short int mask){
    struct ofl_match_tlv *m = malloc(sizeof (struct ofl_match_tlv));
    int len = sizeof(unsigned short int);

    if(mask == 0x0000)
        return;

    m->header = header;
    m->value = malloc(len*2);
    memcpy(m->value, &value, len);
    memcpy(m->value + len, &mask, len);
    hmap_insert(&match->match_fields,&m->hmap_node,DP_FIELD_HASH(header));
    match->header.length += len*2 + 4;
}

void
ofl_structs_match_put32(struct ofl_match *match, unsigned int header, unsigned int value){
    struct ofl_match_tlv *m = xmalloc(sizeof (struct ofl_match_tlv));

    int len = sizeof(unsigned int);

    m->header = header;
    m->value = malloc(len);
    memcpy(m->value, &value, len);
    hmap_insert(&match->match_fields,&m->hmap_node,DP_FIELD_HASH(header));
    match->header.length += len + 4;

}

void
ofl_structs_match_put32m(struct ofl_match *match, unsigned int header, unsigned int value, unsigned int mask){
    struct ofl_match_tlv *m = malloc(sizeof (struct ofl_match_tlv));
    int len = sizeof(unsigned int);

    if(mask == 0x00000000)
           return;

    m->header = header;
    m->value = malloc(len*2);
    memcpy(m->value, &value, len);
    memcpy(m->value + len, &mask, len);
    hmap_insert(&match->match_fields,&m->hmap_node,DP_FIELD_HASH(header));
    match->header.length += len*2 + 4;

}

void
ofl_structs_match_put64(struct ofl_match *match, unsigned int header, unsigned long long int value){
    struct ofl_match_tlv *m = malloc(sizeof (struct ofl_match_tlv));
    int len = sizeof(unsigned long long int);

    m->header = header;
    m->value = malloc(len);
    memcpy(m->value, &value, len);
    hmap_insert(&match->match_fields,&m->hmap_node,DP_FIELD_HASH(header));
    match->header.length += len + 4;

}

void
ofl_structs_match_put64m(struct ofl_match *match, unsigned int header, unsigned long long int value, unsigned long long int mask){
    struct ofl_match_tlv *m = malloc(sizeof (struct ofl_match_tlv));
    int len = sizeof(unsigned long long int);

    m->header = header;
    m->value = malloc(len*2);
    memcpy(m->value, &value, len);
    memcpy(m->value + len, &mask, len);
    hmap_insert(&match->match_fields,&m->hmap_node,DP_FIELD_HASH(header));
    match->header.length += len*2 + 4;

}

void
ofl_structs_match_put_eth(struct ofl_match *match, unsigned int header, unsigned char value[ETH_ADDR_LEN]){
    struct ofl_match_tlv *m = malloc(sizeof (struct ofl_match_tlv));
    int len = ETH_ADDR_LEN;

    m->header = header;
    m->value = malloc(len);
    memcpy(m->value, value, len);
    hmap_insert(&match->match_fields,&m->hmap_node,DP_FIELD_HASH(header));
    match->header.length += len + 4;

}

void
ofl_structs_match_put_eth_m(struct ofl_match *match, unsigned int header, unsigned char value[ETH_ADDR_LEN], unsigned char mask[ETH_ADDR_LEN]){
    struct ofl_match_tlv *m = malloc(sizeof (struct ofl_match_tlv));
    int len = ETH_ADDR_LEN;

    if (!check_all_zero_array(mask, ETH_ADDR_LEN))
    {
        return;
    }

    m->header = header;
    m->value = malloc(len*2);
    memcpy(m->value, value, len);
    memcpy(m->value + len, mask, len);
    hmap_insert(&match->match_fields,&m->hmap_node,DP_FIELD_HASH(header));
    match->header.length += len*2 + 4;

}

void
ofl_structs_match_put_ipv6(struct ofl_match *match, unsigned int header, unsigned char value[IPv6_ADDR_LEN]){

    struct ofl_match_tlv *m = malloc(sizeof (struct ofl_match_tlv));
    int len = IPv6_ADDR_LEN;

    m->header = header;
    m->value = malloc(len);
    memcpy(m->value, value, len);
    hmap_insert(&match->match_fields,&m->hmap_node,DP_FIELD_HASH(header));
    match->header.length += len + 4;

}

void
ofl_structs_match_put_ipv6m(struct ofl_match *match, unsigned int header, unsigned char value[IPv6_ADDR_LEN], unsigned char mask[IPv6_ADDR_LEN]){
    struct ofl_match_tlv *m = malloc(sizeof (struct ofl_match_tlv));
    int len = IPv6_ADDR_LEN;

    if (!check_all_zero_array(mask, ETH_ADDR_LEN))
    {
        return;
    }

    m->header = header;
    m->value = malloc(len*2);
    memcpy(m->value, value, len);
    memcpy(m->value + len, mask, len);
    hmap_insert(&match->match_fields,&m->hmap_node,DP_FIELD_HASH(header));
    match->header.length += len*2 + 4;

}

void
ofl_structs_match_convert_pktf2oflm(struct hmap * hmap_packet_fields, struct ofl_match * match)
/*
* Used to convert between a hmap of "struct packet_fields" to "struct ofl_match"
*/
{
    struct packet_fields *iter;
    size_t len = 0;
    HMAP_FOR_EACH(iter,struct packet_fields, hmap_node, hmap_packet_fields)
    {
        if (OXM_VENDOR(iter->header) != 0x8000)
            continue;
        else {
            len = OXM_LENGTH(iter->header);
            switch(len){
                case(sizeof(unsigned char)):{
                                ofl_structs_match_put8(match, iter->header, *iter->value);
                }
                                break;
                case(sizeof(unsigned short int)): {
                                unsigned short int *v = (unsigned short int*) iter->value;
                                ofl_structs_match_put16(match, iter->header, *v);
                                break;
                }
                 case(sizeof(unsigned int)):{
                                unsigned int *v = (unsigned int*) iter->value;
                                ofl_structs_match_put32(match, iter->header, *v);
                                break;
                }
                case(ETH_ADDR_LEN):{
                        ofl_structs_match_put_eth(match, iter->header, iter->value);
                        break;
                }
                case(sizeof(unsigned long long int)):{
                                unsigned long long int *v = (unsigned long long int*) iter->value;
                                ofl_structs_match_put64(match, iter->header, *v);
                                break;
                }
                case(IPv6_ADDR_LEN):{
                                ofl_structs_match_put_ipv6(match, iter->header, (unsigned char*) iter->value);
                                break;
                }
            }
        }
    }
}


void
ofp_structs_match_convert_pkt2ofp(struct hmap * hmap_packet_fields, struct ofp_match *match,
                                  unsigned char* oxm_fields,struct ofl_exp *exp)
{
    struct packet_fields *iter;
    size_t len = 0;
    unsigned int pad_len = 0 ;
    unsigned int oxm_header = 0;
    unsigned char *p_oxm_field = oxm_fields;

    HMAP_FOR_EACH(iter,struct packet_fields, hmap_node, hmap_packet_fields)
    {
        if (OXM_VENDOR(iter->header) != 0x8000)
            continue;
        else
        {
            len = OXM_LENGTH(iter->header);
            bool has_mask =false;
            if (OXM_HASMASK(iter->header)){
               len = len / 2;
               has_mask = true;
            }

            //store the OXM_HEADER
            if( 0 != len )
            {
                oxm_header = htonl(iter->header);
                memcpy(p_oxm_field, (unsigned char*)(&oxm_header), sizeof oxm_header);
                p_oxm_field = p_oxm_field + sizeof oxm_header;//pointer moves
            }

            switch(len){
                case(sizeof(unsigned char)):{
                     memcpy( p_oxm_field, iter->value, len);//store the value
                     p_oxm_field += len;

                     if( true == has_mask )
                     {
                         memcpy(p_oxm_field, iter->value+len, len);//store the mask
                         p_oxm_field += len;
                     }
                     break;
                }
                case(sizeof(unsigned short int)): {
                     memcpy( p_oxm_field, iter->value, len);//store the value
                     p_oxm_field += len;

                     if( true == has_mask )
                     {
                         memcpy(p_oxm_field, iter->value+len, sizeof(unsigned short int));//store the mask
                         p_oxm_field += sizeof(unsigned short int);
                     }
                     break;
                }
                case(sizeof(unsigned int)):{
                     memcpy( p_oxm_field, iter->value, len);//store the value
                     p_oxm_field += len;

                     if( true == has_mask )
                     {
                         memcpy(p_oxm_field, iter->value+len, len);//store the mask
                         p_oxm_field += len;
                     }
                     break;
                }
                case(ETH_ADDR_LEN):{
                     memcpy( p_oxm_field, iter->value, len );//store the value
                     p_oxm_field += len;

                     if( true == has_mask )
                     {
                         memcpy(p_oxm_field, iter->value+len, len );//store the mask
                         p_oxm_field += len;
                     }
                     break;
                }
                case(sizeof(unsigned long long int)):{
                     memcpy( p_oxm_field, iter->value, len );//store the value
                     p_oxm_field += len;

                     if( true == has_mask )
                     {
                         memcpy(p_oxm_field, iter->value+len, len );//store the mask
                         p_oxm_field += len;
                     }
                     break;
                }
                case(IPv6_ADDR_LEN):{
                     memcpy( p_oxm_field, iter->value, len );//store the value
                     p_oxm_field += len;

                     if( true == has_mask )
                     {
                         memcpy(p_oxm_field, iter->value+len, len );//store the mask
                         p_oxm_field += len;
                     }
                     break;
                }
            }
        }
    }

    //oxm padding
    pad_len = ROUND_UP(ntohs(match->length), 8) - ntohs(match->length);
    if(pad_len > 0)
    {
        memset(p_oxm_field, 0, pad_len);
    }
}
