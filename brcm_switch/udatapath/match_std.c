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
 *   * Neither the name of the CPqD nor the names of its
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

#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include "lib/hash.h"
#include "oflib/oxm-match.h"
#include "match_std.h"
#include "nbee_link/nbee_link.h"
#include "vlog.h"

/* Two matches overlap, if there exists a packet,
   which both match structures match on. */
bool
match_std_overlap(struct ofl_match *a, struct ofl_match *b) {
    return (match_std_nonstrict(a, b) || match_std_nonstrict(b, a));
}

static int
matches_8(unsigned char *a, unsigned char *b) {
     return ((a[0] ^ b[0]) == 0x00);
}     

/* Returns true if two values of 8 bit size match, considering their masks. */
static int
pkt_mask8(unsigned char *a, unsigned char *am, unsigned char *b) {
     return ((~(am[0]) & (a[0] ^ b[0])) == 0x00);
}     

/* Returns true if two values of 16 bit size match */
static int
pkt_match_16(unsigned char *a, unsigned char *b) {
    unsigned short int *a1 = (unsigned short int *) a;
    unsigned short int *b1 = (unsigned short int *) b;
    return ((*a1 ^ ntohs(*b1)) == 0);
}


/* Returns true if two values of 16 bit size match */
static int
matches_16(unsigned char *a, unsigned char *b) {
    unsigned short int *a1 = (unsigned short int *) a;
    unsigned short int *b1 = (unsigned short int *) b;
    return (((*a1 ^ *b1)) == 0);
}


/* Returns true if two values of 16 bit size match, considering their masks. */
static int
pkt_mask16(unsigned char *a, unsigned char *am, unsigned char *b) {
    unsigned short int *a1 = (unsigned short int *) a;
    unsigned short int *b1 = (unsigned short int *) b;
    unsigned short int *mask = (unsigned short int *) am;
    
    return (((*mask) & (*a1 ^ ntohs(*b1))) == 0); /* modify by linke */
}

/* Returns true if two values of 16 bit size match, considering their masks. */
static int
matches_mask16(unsigned char *a, unsigned char *am, unsigned char *b) {
    unsigned short int *a1 = (unsigned short int *) a;
    unsigned short int *b1 = (unsigned short int *) b;
    unsigned short int *mask = (unsigned short int *) am;

    return (((*mask) & (*a1 ^ *b1)) == 0); // modify by linke
}


/*Returns true if two values of 32 bit size match . */
static int
pkt_match_32(unsigned char *a, unsigned char *b) {  
    unsigned int *a1 = (unsigned int *) a;
    unsigned int *b1 = (unsigned int *) b;
    return ((*a1 ^ ntohl(*b1)) == 0);
}

/*Returns true if two values of 32 bit size match . */
static int
matches_32(unsigned char *a, unsigned char *b) {
    unsigned int *a1 = (unsigned int *) a;
    unsigned int *b1 = (unsigned int *) b;
    return ((*a1 ^ *b1) == 0);   // modify by linke
}

/*Returns true if two values of 32 bit size match, considering their masks. */
static int
pkt_mask32(unsigned char *a, unsigned char *am, unsigned char *b) { 
    unsigned int *a1 = (unsigned int *) a;
    unsigned int *b1 = (unsigned int *) b;
    unsigned int *mask = (unsigned int *) am;
    
    return (((*mask) & (*a1 ^ ntohl(*b1))) == 0);   // modify by linke
}

/*Returns true if two values of 32 bit size match, considering their masks. */
static int
matches_mask32(unsigned char *a, unsigned char *am, unsigned char *b) {
    unsigned int *a1 = (unsigned int *) a;
    unsigned int *b1 = (unsigned int *) b;
    unsigned int *mask = (unsigned int *) am;
    return (((*mask) & (*a1 ^ *b1)) == 0);   // modify by linke
}

/* Returns true if two values of 64 bits size match*/
static int
pkt_64(unsigned char *a, unsigned char *b) {
    unsigned long long int *a1 = (unsigned long long int *) a;
    unsigned long long int *b1 = (unsigned long long int *) b;

    return ((*a1 ^ ntohll(*b1)) == 0);
}

/* Returns true if two values of 64 bits size match*/ 
static int
matches_64(unsigned char *a, unsigned char *b) {    
    unsigned long long int *a1 = (unsigned long long int *) a; 
    unsigned long long int *b1 = (unsigned long long int *) b;
    
    return ((*a1 ^ *b1) == 0);
} 

/* Returns true if two values of 64 bits size match, considering their masks.*/ 
static int
pkt_mask64(unsigned char *a,unsigned char *am, unsigned char *b) {   
    unsigned long long int *a1 = (unsigned long long int *) a; 
    unsigned long long int *b1 = (unsigned long long int *) b;
    unsigned long long int *mask = (unsigned long long int *) am;
    
    return (((*mask) & (*a1 ^ ntohll(*b1))) == 0);   // modify by linke
} 

/* Returns true if two values of 64 bits size match, considering their masks.*/
static int
matches_mask64(unsigned char *a,unsigned char *am, unsigned char *b) { 
    unsigned long long int *a1 = (unsigned long long int *) a;
    unsigned long long int *b1 = (unsigned long long int *) b;
    unsigned long long int *mask = (unsigned long long int *) am;

    return (((*mask) & (*a1 ^ *b1)) == 0);      // modify by linke
} 

/* Returns true if the two ethernet addresses match */
static int
eth_match(unsigned char *a, unsigned char *b) {
     return (matches_32(a,b) && matches_16(a+4,b+4) );
}

/* Returns true if the two ethernet addresses match, considering their masks. */
static int
eth_mask(unsigned char *a, unsigned char *am, unsigned char *b) {
     return (matches_mask32(a,am,b) && matches_mask16(a+4,am+4,b+4) );
}

static int
ipv6_match(unsigned char *a, unsigned char *b) {
    return (matches_64(a,b) && matches_64(a+8,b+8));
}

static int
ipv6_mask(unsigned char *a, unsigned char *am, unsigned char *b) {    
    return (matches_mask64(a,am,b) && matches_mask64(a+8,am+8,b+8));
}

#if 0
static unsigned int match_nonmask_header(struct ofl_match_tlv *f)
{
    if (!OXM_HASMASK(f->header))
    {
        return f->header;
    }

    return OXM_HEADER(OXM_VENDOR(f->header), OXM_FIELD(f->header), OXM_LENGTH(f->header)/2);
}
#endif
#if 0
static unsigned int getOxmHeadType(struct ofl_match_tlv *f) {     // added by linke
    unsigned int headerTmp = f->header;
    
    switch (f->header) 
    {
        case OXM_OF_METADATA_W: 
        {
            headerTmp = OXM_OF_METADATA;
            break;
        }
        case OXM_OF_ETH_DST_W: 
        {
            headerTmp = OXM_OF_ETH_DST;
            break;
        }
        case OXM_OF_ETH_SRC_W: 
        {
            headerTmp = OXM_OF_ETH_SRC;
            break;
        }
        case OXM_OF_VLAN_VID_W: 
        {
            headerTmp = OXM_OF_VLAN_VID;
            break;
        }
        case OXM_OF_IPV4_SRC_W: 
        {
            headerTmp = OXM_OF_IPV4_SRC;
            break;
        }
        case OXM_OF_IPV4_DST_W: 
        {
            headerTmp = OXM_OF_IPV4_DST;
            break;
        }
        case OXM_OF_ARP_SPA_W: 
        {
            headerTmp = OXM_OF_ARP_SPA;
            break;
        }
        case OXM_OF_ARP_TPA_W: 
        {
            headerTmp = OXM_OF_ARP_TPA;
            break;
        }
        case OXM_OF_ARP_SHA_W: 
        {
            headerTmp = OXM_OF_ARP_SHA;
            break;
        }
        case OXM_OF_ARP_THA_W: 
        {
            headerTmp = OXM_OF_ARP_THA;
            break;
        }
        case OXM_OF_IPV6_SRC_W: 
        {
            headerTmp = OXM_OF_IPV6_SRC;
            break;
        }
        case OXM_OF_IPV6_DST_W: 
        {
            headerTmp = OXM_OF_IPV6_DST;
            break;
        }
        case OXM_OF_IPV6_FLABEL_W: 
        {
            headerTmp = OXM_OF_IPV6_FLABEL;
            break;
        }
        default: 
        {
            break;
        }
    }

    return headerTmp;
}
#endif

bool packet_match(struct ofl_match *flow_match, struct ofl_match *packet)
{

    struct ofl_match_tlv *f;
    struct packet_fields *packet_f;
    bool ret = false;
    unsigned short int *matchv = NULL;
    bool any_vlan = false;
    unsigned int headerTmp;
    
    if (flow_match->header.length == 0)
    {
        return true;
    }
    /*TODO: Possible combinations of VLAN_ID and masks */
    
    HMAP_FOR_EACH_WITH_HASH(f, struct ofl_match_tlv, hmap_node, DP_FIELD_HASH(OXM_OF_VLAN_VID_W), &flow_match->match_fields)
    {
         unsigned short int *matchv = (unsigned short int*) f->value;
     
         HMAP_FOR_EACH_WITH_HASH(packet_f, struct packet_fields, hmap_node, DP_FIELD_HASH(OXM_OF_VLAN_VID), &packet->match_fields)
         {
              unsigned short int *maskv = (unsigned short int*) (f->value + 2);
              if ((*matchv == OFPVID_PRESENT) && (*maskv == OFPVID_PRESENT))
              {
                 any_vlan = true;
              }
         }
    }
    
    HMAP_FOR_EACH_WITH_HASH(f, struct ofl_match_tlv, hmap_node,DP_FIELD_HASH(OXM_OF_VLAN_VID), &flow_match->match_fields)
    {
        matchv = (unsigned short int*) f->value;
        /* Check if the field is present in the packet */
        HMAP_FOR_EACH_WITH_HASH(packet_f, struct packet_fields, hmap_node, DP_FIELD_HASH(OXM_OF_VLAN_VID), &packet->match_fields)
        {     
            /* Do not match packets with a VLAN Tag */
            if (*matchv == OFPVID_NONE)
            {
                return false;
            }
        }  
    } 
   
    /* Loop through the match fields */
    HMAP_FOR_EACH(f, struct ofl_match_tlv, hmap_node, &flow_match->match_fields)
    {
        /* Check if the field is present in the packet */
        //headerTmp = getOxmHeadType(f);
        headerTmp = f->header;
        
        if (OXM_HASMASK(f->header))
        {
            headerTmp = OXM_HEADER(OXM_VENDOR(f->header),OXM_FIELD(f->header),OXM_LENGTH(f->header)/2);
        }
        
        if(headerTmp == OXM_OF_VLAN_VID)
        {
            matchv = (unsigned short int*) f->value;
            //vlan vid = none 时，packet 没有vlan tag时可以匹配
            if (*matchv == OFPVID_NONE)
            {
                ret = true;
            }
        }

        HMAP_FOR_EACH_WITH_HASH(packet_f, struct packet_fields, hmap_node, DP_FIELD_HASH(headerTmp), &packet->match_fields)
        { 
            int field_len =  OXM_LENGTH(f->header);
            bool has_mask = OXM_HASMASK(f->header);
            ret = true;
                
            if (has_mask) 
            {
                field_len = field_len / 2;
            }
            
            switch (field_len){
                case (sizeof(unsigned char)):
                {
                    if (has_mask){
                        if (pkt_mask8(f->value,f->value + field_len, packet_f->value) == 0){
                          return false;
                        }
                    }
                    else 
                        if (matches_8(f->value, packet_f->value) == 0){
                          return false;
                    }
                    break;   
                }
                case (sizeof(unsigned short int)):
                {
                    if ((headerTmp != OXM_OF_VLAN_VID) || (!any_vlan))
                    {
                        if (has_mask)
                        {
                            if (pkt_mask16(f->value,f->value+ field_len, packet_f->value) == 0)
                            {
                              return false;
                            }
                        }
                        else 
                        {
                            if (pkt_match_16(f->value, packet_f->value) == 0)
                            {
                              return false;
                            }
                        }
                    } else {
                       //if vlan id is present
                       ret = true;
                    }
                    break;
                }
                case (sizeof(unsigned int)):
                {
                    if (has_mask){
                        if (f->header == OXM_OF_IPV4_DST_W || f->header == OXM_OF_IPV4_SRC_W
						    ||f->header == OXM_OF_ARP_SPA_W || f->header == OXM_OF_ARP_TPA_W){
						    if (matches_mask32(f->value,f->value + field_len, packet_f->value) == 0){
                                 return false;
                            }
                        }
                        else
                            if (pkt_mask32(f->value,f->value + field_len, packet_f->value) == 0){
                                return false;
                        }
                    }
                    else
                        if (f->header == OXM_OF_IPV4_DST || f->header == OXM_OF_IPV4_SRC
						    ||f->header == OXM_OF_ARP_SPA || f->header == OXM_OF_ARP_TPA){
						    if (matches_32(f->value, packet_f->value) == 0){
                                 return false;
                            }
                        }

                        else
                            if (pkt_match_32(f->value, packet_f->value) == 0){
                                return false;
                        }
                    break;
                 }
                case (ETH_ADDR_LEN):{
                     if (has_mask){
                        if (eth_mask(f->value,f->value + field_len, packet_f->value) == 0){
                          return false;
                        }
                     }
                    else
                        if (eth_match(f->value, packet_f->value) == 0){
                          return false;
                        }
                    break;
                }
                case (sizeof(unsigned long long int)):{
                    /* metadata in host byte order */
                    if (has_mask) {
                        if (OXM_OF_METADATA_W == f->header)
                        {
                            if (matches_mask64(f->value,f->value + field_len, packet_f->value) == 0)
                            {
                                return false;
                            }
                        }
                        else if (pkt_mask64(f->value,f->value + field_len, packet_f->value) == 0)
                        {
                          return false;
                        }
                    }
                    else {
                        if (OXM_OF_METADATA == f->header)
                        {
                            if (matches_64(f->value, packet_f->value) == 0)
                            {
                                return false;
                            }
                        }
                        else if (pkt_64(f->value, packet_f->value) == 0)
                        {
                          return false;
                        }
                    }
                    break;
                }
		            case (16):{
                    if (has_mask){
                        if (ipv6_mask(f->value,f->value + field_len, packet_f->value) == 0){
                          return false;
                        }
                    }
                    else
                        if (ipv6_match(f->value, packet_f->value) == 0){
                          return false;
                        }
                    break;
                }
            }
        }
            
         if (!ret)
            return ret;
         else 
            ret = false;      
    }

    return true;

}


static inline bool
strict_mask8(unsigned char *a, unsigned char *b, unsigned char *am, unsigned char *bm) {
	return (am[0] == bm[0]) && ((a[0] ^ b[0]) & am[0]) == 0;
}

static inline bool
strict_mask16(unsigned char *a, unsigned char *b, unsigned char *am, unsigned char *bm) {
	unsigned short int *a1 = (unsigned short int *) a;
    unsigned short int *b1 = (unsigned short int *) b;
    unsigned short int *mask_a = (unsigned short int *) am;
	unsigned short int *mask_b = (unsigned short int *) bm;
	return (*mask_a == *mask_b) && ((*a1 ^ *b1) & (*mask_a)) == 0;
}

static inline bool
strict_mask32(unsigned char *a, unsigned char *b, unsigned char *am, unsigned char *bm) {
	unsigned int *a1 = (unsigned int *) a;
    unsigned int *b1 = (unsigned int *) b;
    unsigned int *mask_a = (unsigned int *) am;
	unsigned int *mask_b = (unsigned int *) bm;
  
	return (*mask_a == *mask_b) && (((*a1 ^ *b1) & (*mask_a)) == 0);
}

static inline bool
strict_mask64(unsigned char *a, unsigned char *b, unsigned char *am, unsigned char *bm) {
	unsigned long long int *a1 = (unsigned long long int *) a;
    unsigned long long int *b1 = (unsigned long long int *) b;
    unsigned long long int *mask_a = (unsigned long long int *) am;
	unsigned long long int *mask_b = (unsigned long long int *) bm;
	return (*mask_a == *mask_b) && ((*a1 ^ *b1) & (*mask_a)) == 0;
}

static inline bool
strict_ethaddr(unsigned char *a, unsigned char *b, unsigned char *am, unsigned char *bm) {
	return strict_mask32(a,b,am,bm) &&
		   strict_mask16(a + 4, b + 4, am + 4, bm + 4);
}
		   
		   
static inline bool
strict_ipv6(unsigned char *a, unsigned char *b, unsigned char *am, unsigned char *bm) {
    return strict_mask64(a,b,am,bm) &&
		   strict_mask64(a + 8, b + 8, am + 8, bm + 8);

}

/* Two matches strictly match, if their wildcard fields are the same, and all the
 * non-wildcarded fields match on the same exact values.
 * NOTE: Handling of bitmasked fields is not specified. In this implementation
 * masked fields are checked for equality, and only unmasked bits are compared
 * in the field.
 */
bool
match_std_strict(struct ofl_match *a, struct ofl_match *b) {
  
    struct ofl_match_tlv *flow_mod_match; 
    struct ofl_match_tlv *flow_entry_match;
    bool ret = false;

    /*Both matches all wildcarded */
    if(!a->header.length && !b->header.length )
        return true;
    /* If the matches differ in length, there is no reason to compare
        once they will differ in the number of fields */
    if (a->header.length != b->header.length)
        return false;

   
    /* Loop through the match fields */
    HMAP_FOR_EACH(flow_mod_match, struct ofl_match_tlv, hmap_node, &a->match_fields){
       /* Check if the field is present in the flow entry */
        HMAP_FOR_EACH_WITH_HASH(flow_entry_match, struct ofl_match_tlv, hmap_node, DP_FIELD_HASH(flow_mod_match->header), &b->match_fields){
                bool has_mask;
                int field_len;

                /* Check if both fields have or not a mask */
                if ( (OXM_HASMASK(flow_mod_match->header) && !OXM_HASMASK(flow_entry_match->header))
                    || (!OXM_HASMASK(flow_mod_match->header) && OXM_HASMASK(flow_entry_match->header))){
                    return false;
                }
                ret = true;
                has_mask = OXM_HASMASK(flow_mod_match->header);
                field_len = has_mask ? (OXM_LENGTH(flow_mod_match->header)/2) : OXM_LENGTH(flow_mod_match->header);
                switch (field_len){
                    case (sizeof(unsigned char)):{
                        if (has_mask){
                            if (strict_mask8(flow_mod_match->value, flow_entry_match->value, flow_mod_match->value  + field_len, flow_entry_match->value + field_len) == 0){
                              return false;
                            }
                        }
                        else 
                            if (matches_8(flow_mod_match->value, flow_entry_match->value) == 0){
                              return false;
                        }
                        break;   
                    }
                    case (sizeof(unsigned short int)):{ 
                        if (has_mask){
                            if (strict_mask16(flow_mod_match->value,flow_entry_match->value, flow_mod_match->value + field_len, flow_entry_match->value + field_len) == 0){
                              return false;
                            }
                        }
                        else 
                            if (matches_16(flow_mod_match->value, flow_entry_match->value) == 0){
                              return false;
                        }
                        break;
                    } 
                    case (sizeof(unsigned int)):{ 

                        if (has_mask){
                            if (strict_mask32(flow_mod_match->value,flow_entry_match->value, flow_mod_match->value + field_len, flow_entry_match->value + field_len) == 0 ){
                              return false;
                            }
                        }
                        else 
                            if (matches_32(flow_mod_match->value, flow_entry_match->value) == 0){
                              return false;
                            }
                        break;
                    }
                    case (ETH_ADDR_LEN):{ 
                         if (has_mask){
                            if (strict_ethaddr(flow_mod_match->value,flow_entry_match->value, flow_mod_match->value + field_len,flow_entry_match->value + field_len) == 0){
                              return false;
                            }
                         }
                        else 
                            if (eth_match(flow_mod_match->value, flow_entry_match->value) == 0){
                              return false;
                            }
                        break;
                    }
                    case (sizeof(unsigned long long int)):{ 
                        if (has_mask) {
                            //if (strict_mask64(flow_mod_match->value,flow_entry_match->value + field_len, flow_entry_match->value,flow_entry_match->value + field_len) == 0){
                            if (strict_mask64(flow_mod_match->value,flow_entry_match->value, flow_mod_match->value + field_len, flow_entry_match->value + field_len) == 0){
                              return false;
                            }
                        }
                        else 
                            if (matches_64(flow_mod_match->value, flow_entry_match->value) == 0){
                              return false;
                            }
                        break;
                    }
   		            case (16):{
                        if (has_mask){
                            if (strict_ipv6(flow_mod_match->value,flow_entry_match->value, flow_mod_match->value + field_len, flow_entry_match->value + field_len) == 0){
                              return false;
                            }
                        }
                        else 
                            if (ipv6_match(flow_mod_match->value, flow_entry_match->value) == 0){
                              return false;
                            }
                        break;
                    }
 
            }
           
        }
         if (!ret)
            return ret;
        else ret = false;
    } 

    return true;     
}



static inline bool
nonstrict_mask8(unsigned char *a, unsigned char *b, unsigned char *am, unsigned char *bm) {

    return (~am[0] & (~a[0] | ~b[0] | bm[0]) & (a[0] | b[0] | bm[0])) == 0;
    //if (*bm == 0)
    //    *bm = ~(*bm);
    //return ( am[0] & (~a[0] | ~b[0] | ~bm[0]) & (a[0] | b[0] | ~bm[0])) == 0;
}

static inline bool
nonstrict_mask16(unsigned char *a, unsigned char *b, unsigned char *am, unsigned char *bm) {
    unsigned short int *a1 = (unsigned short int *) a;
    unsigned short int *b1 = (unsigned short int *) b;
    unsigned short int *mask_a = (unsigned short int *) am;
    unsigned short int *mask_b = (unsigned short int *) bm;
    return (~(*mask_a) & (~(*a1) | ~(*b1) | *mask_b) & (*a1| *b1 | *mask_b)) == 0;
    //if (*mask_b == 0)
    //    *mask_b = ~(*mask_b);
    //return ( (*mask_a) & (~(*a1) | ~(*b1) | ~(*mask_b)) & (*a1| *b1 | ~(*mask_b))) == 0;//change by xiaojunjun,mask
}

static inline bool
nonstrict_mask32(unsigned char *a, unsigned char *b, unsigned char *am, unsigned char *bm) {
    unsigned int *a1 = (unsigned int *) a;
    unsigned int *b1 = (unsigned int *) b;
    unsigned int *mask_a = (unsigned int *) am;
    unsigned int *mask_b = (unsigned int *) bm;
    return (~(*mask_a) & (~(*a1) | ~(*b1) | *mask_b) & (*a1| *b1 | *mask_b)) == 0;
    //if (*mask_b == 0)
    //    *mask_b = ~(*mask_b);
    //return ((*mask_a) & (~(*a1) | ~(*b1) | ~(*mask_b)) & (*a1| *b1 | ~(*mask_b))) == 0;
}

static inline bool
nonstrict_mask64(unsigned char *a, unsigned char *b, unsigned char *am, unsigned char *bm) {
    unsigned long long int *a1 = (unsigned long long int *) a;
    unsigned long long int *b1 = (unsigned long long int *) b;
    unsigned long long int *mask_a = (unsigned long long int *) am;
    unsigned long long int *mask_b = (unsigned long long int *) bm;
    return (~(*mask_a) & (~(*a1) | ~(*b1) | *mask_b) & (*a1| *b1 | *mask_b)) == 0;
    //if (*mask_b == 0)
    //    *mask_b = ~(*mask_b);
    //return ( (*mask_a) & (~(*a1) | ~(*b1) | ~(*mask_b)) & (*a1| *b1 | ~(*mask_b))) == 0;
}

static inline bool
nonstrict_ethaddr(unsigned char *a, unsigned char *b, unsigned char *am, unsigned char *bm) {
	return nonstrict_mask32(a,  b, am, bm) &&
		   nonstrict_mask16(a + 4 , b + 4, am + 4, bm + 4);
}

static inline bool
nonstrict_ipv6(unsigned char *a, unsigned char *b, unsigned char *am, unsigned char *bm) {
	return nonstrict_mask64(a, b, am, bm) &&
		   nonstrict_mask64(a + 8, b + 8, am + 8, bm + 8);
}

static bool nonstrict_match(struct ofl_match_tlv *flow_mod_match, struct ofl_match_tlv *flow_entry_match)
{
    bool flow_mod_mask;
    bool flow_entry_mask;
    int flow_mod_len;

    if (!OXM_HASMASK(flow_mod_match->header) && OXM_HASMASK(flow_entry_match->header))
    {
        return false;
    }

    flow_mod_mask = OXM_HASMASK(flow_mod_match->header);
    flow_entry_mask = OXM_HASMASK(flow_entry_match->header);
    flow_mod_len = flow_mod_mask ? (OXM_LENGTH(flow_mod_match->header)/2) : OXM_LENGTH(flow_mod_match->header);

    switch (flow_mod_len)
    {
        case (sizeof(unsigned char)):{
            if (flow_mod_mask){
                unsigned char *entry_mask;
                unsigned char entry_mask_v = 0x0;

                entry_mask = (flow_entry_mask ? (flow_entry_match->value + flow_mod_len) : &entry_mask_v);
                if (nonstrict_mask8(flow_mod_match->value, flow_entry_match->value, flow_mod_match->value + flow_mod_len, entry_mask) == 0){
                  return false;
                }
            }
            else
                if (matches_8(flow_mod_match->value, flow_entry_match->value) == 0){
                  return false;
            }
            break;
        }
        case (sizeof(unsigned short int)):{
            if (flow_mod_mask){
                unsigned char *entry_mask;
                unsigned short int entry_mask_v = 0x0;

                entry_mask = (flow_entry_mask ? (flow_entry_match->value + flow_mod_len) : (unsigned char *)&entry_mask_v);
                if (nonstrict_mask16(flow_mod_match->value, flow_entry_match->value, flow_mod_match->value + flow_mod_len, entry_mask) == 0){
                  return false;
                }
            }
            else
                if (matches_16(flow_mod_match->value, flow_entry_match->value) == 0){
                  return false;
            }
            break;
        }
        case (sizeof(unsigned int)):{

            if (flow_mod_mask){
                unsigned char *entry_mask;
                unsigned int entry_mask_v = 0x0;

                entry_mask = (flow_entry_mask ? (flow_entry_match->value + flow_mod_len) : (unsigned char *)&entry_mask_v);
                if (nonstrict_mask32(flow_mod_match->value, flow_entry_match->value, flow_mod_match->value + flow_mod_len, entry_mask) == 0){
                  return false;
                }
            }
            else
                if (matches_32(flow_mod_match->value, flow_entry_match->value) == 0){
                  return false;
                }
            break;
        }
        case (ETH_ADDR_LEN):{
             if (flow_mod_mask){
                unsigned char *entry_mask;
                unsigned char entry_mask_v[ETH_ADDR_LEN] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

                entry_mask = (flow_entry_mask ? (flow_entry_match->value + flow_mod_len) : entry_mask_v);
                if (nonstrict_ethaddr(flow_mod_match->value,flow_entry_match->value, flow_mod_match->value + flow_mod_len, entry_mask) == 0){
                  return false;
                }
             }
            else
                if (eth_match(flow_mod_match->value, flow_entry_match->value) == 0){
                  return false;
                }
            break;
        }
        case (sizeof(unsigned long long int)):{
            if (flow_mod_mask) {
                unsigned char *entry_mask;
                unsigned long long int entry_mask_v = 0x0;

                entry_mask = (flow_entry_mask ? (flow_entry_match->value + flow_mod_len) : (unsigned char *)&entry_mask_v);
                if (nonstrict_mask64(flow_mod_match->value, flow_entry_match->value, flow_mod_match->value + flow_mod_len, entry_mask) == 0){
                  return false;
                }
            }
            else
                if (matches_64(flow_mod_match->value, flow_entry_match->value) == 0){
                  return false;
                }
            break;
        }
            case (16):{
            if (flow_mod_mask){
                unsigned char *entry_mask;
                unsigned char entry_mask_v[IPv6_ADDR_LEN] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

                entry_mask = (flow_entry_mask ? (flow_entry_match->value + flow_mod_len) : entry_mask_v);
                if (nonstrict_ipv6(flow_mod_match->value,flow_entry_match->value, flow_mod_match->value + flow_mod_len,entry_mask)== 0){
                  return false;
                }
            }
            else
                if (ipv6_match(flow_mod_match->value, flow_entry_match->value) == 0){
                  return false;
                }
            break;
        }
            default:
            {
                assert(0);
                break;
            }
    }
    return true;
}

bool
match_std_nonstrict(struct ofl_match *a, struct ofl_match *b) {

struct ofl_match_tlv *flow_mod_match;
    struct ofl_match_tlv *flow_entry_match;
    bool ret = false;

    /* flow mod message matches all flows */
    if(!a->header.length )
        return true;

    if (!b->header.length)
    {
        return false;
    }

    /* Loop through the match fields */
    HMAP_FOR_EACH(flow_mod_match, struct ofl_match_tlv, hmap_node, &a->match_fields){
        bool same_mask_flag = false;
        bool has_mask = OXM_HASMASK(flow_mod_match->header);

        /* Check if the field is present in the flow entry */
        HMAP_FOR_EACH_WITH_HASH(flow_entry_match, struct ofl_match_tlv, hmap_node, DP_FIELD_HASH(flow_mod_match->header), &b->match_fields){
                same_mask_flag = true;
                ret = nonstrict_match(flow_mod_match, flow_entry_match);
        }

        /* flow mod messages have mask, flow entry don't have mask */
        if (!same_mask_flag && has_mask)
        {
            HMAP_FOR_EACH_WITH_HASH(flow_entry_match, struct ofl_match_tlv, hmap_node, DP_FIELD_HASH(OXM_MAKE_NONWILD_HEADER(flow_mod_match->header)), &b->match_fields){
                ret = nonstrict_match(flow_mod_match, flow_entry_match);
            }
           
        }
         if (!ret)
            return ret;
        else 
            ret = false;
    } 
    return true;

}

