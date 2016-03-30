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

#include <netinet/in.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include "ofl.h"
#include "ofl-utils.h"
#include "ofl-actions.h"
#include "ofl-structs.h"
#include "ofl-messages.h"
#include "ofl-print.h"
#include "ofl-packets.h"
#include "ofl-log.h"
#include "openflow/openflow.h"
#include "oxm-match.h"

#define LOG_MODULE ofl_act_u
OFL_LOG_INIT(LOG_MODULE)

static bool match_vid_none(struct ofl_msg_flow_mod * dm)
{
    struct ofl_match * match;
    unsigned char * p;
    match = (struct ofl_match *)(dm->match);
    p = get_oxm_value(match, OXM_OF_VLAN_VID);
    if( NULL != p )
    {
        if (*(unsigned short int*) p == OFPVID_NONE )
        {
            return true;
        }
    }
    return false;
}
static bool is_ip_proto_ipv4(struct ofl_msg_flow_mod * dm)
{
    struct ofl_match * match;
    unsigned char * p;
    match = (struct ofl_match *)(dm->match);
    p = get_oxm_value(match, OXM_OF_ETH_TYPE);
    if( NULL != p )
    {
        if (*(unsigned short int*) p == 0x0800 )
        {
            return true;
        }
    }
    return false;
}
static ofl_err validate_set_field_actions(struct ofl_msg_flow_mod * dm, unsigned char type,unsigned char *value)
{
    switch(type)
    {
        case OFPXMT_OFB_VLAN_VID:
        {
            unsigned short int vlan_vid = ntohs(*((unsigned short int *)value));
            //unsigned short int val = vlan_vid;

            vlan_vid &= ~OFPVID_PRESENT;
            if(vlan_vid > OFPVID_PRESENT)
            {
                 return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_SET_ARGUMENT);
            }
            break;
        }
        case OFPXMT_OFB_VLAN_PCP:
        {
            unsigned char vlan_pcp = *value;

            if(vlan_pcp > 7)
            {
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_SET_ARGUMENT);
            }
            break;
        }
        case OFPXMT_OFB_MPLS_TC:
        {
            unsigned char mpls_tc = *value;
            if(mpls_tc > 7)
            {
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_SET_ARGUMENT);
            }
            break;
        }
        case OFPXMT_OFB_MPLS_LABEL:
        {
            unsigned int mpls_label = ntohl(*((unsigned int *)value));
            if(mpls_label > 0xFFFFF)
            {
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_SET_ARGUMENT);
            }
            break;
        }
        case OFPXMT_OFB_IPV4_SRC:
        case OFPXMT_OFB_IPV4_DST:
        {
            if( NULL != dm)
            {
                if(true != is_ip_proto_ipv4(dm))
                {
                    return ofl_error(OFPET_BAD_ACTION, OFPBAC_MATCH_INCONSISTENT);
                }
            }
            break;
        }
        default:
            break;
    }

    return 0;
}


ofl_err
ofl_actions_unpack(struct ofl_msg_flow_mod * dm,struct ofp_action_header *src, size_t *len, struct ofl_action_header **dst, struct ofl_exp *exp) {

    if (*len < sizeof(struct ofp_action_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received action is too short (%zu).", *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_SET_LEN);
    }

    if (*len < ntohs(src->len)) {
        OFL_LOG_WARN(LOG_MODULE, "Received action has invalid length (set to %u, but only %zu received).", ntohs(src->len), *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_TYPE);
    }

    /*
    if ((ntohs(src->len) % 8) != 0) {
        OFL_LOG_WARN(LOG_MODULE, "Received action length is not a multiple of 64 bits (%u).", ntohs(src->len));
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_SET_LEN);
    }
    */

    if((ntohs(src->type) == OFPAT_OUTPUT)&&(ntohs(src->len) != 16))
    {
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    if(ntohs(src->type) == 30)
    {
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_TYPE);

    }

    if( NULL != dm)
    {
        switch (ntohs(src->type)) {
            case OFPAT_POP_VLAN:{
                if( true == match_vid_none(dm) )
                {
                    return ofl_error(OFPET_BAD_ACTION, OFPBAC_MATCH_INCONSISTENT);
                }
                 break;
            }
            default :
                break;
        }
    }

    switch (ntohs(src->type)) {
        case OFPAT_OUTPUT: {
            struct ofp_action_output *sa;
            struct ofl_action_output *da;

            if (*len < sizeof(struct ofp_action_output)) {
                OFL_LOG_WARN(LOG_MODULE, "Received OUTPUT action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_output *)src;


            if(ntohl(sa->port) == OFPP_MAX)
            {
                return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_PORT);
            }

            if (ntohl(sa->port) == 0 ||
                (ntohl(sa->port) >= OFPP_MAX && ntohl(sa->port) < OFPP_IN_PORT) ||
                ntohl(sa->port) == OFPP_ANY) {
                if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
                    char *ps = ofl_port_to_string(ntohl(sa->port));
                    OFL_LOG_WARN(LOG_MODULE, "Received OUTPUT action has invalid port (%s).", ps);
                    free(ps);
                }
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT);
            }

            da = (struct ofl_action_output *)malloc(sizeof(struct ofl_action_output));
            da->port = ntohl(sa->port);
            da->max_len = ntohs(sa->max_len);

            *len -= sizeof(struct ofp_action_output);
            *dst = (struct ofl_action_header *)da;
            break;
        }
        case OFPAT_COPY_TTL_OUT: {
            //ofp_action_header length was already checked
            *len -= sizeof(struct ofp_action_header);
            *dst = (struct ofl_action_header *)malloc(sizeof(struct ofl_action_header));
            break;
        }

        case OFPAT_COPY_TTL_IN: {
            //ofp_action_header length was already checked
            *len -= sizeof(struct ofp_action_header);
            *dst = (struct ofl_action_header *)malloc(sizeof(struct ofl_action_header));
            break;
        }

        case OFPAT_SET_MPLS_TTL: {
            struct ofp_action_mpls_ttl *sa;
            struct ofl_action_mpls_ttl *da;

            if (*len < sizeof(struct ofp_action_mpls_ttl)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_MPLS_TTL action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_mpls_ttl *)src;

            da = (struct ofl_action_mpls_ttl *)malloc(sizeof(struct ofl_action_mpls_ttl));
            da->mpls_ttl = sa->mpls_ttl;

            *len -= sizeof(struct ofp_action_mpls_ttl);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_DEC_MPLS_TTL: {
            //ofp_action_header length was already checked
            *len -= sizeof(struct ofp_action_mpls_ttl);
            *dst = (struct ofl_action_header *)malloc(sizeof(struct ofl_action_header));
            break;
        }

        case OFPAT_PUSH_VLAN:
        case OFPAT_PUSH_PBB:
        case OFPAT_PUSH_MPLS: {
            struct ofp_action_push *sa;
            struct ofl_action_push *da;

            if (*len < sizeof(struct ofp_action_push)) {
                OFL_LOG_WARN(LOG_MODULE, "Received PUSH_VLAN/MPLS/PBB action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_push *)src;

            if (((ntohs(src->type) == OFPAT_PUSH_VLAN) &&
                    (ntohs(sa->ethertype) != ETH_TYPE_VLAN &&
                     ntohs(sa->ethertype) != ETH_TYPE_VLAN_PBB)) ||
                ((ntohs(src->type) == OFPAT_PUSH_MPLS) &&
                    (ntohs(sa->ethertype) != ETH_TYPE_MPLS &&
                     ntohs(sa->ethertype) != ETH_TYPE_MPLS_MCAST)) ||
                ((ntohs(src->type) == OFPAT_PUSH_PBB) &&
                    (ntohs(sa->ethertype) != ETH_TYPE_PBB))) {
                OFL_LOG_WARN(LOG_MODULE, "Received PUSH_VLAN/MPLS/PBB has invalid eth type. (%u)", ntohs(sa->ethertype));
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
            }

            da = (struct ofl_action_push *)malloc(sizeof(struct ofl_action_push));
            da->ethertype = ntohs(sa->ethertype);

            *len -= sizeof(struct ofp_action_push);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_POP_VLAN:
        case OFPAT_POP_PBB: {
            //ofp_action_header length was already checked
            *len -= sizeof(struct ofp_action_header);
            *dst = (struct ofl_action_header *)malloc(sizeof(struct ofl_action_header));
            break;
        }

        case OFPAT_POP_MPLS: {
            struct ofp_action_pop_mpls *sa;
            struct ofl_action_pop_mpls *da;

            if (*len < sizeof(struct ofp_action_pop_mpls)) {
                OFL_LOG_WARN(LOG_MODULE, "Received POP_MPLS action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_pop_mpls *)src;

            da = (struct ofl_action_pop_mpls *)malloc(sizeof(struct ofl_action_pop_mpls));
            da->ethertype = ntohs(sa->ethertype);

            *len -= sizeof(struct ofp_action_pop_mpls);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_SET_QUEUE: {
            struct ofp_action_set_queue *sa;
            struct ofl_action_set_queue *da;

            if (*len < sizeof(struct ofp_action_set_queue)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_QUEUE action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_set_queue *)src;

            da = (struct ofl_action_set_queue *)malloc(sizeof(struct ofl_action_set_queue));
            da->queue_id = ntohl(sa->queue_id);

            *len -= sizeof(struct ofp_action_set_queue);
            *dst = (struct ofl_action_header *)da;
            if(da->queue_id > 8)
            {
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_QUEUE);
            }
            break;
        }

        case OFPAT_GROUP: {
            struct ofp_action_group *sa;
            struct ofl_action_group *da;

            if (*len < sizeof(struct ofp_action_group)) {
                OFL_LOG_WARN(LOG_MODULE, "Received GROUP action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_group *)src;

            if (ntohl(sa->group_id) > OFPG_MAX) {
                if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
                    char *gs = ofl_group_to_string(ntohl(sa->group_id));
                    OFL_LOG_WARN(LOG_MODULE, "Received GROUP action has invalid group id (%s).", gs);
                    free(gs);
                }
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_GROUP);
            }

            da = (struct ofl_action_group *)malloc(sizeof(struct ofl_action_group));
            da->group_id = ntohl(sa->group_id);

            *len -= sizeof(struct ofp_action_group);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_SET_NW_TTL: {
            struct ofp_action_nw_ttl *sa;
            struct ofl_action_set_nw_ttl *da;

            if (*len < sizeof(struct ofp_action_nw_ttl)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_NW_TTL action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_nw_ttl *)src;

            da = (struct ofl_action_set_nw_ttl *)malloc(sizeof(struct ofl_action_set_nw_ttl));
            da->nw_ttl = sa->nw_ttl;

            *len -= sizeof(struct ofp_action_nw_ttl);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_DEC_NW_TTL: {
            //ofp_action_header length was already checked
            *len -= sizeof(struct ofp_action_header);
            *dst = (struct ofl_action_header *)malloc(sizeof(struct ofl_action_header));
            break;
        }

        case OFPAT_SET_FIELD: {
            ofl_err error;
            struct ofp_action_set_field *sa;
            struct ofl_action_set_field *da;
            unsigned char *value;

            sa = (struct ofp_action_set_field*) src;
            da = (struct ofl_action_set_field *)malloc(sizeof(struct ofl_action_set_field));
            da->field = (struct ofl_match_tlv*) malloc(sizeof(struct ofl_match_tlv));

            memcpy(&da->field->header,sa->field,4);
            da->field->header = ntohl(da->field->header);
            value = (unsigned char *) src + sizeof (struct ofp_action_set_field);
            da->field->value = malloc(OXM_LENGTH(da->field->header));

            /*TODO: need to check if other fields are valid */
            if(da->field->header == OXM_OF_IN_PORT || da->field->header == OXM_OF_IN_PHY_PORT
                                    || da->field->header == OXM_OF_METADATA || da->field->header == OXM_OF_ARP_SPA){
                /* 释放内存 */
                free(da->field->value);
                free(da->field);
                free(da);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_SET_TYPE);
            }

            if((src->type == OFPXMT_OFB_IPV4_SRC)&&(src->len != 16))
            {
                /* 释放内存 */
                free(da->field->value);
                free(da->field);
                free(da);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_SET_LEN);

            }
            error = validate_set_field_actions(dm, OXM_FIELD(da->field->header),value);
            if( error != 0)
            {
                /* 释放内存 */
                free(da->field->value);
                free(da->field);
                free(da);
                return error;
            }

            switch(OXM_LENGTH(da->field->header)){
                case 1:
                case 6:
                case 16:
                    memcpy(da->field->value , value, OXM_LENGTH(da->field->header));
                    break;

                case 2:{
                    unsigned short int v = ntohs(*((unsigned short int*) value));
                    memcpy(da->field->value , &v, OXM_LENGTH(da->field->header));
                    break;
                }

                case 3:{
                    return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_SET_LEN);
                }

                case 4:{
                    unsigned int v = htonl(*((unsigned int*) value));
                    memcpy(da->field->value , &v, OXM_LENGTH(da->field->header));
                    break;
                }
                case 8:{
                    unsigned long long int v = hton64(*((unsigned long long int*) value));
                    memcpy(da->field->value , &v, OXM_LENGTH(da->field->header));
                    break;
                }
            }
            *len -= ROUND_UP(ntohs(src->len),8);
            *dst = (struct ofl_action_header *)da;

            if((da->field->header == OXM_OF_VLAN_VID)&&((da->field->value)[0] == 0x10)&&((da->field->value)[1] == 0x00))
            {
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_SET_ARGUMENT);
            }
            break;
    }

        case OFPAT_EXPERIMENTER: {
            ofl_err error;

            if (*len < sizeof(struct ofp_action_experimenter_header)) {
                OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            if (exp == NULL || exp->act == NULL || exp->act->unpack == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER action, but no callback is given.");
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_EXPERIMENTER);
            }
            error = exp->act->unpack(src, len, dst);
            if (error) {
                return error;
            }
            break;
        }

        default: {
            OFL_LOG_WARN(LOG_MODULE, "Received unknown action type (%u).", ntohs(src->type));
            return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_TYPE);
        }
    }
    (*dst)->type = (enum ofp_action_type)ntohs(src->type);

    return 0;
}
