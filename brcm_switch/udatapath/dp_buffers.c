/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

/* The original Stanford code has been modified during the implementation of
 * the OpenFlow 1.1 userspace switch.
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <stdbool.h>
#include <stdint.h>
#include <math.h>

#include "dp_buffers.h"
#include "timeval.h"
#include "packet.h"
#include "vlog.h"
#include "flow_entry.h"
#include "flow_table_exact.h"

#define LOG_MODULE VLM_dp_buf

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);


/* Buffers are identified by a 31-bit opaque ID.  We divide the ID
 * into a buffer number (low bits) and a cookie (high bits).  The buffer number
 * is an index into an array of buffers.  The cookie distinguishes between
 * different packets that have occupied a single buffer.  Thus, the more
 * buffers we have, the lower-quality the cookie... */
#define PKT_BUFFER_BITS 10
#define PKT_COOKIE_BITS (32 - PKT_BUFFER_BITS)

#define N_PKT_BUFFERS (1 << PKT_BUFFER_BITS)
#define PKT_BUFFER_MASK (N_PKT_BUFFERS - 1)
#define N_DATA_BUFFERS 4096
#define N_PKT_UNIT 2048
#define N_HASH_DIV 4087
#define N_PKT_IN_PIPELINE 1

#define OVERWRITE_SECS  1
#define RESEND_SECS 2
#define OVEROUT_SECS 20

struct data_type{
    struct list node;
    bool run_pipeline;
    unsigned int  hash;
    unsigned int num_pkt_in_pipeline;
    unsigned int num_pkt;
    time_t         timeout;
    unsigned int key_len;
    unsigned char   *key;
};

struct data_unit {
    struct list node;
    unsigned int  hash;
    struct packet *pkt;
    unsigned int       cookie;
    time_t         timeout;
};

struct data_buffer{
    struct list unit_head;
    struct list type_head;
    unsigned int units_num;
    time_t         timeout;
};

struct packet_buffer {
    struct packet *pkt;
    unsigned int       cookie;
    time_t         timeout;
};

// NOTE: The current implementation assumes that a packet is only saved once
//       to the buffers. Thus, if two entities save it, and one retrieves it,
//       the other will receive an invalid buffer response.
//       In the current implementation this should not happen.

struct data_buffers {
    struct datapath       *dp;
    struct data_buffer   buffers[N_DATA_BUFFERS];
    struct data_buffer   hwbuf[N_DATA_BUFFERS];
};

struct dp_buffers {
    struct datapath       *dp;
    size_t                 buffer_idx;
    size_t                 buffers_num;
    struct packet_buffer   buffers[N_PKT_BUFFERS];
};

static unsigned char *malloc_pkt_key(int len)
{
    unsigned char *ptr;
    ptr = xmalloc(len);
    memset(ptr,0,len);
    return ptr;
}

static void free_pkt_key(unsigned char* key)
{
    if(key != NULL)
    {
        free(key);
    }

    return;
}

static struct data_type*
    dp_buffers_type_create(int len_key){
    struct data_type *dpt = xmalloc(sizeof(struct data_type));
    if(dpt != NULL)
    {
        list_init(&dpt->node);
        dpt->hash = 0;
        dpt->run_pipeline = true;
        dpt->num_pkt_in_pipeline = 0;
        dpt->num_pkt = 0;
        dpt->timeout = 0;
        dpt->key_len = len_key;
        dpt->key = malloc_pkt_key(len_key);
    }

    return dpt;
}

static void dp_buffers_type_destroy(struct data_type *p)
{
    if(NULL != p)
    {
        free(p);
    }

    return ;
}
#if 0
static struct data_unit*
    dp_buffers_unit_create(){
    struct data_unit *dpu = xmalloc(sizeof(struct data_unit));
    if(dpu != NULL)
    {
        list_init(&dpu->node);
        dpu->hash = 0;
        dpu->pkt = NULL;
        dpu->cookie = 0;
        dpu->timeout = 0;
    }

    return dpu;
}

static void dp_buffers_unit_destroy(struct data_unit *p)
{
    if(NULL != p)
    {
        free(p);
    }

    return;
}
#endif
struct dp_buffers *
dp_buffers_create(struct datapath *dp) {
    struct dp_buffers *dpb = xmalloc(sizeof(struct dp_buffers));
    size_t i;

    dpb->dp          = dp;
    dpb->buffer_idx  = (size_t)-1;
    dpb->buffers_num = N_PKT_BUFFERS;

    for (i=0; i<N_PKT_BUFFERS; i++) {
        dpb->buffers[i].pkt     = NULL;
        dpb->buffers[i].cookie  = UINT32_MAX;
        dpb->buffers[i].timeout = 0;
    }

    return dpb;
}

struct data_buffers *
dp_data_buffers_create(struct datapath *dp) {
    struct data_buffers *dpb = xmalloc(sizeof(struct data_buffers));
    size_t i;

    dpb->dp          = dp;

    for (i=0; i<N_DATA_BUFFERS; i++) {
        dpb->buffers[i].units_num = 0;
        dpb->buffers[i].timeout = 0;
        list_init(&(dpb->buffers[i].type_head));
        list_init(&(dpb->buffers[i].unit_head));

        dpb->hwbuf[i].units_num = 0;
        dpb->hwbuf[i].timeout = 0;
        list_init(&(dpb->hwbuf[i].type_head));
        list_init(&(dpb->hwbuf[i].unit_head));
    }

    return dpb;
}

size_t
dp_buffers_size(struct dp_buffers *dpb) {
    return dpb->buffers_num;
}



void dp_delete_data_type(struct data_buffers *dpb, void *data)
{
    struct data_buffer *p;
    struct data_type *cur, *n, *org;
    unsigned int buffer_idx;

    if (!data)
        return;

    org = (struct data_type *)data;

    buffer_idx = org->hash % N_HASH_DIV;
    p = &dpb->hwbuf[buffer_idx];

    LIST_FOR_EACH_SAFE(cur, n, struct data_type, node, &p->type_head)
    {
        if((org->hash== cur->hash)
            && (cur->key_len == org->key_len)
            && (!memcmp(cur->key,org->key,cur->key_len)))
        {
            list_remove(&cur->node);
            //free(org->key);
            //free(org);
        }
    }
    free(org->key);
    free(org);

}

bool dp_hw_download(struct data_buffers *dpb, struct packet *pkt, struct path_contex *context)
{
    struct data_buffer *p;
    struct data_type *type;
    unsigned int hash = 0;
    unsigned char *pkt_key;
    unsigned int buffer_idx;
    unsigned int len;
    bool re = true;
    unsigned char type_new = 1;

    //return true;
    g_path_count ++;
    len = ROUND_UP(pkt->handle_std->match.header.length, sizeof(unsigned int));
    pkt_key = malloc_pkt_key(len);

    hash = packet_hash_pi(pkt_key,pkt,len);
    hash = abs(hash);

    buffer_idx = hash % N_HASH_DIV;

    p = &dpb->hwbuf[buffer_idx];
    /*if((p->timeout == 0) || (p->timeout + OVEROUT_SECS < time_now_sec()))
    {
        p->timeout = time_now_sec();
    }*/

    LIST_FOR_EACH(type,struct data_type,node,&p->type_head)
    {
        if((hash == type->hash)
            && (type->key_len == len)
            && (!memcmp(type->key,pkt_key,len)))
        {
            if((time_now_sec() - type->timeout  < OVEROUT_SECS)&&(0 == pkt->reason))
            {
                re = false;
            }
            else
            {
                type->timeout = time_now_sec();
                type_new = 0;
            }
            break;
        }
    }

    if((true == re) && (1 == type_new))
    {
        type = dp_buffers_type_create(len);
        type->hash = hash;
        memcpy(type->key,pkt_key,len);
        type->num_pkt = 0;
        type->num_pkt_in_pipeline = 0;
        type->timeout = time_now_sec();
        list_push_back(&p->type_head,&type->node);
        p->units_num ++;
        context->data_type = type;

    }

    free_pkt_key(pkt_key);

    return re;
}

unsigned int
dp_buffers_save(struct dp_buffers *dpb, struct packet *pkt) {
    struct packet_buffer *p;
    unsigned int id;

    /* if packet is already in buffer, do not save again */
    if (pkt->buffer_id != OFP_NO_BUFFER) {
        if (dp_buffers_is_alive(dpb, pkt->buffer_id)) {
            return pkt->buffer_id;
        }
    }

    dpb->buffer_idx = (dpb->buffer_idx + 1) & PKT_BUFFER_MASK;

    p = &dpb->buffers[dpb->buffer_idx];
    if (p->pkt != NULL) {
        if (time_now() < p->timeout) {
            return OFP_NO_BUFFER;
        } else {
            p->pkt->buffer_id = OFP_NO_BUFFER;
            packet_destroy(p->pkt);
        }
    }
    /* Don't use maximum cookie value since the all-bits-1 id is
     * special. */
    if (++p->cookie >= (1u << PKT_COOKIE_BITS) - 1)
        p->cookie = 0;
    p->pkt = pkt;
    p->timeout = time_now() + OVERWRITE_SECS;
    id = dpb->buffer_idx | (p->cookie << PKT_BUFFER_BITS);

    pkt->buffer_id  = id;

    return id;
}

unsigned int
dp_flow_filter(struct data_buffers *dpb, struct packet *pkt,unsigned char *send_flag) {
    struct data_buffer *p;
    struct data_type *type;
    unsigned int hash = 0;
    unsigned char *pkt_key;
    unsigned char pkt_type_exit = 0;
    unsigned int buffer_idx;
    unsigned int len;
    *send_flag = 0;

    len = ROUND_UP(pkt->handle_std->match.header.length, sizeof(unsigned int));
    pkt_key = malloc_pkt_key(len);

    hash = packet_hash_pi(pkt_key,pkt,len);
    hash = abs(hash);

    buffer_idx = hash % N_HASH_DIV;


    p = &dpb->buffers[buffer_idx];

    //make sure the packet type
    LIST_FOR_EACH(type,struct data_type,node,&p->type_head)
    {
        if((type->key_len == len)&&(hash == type->hash)&&(0 == memcmp(pkt_key,type->key,len)))
        {
            pkt_type_exit = 1;
            break;
        }
    }


    if(0 == pkt_type_exit)
    {
        type = dp_buffers_type_create(len);
        type->hash = hash;
        memcpy(type->key,pkt_key,len);
        type->num_pkt = 0;
        type->num_pkt_in_pipeline = 0;
        type->timeout = time_now_sec() + RESEND_SECS;
        type->run_pipeline = true;
        list_push_back(&p->type_head,&type->node);
        *send_flag = 1;
    }

    // u = dp_buffers_unit_create();

    if(type->num_pkt_in_pipeline < N_PKT_IN_PIPELINE)
    {
        *send_flag = 1;
        type->num_pkt_in_pipeline ++;
    }

    if(time_now_sec() > type->timeout)
    {
        *send_flag = 1;
        type->timeout = time_now_sec() + RESEND_SECS;
        type->num_pkt_in_pipeline = 1;
    }

    /*do not limit transmiss flow*/
    if(false == type->run_pipeline)
    {
        *send_flag = 1;
    }

    free_pkt_key(pkt_key);
    pkt->hash = hash;

    return hash;
}

void dp_flow_set_flag(struct data_buffers *dpb, unsigned int id,bool flag)
{
    struct data_buffer *p;
    unsigned int buffer_idx;
    struct data_type *type;

    buffer_idx = id % N_HASH_DIV;
    p = &dpb->buffers[buffer_idx];


    LIST_FOR_EACH(type,struct data_type,node,&p->type_head)
    {
        if(id == type->hash)
        {
            type->run_pipeline = flag;
            break;
        }
    }

    return;
}

struct packet *
dp_buffers_retrieve(struct dp_buffers *dpb, unsigned int id) {
    struct packet *pkt = NULL;
    struct packet_buffer *p;

    p = &dpb->buffers[id & PKT_BUFFER_MASK];
    if (p->cookie == id >> PKT_BUFFER_BITS && p->pkt != NULL) {
        pkt = p->pkt;
        pkt->buffer_id = OFP_NO_BUFFER;
        pkt->packet_out = false;

        p->pkt = NULL;
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "cookie mismatch: %x != %x\n",
                          id >> PKT_BUFFER_BITS, p->cookie);
    }

    return pkt;
}
ofl_err
dp_buffers_verify(struct dp_buffers *dpb, unsigned int id) {
    struct packet *pkt = NULL;
    struct packet_buffer *p;
    p = &dpb->buffers[id & PKT_BUFFER_MASK];
    if (p->cookie == id >> PKT_BUFFER_BITS && p->pkt != NULL)
    {
        return 0;
    }
    else if(p->cookie == id >> PKT_BUFFER_BITS)
    {
    	return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BUFFER_EMPTY);
    }
    else
    {
    	return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BUFFER_UNKNOWN);
    }
}

bool
dp_buffers_is_alive(struct dp_buffers *dpb, unsigned int id) {
    struct packet_buffer *p;

    p = &dpb->buffers[id & PKT_BUFFER_MASK];
    return ((p->cookie == id >> PKT_BUFFER_BITS) &&
            (time_now() < p->timeout));
}


void
dp_buffers_discard(struct dp_buffers *dpb, unsigned int id, bool destroy) {
    struct packet_buffer *p;

    p = &dpb->buffers[id & PKT_BUFFER_MASK];

    if (p->cookie == id >> PKT_BUFFER_BITS) {
        if (destroy) {
            p->pkt->buffer_id = OFP_NO_BUFFER;
            packet_destroy(p->pkt);
        }
        p->pkt = NULL;
    }
}

