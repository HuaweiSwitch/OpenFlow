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
 * Author: Zolt谩n Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include "dp_exp.h"
#include "dp_ports.h"
#include "datapath.h"
#include "packets.h"
#include "pipeline.h"
#include "oflib/ofl.h"
#include "oflib/ofl-messages.h"
#include "oflib-exp/ofl-exp-openflow.h"
#include "oflib/ofl-log.h"
#include "util.h"

#include "vlog.h"
#if defined(OF_HW_PLAT) && !defined(USE_NETDEV)
#include "common/port.h"

#include "Hybrid_Framework_Common.h"
#include "Hybrid_Framework_Linux.h"

#endif
#define LOG_MODULE VLM_dp_ports

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

#if defined(OF_HW_PLAT)
#include <pthread.h>
#include "rbuff.h"
#include "common/port.h"
#include "dpal_pub.h"
#endif

PORT_STATUS_REF_S g_port_status_ref = {0};

#if defined(OF_HW_PLAT) && !defined(USE_NETDEV)
/* Queue to decouple receive packet thread from rconn control thread */
/* Could make mutex per-DP */
static pthread_mutex_t pkt_q_mutex = PTHREAD_MUTEX_INITIALIZER;
#define PKT_Q_LOCK pthread_mutex_lock(&pkt_q_mutex)
#define PKT_Q_UNLOCK pthread_mutex_unlock(&pkt_q_mutex)

static void
dp_port_time_update(struct sw_port *port) {
    port->stats->duration_sec  =  (time_now_msec() - port->created) / 1000;
    port->stats->duration_nsec = ((time_now_msec() - port->created) % 1000) * 1000;
}

static void port_stats_updata(struct port_stats * pstStat, struct sw_port * port)
{
    struct ofl_port_stats *stats = port->stats;

    stats->port_no    = pstStat->port_no;
    stats->rx_packets = pstStat->rx_packets;
    stats->tx_packets = pstStat->tx_packets;
    //stats->rx_bytes   = pstStat->rx_bytes - CRC32_BYTE * pstStat->rx_packets;
    //stats->tx_bytes   = pstStat->tx_bytes - CRC32_BYTE * pstStat->tx_packets;
    stats->rx_bytes   = pstStat->rx_bytes;
    stats->tx_bytes   = pstStat->tx_bytes;
    stats->rx_dropped = pstStat->rx_dropped;
    stats->tx_dropped = pstStat->tx_dropped;
    stats->rx_errors  = pstStat->rx_errors;
    stats->tx_errors  = pstStat->tx_errors;
    stats->rx_frame_err = pstStat->rx_frame_err;
    stats->rx_over_err  = pstStat->rx_over_err;
    stats->rx_crc_err = pstStat->rx_crc_err;
    stats->collisions = pstStat->collisions;

    dp_port_time_update(port);

    return ;
}

static void
enqueue_pkt(struct datapath *dp, struct ofpbuf *buffer, unsigned int port_no,
            int reason)
{
    struct hw_pkt_q_entry *q_entry;

    if ((q_entry = xmalloc(sizeof(*q_entry))) == NULL) {
        VLOG_WARN(LOG_MODULE, "Could not alloc q entry\n");
        /* FIXME: Dealloc buffer */
        return;
    }
    q_entry->buffer = buffer;
    q_entry->next = NULL;
    q_entry->port_no = port_no;
    q_entry->reason = reason;
    pthread_mutex_lock(&pkt_q_mutex);
    if (dp->hw_pkt_list_head == NULL) {
        dp->hw_pkt_list_head = q_entry;
    } else {
        dp->hw_pkt_list_tail->next = q_entry;
    }
    dp->hw_pkt_list_tail = q_entry;
    pthread_mutex_unlock(&pkt_q_mutex);
}
static int dequeue_net_pkt(struct datapath *dp,
                       struct ofpbuf **buffer,
                       unsigned int *port_no,
                       int *reason)
{
      // 先注释掉
#if 0
    struct forwarding_context *ctx;

    ctx = fwding_net_ctx();
    if (ctx)
    {
        *buffer = (struct ofpbuf *)ctx->buff;
        *port_no = ctx->in_port;
        *reason = ctx->reason;
        fwding_ctx_release(ctx);

        g_port_recv_count ++;
        return 1;
    }

    (void)dp;
#endif

    return 0;
}

/* ctx->buff freed by others */
void fwding_ctx_release(struct forwarding_context *ctx)
{
    free(ctx);

    return;
}

/* If queue non-empty, fill out params and return 1; else return 0 */
static int dequeue_pkt(struct datapath *dp,
                       struct ofpbuf **buffer,
                       unsigned int *port_no,
                       int *reason, unsigned char *rx_cos, unsigned char *flag)
{
    struct forwarding_context *ctx;

    ctx = fwding_ctx();
    if (ctx)
    {
        *buffer = (struct ofpbuf *)ctx->buff;
        *port_no = ctx->in_port;
        *reason = ctx->reason;
        *rx_cos = ctx->rx_cos;
        *flag = ctx->untag_flag;
        fwding_ctx_release(ctx);

        g_port_recv_count ++;
        return 1;
    }

    (void)dp;
    return 0;
}
#else
static void port_stats_updata(port_stats * pstStat, sw_port * port)
{
    return;
}

#endif

struct rbuff *port_rbuff;

static PORT_STATUS_REF_S * create_new_port_status_node(UINT32 port)
{
    PORT_STATUS_REF_S * pstNode = NULL;

    pstNode = xmalloc(sizeof(PORT_STATUS_REF_S));
    if (NULL == pstNode)
    {
        return NULL;
    }

    list_init(&(pstNode->node));
    pstNode->port = port;

    list_insert(&(g_port_status_ref.node), &(pstNode->node));
    return pstNode;
}

static PORT_STATUS_REF_S * port_node_get_by_port(unsigned int port)
{
    PORT_STATUS_REF_S * pstNode = NULL;
    if(0 == (&(g_port_status_ref.node))->prev)
    {
        VLOG_DBG(LOG_MODULE, "port state list has not init,pre is null");
        return NULL;
    }
    if(0 == (&(g_port_status_ref.node))->next)
    {
        VLOG_DBG(LOG_MODULE, "port state list has not init,next is null");
        return NULL;
    }
    LIST_FOR_EACH(pstNode, PORT_STATUS_REF_S, node, &(g_port_status_ref.node))
    {
        if (pstNode->port == port)
        {
            return pstNode;
        }
    }
    pstNode = create_new_port_status_node(port);
    return pstNode;
}


/* wangxin 临时添加 */
#if 1 /* 端口统计回复 */
struct rbuff * g_port_stat_buff = NULL;
unsigned int g_Port_Statistics_xid = 0;

int Port_Statisitcs_put(void *recvdata, unsigned int revnum)
{
    void *msg;

    if(g_port_stat_buff == NULL)
    {
        g_port_stat_buff = rbuff_alloc(10000);
    }

    if(rbuff_full(g_port_stat_buff))
    {
        return -1;
    }

    msg = malloc(revnum + sizeof(unsigned int));
    if (msg == NULL)
    {
        return -1;
    }

    *(unsigned int *)msg = revnum;

    memcpy((unsigned int *)msg + 1, recvdata, revnum);

    rbuff_put(g_port_stat_buff, msg);

    return 0;
}

void * Port_Statisitcs_get(void)
{
    return rbuff_get(g_port_stat_buff);
}

void Port_Statisitcs_release(void *msg)
{
    free(msg);

    return;
}


unsigned int Port_State_Init(struct datapath *dp)
{
    unsigned int        uiloop  = 0;
    PORT_STATUS_REF_S * pstNode = NULL;


    list_init(&(g_port_status_ref.node));

    for (uiloop = 0; uiloop < dp->portnumber; uiloop++)
    {
        pstNode = create_new_port_status_node(dp->ports[uiloop].port_no);
        if (NULL == pstNode)
        {
            VLOG_ERR(LOG_MODULE, "Create port status node fail,ifindex = %d\n", dp->ports[uiloop].port_no);
        }
    }

    port_rbuff = rbuff_alloc(1000);
    VLOG_DBG(LOG_MODULE, "Port state init ok \n");

    return VOS_OK;
}


void port_evt_handle(int port, unsigned int linkst)
{
    int ret;
    ports_action *portsact ;
    PORT_STATUS_REF_S *portnode = NULL;

    portsact = (ports_action *)malloc(sizeof(struct port_action));
    if (NULL == portsact)
    {
        VLOG_ERR(LOG_MODULE, "malloc for port state error,port:%d\n", port);
        return;
    }
    switch (linkst)
    {
        case PORT_UP:
        {
            portsact->port_flag = PORT_UP;
            //l3_nhp_failover_set(port, FE_FALSE);
            VLOG_INFO(LOG_MODULE, "Port %d UP\n",port);
            break;
        }
        case PORT_DOWN:
        {
            portsact->port_flag = PORT_DOWN;
            //l3_nhp_failover_set(port, FE_TRUE);
            VLOG_INFO(LOG_MODULE, "Port %d DOWN\n",port);
            break;
        }
        case PORT_BLOCK:
        {
            portsact->port_flag = PORT_BLOCK;
            //l3_nhp_failover_set(port, FE_TRUE);;
            VLOG_INFO(LOG_MODULE, "Port %d BLOCK\n",port);
            break;
        }
        default:
        {
            break;
        }
    }
    portsact->port_no = port;
    if (port_rbuff == NULL)
    {
        port_rbuff = rbuff_alloc(10000);
    }
    if(rbuff_full(port_rbuff))
    {
        free(portsact);
        return;
    }
    rbuff_put(port_rbuff,portsact);
    return;
}

void Port_Statisitcs_reply(struct datapath *dp)
{
    unsigned int uiRet = 0;
    unsigned int uiLoop = 0;
    unsigned int revnum = 0;
    void *msgHead = Port_Statisitcs_get();
    void *msg = NULL;
    DPAL_PROC_S stProc = {0};
    struct sw_port    * port;
    struct port_stats * pstStat;
    struct ofl_msg_multipart_reply_port reply =
            {{{.type = OFPT_MULTIPART_REPLY},
              .type = OFPMP_PORT_STATS, .flags = 0x0000},
             .stats_num   = 0,
             .stats       = NULL};
    DPAL_PROC_DATA_S *pstProcData = NULL;

    if (NULL == msgHead)
    {
        return;
    }

    revnum = *(unsigned int *)msgHead;
    msg = (void *)((unsigned int *)msgHead + 1);

    uiRet = DPAL_TranslatePortStat(msg, revnum, &stProc);
    if (0 != uiRet)
    {
        Port_Statisitcs_release(msgHead);
        return;
    }

    Port_Statisitcs_release(msgHead);

    pstProcData = stProc.pstProcData;
    reply.stats = xmalloc(sizeof(struct ofl_port_stats *) * stProc.uiProNUM);
    for (uiLoop = 0; uiLoop < stProc.uiProNUM; uiLoop++)
    {
        pstStat = (struct port_stats *)(pstProcData[uiLoop].pData);
        port = dp_ports_lookup(dp, pstStat->port_no);
        if (NULL == port)
        {
            VLOG_ERR(LOG_MODULE, "\r\n Not find port, ifindex = %d.", pstStat->port_no);
            continue;
        }

        port_stats_updata(pstStat, port);
        reply.stats[reply.stats_num] = port->stats;
        reply.stats_num++;
    }

    DPAL_DestroyData(&stProc);

    dp_send_message_asynchronism(dp, (struct ofl_msg_header *)&reply, g_Port_Statistics_xid);

    free(reply.stats);

    return;
}

#endif


/* FIXME: Should not depend on udatapath_as_lib */
#if defined(OF_HW_PLAT) && !defined(USE_NETDEV)
/*
 * Receive packet handling for hardware driver controlled ports
 *
 * FIXME:  For now, call the pkt fwding directly; eventually may
 * want to enqueue packets at this layer; at that point must
 * make sure poll event is registered or timer kicked
 */
static int
hw_packet_in(unsigned int port_no, of_packet_t *packet, int reason,
             void *cookie)
{
    struct sw_port *port;
    struct ofpbuf *buffer = NULL;
    struct datapath *dp = (struct datapath *)cookie;
    const int headroom = 128 + 2;
    const int hard_header = VLAN_ETH_HEADER_LEN;
    const int tail_room = sizeof(unsigned int);  /* For crc if needed later */

    VLOG_INFO(LOG_MODULE, "dp rcv packet on port %d, size %d\n",
              port_no, packet->length);
    if ((port_no < 1) || port_no > DP_MAX_PORTS) {
        VLOG_ERR(LOG_MODULE, "Bad receive port %d\n", port_no);
        /* TODO increment error counter */
        return -1;
    }
    port = dp_ports_lookup(dp, port_no);
    if(!port)
    {
        VLOG_ERR(LOG_MODULE, "Get port point error, port: %d\n", port_no);
        return -1;
    }
    if (!PORT_IN_USE(port)) {
        VLOG_WARN(LOG_MODULE, "Receive port not active: %d\n", port_no);
        return -1;
    }
    if (!IS_HW_PORT(port)) {
        VLOG_ERR(LOG_MODULE, "Receive port not controlled by HW: %d\n", port_no);
        return -1;
    }
    /* Note:  We're really not counting these for port stats as they
     * should be gotten directly from the HW */
    //port->stats->rx_packets++;
    //port->stats->rx_bytes += packet->length;

    /* For now, copy data into OFP buffer; eventually may steal packet
     * from RX to avoid copy.  As per dp_run, add headroom and offset bytes.
     */
    buffer = ofpbuf_new(headroom + hard_header + packet->length + tail_room);
    if (buffer == NULL) {
        VLOG_WARN(LOG_MODULE, "Could not alloc ofpbuf on hw pkt in\n");
        fprintf(stderr, "Could not alloc ofpbuf on hw pkt in\n");
    } else {
        buffer->data = (char*)buffer->data + headroom;
        buffer->size = packet->length;
        memcpy(buffer->data, packet->data, packet->length);
        enqueue_pkt(dp, buffer, port_no, reason);
        poll_immediate_wake();
    }

    return 0;
}
#endif

#if defined(OF_HW_PLAT)
int
dp_hw_drv_init(struct datapath *dp)
{
    dp->hw_pkt_list_head = NULL;
    dp->hw_pkt_list_tail = NULL;

    // 临时先注释掉
    //dp->hw_drv = new_of_hw_driver();
    if (dp->hw_drv == NULL) {
        VLOG_ERR(LOG_MODULE, "Could not create HW driver");
        return -1;
    }
#if !defined(USE_NETDEV)
    if (dp->hw_drv->packet_receive_register(dp->hw_drv,
                                            hw_packet_in, dp) < 0) {
        VLOG_ERR(LOG_MODULE, "Could not register with HW driver to receive pkts");
    }
#endif

    return 0;
}

#endif


/* Runs a datapath packet through the pipeline, if the port is not set to down. */
static void
process_buffer(struct datapath *dp, struct sw_port *p, struct ofpbuf *buffer) {
    struct packet *pkt;
    unsigned char uInPipeline = 0;

    //unsigned int i;

    if ((!p || !p->conf) || p->conf->config & ((OFPPC_NO_RECV | OFPPC_PORT_DOWN) != 0))
    {
        g_no_match ++;
        ofpbuf_delete(buffer);
        return;
    }

    // packet takes ownership of ofpbuf buffer
    pkt = packet_create(dp, p->stats->port_no, buffer, false);

    if(true == dp->packet_in_limit)
    {
        dp_flow_filter(dp->data_buffers, pkt,&uInPipeline);
        if(0 == uInPipeline)
        {
            packet_destroy(pkt);
            return;
        }
    }

    pipeline_process_packet(dp->pipeline, pkt);
}
#define PACKET_COUNT 10

void
dp_ports_run(struct datapath *dp) {

#if defined(OF_HW_PLAT) && !defined(USE_NETDEV)
    {
        struct ofpbuf *buffer;
        unsigned int port_no;
        int reason;
        unsigned char rx_cos, flag;
        struct sw_port *p;
        static int receive_count = 0;

        while (dequeue_pkt(dp, &buffer, &port_no, &reason, &rx_cos, &flag))
        {
            p = dp_ports_lookup(dp, port_no);
            /* FIXME:  We're throwing away the reason that came from HW */
            receive_count ++;

            //we will drop the packet from port which  it is not notify controller.
            if (NULL == p || p->conf == NULL)
            {
                ofpbuf_delete(buffer);
                break;
            }

            if (VLOG_IS_DBG_ENABLED(ALTA_LOG_MODULE))
            {
                VLOG_DBG(LOG_MODULE, "recv data:\n");
                ofp_hex_dump(stdout, buffer->data, buffer->size, 0, 1);
            }

            process_buffer(dp, p, buffer);

            //if (receive_count >= PACKET_COUNT)
            if (receive_count >= 1)
            {
                receive_count = 0;
                break;
            }
        }
    }

    /* 端口统计回复 */
    {
        Port_Statisitcs_reply(dp);
    }

    return;
#else
    static struct ofpbuf *buffer = NULL;
    struct sw_port *p, *pn;
    LIST_FOR_EACH_SAFE (p, pn, struct sw_port, node, &dp->port_list) {
        int error;

        if (IS_HW_PORT(p)) {
            continue;
        }
        if (buffer == NULL) {
            /* Allocate buffer with some headroom to add headers in forwarding
             * to the controller or adding a vlan tag, plus an extra 2 bytes to
             * allow IP headers to be aligned on a 4-byte boundary.  */
            const int headroom = 128 + 2;
            const int hard_header = VLAN_ETH_HEADER_LEN;
            const int mtu = netdev_get_mtu(p->netdev);
            buffer = ofpbuf_new_with_headroom(hard_header + mtu, headroom);
        }
        error = netdev_recv(p->netdev, buffer);
        if (!error) {
            p->stats->rx_packets++;
            p->stats->rx_bytes += buffer->size;
            // process_buffer takes ownership of ofpbuf buffer
            process_buffer(dp, p, buffer);
            buffer = NULL;
        } else if (error != EAGAIN) {
            VLOG_ERR_RL(LOG_MODULE, &rl, "error receiving data from %s: %s",
                        netdev_get_name(p->netdev), strerror(error));
        }
    }
  #endif
}
//extern struct rbuff * g_fwd_buff;
//extern struct rbuff * g_net_fwd_buff;
//extern struct rbuff * g_out_buff;
struct sw_port *mng_port = NULL;
//const char *mng_netdev_name = "eth5";

struct f64
{
    unsigned char switch_pri:4;
    unsigned char vtype :2;
    unsigned char frame_type :2;
    unsigned char usr;

    unsigned char vlan_id_hi:4;
    unsigned char unused:1;
    unsigned char vlan_pri:3;
    unsigned char vlan_id_lo;

    unsigned short int src_glort;
    unsigned short int dst_glort;
};


#define F64_SIZE 8
#define MAC_SIZE 12


UINT32 dp_set_port_status(unsigned int uiPort, unsigned int uiEnable)
{
    ports_action *portsact ;
    PORT_STATUS_REF_S *portnode = NULL;

    portsact = (ports_action *)malloc(sizeof(struct port_action));
    if (NULL == portsact)
    {
        VLOG_ERR(LOG_MODULE, "malloc for port state error, port: %d\n", uiPort);
        return -1;
    }

    switch (uiEnable)
    {
        case PORT_UP:
        {
            portsact->port_flag = PORT_UP;
            VLOG_INFO(LOG_MODULE, "Port %d UP\n",uiPort);
            break;
        }

        case PORT_DOWN:
        {
            portsact->port_flag = PORT_DOWN;
            VLOG_INFO(LOG_MODULE, "Port %d DOWN\n",uiPort);
            break;
        }

        default:
        {
            break;
        }
    }

    portsact->port_no = uiPort;
    if (port_rbuff == NULL)
    {
        port_rbuff = rbuff_alloc(10000);
    }

    if(rbuff_full(port_rbuff))
    {
        /* 释放内存 */
        free(portsact);
        return -1;
    }

    rbuff_put(port_rbuff,portsact);

    return 0;
}

// open mng port;
static int dp_mng_port_open(struct datapath *dp)
{
    int error;

    //manager net device;
    //struct netdev * netdev = NULL;

    mng_port =  xmalloc(sizeof *mng_port);
    memset(mng_port,0,sizeof *mng_port);
    mng_port->dp = dp;
    mng_port->netdev = NULL;

    mng_port->stats = xmalloc(sizeof(struct ofl_port_stats));
    memset(mng_port->stats, 0, sizeof(struct ofl_port_stats));
    mng_port->stats->port_no = MNG_PORT_NUM;
    mng_port->created = time_now_msec();

    error = netdev_open(dp->mng_netdev_name, NETDEV_ETH_TYPE_ANY, &(mng_port->netdev));
    if (error)
    {
        mng_port->netdev = NULL;
        return error;
    }
    error = netdev_set_flags(mng_port->netdev, NETDEV_UP | NETDEV_PROMISC, false);
    if (error)
    {
        VLOG_ERR(LOG_MODULE, "failed to set promiscuous mode on %s device", dp->mng_netdev_name);
        netdev_close(mng_port->netdev);
        mng_port->netdev = NULL;
        return error;
    }

    mng_port->dp = dp;
    mng_port->conf = xmalloc(sizeof(struct ofl_port));
    mng_port->conf->port_no    = MNG_PORT_NUM;
    //memcpy(mng_port->conf->hw_addr, netdev_get_etheraddr(netdev), ETH_ADDR_LEN);
    mng_port->conf->name       = strcpy(xmalloc(strlen(dp->mng_netdev_name) + 1), dp->mng_netdev_name);
    mng_port->conf->config     = 0x00000000;
    mng_port->conf->state      = 0x00000000;
    //mng_port->conf->curr       = netdev_get_features(netdev, NETDEV_FEAT_CURRENT);
    //mng_port->conf->advertised = netdev_get_features(netdev, NETDEV_FEAT_ADVERTISED);
    //mng_port->conf->supported  = netdev_get_features(netdev, NETDEV_FEAT_SUPPORTED);
    //mng_port->conf->peer       = netdev_get_features(netdev, NETDEV_FEAT_PEER);
    //mng_port->conf->curr_speed = port_speed(mng_port->conf->curr);
    //mng_port->conf->max_speed  = port_speed(mng_port->conf->supported);

    return 0;
}


static int remove_f64(struct ofpbuf *buffer)
{
    memmove((unsigned char *)(buffer->data) + F64_SIZE, buffer->data, MAC_SIZE);
    buffer->data +=  F64_SIZE;
    buffer->size -= F64_SIZE;
    return 0;
}

static int unpaket_buff(struct sw_port *mng_port , struct ofpbuf *buffer)
{

    unsigned short int vlan;
    unsigned short int pcp;
    unsigned short int eth_type;


    struct f64 *isl_f64 = (unsigned char *)(buffer->data) + 12;
    mng_port->stats->port_no = ntohs(isl_f64->src_glort);

    vlan = (isl_f64->vlan_id_hi << 8) + isl_f64->vlan_id_lo;
    pcp = isl_f64->vlan_pri;
    eth_type = 0x8100;

    remove_f64(buffer);
    if( vlan > 1)
    {
        insert_vlan(vlan, pcp, eth_type, buffer);
    }

    // delete  4 bytes 0000 at tail;
    //buffer->size -= 4;

    return 0;
}

#if 0
void *dp_mng_port_thread(void* arg)
{
    static struct forwarding_context *ctx = NULL;

    int error;
    struct datapath * dp;
    const int headroom = 128 + 2;
    const int hard_header = VLAN_ETH_HEADER_LEN;
    unsigned char *mac;
    unsigned char *data;
    dp = (struct datapath *)arg;

    sleep(1);

    if(NULL == mng_port)
    {
        dp_mng_port_open(dp);
    }
    if(NULL == mng_port->netdev)
    {
        return 0;
    }

    const int mtu = netdev_get_mtu(mng_port->netdev);
    while(1)
    {
        // recive;
        if( ctx == NULL)
        {
            ctx = fwding_ctx_alloc(MNG_PORT_NUM, headroom, hard_header + mtu);
        }

        error = netdev_recv(mng_port->netdev, (struct ofpbuf *)ctx->buff);

        if (!error)
        {
            mng_port->stats->rx_packets++;
            mng_port->stats->rx_bytes += ((struct ofpbuf *)ctx->buff)->size;
            mng_port->stats->port_no = MNG_PORT_NUM;

            // process_buffer takes ownership of ofpbuf buffer
            unpaket_buff(mng_port, (struct ofpbuf *)ctx->buff);
            mac = netdev_ge_mac(mng_port->netdev);
            data = ((struct ofpbuf *)ctx->buff)->data;

            if( (memcmp(mac, data+ETH_ADDR_LEN, ETH_ADDR_LEN) == 0)
            || rbuff_full(g_net_fwd_buff)
            || (mng_port->stats->port_no > MAX_DATAPATH_PORT_NO) )
            {
            ofpbuf_clear((struct ofpbuf *)ctx->buff);
            ofpbuf_reserve((struct ofpbuf *)ctx->buff, headroom);
            continue;
            }
            ctx->in_port = mng_port->stats->port_no;

            //ofp_hex_dump(stdout, data, ((struct ofpbuf *)ctx->buff)->size, 0, 1);

            rbuff_put(g_net_fwd_buff, ctx);
            ctx = NULL;
        }
        // send;
        {
            struct ofpbuf * out_buf;

            out_buf = rbuff_get(g_out_buff);
            if( out_buf != NULL)
            {
                ofp_hex_dump(stdout, out_buf->data, out_buf->size, 0, 1);
                netdev_send(mng_port->netdev, out_buf, 0);
                ofpbuf_delete(out_buf);
            }
        }

    }

    return 0;
}


// send by mng port;
int dp_mng_port_snd(int sw, struct ofpbuf *buffer, unsigned short int dport, unsigned short int vlan)
{
    struct ofpbuf * buf = NULL;
    struct f64 isl_tag;

    unsigned char vlan_type[2] = {0x81, 0x00};
    if( memcmp( vlan_type, (unsigned char *)(buffer->data) + 12, 2) ==0)
    {
        vlan = * (unsigned short int*)((unsigned char *)(buffer->data)+14);
    }

    isl_tag.frame_type = 0x2;
    isl_tag.vtype = 0;
    isl_tag.switch_pri = 0x8;
    isl_tag.usr = 0x0;

    vlan = ntohs(vlan);
    isl_tag.vlan_pri = (vlan >> 13) & 0x7;
    isl_tag.unused = 0;
    isl_tag.vlan_id_hi = (vlan >> 8) & 0xf;
    isl_tag.vlan_id_lo = vlan & 0xff;

    isl_tag.dst_glort = ntohs(dport);
    isl_tag.src_glort = 0;

    if(NULL == mng_port)
        return 0;
    if(NULL == mng_port->netdev)
        return 0;


    buf = ofpbuf_clone_with_headroom(buffer, F64_SIZE);
    ofpbuf_push_zeros(buf, sizeof(isl_tag));
    memmove(buf->data, (unsigned char *)(buf->data) + F64_SIZE, MAC_SIZE);
    memcpy((unsigned char *)(buf->data) + MAC_SIZE, (void*)&isl_tag, F64_SIZE);

    vlan = (isl_tag.vlan_id_hi << 8) + isl_tag.vlan_id_lo;
    if (vlan >= MIN_VLAN_ID && vlan <= MAX_VLAN_ID)
    {
       //****fmChangeVlanPort(sw,vlan,dport,1);
    }

    netdev_send(mng_port->netdev, buf, 0);
    ofpbuf_delete(buf);


}
#endif
/* Returns the speed value in kbps of the highest bit set in the bitfield. */
 unsigned int port_speed(unsigned int conf) {
    if ((conf & OFPPF_1TB_FD) != 0)   return 1024 * 1024 * 1024;
    if ((conf & OFPPF_100GB_FD) != 0) return  100 * 1024 * 1024;
    if ((conf & OFPPF_40GB_FD) != 0)  return   40 * 1024 * 1024;
    if ((conf & OFPPF_10GB_FD) != 0)  return   10 * 1024 * 1024;
    if ((conf & OFPPF_1GB_FD) != 0)   return        1024 * 1024;
    if ((conf & OFPPF_1GB_HD) != 0)   return        1024 * 1024;
    if ((conf & OFPPF_100MB_FD) != 0) return         100 * 1024;
    if ((conf & OFPPF_100MB_HD) != 0) return         100 * 1024;
    if ((conf & OFPPF_10MB_FD) != 0)  return          10 * 1024;
    if ((conf & OFPPF_10MB_HD) != 0)  return          10 * 1024;

    return 0;
}

/* Creates a new port, with queues. */
static int
new_port(struct datapath *dp, struct sw_port *port, unsigned int port_no,
         const char *netdev_name, const unsigned char *new_mac, unsigned int max_queues)
{
    struct netdev *netdev;
    struct in6_addr in6;
    struct in_addr in4;
    int error;
    unsigned long long int now;

    now = time_now_msec();

    max_queues = MIN(max_queues, NETDEV_MAX_QUEUES);

    error = netdev_open(netdev_name, NETDEV_ETH_TYPE_ANY, &netdev);
    if (error) {
        return error;
    }
    if (new_mac && !eth_addr_equals(netdev_get_etheraddr(netdev), new_mac)) {
        /* Generally the device has to be down before we change its hardware
         * address.  Don't bother to check for an error because it's really
         * the netdev_set_etheraddr() call below that we care about. */
        netdev_set_flags(netdev, 0, false);
        error = netdev_set_etheraddr(netdev, new_mac);
        if (error) {
            VLOG_WARN(LOG_MODULE, "failed to change %s Ethernet address "
                      "to "ETH_ADDR_FMT": %s",
                      netdev_name, ETH_ADDR_ARGS(new_mac), strerror(error));
        }
    }
    error = netdev_set_flags(netdev, NETDEV_UP | NETDEV_PROMISC, false);
    if (error) {
        VLOG_ERR(LOG_MODULE, "failed to set promiscuous mode on %s device", netdev_name);
        netdev_close(netdev);
        return error;
    }
    if (netdev_get_in4(netdev, &in4)) {
        VLOG_ERR(LOG_MODULE, "%s device has assigned IP address %s",
                 netdev_name, inet_ntoa(in4));
    }
    if (netdev_get_in6(netdev, &in6)) {
        char in6_name[INET6_ADDRSTRLEN + 1];
        inet_ntop(AF_INET6, &in6, in6_name, sizeof in6_name);
        VLOG_ERR(LOG_MODULE, "%s device has assigned IPv6 address %s",
                 netdev_name, in6_name);
    }

    if (max_queues > 0) {
        error = netdev_setup_slicing(netdev, max_queues);
        if (error) {
            VLOG_ERR(LOG_MODULE, "failed to configure slicing on %s device: "\
                     "check INSTALL for dependencies, or rerun "\
                     "using --no-slicing option to disable slicing",
                     netdev_name);
            netdev_close(netdev);
            return error;
        }
    }

    /* NOTE: port struct is already allocated in struct dp */
    memset(port, '\0', sizeof *port);

    port->dp = dp;

    port->conf = xmalloc(sizeof(struct ofl_port));
    port->conf->port_no    = port_no;
    memcpy(port->conf->hw_addr, netdev_get_etheraddr(netdev), ETH_ADDR_LEN);
    port->conf->name       = strcpy(xmalloc(strlen(netdev_name) + 1), netdev_name);
    port->conf->config     = 0x00000000;
    port->conf->state      = 0x00000000;
    port->conf->curr       = netdev_get_features(netdev, NETDEV_FEAT_CURRENT);
    port->conf->advertised = netdev_get_features(netdev, NETDEV_FEAT_ADVERTISED);
    port->conf->supported  = netdev_get_features(netdev, NETDEV_FEAT_SUPPORTED);
    port->conf->peer       = netdev_get_features(netdev, NETDEV_FEAT_PEER);
    port->conf->curr_speed = port_speed(port->conf->curr);
    port->conf->max_speed  = port_speed(port->conf->supported);

    if (IS_HW_PORT(port))
    {
#if defined(OF_HW_PLAT) && !defined(USE_NETDEV)
        of_hw_driver_t *hw_drv;

        hw_drv = port->dp->hw_drv;
       
        /* Update local port state */
        if (hw_drv->port_link_get(hw_drv, port_no))
        {
            port->conf->state &= ~OFPPS_LINK_DOWN;
        }
        else
        {
            port->conf->state |= OFPPS_LINK_DOWN;
        }

        if (hw_drv->port_enable_get(hw_drv, port_no))
        {
            port->conf->config &= ~OFPPC_PORT_DOWN;
        }
        else
        {
            port->conf->config |= OFPPC_PORT_DOWN;
        }

        /* FIXME:  Add current, supported and advertised features */
#endif
    }

    port->stats = xmalloc(sizeof(struct ofl_port_stats));
    port->stats->port_no = port_no;
    port->stats->rx_packets   = 0;
    port->stats->tx_packets   = 0;
    port->stats->rx_bytes     = 0;
    port->stats->tx_bytes     = 0;
    port->stats->rx_dropped   = 0;
    port->stats->tx_dropped   = 0;
    port->stats->rx_errors    = 0;
    port->stats->tx_errors    = 0;
    port->stats->rx_frame_err = 0;
    port->stats->rx_over_err  = 0;
    port->stats->rx_crc_err   = 0;
    port->stats->collisions   = 0;
    port->stats->duration_sec = 0;
    port->stats->duration_nsec = 0;
    port->flags |= SWP_USED;
    port->netdev = netdev;
    port->max_queues = max_queues;
    port->num_queues = 0;
    port->created = now;

    memset(port->queues, 0x00, sizeof(port->queues));

    list_push_back(&dp->port_list, &port->node);
    dp->ports_num++;

    {
    /* Notify the controllers that this port has been added */
    struct ofl_msg_port_status msg =
            {{.type = OFPT_PORT_STATUS},
             .reason = OFPPR_ADD, .desc = port->conf};

    dp_send_message(dp, (struct ofl_msg_header *)&msg, NULL/*sender*/);
    }

    return 0;
}

#if defined(OF_HW_PLAT) && !defined(USE_NETDEV)
int dp_ports_add(int port_index, struct datapath *dp)
{
    char port_name[MAX_PORTNAME_LEN]={0};
    int port_no = dp->ports[port_index].port_no;
    struct sw_port *port;
    struct ofl_msg_port_status msg;

    port = dp_ports_lookup(dp, port_no);
    if(!port)
    {
        VLOG_ERR(LOG_MODULE, "Get port point error, port: %d\n", port_no);
        return -1;
    }
    port->flags |= SWP_USED | SWP_HW_DRV_PORT;
    port->dp = dp;

    port->conf = xmalloc(sizeof(struct ofl_port));
    memset(port->conf, 0, sizeof(struct ofl_port));

    //strncpy(port_name, dp->ifname[port_index], MAX_PORTNAME_LEN);
    snprintf(port_name, sizeof(port_name), "%s%d", "xe", port_index);
    port->conf->port_no = port_no;
    port->conf->name = strdup(port_name);

    memset(port->conf->hw_addr, 0, sizeof(port->conf->hw_addr));
    port->conf->state |=
        get_port_link(port_no) == PORT_UP ? OFPPS_LIVE : OFPPS_LINK_DOWN;
    port->conf->config &= ~OFPPC_PORT_DOWN;

    port->stats = xmalloc(sizeof(struct ofl_port_stats));
    memset(port->stats, 0, sizeof(struct ofl_port_stats));
    port->stats->port_no = port_no;

    port->max_queues = NETDEV_MAX_QUEUES;
    port->num_queues = 0;
    port->netdev = NULL;
    memset(port->queues, 0, sizeof(port->queues));

    port->created = time_now_msec();
    port->conf->hw_addr[0] = 0x0c;
    port->conf->hw_addr[1] = 0x37;
    port->conf->hw_addr[2] = 0xdc;
    port->conf->hw_addr[3] = (dp->id >> 16) & 0xff;
    port->conf->hw_addr[4] = (dp->id >> 8) & 0xff;
    port->conf->hw_addr[5] = (dp->id >> 0) & 0xff;
    list_push_back(&dp->port_list, &port->node);
    dp->ports_num++;

    msg.header.type = OFPT_PORT_STATUS;
    msg.reason = OFPPR_ADD;
    msg.desc = port->conf;

    VLOG_DBG(LOG_MODULE, "ifindex:%d, ifname:%s", port->conf->port_no, port_name);

    dp_send_message(dp, (struct ofl_msg_header *)&msg, NULL);

    return 0;
}
#else /* Not HW platform support */

int
dp_ports_add(struct datapath *dp, const char *netdev)
{
    unsigned int port_no;
    for (port_no = 1; port_no < DP_MAX_PORTS; port_no++)
    {
        struct sw_port *port = &dp->ports[port_no];
        if (port->netdev == NULL) {
            return new_port(dp, port, port_no, netdev, NULL, dp->max_queues);
        }
    }
    return EXFULL;
}
#endif /* OF_HW_PLAT */



int
dp_ports_add_local(struct datapath *dp, const char *netdev)
{
    if (!dp->local_port) {
        unsigned char ea[ETH_ADDR_LEN];
        struct sw_port *port;
        int error;

        port = xcalloc(1, sizeof *port);
        eth_addr_from_uint64(dp->id, ea);
        error = new_port(dp, port, OFPP_LOCAL, netdev, ea, 0);
        if (!error) {
            dp->local_port = port;
        } else {
            free(port);
        }
        return error;
    } else {
        return EXFULL;
    }
}


struct sw_port *
dp_ports_lookup(struct datapath *dp, unsigned int port_no)
{
    int i;
    for (i = 0; i < DP_MAX_PORTS; i ++)
    {
        if (-1 == dp->ports[i].port_no){break;}
        if (dp->ports[i].port_no == port_no)
        {
            return &(dp->ports[i]);
        }

    }
    return NULL;
}

struct sw_queue *
dp_ports_lookup_queue(struct sw_port *p, unsigned int queue_id)
{
    struct sw_queue *q;

    if (queue_id < p->max_queues) {
        q = &(p->queues[queue_id]);

        if (q->port != NULL) {
            return q;
        }
    }

    return NULL;
}

int fwding_pkt(unsigned int *ports, unsigned int port_cnt, struct ofpbuf *buff, int queue_id)
{
    unsigned int uiRet = 0;
    DPAL_MESSAGE_PKT_S  stFwdPkt  = {0};
    DPAL_MESSAGE_DATA_S stMSGData = {0};

    stFwdPkt.puiIfIndex  = ports;
    stFwdPkt.usIfNum     = port_cnt;
    stFwdPkt.usPktLength = buff->size;
    stFwdPkt.pPKT        = buff->data;

    uiRet = DPAL_TranslatePkt(DPAL_MSG_TYPE_PKT, (void *)&stFwdPkt, &stMSGData);
    if (uiRet)
    {
        VLOG_ERR(LOG_MODULE, "fwding_pkt translate message failed.\n");
        return uiRet;
    }

    //发送报文
    uiRet = Hybrid_Chatwith_V8_new(&stMSGData);
    if (uiRet)
    {
        VLOG_ERR(LOG_MODULE, "fwding_pkt send message failed.\n");
        free(stMSGData.pData);
        return uiRet;
    }

    free(stMSGData.pData);

    return 0;
}

void
dp_ports_output(struct datapath *dp, struct ofpbuf *buffer, unsigned int out_port,
              unsigned int queue_id)
{
    unsigned short int class_id;
    struct sw_queue * q;
    struct sw_port *p;

    if (dp == NULL)
    {
        return;
    }

    p = dp_ports_lookup(dp, out_port);

/* FIXME:  Needs update for queuing */
#if defined(OF_HW_PLAT) && !defined(USE_NETDEV)
    if ((p != NULL) && IS_HW_PORT(p))
    {
        //****dpdk_enqueue_pkt(out_port, buffer);
        fwding_pkt(&out_port, 1, buffer, queue_id);
        dp->vlan = 0;
        return;
    }

    /* Fall through to software controlled ports if not HW port */
#endif
    if (p != NULL && p->netdev != NULL) {

        if (!(p->conf->config & OFPPC_PORT_DOWN)) {
            /* avoid the queue lookup for best-effort traffic */
            if (queue_id == 0) {
                q = NULL;
                class_id = 0;
            }
            else {
                /* silently drop the packet if queue doesn't exist */
                q = dp_ports_lookup_queue(p, queue_id);
                if (q != NULL) {
                    class_id = q->class_id;
                }
                else {
                    goto error;
                }
            }

            if (!netdev_send(p->netdev, buffer, class_id)) {
                //p->stats->tx_packets++;
                //p->stats->tx_bytes += buffer->size;
                if (q != NULL) {
                    q->stats->tx_packets++;
                    q->stats->tx_bytes += buffer->size;
                }
            } else {
                p->stats->tx_dropped++;
            }
        }
        /* NOTE: no need to delete buffer, it is deleted along with the packet in caller. */
        return;
    }

 error:
     /* NOTE: no need to delete buffer, it is deleted along with the packet. */
    VLOG_DBG_RL(LOG_MODULE, &rl, "can't forward to bad port:queue(%d:%d)\n", out_port,
                queue_id);
}

int
dp_ports_output_all(struct datapath *dp, struct ofpbuf *buffer,
                    int in_port, bool flood, unsigned int queue_id)
{
    struct sw_port *p;

    LIST_FOR_EACH (p, struct sw_port, node, &dp->port_list)
    {
        if (p->stats->port_no == in_port||p->conf->state != OFPPS_LIVE)
        {
            continue;
        }
        if (flood && p->conf->config & OFPPC_NO_FWD)
        {
            continue;
        }

        dp_ports_output(dp, buffer, p->stats->port_no, queue_id);
    }

    return 0;
}

ofl_err
dp_ports_handle_port_mod(struct datapath *dp, struct ofl_msg_port_mod *msg,
                                                const struct sender *sender)
{
    // 先注释掉
//#if 0
    /*int i;*/
    struct sw_port *p;
    struct ofl_msg_port_status port_status_msg;

    if(sender->remote->role == OFPCR_ROLE_SLAVE)
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_IS_SLAVE);

    p = dp_ports_lookup(dp, msg->port_no);

    if (p == NULL) {
        return ofl_error(OFPET_PORT_MOD_FAILED,OFPPMFC_BAD_PORT);
    }

    /* Make sure the port id hasn't changed since this was sent */

    if (VLOG_IS_DBG_ENABLED(ALTA_LOG_MODULE))
    {
        char *msg_str = ofl_msg_to_string((struct ofl_msg_header *)msg, NULL);
        VLOG_DBG(ALTA_LOG_MODULE, "flow mod: %s", msg_str);
        free(msg_str);
    }

    if( memcmp( p->conf->hw_addr, msg->hw_addr, ETH_ADDR_LEN) )
    {
        return ofl_error(OFPET_PORT_MOD_FAILED,OFPPMFC_BAD_HW_ADDR);
    }
    if((p->conf->advertised != msg->advertise) && (0 != msg->advertise))
    {
        return ofl_error(OFPET_PORT_MOD_FAILED,OFPPMFC_BAD_ADVERTISE);
    }

    if (msg->mask)
    {
        p->conf->config &= ~msg->mask;
        p->conf->config |= msg->config & msg->mask;
    }

    if(p->conf->config & OFPPC_PORT_DOWN)
    {
        //port_mod(p->conf->port_no,PORT_DOWN);
        dp_set_port_status(p->conf->port_no, PORT_DOWN);
    }

    if(!(p->conf->config & OFPPC_PORT_DOWN) )
    {
        //port_mod(p->conf->port_no,PORT_UP);
        dp_set_port_status(p->conf->port_no, PORT_UP);
    }
#if 0
    if(p->conf->config & OFPPC_NO_RECV )
    {
        port_mod(p->conf->port_no,PORT_NO_RECV);
    }

    if(p->conf->config & OFPPC_NO_FWD)
    {
        port_mod(p->conf->port_no,PORT_NO_FWD);
    }

    if(p->conf->config & OFPPC_NO_PACKET_IN)
    {
       port_mod(p->conf->port_no,PORT_UP);
    }
#endif
    VLOG_INFO(LOG_MODULE, "dp_ports_handle_port_mod  p->conf->config:%d,\n",
                p->conf->config);

    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);

     port_status_msg.header.type = OFPT_PORT_STATUS;
     port_status_msg.reason = OFPPR_MODIFY;
     port_status_msg.desc = p->conf;

     dp_send_message(dp, (struct ofl_msg_header *)&port_status_msg, sender);
     //dp_send_message(dp, (struct ofl_msg_header *)&port_status_msg, NULL/*sender*/);
//#endif

    return 0;
}

int port_num(void)
{
    return MAX_PORT_NO_dp;
}

ofl_err
dp_ports_handle_stats_request_port(struct datapath *dp,
                                  struct ofl_msg_multipart_request_port *msg,
                                  const struct sender *sender)
{
    size_t i = 0;
    unsigned int uiRet = 0;
    struct sw_port *port;
    DPAL_INTERFACE_LIST_S stInterfaceList = {0};
    DPAL_MESSAGE_DATA_S   stMSGData       = {0};
    DPAL_QUERY_DATA_S     stQueryData     = {0};

    if (msg->port_no == OFPP_ANY)
    {
        LIST_FOR_EACH(port, struct sw_port, node, &dp->port_list)
        {
            if (i < MAX_PORT_NUMBER)
            {
                stInterfaceList.astInterface[i].uiIfindex = port->port_no;
                stInterfaceList.uiPortnumber++;
            }
            else
            {
                VLOG_ERR(LOG_MODULE, "\r\n Port num is illegal, number = %d.", i);
            }
            i++;
        }
    }
    else
    {
        port = dp_ports_lookup(dp, msg->port_no);
        if (port != NULL )
        {
            stInterfaceList.astInterface[i].uiIfindex = port->port_no;
            stInterfaceList.uiPortnumber++;
        }
        else
        {
            VLOG_ERR(LOG_MODULE, "\r\n Port NO. is illegal, Port NO. = %d.", msg->port_no);
        }
    }

    g_Port_Statistics_xid = sender->xid;

    stQueryData.uiConfigType = DPAL_CONFIG_TYPE_INTERFACE;
    stQueryData.pData        = (void *)&stInterfaceList;
    uiRet = DPAL_TranslatePkt(DPAL_MSG_TYPE_STATISTICS, (void *)&stQueryData, &stMSGData);
    if (uiRet)
    {
        VLOG_ERR(LOG_MODULE, "DPAL_TranslatePkt port statics failed!\n");
        return uiRet;
    }

    //发送报文
    uiRet = Hybrid_Chatwith_V8_new(&stMSGData);
    if (uiRet)
    {
        VLOG_ERR(LOG_MODULE, "alta logic get entry count, send to v8 failed!\n");
        free(stMSGData.pData);
        return uiRet;
    }

    free(stMSGData.pData);

    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);

    return 0;
}

unsigned int g_first_port_desc_req = 0;

ofl_err
dp_ports_handle_port_desc_request(struct datapath *dp,
                                  struct ofl_msg_multipart_request_header *msg UNUSED,
                                  const struct sender *sender UNUSED){
    struct sw_port *port;
    size_t i = 0;


    struct ofl_msg_multipart_reply_port_desc reply =
            {{{.type = OFPT_MULTIPART_REPLY},
             .type = OFPMP_PORT_DESC, .flags = 0x0000},
             .stats_num   = 0,
             .stats       = NULL};

    reply.stats_num = dp->ports_num;
    reply.stats     = xmalloc(sizeof(struct ofl_port *) * dp->ports_num);

    LIST_FOR_EACH(port, struct sw_port, node, &dp->port_list)
    {
        if(g_first_port_desc_req == 0)
        {
            VLOG_DBG(LOG_MODULE, "port i =%d,qian hw =0x%x\n",i,port->conf->hw_addr[5]);
            port->conf->hw_addr[5] = port->conf->hw_addr[5] + i;
            VLOG_DBG(LOG_MODULE, "port i =%d,hou hw =0x%x\n",i,port->conf->hw_addr[5]);
        }
        port->conf->curr = 12352;
        port->conf->advertised =  12352;
        port->conf->supported = 12352;
        port->conf->curr_speed = 1048576;
        port->conf->max_speed = 1048576;
        reply.stats[i] = port->conf;
        i++;
    }

    g_first_port_desc_req ++;

    dp_send_message(dp, (struct ofl_msg_header *)&reply, sender);

    free(reply.stats);
    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);

    return 0;
}

static void
dp_ports_queue_update(struct sw_queue *queue) {
    queue->stats->duration_sec  =  (time_now_msec() - queue->created) / 1000;
    queue->stats->duration_nsec = ((time_now_msec() - queue->created) % 1000) * 1000;

    //查询端口队里统计，先注释
    //update_queue_count(queue->stats->port_no, queue->stats->queue_id,
    //    &queue->stats->tx_bytes, &queue->stats->tx_packets, &queue->stats->tx_errors);
}

ofl_err
dp_ports_handle_stats_request_queue(struct datapath *dp,
                                  struct ofl_msg_multipart_request_queue *msg,
                                  const struct sender *sender) {
    struct sw_port *port;

    struct ofl_msg_multipart_reply_queue reply =
            {{{.type = OFPT_MULTIPART_REPLY},
              .type = OFPMP_QUEUE, .flags = 0x0000},
             .stats_num   = 0,
             .stats       = NULL};

    if (msg->port_no == OFPP_ANY) {
        size_t i,idx = 0, num = 0;

        LIST_FOR_EACH(port, struct sw_port, node, &dp->port_list) {
            if (msg->queue_id == OFPQ_ALL) {
                num += port->num_queues;
            } else {
                if (msg->queue_id < port->max_queues) {
                    if (port->queues[msg->queue_id].port != NULL) {
                        num++;
                    }
                }
            }
        }

        reply.stats_num = num;
        reply.stats     = xmalloc(sizeof(struct ofl_port_stats *) * num);

        LIST_FOR_EACH(port, struct sw_port, node, &dp->port_list) {
            if (msg->queue_id == OFPQ_ALL) {
                for(i=0; i<port->max_queues; i++) {
                    if (port->queues[i].port != NULL) {
                        dp_ports_queue_update(&port->queues[i]);
                        reply.stats[idx] = port->queues[i].stats;
                        idx++;
                    }
                }
            } else {
                if (msg->queue_id < port->max_queues) {
                    if (port->queues[msg->queue_id].port != NULL) {
                        dp_ports_queue_update(&port->queues[msg->queue_id]);
                        reply.stats[idx] = port->queues[msg->queue_id].stats;
                        idx++;
                    }
                }
            }
        }

    } else {
        port = dp_ports_lookup(dp, msg->port_no);

        if (port != NULL )
        {
            size_t i, idx = 0;

            if (msg->queue_id == OFPQ_ALL) {
                reply.stats_num = port->num_queues;
                reply.stats = xmalloc(sizeof(struct ofl_port_stats *) * port->num_queues);

                for(i=0; i<port->max_queues; i++) {
                    if (port->queues[i].port != NULL) {
                        dp_ports_queue_update(&port->queues[i]);
                        reply.stats[idx] = port->queues[i].stats;
                        idx++;
                    }
                }
            } else {
                if (msg->queue_id < port->max_queues) {
                    if (port->queues[msg->queue_id].port != NULL) {
                        reply.stats_num = 1;
                        reply.stats = xmalloc(sizeof(struct ofl_port_stats *));
                        dp_ports_queue_update(&port->queues[msg->queue_id]);
                        reply.stats[0] = port->queues[msg->queue_id].stats;
                    }
                }
            }
        }
    }

    dp_send_message(dp, (struct ofl_msg_header *)&reply, sender);

    free(reply.stats);
    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);

    return 0;
}

ofl_err
dp_ports_handle_queue_get_config_request(struct datapath *dp,
                              struct ofl_msg_queue_get_config_request *msg,
                                                const struct sender *sender) {
    struct sw_port *p;

    if (OFPP_ANY == msg->port)
    {
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
    }

    p = dp_ports_lookup(dp, msg->port);

    if (p == NULL || (p->stats->port_no != msg->port))//报错行
    {
        return ofl_error(OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_PORT);
    }
    else
    {
        size_t i, idx = 0;

        struct ofl_msg_queue_get_config_reply reply =
                {{.type = OFPT_QUEUE_GET_CONFIG_REPLY},
                 .port       = msg->port,
                 .queues_num = p->num_queues,
                 .queues     = xmalloc(sizeof(struct ofl_packet_queue *) * p->num_queues)};
        for (i=0; i<p->max_queues; i++) {
            if (p->queues[i].port != NULL) {
                reply.queues[idx] = p->queues[i].props;
                idx++;
            }
        }

        dp_send_message(dp, (struct ofl_msg_header *)&reply, sender);

        free(reply.queues);
        ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);
        return 0;
    }
}

/*
 * Queue handling
 */

static int
new_queue(struct sw_port * port, struct sw_queue * queue,
          unsigned int queue_id, unsigned short int class_id)
{
    unsigned long long int now = time_now_msec();

    memset(queue, '\0', sizeof *queue);
    queue->port = port;
    queue->created = now;
    queue->stats = xmalloc(sizeof(struct ofl_queue_stats));

    queue->stats->port_no = port->stats->port_no;
    queue->stats->queue_id = queue_id;
    queue->stats->tx_bytes = 0;
    queue->stats->tx_packets = 0;
    queue->stats->tx_errors = 0;
    queue->stats->duration_sec = 0;
    queue->stats->duration_nsec = 0;

    /* class_id is the internal mapping to class. It is the offset
     * in the array of queues for each port. Note that class_id is
     * local to port, so we don't have any conflict.
     * tc uses 16-bit class_id, so we cannot use the queue_id
     * field */
    queue->class_id = class_id;

    queue->props = xmalloc(sizeof(struct ofl_packet_queue));
    queue->props->queue_id = queue_id;
    queue->props->properties = xmalloc(sizeof(struct ofl_queue_prop_header *));
    queue->props->properties_num = 2;
    queue->props->properties[0] = xmalloc(sizeof(struct ofl_queue_prop_min_rate));
    queue->props->properties[1] = xmalloc(sizeof(struct ofl_queue_prop_max_rate));
    ((struct ofl_queue_prop_min_rate *)(queue->props->properties[0]))->header.type = OFPQT_MIN_RATE;
    ((struct ofl_queue_prop_min_rate *)(queue->props->properties[0]))->rate = OFPQ_MIN_RATE_UNCFG;
    ((struct ofl_queue_prop_max_rate *)(queue->props->properties[1]))->header.type = OFPQT_MAX_RATE;
    ((struct ofl_queue_prop_max_rate *)(queue->props->properties[1]))->rate = OFPQ_MAX_RATE_UNCFG;

    port->num_queues++;
    return 0;
}

static int
port_add_queue(struct sw_port *p, unsigned int queue_id)
{
    if (queue_id >= p->max_queues) {
        return EXFULL;
    }

    if (p->queues[queue_id].port != NULL) {
        return EXFULL;
    }

    return new_queue(p, &(p->queues[queue_id]), queue_id, queue_id);
}

static int
port_delete_queue(struct sw_port *p, struct sw_queue *q)
{
    memset(q,'\0', sizeof *q);
    p->num_queues--;
    return 0;
}

int dp_port_init_queue(struct datapath *dp,int port_no)
{
    struct sw_port *p;
    struct sw_queue *q;
    int error = 0;
    int i;

    p = dp_ports_lookup(dp, port_no);

    for(i = 0;i < p->max_queues; i++)
    {
        q = dp_ports_lookup_queue(p, i);
        if (q == NULL)
        {
            /* create new queue */
            error = port_add_queue(p, i);
            if (error == EXFULL)
            {
                return -1;
            }
        }
    }

    return 0;
}

#define TOTAL_WEIGHT   1000000

//设置最少带宽的思路:由于openflow设置的min_rate是实际带宽的千分比，所以直接把min_rate值乘以1000放
//入权重字段即可。前期测试发现权重值如果太大，例如三个queue的比值是6:3:1,发包速率是60%,50%,50%
//硬件中三个group的权重分别是6000000,3000000,1000000.期望结果是第1个流不丢包，但实际测试发现会丢包，经调测发现
//权重值改为600000,300000,100000后就不出现丢包了。
//由此可知权重此不能设置过大。
ofl_err
dp_ports_handle_queue_modify(struct datapath *dp, struct ofl_exp_openflow_msg_queue *msg,
        const struct sender *sender UNUSED) {
    // NOTE: assumes the packet queue has exactly one property, for min rate
    /*int i;*/
    struct sw_port *p;
    struct sw_queue *q;
    int uint = 0;
    unsigned short int port_speed = 0;
    unsigned long long int value;
    unsigned short int rate = 1000;
    /*unsigned long long int total_weight = TOTAL_WEIGHT;*/
    unsigned short int queue_id = msg->queue->queue_id;

    unsigned long long int min_rate = ((struct ofl_queue_prop_min_rate *)msg->queue->properties[0])->rate;
    unsigned long long int max_rate = ((struct ofl_queue_prop_max_rate *)msg->queue->properties[1])->rate;

    int error = 0;

    p = dp_ports_lookup(dp, msg->port_id);
    if (PORT_IN_USE(p))
    {
        q = dp_ports_lookup_queue(p, queue_id);
        if (q == NULL)
        {
            /* create new queue */
            error = port_add_queue(p, queue_id);
            if (error == EXFULL)
            {
                return ofl_error(OFPET_QUEUE_OP_FAILED, OFPQOFC_EPERM);
            }
        }

        /* queue exists - modify it */
#if defined(OF_HW_PLAT) && !defined(USE_NETDEV)
//       if (min_rate == 0)
//       {
//           for ( i = 0 ; i< queue_id; i++)
//           {
//                min_rate += dp->alta_queue[i];
//           }
//           min_rate =  (total_weight - min_rate) / rate;
//       }
//
//       dp->alta_queue[queue_id] = min_rate * rate;

/*     error = qos_conf_queue(p->stats->port_no,queue_id,OFPQT_MIN_RATE,min_rate * rate);
       if (error)
       {
            VLOG_ERR(LOG_MODULE, "Failed to update queue %d min rate", queue_id);
            return ofl_error(OFPET_QUEUE_OP_FAILED, OFPQOFC_EPERM);
       }
*/

       // 先注释掉
       //port_speed = port_speed_features (p->stats->port_no);
       switch (port_speed)
       {
           case OFPPF_10MB_HD:
           case OFPPF_10MB_FD:
           {
               value = 10000;
               break;
           }
           case OFPPF_100MB_HD:
           case OFPPF_100MB_FD:
           {
               value = 100000;
               break;
           }
           case OFPPF_1GB_HD:
           case OFPPF_1GB_FD:
           {
               value = 1000000;
               break;
           }
           case OFPPF_10GB_FD:
           {
               value = 10000000;
               break;
           }
           case OFPPF_40GB_FD:
           {
               value = 40000000;
               break;
           }
           default:
           {
               value = 10000000;
               break;
           }
       }

#else
        error = netdev_change_class(p->netdev, q->class_id, min_rate, max_rate);
        if (error)
        {
            VLOG_ERR(LOG_MODULE, "Failed to update queue %d", msg->queue->queue_id);
            return ofl_error(OFPET_QUEUE_OP_FAILED, OFPQOFC_EPERM);
        }
#endif
        q = &(p->queues[queue_id]);
        ((struct ofl_queue_prop_min_rate *)q->props->properties[0])->rate = min_rate;
        ((struct ofl_queue_prop_max_rate *)q->props->properties[1])->rate = max_rate;

    }
    else
    {
        VLOG_ERR(LOG_MODULE, "Failed to create/modify queue - port %d doesn't exist", msg->port_id);
        return ofl_error(OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_PORT);
    }
    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);
    return 0;
}


ofl_err
dp_ports_handle_queue_delete(struct datapath *dp, struct ofl_exp_openflow_msg_queue *msg,
                                                  const struct sender *sender UNUSED) {
    struct sw_port *p;
    struct sw_queue *q;

    p = dp_ports_lookup(dp, msg->port_id);
    if (p != NULL && p->netdev != NULL)
    {
        q = dp_ports_lookup_queue(p, msg->queue->queue_id);
        if (q != NULL)
        {
#if !defined(OF_HW_PLAT)
            netdev_delete_class(p->netdev,q->class_id);
#endif
            port_delete_queue(p, q);

            ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);
            return 0;
        }
        else
        {
            return ofl_error(OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_QUEUE);
        }
    }

    return ofl_error(OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_PORT);
}


bool check_port_link_status(struct sw_port *p)
{
    bool bRet = false;

    if (p != NULL)
    {
        bRet = port_up(p->conf->port_no);
    }

    if(VLOG_IS_DBG_ENABLED(ALTA_LOG_MODULE) && p != NULL)
    {
        VLOG_DBG(LOG_MODULE, "port id:%d link %s \n", p->conf->port_no, bRet ? "up":"down");
    }

    return bRet;
}

/* if port is ok return 1,else 0*/
int port_up(int port_no)
{
    return PORT_UP;
}

