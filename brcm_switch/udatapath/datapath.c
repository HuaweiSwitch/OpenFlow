/* Copyright (c) 2008, 2009 The Board of Trustees of The Leland Stanford
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
 * the OpenFlow 1.2 userspace switch.
 *
 */

#include "datapath.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "csum.h"
#include "dp_buffers.h"
#include "dp_control.h"
#include "ofp.h"
#include "ofpbuf.h"
#include "group_table.h"
#include "meter_table.h"
#include "oflib/ofl.h"
#include "oflib-exp/ofl-exp.h"
#include "oflib-exp/ofl-exp-nicira.h"
#include "oflib/ofl-messages.h"
#include "oflib/ofl-log.h"
#include "openflow/openflow.h"
#include "openflow/nicira-ext.h"
#include "openflow/private-ext.h"
#include "openflow/openflow-ext.h"
#include "pipeline.h"
#include "poll-loop.h"
#include "rconn.h"
#include "stp.h"
#include "vconn.h"
#include "timer_wheel.h"
#include "dp_ports.h"
#include "dp_capabilities.h"
#include "utilities/dpctl.h"
#include "util.h"

#if defined(OF_HW_PLAT)
#include "common/port.h"
#include "rbuff.h"
#endif

struct rbuff * g_fwd_buff = NULL;
struct rbuff * g_net_fwd_buff;
struct rbuff * g_out_buff;

unsigned int g_msgType = 0;
unsigned int configType = 0;

#define LOG_MODULE VLM_dp

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);


static struct remote *remote_create(struct datapath *, struct rconn *);
static void remote_run(struct datapath *, struct remote *);
static void remote_wait(struct remote *);
static void remote_destroy(struct remote *);

#if defined(OF_HW_PLAT)
static int port_status_change(struct datapath *dp, struct rbuff *port_rbuff);
#endif

#define MFR_DESC     "Opensource"
#define HW_DESC      "OpenFlow1.3 Switch CE7850-32Q-EI"
#define SW_DESC      "CE7850 V100R003C00SPC600"
#define DP_DESC      "Opensource"
#define SERIAL_NUM   "0231C001"


/* Callbacks for processing experimenter messages in OFLib. */
static struct ofl_exp_msg dp_exp_msg =
        {.pack      = ofl_exp_msg_pack,
         .unpack    = ofl_exp_msg_unpack,
         .free      = ofl_exp_msg_free,
         .to_string = ofl_exp_msg_to_string};

static struct ofl_exp dp_exp =
        {.act   = NULL,
         .inst  = NULL,
         .match = NULL,
         .stats = NULL,
         .msg   = &dp_exp_msg};

/* Generates and returns a random datapath id. */
static unsigned long long int gen_datapath_id(void)
{
    unsigned char ea[ETH_ADDR_LEN];
    eth_addr_random(ea);
    return eth_addr_to_uint64(ea);
}

void dp_new_table(struct datapath *dp)
{
    dp->buffers = dp_buffers_create(dp);
    dp->data_buffers = dp_data_buffers_create(dp);
    dp->pipeline = pipeline_create(dp);
    dp->groups = group_table_create(dp);
    dp->meters = meter_table_create(dp);
}

struct datapath * dp_new(void)
{
    int i = 0;
    int err = 0;
    struct datapath *dp;
    dp = xmalloc(sizeof(struct datapath));

    dp->mfr_desc   = strncpy(xmalloc(DESC_STR_LEN), MFR_DESC, DESC_STR_LEN);
    dp->mfr_desc[DESC_STR_LEN-1]     = 0x00;
    dp->hw_desc    = strncpy(xmalloc(DESC_STR_LEN), HW_DESC, DESC_STR_LEN);
    dp->hw_desc[DESC_STR_LEN-1]      = 0x00;
    dp->sw_desc    = strncpy(xmalloc(DESC_STR_LEN), SW_DESC, DESC_STR_LEN);
    dp->sw_desc[DESC_STR_LEN-1]      = 0x00;
    dp->dp_desc    = strncpy(xmalloc(DESC_STR_LEN), DP_DESC, DESC_STR_LEN);
    dp->dp_desc[DESC_STR_LEN-1]      = 0x00;
    dp->serial_num = strncpy(xmalloc(SERIAL_NUM_LEN), SERIAL_NUM, SERIAL_NUM_LEN);
    dp->serial_num[SERIAL_NUM_LEN-1] = 0x00;
    dp->mng_netdev_name = strncpy(xmalloc(INTERFACE_LEN), "eth4", INTERFACE_LEN);
    dp->mng_netdev_name[INTERFACE_LEN -1] = 0X00;


    dp->id = gen_datapath_id();

    dp->generation_id = -1;

    dp->last_timeout = time_now_sec();
    list_init(&dp->remotes);
    dp->listeners = NULL;
    dp->n_listeners = 0;

    memset(dp->ports, 0x00, sizeof (dp->ports));
    dp->local_port = NULL;
    for (i = 0; i < DP_MAX_PORTS; i++)
    {
        dp->ports[i].port_no = 0xffffffff;
    }

    list_init(&dp->port_list);
    dp->ports_num = 0;
    dp->max_queues = NETDEV_MAX_QUEUES;

    dp->exp = &dp_exp;

    dp->config.flags         = OFPC_FRAG_NORMAL;
    dp->config.miss_send_len = OFP_DEFAULT_MISS_SEND_LEN;
    dp->meter_choose_band = -1;
    dp->soft_switch = false;
    dp->vlan_ignore = false;
    dp->use_mac_table = false;
    dp->enty_xid = 0;
    dp->flow_table_type = AFTT_FULL_WILDCARD;

    //修改支持下发硬表时有20S的时间间隔
    dp->packet_in_limit = true;

    dp->use_exact_table = false;
    list_init(&dp->ofp_path);
    dp->delay_time = 8;
    dp->mac_aging_time = DEFAULT_MAC_AGING_TIME;
    dp->flow_table_max_entries = FLOW_TABLE_MAX_ENTRIES;
    dp->no_del_flow_entry = false;
    dp->openflowreset = false;
    err = pthread_rwlock_init(&dp->rw_lock,NULL);
    if ( err !=0 ) {
        VLOG_ERR(LOG_MODULE, "init rw lock failed err:%d.\n",err);
    }

    memset(dp->alta_queue, 0, NETDEV_MAX_QUEUES);

    memset(dp->ip, 0, MAX_IP_V4_LEN+1);
    memset(dp->username, 0, MAX_USER_NAME_LEN+1);
    memset(dp->vlanranges, 0, MAX_VLANS_RANGES_LEN+1);
    memset(dp->vlanBit, 0, MAX_VLANS_BIT_LEN);
    memset(dp->vlans, 0, MAX_VLAN_NUMBER);
    for (i = 0; i < MAX_PORT_NUMBER; i++)
    {
        memset(dp->ifname[i], 0, MAX_PORTNAME_LEN);
    }
    memset(dp->pvid, 0, MAX_PVID_NUMBER);
    dp->vlannumber = 0;
    dp->portnumber = 0;
    dp->pvidnumber = 0;

    if(strlen(dp->dp_desc) == 0) {
        /* just use "$HOSTNAME pid=$$" */
        char hostnametmp[DESC_STR_LEN];
        gethostname(hostnametmp, DESC_STR_LEN);
        snprintf(dp->dp_desc, DESC_STR_LEN, "%s pid=%u", hostnametmp, getpid());
    }

    /* FIXME: Should not depend on udatapath_as_lib */
    #if defined(OF_HW_PLAT)
        dp_hw_drv_init(dp);
    #endif

    return dp;
}



void dp_add_pvconn(struct datapath *dp, struct pvconn *pvconn)
{
    dp->listeners = xrealloc(dp->listeners,
                             sizeof *dp->listeners * (dp->n_listeners + 1));
    dp->listeners[dp->n_listeners++] = pvconn;
}

void dp_run(struct datapath *dp)
{
    struct remote *r, *rn;
    size_t i;
    time_t now = time_now_sec();

    if (now != dp->last_timeout) {
        dp->last_timeout = now;
        pipeline_timeout(dp->pipeline);
    }


    // 迭代3
    port_status_change(dp, port_rbuff);
    //meter_table_add_tokens(dp->meters);
    dp_ports_run(dp);//处理接收到的数据报文

    /* Talk to remotes. */
    LIST_FOR_EACH_SAFE (r, rn, struct remote, node, &dp->remotes) {
        remote_run(dp, r);
    }

    for (i = 0; i < dp->n_listeners; ) {
        struct pvconn *pvconn = dp->listeners[i];
        struct vconn *new_vconn;
        int retval = pvconn_accept(pvconn, OFP_VERSION, &new_vconn);
        if (!retval) {
            remote_create(dp, rconn_new_from_vconn("passive", new_vconn));
        } else if (retval != EAGAIN) {
            VLOG_WARN_RL(LOG_MODULE, &rl, "accept failed (%s)", strerror(retval));
            dp->listeners[i] = dp->listeners[--dp->n_listeners];
            continue;
        }
        i++;
    }
}

static void remote_run(struct datapath *dp, struct remote *r)
{
    ofl_err error;
    size_t i;

    rconn_run(r->rconn);

    /* Do some remote processing, but cap it at a reasonable amount so that
     * other processing doesn't starve. */
    for (i = 0; i < 50; i++) {
        if (!r->cb_dump) {
            struct ofpbuf *buffer;

            buffer = rconn_recv(r->rconn);
            if (buffer == NULL)
            {
                /*break;add for BII_testgroup260.Testcase_260_40_FlowmodCookies
                  reason:sometimes ,the msg from ctrl is slower than the packet in,so continue to receive 50 times.*/
                continue;
            }
            else
            {
                struct ofl_msg_header *msg;
                struct sender sender = {.remote = r};

                VLOG_DBG(LOG_MODULE, "\n------------------------Receive Msg From Control\n");
                VLOG_DBG(LOG_MODULE, "\nReceive Msg From Control buffer->size=%ld\n",buffer->size);

                if(buffer->size > 20000)
                {
                    VLOG_DBG(LOG_MODULE, "super long packet3\n");
                    //return ofl_error(OFPET_BAD_REQUEST, OFPBRC_MULTIPART_BUFFER_OVERFLOW);

                    {
                        struct ofl_msg_error err =
                                {{.type = OFPT_ERROR},
                                 .type = OFPET_BAD_REQUEST,
                                 .code = OFPBRC_MULTIPART_BUFFER_OVERFLOW,
                                 .data_length = 64,
                                 .data        = buffer->data};
                        dp_send_message(dp, (struct ofl_msg_header *)&err, &sender);
                        continue;
                    }
                }

                struct ofp_header *temp=NULL;
                struct ofp_multipart_request *temp1=NULL;
                temp = (struct ofp_header *)buffer->data;
                temp1 = (struct ofp_multipart_request *)buffer->data;

                if((OFPT_MULTIPART_REQUEST == temp->type) && (OFPMP_TABLE_FEATURES == temp1->type))
                {
                    if(buffer->size > 10000)
                    {
                        struct ofl_msg_error err =
                                {{.type = OFPT_ERROR},
                                 .type = OFPET_BAD_REQUEST,
                                 .code = OFPBRC_BAD_LEN,
                                 .data_length = 64,
                                 .data        = buffer->data};
                        dp_send_message(dp, (struct ofl_msg_header *)&err, &sender);
                        continue;
                    }
                }

                error = ofl_msg_unpack(buffer->data, buffer->size, &msg, &(sender.xid), dp->exp);

                if (!error) {
                    error = handle_control_msg(dp, msg, &sender);

                    if (error) {
                        ofl_msg_free(msg, dp->exp);
                    }
                }

                if (error) {
                    struct ofl_msg_error err =
                            {{.type = OFPT_ERROR},
                             .type = ofl_error_type(error),
                             .code = ofl_error_code(error),
                             .data_length = buffer->size,
                             .data        = buffer->data};
                    dp_send_message(dp, (struct ofl_msg_header *)&err, &sender);
                }

                VLOG_DBG(LOG_MODULE, "g_msgType2 = %d\n",g_msgType);

                if(g_msgType == 9)
                {
                    VLOG_DBG(LOG_MODULE, "enter OFPT_SET_CONFIG\n");

                    VLOG_DBG(LOG_MODULE, "configType = %d\n", configType);
                    if(configType == 0x02)
                    {
                        VLOG_DBG(LOG_MODULE, "dp_send_message error\n");
                        struct ofl_msg_error err =
                                {{.type = OFPT_ERROR},
                                 .type = 10,
                                 .code = 0,
                                 .data_length = buffer->size,
                                 .data        = buffer->data};
                        dp_send_message(dp, (struct ofl_msg_header *)&err, &sender);
                        VLOG_DBG(LOG_MODULE, "dp_send_message error end\n");

                    }
                    VLOG_DBG(LOG_MODULE, "leave OFPT_SET_CONFIG");
                }

                ofpbuf_delete(buffer);
            }
        } else {
            if (r->n_txq < TXQ_LIMIT) {
                int error = r->cb_dump(dp, r->cb_aux);
                if (error <= 0) {
                    if (error) {
                        VLOG_WARN_RL(LOG_MODULE, &rl, "Callback error: %s.",
                                     strerror(-error));
                    }
                    r->cb_done(r->cb_aux);
                    r->cb_dump = NULL;
                }
            } else {
                break;
            }
        }
    }

    if (!rconn_is_alive(r->rconn)) {
        remote_destroy(r);
    }
}

static void
remote_wait(struct remote *r)
{
    rconn_run_wait(r->rconn);
    rconn_recv_wait(r->rconn);
}

static void remote_destroy(struct remote *r)
{
    if (r) {
        if (r->cb_dump && r->cb_done) {
            r->cb_done(r->cb_aux);
        }
        list_remove(&r->node);
        rconn_destroy(r->rconn);
        free(r);
    }
}

static struct remote *remote_create(struct datapath *dp, struct rconn *rconn)
{
    size_t i;
    struct remote *remote = xmalloc(sizeof *remote);
    list_push_back(&dp->remotes, &remote->node);
    remote->rconn = rconn;
    remote->cb_dump = NULL;
    remote->n_txq = 0;
    remote->role = OFPCR_ROLE_EQUAL;
    /* Set the remote configuration to receive any asynchronous message*/
    remote->config.packet_in_mask[0]= 0x3;
    remote->config.port_status_mask[0]= 0x7;
    remote->config.flow_removed_mask[0]=0x0f;

    remote->config.packet_in_mask[1]=0x0;
    remote->config.port_status_mask[1]= 0x7;
    remote->config.flow_removed_mask[1]=0x0;
    return remote;
}


void dp_wait(struct datapath *dp)
{
    struct remote *r;
    size_t i;

#if !defined(OF_HW_PLAT)
    LIST_FOR_EACH (p, struct sw_port, node, &dp->port_list)
    {
        if (IS_HW_PORT(p)) {
            continue;
        }
        netdev_recv_wait(p->netdev);
    }
#endif
    LIST_FOR_EACH (r, struct remote, node, &dp->remotes)
    {
        remote_wait(r);
    }
    for (i = 0; i < dp->n_listeners; i++)
    {
        pvconn_wait(dp->listeners[i]);
    }
}

void dp_set_dpid(struct datapath *dp, unsigned long long int dpid)
{
    dp->id = dpid;
}

void dp_set_mfr_desc(struct datapath *dp, char *mfr_desc)
{
    strncpy(dp->mfr_desc, mfr_desc, DESC_STR_LEN);
    dp->mfr_desc[DESC_STR_LEN-1] = 0x00;
}

void dp_set_hw_desc(struct datapath *dp, char *hw_desc)
{
    strncpy(dp->hw_desc, hw_desc, DESC_STR_LEN);
    dp->hw_desc[DESC_STR_LEN-1] = 0x00;
}

void dp_set_sw_desc(struct datapath *dp, char *sw_desc)
{
    strncpy(dp->sw_desc, sw_desc, DESC_STR_LEN);
    dp->sw_desc[DESC_STR_LEN-1] = 0x00;
}

void dp_set_dp_desc(struct datapath *dp, char *dp_desc)
{
    strncpy(dp->dp_desc, dp_desc, DESC_STR_LEN);
    dp->dp_desc[DESC_STR_LEN-1] = 0x00;
}

void dp_set_serial_num(struct datapath *dp, char *serial_num)
{
    strncpy(dp->serial_num, serial_num, SERIAL_NUM_LEN);
    dp->serial_num[SERIAL_NUM_LEN-1] = 0x00;
}

void dp_set_max_queues(struct datapath *dp, unsigned int max_queues)
{
    dp->max_queues = max_queues;
}

unsigned int dp_is_ip_digit(char aDigit)
{
    unsigned int uiFlag = VOS_ERR;
    if(aDigit >= '0' && aDigit <= '9')
    {
        uiFlag = VOS_OK;
    }
    return uiFlag;
}

unsigned int dp_is_ip_formatvalid(char* paIP)
{
    unsigned int uiDotCnt = 0;
    unsigned int uiFlag = VOS_ERR;
    while(*paIP != '\0')
    {
        if(*paIP == '.')
        {
            uiDotCnt++;
        }
        else if(VOS_OK != dp_is_ip_digit(*paIP))
        {
            return VOS_ERR;
        }
        uiFlag = VOS_OK;
        paIP++;
    }
    if(uiDotCnt == 3)
    {
        return uiFlag;
    }
    else
    {
        return VOS_ERR;
    }
}

unsigned int dp_is_ip_valuevalid(char* paIP)
{
    unsigned int uiInteger = 0;
    while(*paIP != '\0')
    {
        if(VOS_OK == dp_is_ip_digit(*paIP))
        {
            uiInteger = uiInteger*10 + *paIP - '0';
        }
        else
        {
            if(uiInteger > MAX_IP_VALUE)
            {
                return VOS_ERR;
            }
            uiInteger = 0;
        }
        paIP++;
    }
    if(uiInteger > MAX_IP_VALUE)
    {
        return VOS_ERR;
    }
    return VOS_OK;
}

void dp_is_ip_valid(struct datapath *dp, char* paIP)
{
    unsigned int uiRet = VOS_ERR;
    if (VOS_NULL == paIP || VOS_NULL == dp)
    {
        ofp_fatal(0, "[ERROR]Failed to get ip, ip is NULL");
    }

    if (strlen(paIP) > MAX_IP_V4_LEN)
    {
        ofp_fatal(0, "argument to -i or --ip must be NUMBER "
                  "the length of ip is over MAX_IP_V4_LEN");
    }

    if (VOS_OK == dp_is_ip_formatvalid(paIP) && VOS_OK == dp_is_ip_valuevalid(paIP))
    {
        strncpy(dp->ip, paIP, MAX_IP_V4_LEN);
        dp->ip[MAX_IP_V4_LEN] = 0x00;
    }
    else
    {
        ofp_fatal(0, "[ERROR]Failed to get ip, ip is invaild");
    }
}

char aPortSegment[MAX_PORT_NUMBER][MAX_PORTS_RANGES_LEN+1] = {0};    // 存放配置文件中的PORT段
char aVlanStorage[MAX_VLAN_NUMBER][MAX_SEGMENT_LEN+1] = {0};         // 存放配置文件中的VLAN段
char aPortStorage[MAX_PORT_NUMBER][MAX_SEGMENT_LEN+1] = {0};         // 存放配置文件中的PORT段
char aPvidStorage[MAX_PVID_NUMBER][MAX_SEGMENT_LEN+1] = {0};         // 存放配置文件中的PORT段


void dp_split_ranges(char *paRanges, char paStorage[][MAX_SEGMENT_LEN+1], unsigned int *puiSegNum)
{
    unsigned int uiLoopi = 0;
    unsigned int uiLoopj = 0;
    unsigned int uiLen   = 0;

    // 入参判空
    if (paRanges == VOS_NULL || paStorage == VOS_NULL || puiSegNum == VOS_NULL)
    {
        ofp_fatal(0, "[ERROR]Failed to get vlan or port or pvid message");
    }

    uiLen = strlen(paRanges);
    *puiSegNum = 0;

    // 按逗号分隔每个vlan段或port段
    while (uiLoopi < uiLen)
    {
        uiLoopj = 0;
        while ((paRanges[uiLoopi] != ',') && (uiLoopi < uiLen))
        {
            //将分隔的每段存入paStorage中
            paStorage[*puiSegNum][uiLoopj++] = paRanges[uiLoopi];
            uiLoopi++;
        }
        paStorage[*puiSegNum][uiLoopj] = '\0';
        (*puiSegNum)++;
        uiLoopi++;
    }
    if (*puiSegNum == 0)
    {
        ofp_fatal(0, "[ERROR]Failed to get vlan or port or pvid segment");
    }
}


void dp_parse_leftval(char *paStorage, char *paLeftval, unsigned int *puiLen)
{
    unsigned int uiLoopi = 0;
    unsigned int uiLoopj = 0;

    // 入参判空
    if (paStorage == VOS_NULL || paLeftval == VOS_NULL || puiLen == VOS_NULL)
    {
        ofp_fatal(0, "[ERROR]Failed to get left value of vlan segment");
    }

    *puiLen = 0;

    // 将每个vlan段或port段按逗号分离出左值
    while (paStorage[uiLoopi] != '-' && paStorage[uiLoopi] != '\0')
    {
        paLeftval[uiLoopj++] = paStorage[uiLoopi];
        uiLoopi++;
    }
    paLeftval[uiLoopj] = '\0';
    *puiLen = uiLoopj;
}


void dp_parse_rightval(char *paStorage, char *paRightval, unsigned int *puiLen)
{
    unsigned int uiLoopi = 0;
    unsigned int uiLoopj = 0;

    // 入参判空
    if (paStorage == VOS_NULL || paRightval == VOS_NULL || puiLen == VOS_NULL)
    {
        ofp_fatal(0, "[ERROR]Failed to get right value of vlan segment");
    }

    // vlan段或port段只有一个值的情况
    if (paStorage[*puiLen] == '\0' || paStorage[*puiLen] != '-')
    {
        *paRightval = 0;
        return;
    }

    // 将每个vlan段或port段按逗号分离出右值
    uiLoopi = *puiLen + 1;
    while (paStorage[uiLoopi] != '\0')
    {
        paRightval[uiLoopj++] = paStorage[uiLoopi];
        uiLoopi++;
    }
    paRightval[uiLoopj] = '\0';
    *puiLen = uiLoopj;
}


unsigned int dp_judge_illegal(char *paStorage)
{
    unsigned int uiLoopi     = 0;
    unsigned int uiLoopj     = 0;
    char     *paTmpBegin = VOS_NULL;
    char     *paTmpEnd = VOS_NULL;

    // 入参判空
    if (paStorage == VOS_NULL)
    {
        return VOS_ERR;
    }
    paTmpBegin = paStorage;
    paTmpEnd = paStorage;

    // 忽略单个vlan值和单个port值前后的空格
    while (*paTmpBegin == ' ')
    {
        paTmpBegin++;
    }
    while (*paTmpEnd != '\0')
    {
        paTmpEnd++;
    }
    paTmpEnd--;
    while (*paTmpEnd == ' ')
    {
        paTmpEnd--;
    }
    while (paTmpBegin != paTmpEnd + 1)
    {
        paStorage[uiLoopi++] = *paTmpBegin;
        paTmpBegin++;
    }
    paStorage[uiLoopi] = '\0';

    // 如果单个vlan值和单个port值内有空格，则不合法
    for (uiLoopj = 0; uiLoopj <  uiLoopi; uiLoopj++)
    {
        if (paStorage[uiLoopj] == ' ')
        {
            return VOS_ERR;
        }
    }
    return VOS_OK;
}


void dp_split_vlan(char paStorage[][MAX_SEGMENT_LEN+1], unsigned int *uiVlanSegNum, struct datapath *dp)
{
    unsigned int uiLoopi     = 0;
    unsigned int uiLoopj     = 0;
    unsigned int uiLoopk     = 0;
    unsigned int uiLen       = 0;
    unsigned int uiVlanNum   = 0;
    unsigned int uiBeginVal  = 0;                  //Vlan段的左值
    unsigned int uiEndVal    = 0;                  //Vlan段的右值
    unsigned int uiRet       = VOS_OK;
    char*    paTmp       = VOS_NULL;

    // 入参判空
    if ((VOS_NULL == paStorage) || ('\0' == paStorage[0]))
    {
        ofp_fatal(0, "[ERROR]Failed to get vlan message, vlan message is null");
    }

    paTmp = xmalloc(MAX_VLANID_LEN*sizeof(char));
    memset(paTmp, 0, MAX_VLANID_LEN);

    //对每个Vlan段，解析其左值和右值
    for (uiLoopi = 0; uiLoopi< *uiVlanSegNum; uiLoopi++)
    {
        uiLoopj = 0;

        //解析左值
        dp_parse_leftval(paStorage[uiLoopi], paTmp, &uiLen);

        // 判断是否合法
        if (VOS_OK == dp_judge_illegal(paTmp))
        {
            uiBeginVal = atoi(paTmp);
        }
        else
        {
            ofp_fatal(0, "[ERROR]The vlan value: %s in configure file is illegal\n", paTmp);
        }
        //解析右值，如果只有一个值，将右值赋值为0
        dp_parse_rightval(paStorage[uiLoopi], paTmp, &uiLen);

        // 判断是否合法
        if (VOS_OK == dp_judge_illegal(paTmp))
        {
            uiEndVal = atoi(paTmp);
        }
        else
        {
            ofp_fatal(0, "[ERROR]The vlan value: %s in configure file is illegal\n", paTmp);
        }

        //如果右值不为0，对左值至右值进行遍历，将单个Vlan值存入结构体dp中的数组vlan中
        if (uiEndVal != 0)
        {
            //如果Vlan值不在2-4095之间，或左值大于右值打印错误信息
            if (uiBeginVal > uiEndVal || uiBeginVal < MIN_VLAN || uiBeginVal > MAX_VLAN || uiEndVal < MIN_VLAN || uiEndVal > MAX_VLAN)
            {
                ofp_fatal(0, "[ERROR]The vlan segment: %d - %d in configure file is illegal\n", uiBeginVal, uiEndVal);
            }

            //如果左值等于右值，只存储其中一个值
            if (uiBeginVal == uiEndVal)
            {
                dp->vlans[uiVlanNum] = uiBeginVal;
                uiVlanNum++;
            }
            else
            {
                //遍历左值至右值，分别存储
                for(uiLoopk = uiBeginVal; uiLoopk <= uiEndVal; uiLoopk++)
                {
                    dp->vlans[uiVlanNum] = uiLoopk;
                    uiVlanNum++;
                }
            }
        }
        else
        {
            //如果Vlan值不在2-4095之间，或左值大于右值打印错误信息
            if (uiBeginVal < MIN_VLAN || uiBeginVal > MAX_VLAN)
            {
                ofp_fatal(0, "[ERROR]The vlan segment: %d in configure file is illegal\n", uiBeginVal);
            }

            //如果右值为0，直接存储左值
            dp->vlans[uiVlanNum] = uiBeginVal;
            uiVlanNum++;
        }
        if (uiVlanNum > MAX_VLAN_NUMBER)
        {
            xfree (paTmp);
            ofp_fatal(0, "[ERROR]The total number of vlans is larger than MAX_VLAN_NUMBER");
        }
    }
    dp->vlannumber = uiVlanNum;
    xfree (paTmp);
}


void dp_parse_singleport(char *paPortStr, char *paPortBegin, char *paPortEnd, unsigned int uiPortLen)
{
    unsigned int uiLoopi   = uiPortLen - 1;
    unsigned int uiLoopj   = 0;
    unsigned int uiLoopk   = 0;
    int      iLoopPort = 0;

    // 入参判空
    if (paPortStr == VOS_NULL || paPortBegin == VOS_NULL || paPortEnd == VOS_NULL)
    {
        ofp_fatal(0, "[ERROR]Failed to get port message");
    }
    while (paPortStr[uiLoopi--] != '/')
    {
        iLoopPort++;
    }
    uiLoopi = uiPortLen - 1;
    paPortEnd[iLoopPort] = '\0';
    while (iLoopPort > 0)
    {
        paPortEnd[iLoopPort-uiLoopj-1] = paPortStr[uiLoopi--];
        iLoopPort--;
    }

    for (uiLoopk = 0; uiLoopk <= uiLoopi; uiLoopk++)
    {
        paPortBegin[uiLoopk] = paPortStr[uiLoopk];
    }
    paPortBegin[uiLoopk] = '\0';
}


unsigned int dp_is_splitport(char *paStorage)
{
    char *pStorageTmp = paStorage;

    // 入参判空
    if (VOS_NULL == paStorage)
    {
        return VOS_ERR;
    }

    // 如果有冒号，说明是拆分口
    while (*pStorageTmp != '\0')
    {
        if (*pStorageTmp == ':')
        {
            return VOS_OK;
        }
        pStorageTmp++;
    }
    return VOS_ERR;
}


void dp_deal_commonport(char *paLeftval, char *paRightval, unsigned int *puiPortNum, struct datapath *dp)
{
    unsigned int  uiLenBegin =   0;
    unsigned int  uiLenEnd   =   0;
    unsigned int  uiBeginNum =   0;
    unsigned int  uiEndNum   =   0;
    unsigned int  uiLoop     =   0;
    char*     paBeginStr =   VOS_NULL;
    char*     paEndStr   =   VOS_NULL;
    char*     paTmpBegin =   VOS_NULL;
    char*     paTmpEnd   =   VOS_NULL;
    char*     paTmp      =   VOS_NULL;

    if (VOS_NULL == paLeftval || VOS_NULL == paRightval || VOS_NULL == puiPortNum || VOS_NULL == dp)
    {
        ofp_fatal(0, "[ERROR]Failed to get port message when deal with common port");
    }

    paBeginStr = xmalloc(MAX_PORTNAME_LEN*sizeof(char));
    paEndStr   = xmalloc(MAX_PORTNAME_LEN*sizeof(char));
    paTmpBegin = xmalloc(MAX_PORTNAME_LEN*sizeof(char));
    paTmpEnd   = xmalloc(MAX_PORTNAME_LEN*sizeof(char));
    paTmp      = xmalloc(MAX_PORTNAME_LEN*sizeof(char));
    memset(paBeginStr, 0, MAX_PORTNAME_LEN);
    memset(paEndStr, 0, MAX_PORTNAME_LEN);
    memset(paTmpBegin, 0, MAX_PORTNAME_LEN);
    memset(paTmpEnd, 0, MAX_PORTNAME_LEN);
    memset(paTmp, 0, MAX_PORTNAME_LEN);

    uiLenBegin = strlen(paLeftval);
    uiLenEnd = strlen(paRightval);

    //如果左值的长度大于右值的长度，打印错误信息
    if (uiLenBegin > uiLenEnd)
    {
        ofp_fatal(0, "[ERROR]The port segment %s - %s in configure file is illegal\n", paLeftval, paRightval);
    }
    //如果左值的长度小于等于右值的长度
    else
    {
        //将左值的倒数第一个"/"之前的字符串存入tempb,之后的字符串存入bch
        dp_parse_singleport(paLeftval, paTmpBegin, paBeginStr, uiLenBegin);
        //将右值的倒数第一个"/"之前的字符串存入tempe,之后的字符串存入ech
        dp_parse_singleport(paRightval, paTmpEnd, paEndStr, uiLenEnd);
        if (strlen(paTmpBegin) != strlen(paTmpEnd))
        {
            ofp_fatal(0, "[ERROR]The port segment %s - %s in configure file is illegal\n", paLeftval, paRightval);
        }
        else
        {
            if (strncmp(paTmpBegin, paTmpEnd, strlen(paTmpEnd)) != 0)
            {
                ofp_fatal(0, "[ERROR]The port segment %s - %s in configure file is illegal\n", paLeftval, paRightval);
            }
            else
            {
                uiBeginNum = atoi(paBeginStr);
                uiEndNum = atoi(paEndStr);
                //如果左值和右值的最后一个字符相等，说明左值等于右值，只存储其中一个
                if (uiBeginNum == uiEndNum)
                {
                    strncpy(dp->ifname[*puiPortNum], paLeftval, uiLenBegin);
                    (*puiPortNum)++;
                }
                //如果左值的最后一个字符大于右值的最后一个字符，打印错误信息
                else if (uiBeginNum > uiEndNum)
                {
                    ofp_fatal(0, "[ERROR]The port segment %s - %s in configure file is illegal\n", paLeftval, paRightval);
                }
                //按左值的最后一个字符至右值的最后一个字符进行遍历，分别存储至结构体dp的ifnames数组中
                else
                {
                    for (uiLoop = uiBeginNum; uiLoop <= uiEndNum; uiLoop++)
                    {
                        if (MAX_PORTNAME_LEN >= strlen(paTmpBegin))
                        {
                            strncpy(dp->ifname[*puiPortNum], paTmpBegin, strlen(paTmpBegin));
                            sprintf(paTmp, "%d", uiLoop);
                            if (MAX_PORTNAME_LEN >= strlen(paTmp))
                            {
                                strncat(dp->ifname[*puiPortNum], paTmp, strlen(paTmp));
                                (*puiPortNum)++;
                            }
                        }
                    }
                }
            }
        }
    }
    xfree(paBeginStr);
    xfree(paEndStr);
    xfree(paTmpBegin);
    xfree(paTmpEnd);
    xfree(paTmp);
}


void dp_deal_splitport(char *paLeftval, char *paRightval, unsigned int *puiPortNum, struct datapath *dp)
{
    char     *paLeftStr     = VOS_NULL;
    char     *paRightStr    = VOS_NULL;
    char     *paLeftLoop    = VOS_NULL;
    char     *paRightLoop   = VOS_NULL;
    char     *paLeftTmp     = VOS_NULL;
    char     *paRightTmp    = VOS_NULL;
    char     *paLoopTmp     = VOS_NULL;
    unsigned int uiLeftNum      = 0;
    unsigned int uiRightNum     = 0;
    unsigned int uiLoop         = 0;
    if (VOS_NULL == paLeftval || VOS_NULL == paRightval || VOS_NULL == puiPortNum || VOS_NULL == dp)
    {
        ofp_fatal(0, "[ERROR]Failed to get port message when deal with split port");
    }
    paLeftTmp  = paLeftval;
    paRightTmp = paRightval;
    paLeftStr  = strtok(paLeftTmp, ":");
    if (VOS_NULL == paLeftStr)
    {
        ofp_fatal(0, "[ERROR]Failed to get left split port message in dp_deal_splitport");
    }
    paLeftLoop = strtok(VOS_NULL, ":");
    uiLeftNum = atoi(paLeftLoop);
    paRightStr = strtok(paRightTmp, ":");
    if (VOS_NULL == paRightStr)
    {
        ofp_fatal(0, "[ERROR]Failed to get right split port message in dp_deal_splitport");
    }
    paRightLoop = strtok(VOS_NULL, ":");
    uiRightNum = atoi(paRightLoop);
    paLoopTmp = xmalloc(MAX_PORTNAME_LEN*sizeof(char));
    memset(paLoopTmp, 0, MAX_PORTNAME_LEN);
    if (0== strcmp(paLeftStr, paRightStr) && uiLeftNum >= 1 && uiLeftNum <= uiRightNum)
    {
        if (uiLeftNum == uiRightNum)
        {
            if (MAX_PORTNAME_LEN >= strlen(paLeftStr))
            {
                strncpy(dp->ifname[*puiPortNum], paLeftStr, strlen(paLeftStr));
                sprintf(paLoopTmp, "%d", uiLeftNum);
                strncat(dp->ifname[*puiPortNum], ":", strlen(":"));
                if (MAX_PORTNAME_LEN >= strlen(paLoopTmp))
                {
                    strncat(dp->ifname[*puiPortNum], paLoopTmp, strlen(paLoopTmp));
                    (*puiPortNum)++;
                }
            }
        }
        else
        {
            for (uiLoop = uiLeftNum; uiLoop <= uiRightNum; uiLoop++)
            {
                if (MAX_PORTNAME_LEN >= strlen(paLeftStr))
                {
                    strncpy(dp->ifname[*puiPortNum], paLeftStr, strlen(paLeftStr));
                    sprintf(paLoopTmp, "%d", uiLoop);
                    strncat(dp->ifname[*puiPortNum], ":", strlen(":"));
                    if (MAX_PORTNAME_LEN >= strlen(paLoopTmp))
                    {
                        strncat(dp->ifname[*puiPortNum], paLoopTmp, strlen(paLoopTmp));
                        (*puiPortNum)++;
                    }
                }
            }
        }
    }
    else
    {
        ofp_fatal(0, "[ERROR]The port segment %s - %s in configure file is illegal\n", paLeftval, paRightval);
    }
    xfree(paLoopTmp);
}

void dp_parse_portgroup(char *paBegin, char *paEnd, unsigned int *puiLoop, char aPortSegment[][MAX_PORTS_RANGES_LEN+1])
{
    unsigned int uiLoopi = 0;

    if (VOS_NULL == paBegin || VOS_NULL == paEnd || VOS_NULL == puiLoop || VOS_NULL == aPortSegment)
    {
        ofp_fatal(0, "[ERROR]Failed to get port message when parse port group");
    }

    while(*paBegin != '(' && *paBegin != '\0')
    {
        paBegin++;
    }

    paBegin++;

    while (*paEnd != ')' && *paEnd != '\0')
    {
        paEnd++;
    }

    while (0 != strcmp(paBegin, paEnd))
    {
        aPortSegment[*puiLoop][uiLoopi++] = *paBegin;
        paBegin++;
    }

    aPortSegment[*puiLoop][uiLoopi] = '\0';

}

void dp_parse_portbeforegroup(char *paBegin, char *paEnd, unsigned int *puiLoop, char aPortSegment[][MAX_PORTS_RANGES_LEN+1])
{
    unsigned int uiLoopi = 0;

    if (VOS_NULL == paBegin || VOS_NULL == paEnd || VOS_NULL == puiLoop || VOS_NULL == aPortSegment)
    {
        ofp_fatal(0, "[ERROR]Failed to get port message when parse port message before port group");
    }

    while (*paEnd != ',' && *paEnd != '\0')
    {
        paEnd--;
    }

    while (0 != strcmp(paBegin, paEnd) && (*paBegin != ')'))
    {
        aPortSegment[*puiLoop][uiLoopi++] = *paBegin;
        paBegin++;
    }

    aPortSegment[*puiLoop][uiLoopi] = '\0';

}

void dp_split_portgroups
(
    char *paStorage,
    char aPortSegment[][MAX_PORTS_RANGES_LEN+1],
    char aPortStorage[][MAX_SEGMENT_LEN+1],
    unsigned int uiPvidFlag[MAX_PORT_NUMBER],
    unsigned int *puiPortGroupNum,
    struct datapath *dp
)
{
    unsigned int uiLoopi = 0;
    unsigned int uiLoopj = 0;
    unsigned int uiFlag  = 0;
    unsigned int uiBegin = 0;
    unsigned int uiEnd = 0;
    unsigned int puiPortSegNum = 0;
    char *paStorageTmpb = VOS_NULL;
    char *paStorageTmpe = VOS_NULL;
    char *paGroup = VOS_NULL;

    if (VOS_NULL == paStorage || '\0' == paStorage )
    {
        ofp_fatal(0, "[ERROR]Failed to get port message, port message is null");
    }

    while (*paStorage == ' ')
    {
        paStorage++;
    }

    paStorageTmpb = paStorage;
    paStorageTmpe = paStorage;
    paGroup = paStorage;

    while (VOS_NULL != paStorageTmpe && VOS_NULL != paGroup)
    {
        paGroup = strstr(paGroup, "group");
        paStorageTmpe = paGroup;
        if (VOS_NULL != paGroup)
        {
            paStorageTmpe = paGroup;
            if (0 == strcmp(paStorageTmpb, paStorageTmpe))
            {
                dp_parse_portgroup(paStorageTmpb, paStorageTmpe, &uiLoopi, aPortSegment);

                uiBegin = dp->portnumber;
                dp_split_ranges(aPortSegment[uiLoopi], aPortStorage, &puiPortSegNum);


                dp_split_port(aPortStorage, &puiPortSegNum, dp);

                uiEnd = dp->portnumber;

                for (uiLoopj = uiBegin; uiLoopj < uiEnd; uiLoopj++)
                {
                    uiPvidFlag[uiLoopj] = uiFlag;
                }
                (*puiPortGroupNum) ++;
            }
            else
            {
                dp_parse_portbeforegroup(paStorageTmpb, paStorageTmpe, &uiLoopi, aPortSegment);


                uiBegin = dp->portnumber;
                dp_split_ranges(aPortSegment[uiLoopi], aPortStorage, &puiPortSegNum);

                dp_split_port(aPortStorage, &puiPortSegNum, dp);

                uiEnd = dp->portnumber;

                for (uiLoopj = uiBegin; uiLoopj < uiEnd; uiLoopj++)
                {
                    uiPvidFlag[uiLoopj] = uiFlag++;
                }
                (*puiPortGroupNum) += uiEnd - uiBegin;

                uiLoopi++;
                uiLoopj = 0;

                dp_parse_portgroup(paStorageTmpb, paStorageTmpe, &uiLoopi, aPortSegment);


                uiBegin = dp->portnumber;
                dp_split_ranges(aPortSegment[uiLoopi], aPortStorage, &puiPortSegNum);

                dp_split_port(aPortStorage, &puiPortSegNum, dp);

                uiEnd = dp->portnumber;
                for (uiLoopj = uiBegin; uiLoopj < uiEnd; uiLoopj++)
                {
                    uiPvidFlag[uiLoopj] = uiFlag;
                }
                (*puiPortGroupNum)++;
            }

            uiFlag++;
            uiLoopi++;
            uiLoopj = 0;

            while(')' != *paStorageTmpb && '\0' != *paStorageTmpb)
            {
                paStorageTmpb++;
            }

            paStorageTmpb++;
            while (',' != *paStorageTmpb && '\0' != *paStorageTmpb)
            {
                paStorageTmpb++;
            }

            paStorageTmpb++;
            while (' ' == *paStorageTmpb && '\0' != *paStorageTmpb)
            {
                paStorageTmpb++;
            }
            paStorageTmpe = paStorageTmpb;
            paGroup = paStorageTmpe;
            if (*paStorageTmpe == '\0')
            {
                return ;
            }
        }
        else
        {
            while ('\0' != *paStorageTmpb)
            {
                aPortSegment[uiLoopi][uiLoopj++] = *paStorageTmpb;
                paStorageTmpb++;
            }
            aPortSegment[uiLoopi][uiLoopj] = '\0';

            uiBegin = dp->portnumber;
            dp_split_ranges(aPortSegment[uiLoopi], aPortStorage, &puiPortSegNum);

            dp_split_port(aPortStorage, &puiPortSegNum, dp);

            uiEnd = dp->portnumber;
            for (uiLoopj = uiBegin; uiLoopj < uiEnd; uiLoopj++)
            {
                uiPvidFlag[uiLoopj] = uiFlag++;
            }
            (*puiPortGroupNum) += uiEnd - uiBegin;
        }

    }

}



void dp_split_port(char paStorage[][MAX_SEGMENT_LEN+1], unsigned int *PortSegNum, struct datapath *dp)
{
    unsigned int  uiLoopi      =   0;
    unsigned int  uiPortNum    =   0;
    unsigned int  uiLen        =   0;
    unsigned int  uiRet        =   0;
    char*     paBeginVal   =   NULL;            //Port段的左值
    char*     paEndVal     =   NULL;            //Port段的右值

    if (paStorage == VOS_NULL || *PortSegNum == 0 || dp == VOS_NULL)
    {
        ofp_fatal(0, "[ERROR]Failed to get port message");
    }

    paBeginVal = xmalloc(MAX_PORTNAME_LEN*sizeof(char));
    paEndVal   = xmalloc(MAX_PORTNAME_LEN*sizeof(char));
    memset(paBeginVal, 0, MAX_PORTNAME_LEN);
    memset(paEndVal, 0, MAX_PORTNAME_LEN);

    uiPortNum = dp->portnumber;

    //对每个Port段，解析其左值和右值
    for (uiLoopi = 0; uiLoopi< *PortSegNum; uiLoopi++)
    {
        //解析出左值
        dp_parse_leftval(paStorage[uiLoopi], paBeginVal, &uiLen);
        if (VOS_ERR == dp_judge_illegal(paBeginVal))
        {
            ofp_fatal(0, "[ERROR]The port value: %s in configure file is illegal\n", paStorage[uiLoopi]);
        }
        // 判断是否为eth-trunk口
        if (('e' == paBeginVal[0] || 'E' == paBeginVal[0])
            && ('t' == paBeginVal[1] || 'T' == paBeginVal[1])
            && ('h' == paBeginVal[2] || 'H' == paBeginVal[2]))
        {
            if (3 != strlen(paBeginVal))
            {
                ofp_fatal(0, "[ERROR]The port value: %s in configure file is illegal\n", paStorage[uiLoopi]);
            }
            dp_parse_rightval(paStorage[uiLoopi], paEndVal, &uiLen);
            if (VOS_ERR == dp_judge_illegal(paEndVal))
            {
                ofp_fatal(0, "[ERROR]The port value: %s in configure file is illegal\n", paStorage[uiLoopi]);
            }
            if (('t' == paEndVal[0] || 'T' == paEndVal[0])
                && ('r' == paEndVal[1] || 'R' == paEndVal[1])
                && ('u' == paEndVal[2] || 'U' == paEndVal[2])
                && ('n' == paEndVal[3] || 'N' == paEndVal[3])
                && ('k' == paEndVal[4] || 'K' == paEndVal[4]))
            {
                if (5 != strlen(paEndVal))
                {
                    ofp_fatal(0, "[ERROR]The port value: %s in configure file is illegal\n", paStorage[uiLoopi]);
                }
                strncpy(dp->ifname[uiPortNum], "eth", strlen(paBeginVal)+1);
                strncat(dp->ifname[uiPortNum], "-", strlen("-"));
                strncat(dp->ifname[uiPortNum], "trunk", strlen(paEndVal)+1);
                uiPortNum++;
                continue;
            }
            else
            {
                ofp_fatal(0, "[ERROR]The port value: %s in configure file is illegal\n", paStorage[uiLoopi]);
            }
        }
        //解析出右值，如果Port段只有一个值，将右值赋值为0
        dp_parse_rightval(paStorage[uiLoopi], paEndVal, &uiLen);
        if (VOS_ERR == dp_judge_illegal(paEndVal))
        {
            ofp_fatal(0, "[ERROR]The port value: %s in configure file is illegal\n", paStorage[uiLoopi]);
        }
        //如果右值为0，只存储左值至结构体dp的ifnames中
        if (*paEndVal == 0)
        {
            strncpy(dp->ifname[uiPortNum], paBeginVal, strlen(paBeginVal));
            uiPortNum++;
        }
        //对左值至右值进行遍历
        else
        {
            if (VOS_ERR == dp_is_splitport(paBeginVal))
            {
                dp_deal_commonport(paBeginVal, paEndVal, &uiPortNum, dp);
            }
            else
            {
                dp_deal_splitport(paBeginVal, paEndVal, &uiPortNum, dp);
            }
        }
        if (uiPortNum > MAX_PORT_NUMBER)
        {
            xfree (paBeginVal);
            xfree (paEndVal);
            ofp_fatal(0, "[ERROR]The total number of ports is larger than MAX_PORT_NUMBER");
        }
    }

    dp->portnumber = uiPortNum;
    xfree (paBeginVal);
    xfree (paEndVal);
}

void dp_split_pvid(char *paStorage, unsigned int *uiPvidFlag, unsigned int *uiPvidSegNum, unsigned int *uiPortGroupNum, struct datapath *dp)
{
    unsigned int uiLoopi = 0;
    unsigned int uiLoopj = 0;
    unsigned int uiRet   = 0;
    unsigned int uiPvidTmp = 0;
    if (VOS_NULL == paStorage || '\0' == paStorage)
    {
        ofp_fatal(0, "[ERROR]Failed to get pvid message, pvid message is null");
    }

    dp_split_ranges(paStorage, aPvidStorage, uiPvidSegNum);
    dp->pvidnumber = *uiPvidSegNum;
    if (*uiPortGroupNum != *uiPvidSegNum)
    {
        ofp_fatal(0, "[ERROR]The number of pvid and port group is not same");
    }

    for (uiLoopi = 0; uiLoopi < dp->pvidnumber; uiLoopi++)
    {
        uiRet = dp_judge_illegal(aPvidStorage[uiLoopi]);
        if (VOS_ERR == uiRet)
        {
            ofp_fatal(0, "[ERROR]PVID %s in configure file is illegal", aPvidStorage[uiLoopi]);
        }
        uiPvidTmp = atoi(aPvidStorage[uiLoopi]);
        if (uiPvidTmp < MIN_VLAN || uiPvidTmp > MAX_VLAN)
        {
            ofp_fatal(0, "[ERROR]PVID %d in configure file is illegal", uiPvidTmp);
        }
        while (uiLoopi == uiPvidFlag[uiLoopj])
        {
            dp->pvid[uiLoopj] = uiPvidTmp;
            uiLoopj++;
        }
    }
}



void dp_set_vlan_port_pvid(struct datapath *dp, char *paSerialNum)
{
    unsigned int uiLoopi         = 0;
    unsigned int uiLoopj         = 0;
    unsigned int uiVlanSeg       = 0;
    unsigned int uiPortGroupNum  = 0;
    unsigned int uiPvidSeg       = 0;
    unsigned int uiFlag          = 1;
    unsigned int uiPvidFlag[MAX_PORT_NUMBER] = {0};
    char*    paVlanStore     = VOS_NULL;   // 存放配置文件中的VLAN信息
    char*    paPortStore     = VOS_NULL;   // 存放配置文件中的PORT信息
    char*    paPvidStore     = VOS_NULL;
    char*    paContrl        = VOS_NULL;   // 存放VLAN或PORT信息前的控制字符
    char     aTmp[1024]      = {0};
    FILE*    fpCfg;

    if (dp == VOS_NULL || paSerialNum == VOS_NULL)
    {
        ofp_fatal(0, "[ERROR]Failed to get vlan or port message");
    }

    paVlanStore = xmalloc(MAX_VLANS_RANGES_LEN*sizeof(char));
    paPortStore = xmalloc(MAX_PORTS_RANGES_LEN*sizeof(char));
    paPvidStore = xmalloc(MAX_PVID_RANGES_LEN*sizeof(char));
    memset(paVlanStore, 0, MAX_VLANS_RANGES_LEN);
    memset(paPortStore, 0, MAX_PORTS_RANGES_LEN);
    memset(paPvidStore, 0, MAX_PVID_RANGES_LEN);

    // 打开vlan和端口的配置文件，并解析Vlan和端口信息
    if ((fpCfg = fopen(paSerialNum, "r")) == VOS_NULL)
    {
        ofp_fatal(0, "[ERROR]Failed to open the file, agrument to -f or --conffile must be a file with a path");
    }
    while (uiFlag)
    {
        fgets(aTmp, 1024, fpCfg);
        uiLoopi = 0;
        uiLoopj = 0;

        while (' ' == aTmp[uiLoopi])
        {
            uiLoopi++;
        }

        while (aTmp[uiLoopi]!='\0' && aTmp[uiLoopi]!='\n' && aTmp[uiLoopi]!='\r')
        {
            aTmp[uiLoopj++] = aTmp[uiLoopi++];
        }
        aTmp[uiLoopj] = '\0';

        // 读取配置文件中的VLAN信息，存入paVlanStore中
        if (0 == strncmp(aTmp, "vlan", 4))
        {
            uiLoopi = 4;
            uiLoopj = 0;
            while (':' != aTmp[uiLoopi])
            {
                if (' ' != aTmp[uiLoopi])
                {
                    ofp_fatal(0, "[ERROR]Illegal character in vlan control character");
                }
                uiLoopi++;
            }
            uiLoopi++;
            while(aTmp[uiLoopi]!='\0' && aTmp[uiLoopi]!='\n' && aTmp[uiLoopi]!='\r')
            {
                paVlanStore[uiLoopj++] = aTmp[uiLoopi++];
            }
            if (uiLoopj > MAX_VLANS_RANGES_LEN)
            {
                ofp_fatal(0, "[ERROR]The length of vlan message is over the max range");
            }
            paVlanStore[uiLoopj] = '\0';
        }
        // 读取配置文件中的PORT信息，存入paPortStore中
        else if (0 == strncmp(aTmp, "port", 4))
        {
            uiLoopi = 4;
            uiLoopj = 0;
            while (':' != aTmp[uiLoopi])
            {
                if (' ' != aTmp[uiLoopi])
                {
                    ofp_fatal(0, "[ERROR]Illegal character in port control character");
                }
                uiLoopi++;
            }
            uiLoopi++;
            while(aTmp[uiLoopi]!='\0' && aTmp[uiLoopi]!='\n' && aTmp[uiLoopi]!='\r')
            {
                paPortStore[uiLoopj++]=aTmp[uiLoopi++];
            }
            if (uiLoopj > MAX_PORTS_RANGES_LEN)
            {
                ofp_fatal(0, "[ERROR]The length of port message is over the max range");
            }
            paPortStore[uiLoopj] = '\0';
        }
        // 读取配置文件中的PVID信息，存入paPvidStore中
        else if (0 == strncmp(aTmp, "pvid", 4))
        {
            uiLoopi = 4;
            uiLoopj = 0;
            while (':' != aTmp[uiLoopi])
            {
                if (' ' != aTmp[uiLoopi])
                {
                    ofp_fatal(0, "[ERROR]Illegal character in pvid control character");
                }
                uiLoopi++;
            }
            uiLoopi++;
            while(aTmp[uiLoopi]!='\0' && aTmp[uiLoopi]!='\n' && aTmp[uiLoopi]!='\r')
            {
                paPvidStore[uiLoopj++]=aTmp[uiLoopi++];
            }
            if (uiLoopj > MAX_PVID_RANGES_LEN)
            {
                ofp_fatal(0, "[ERROR]The length of pvid message is over the max range");
            }
            paPvidStore[uiLoopj] = '\0';
        }
        if (feof(fpCfg))
        {
            uiFlag = 0;
        }
    }

    fclose(fpCfg);

    // 解析vlan段
    dp_split_ranges(paVlanStore, aVlanStorage, &uiVlanSeg);

    // 解析vlan值
    dp_split_vlan(aVlanStorage, &uiVlanSeg, dp);

    // 解析port值
    dp_split_portgroups(paPortStore, aPortSegment, aPortStorage, uiPvidFlag, &uiPortGroupNum, dp);

    // 解析pvid值
    dp_split_pvid(paPvidStore, uiPvidFlag, &uiPvidSeg, &uiPortGroupNum, dp);


    VLOG_DBG(LOG_MODULE, "vlan num is: %d\n", dp->vlannumber);
    VLOG_DBG(LOG_MODULE, "port num is: %d\n", dp->portnumber);
    VLOG_DBG(LOG_MODULE, "pvid num is: %d\n", dp->pvidnumber);

    xfree(paVlanStore);
    xfree(paPortStore);
    xfree(paPvidStore);
}

#if 1

struct forwarding_context * fwding_ctx_alloc(int in_port, int head_size, int buff_size)
{
    struct forwarding_context *ctx;

    ctx = malloc(sizeof(*ctx));
    assert(ctx);

    memset(ctx, 0, sizeof(*ctx));
    ctx->buff = ofpbuf_new_with_headroom(buff_size, head_size+128); 
    ctx->in_port = in_port;

    return ctx;
}

int get_port_link(int port_no)
{
    return PORT_UP;
}

/* 为编译，临时定义 */
typedef struct tag_OPENFLOW_CtlWord_Sendtolinux_Linux_T2
{
    unsigned int   uiPktLen;
    unsigned int   ulIfIndex;                  /*!< 端口的ifindex索引 */
    unsigned int   ulRecvReason;
    unsigned char  ucUntagFlag;
    unsigned char  ucCos;
    unsigned char  ucRes[10];
}OPENFLOW_CtlWord_Sendtolinux_Linux_S_T2;

unsigned int fwding_evt_handle(unsigned int    ulNetID,       /*!<芯片号*/
                           void       *pData,         /*!<数据报文指针*/
                           unsigned int    ulLen,         /*!<报文长度*/
                           void       *pstCtrlWord,   /*!<控制结构，见 FE_XGS_NI_CTRL_WORD_S*/
                           unsigned char   **ppucBuf        /*!<该参数用于交换指针，先阶段不用，*/
                          )
{
    int in_port = 0;
    struct forwarding_context *ctx;
    OPENFLOW_CtlWord_Sendtolinux_Linux_S_T2 *ctrl_word;

    VLOG_DBG(LOG_MODULE, "Enter fwding_evt_handle\n");

    if(!pData || !pstCtrlWord || ulLen <= ETH_HEADER_LEN)
        return -1;

    ctrl_word = (OPENFLOW_CtlWord_Sendtolinux_Linux_S_T2 *)pstCtrlWord;


    if(g_fwd_buff == 0)
    {
        g_fwd_buff = rbuff_alloc(100);
    }

    if(rbuff_full(g_fwd_buff))
    {
        g_port_recv_drop++;
        return -1;
    }

    /*修改原因:大包与小包mod号不同，openflow侧将mod全部置为0*/
    //in_port = (ctrl_word->usSrcMod << 16) | ctrl_word->ucSrcPort;
    in_port = ctrl_word->ulIfIndex;

    ctx = fwding_ctx_alloc(in_port, 0, ulLen);
    ctx->reason = ctrl_word->ulRecvReason;
    ctx->rx_cos = ctrl_word->ucCos;
    ctx->untag_flag = ctrl_word->ucUntagFlag;


    ofpbuf_put((struct ofpbuf *)ctx->buff, pData, ulLen);
    if (ctrl_word->ucUntagFlag == 0)
    {
        //delete vlan tag, can do in process_buffer()
        delete_vlan((struct ofpbuf *)ctx->buff);
    }

    rbuff_put(g_fwd_buff, ctx);
    VLOG_DBG(LOG_MODULE, "put packet in to buff success\n");

    return 0;
}

void * fwding_ctx(void)
{
    return rbuff_get(g_fwd_buff);
}
#endif


static int send_openflow_buffer_to_remote(struct ofpbuf *buffer, struct remote *remote)
{
    int retval = rconn_send_with_limit(remote->rconn, buffer, &remote->n_txq, TXQ_LIMIT);

    if (retval) {
        //VLOG_WARN_RL(LOG_MODULE, &rl, "send to %s failed: %s",
        //             rconn_get_name(remote->rconn), strerror(retval));
        VLOG_ERR_RL(LOG_MODULE, &rl, "send to %s failed: %s \n",
                 rconn_get_name(remote->rconn), strerror(retval));
    }

    return retval;
}

int send_openflow_buffer(struct datapath *dp,
                         struct ofpbuf *buffer,
                         const struct sender *sender)
{
    update_openflow_length(buffer);
    if (sender)
    {
        /* Send back to the sender. */
        return send_openflow_buffer_to_remote(buffer, sender->remote);

    }
    else
    {
        /* Broadcast to all remotes. */
        struct remote *r, *prev = NULL;
        unsigned char msg_type;
        /* Get the type of the message */
        memcpy(&msg_type,((char* ) buffer->data) + 1, sizeof(unsigned char));
        LIST_FOR_EACH (r, struct remote, node, &dp->remotes)
        {
            /* do not send to remotes with slave role apart from port status */
            if (r->role == OFPCR_ROLE_EQUAL || r->role == OFPCR_ROLE_MASTER)
            {
                /*Check if the message is enabled in the asynchronous configuration*/
                switch(msg_type){
                    case (OFPT_PACKET_IN):{
                        struct ofp_packet_in *p = (struct ofp_packet_in*)buffer->data;
                        /* Do not send message if the reason is not enabled */
                        if((p->reason == OFPR_NO_MATCH) && !(r->config.packet_in_mask[0] & 0x1))
                            continue;
                        if((p->reason == OFPR_ACTION) && !(r->config.packet_in_mask[0] & 0x2))
                            continue;
                        if((p->reason == OFPR_INVALID_TTL) && !(r->config.packet_in_mask[0] & 0x4))
                            continue;
                        break;
                    }
                    case (OFPT_PORT_STATUS):{
                        struct ofp_port_status *p = (struct ofp_port_status*)buffer->data;
                        if((p->reason == OFPPR_ADD) && !(r->config.port_status_mask[0] & 0x1))
                            continue;
                        if((p->reason == OFPPR_DELETE) && !(r->config.port_status_mask[0] & 0x2))
                            continue;
                        if((p->reason == OFPPR_MODIFY) && !(r->config.port_status_mask[0] & 0x4))
                            continue;
                    }
                    case (OFPT_FLOW_REMOVED):{
                        struct ofp_flow_removed *p= (struct ofp_flow_removed *)buffer->data;
                        if((p->reason == OFPRR_IDLE_TIMEOUT) && !(r->config.flow_removed_mask[0] & 0x1))
                            continue;
                        if((p->reason == OFPRR_HARD_TIMEOUT) && !(r->config.flow_removed_mask[0] & 0x2))
                            continue;
                        if((p->reason == OFPRR_DELETE) && !(r->config.flow_removed_mask[0] & 0x4))
                            continue;
                        if((p->reason == OFPRR_GROUP_DELETE) && !(r->config.flow_removed_mask[0] & 0x8))
                            continue;
                        if((p->reason == OFPRR_METER_DELETE) && !(r->config.flow_removed_mask[0] & 0x10))
                            continue;
                    }
                }
            }
            else {
                /* In this implementation we assume that a controller with role slave
                   can is able to receive only port stats messages */
                if (r->role == OFPCR_ROLE_SLAVE && msg_type != OFPT_PORT_STATUS) {
                    continue;
                }
                else {
                    struct ofp_port_status *p = (struct ofp_port_status*)buffer->data;
                    if((p->reason == OFPPR_ADD) && !(r->config.port_status_mask[1] & 0x1))
                        continue;
                    if((p->reason == OFPPR_DELETE) && !(r->config.port_status_mask[1] & 0x2))
                        continue;
                    if((p->reason == OFPPR_MODIFY) && !(r->config.port_status_mask[1] & 0x4))
                        continue;
                }
            }
            if (prev) {
                send_openflow_buffer_to_remote(ofpbuf_clone(buffer), prev);
            }
            prev = r;
        }
        if (prev) {
            send_openflow_buffer_to_remote(buffer, prev);
        } else {
            ofpbuf_delete(buffer);
        }
        return 0;
    }
}

int dp_send_message(struct datapath *dp, struct ofl_msg_header *msg,
                     const struct sender *sender) {
    struct ofpbuf *ofpbuf;
    unsigned char *buf;
    size_t buf_size;
    int error;

    if (VLOG_IS_DBG_ENABLED(ALTA_LOG_MODULE)) {
        char *msg_str = ofl_msg_to_string(msg, dp->exp);
        VLOG_DBG(ALTA_LOG_MODULE, "sending: %s", msg_str);
        free(msg_str);
    }

    if(msg->type == OFPT_PACKET_IN)
    {
        g_pkt_in ++;
    }
    error = ofl_msg_pack(msg, sender == NULL ? 0 : sender->xid, &buf, &buf_size, dp->exp);
    if (error) {
        VLOG_WARN_RL(LOG_MODULE, &rl, "There was an error packing the message!");
        return error;
    }

    ofpbuf = ofpbuf_new(0);
    ofpbuf_use(ofpbuf, buf, buf_size);
    ofpbuf_put_uninit(ofpbuf, buf_size);

    error = send_openflow_buffer(dp, ofpbuf, sender);
    if (error) {
        VLOG_WARN_RL(LOG_MODULE, &rl, "There was an error sending the message!");
        /* TODO Zoltan: is delete needed? */
        //ofpbuf_delete(ofpbuf);
        return error;
    }
    return 0;
}

int
dp_send_message_asynchronism(struct datapath *dp, struct ofl_msg_header *msg,
                     unsigned int xid) {
    struct ofpbuf *ofpbuf;
    unsigned char *buf;
    size_t buf_size;
    int error;

    if (VLOG_IS_DBG_ENABLED(ALTA_LOG_MODULE)) {
        char *msg_str = ofl_msg_to_string(msg, dp->exp);
        VLOG_DBG(ALTA_LOG_MODULE, "sending: %s", msg_str);
        free(msg_str);
    }

    if(msg->type == OFPT_PACKET_IN)
    {
        g_pkt_in ++;
    }
    error = ofl_msg_pack(msg, xid, &buf, &buf_size, dp->exp);
    if (error) {
        VLOG_WARN_RL(LOG_MODULE, &rl, "There was an error packing the message!");
        return error;
    }

    ofpbuf = ofpbuf_new(0);
    ofpbuf_use(ofpbuf, buf, buf_size);
    ofpbuf_put_uninit(ofpbuf, buf_size);

    error = send_openflow_buffer(dp, ofpbuf, NULL);
    if (error) {
        VLOG_WARN_RL(LOG_MODULE, &rl, "There was an error sending the message!");
        /* TODO Zoltan: is delete needed? */
        //ofpbuf_delete(ofpbuf);
        return error;
    }
    return 0;
}

ofl_err
dp_handle_set_desc(struct datapath *dp, struct ofl_exp_openflow_msg_set_dp_desc *msg,
                                            const struct sender *sender UNUSED) {
    dp_set_dp_desc(dp, msg->dp_desc);
    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);
    return 0;
}

ofl_err
dp_handle_show_perf(struct datapath *dp, struct ofl_exp_openflow_msg_show_perf *msg,
                                            const struct sender *sender)
{
    (void)sender;
    OF_PERF_SHOW_LOG();
    OF_PERF_SHOW_PKTIN();
    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);
    return 0;
}

ofl_err
dp_handle_hw_config(struct datapath *dp, struct ofl_exp_openflow_msg_hw_config *msg,
                                            const struct sender *sender)
{
    (void)sender;
    if (msg->config & HEC_SOFT_ENABLE)
    {
       dp->soft_switch = true;
    }

    if (msg->config & HEC_ALTA_PORT_RESET)
    {

    }

    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);
    return 0;
}

#define QOS_GROUP_MAX 32
struct ofl_exp_openflow_map_queue qos_group_array[QOS_GROUP_MAX];
unsigned int qos_group_num = 0;

static const char *cmd_str[] = {"add", "mod", "apply"};
static const char *type_str[] =  {"qos_group_sp", "qos_group_drr", "qos_group_drr", "qos_group_max"};
static void map_queue_infor(struct ofl_exp_openflow_map_queue *msg)
{
    int i;

    VLOG_DBG(LOG_MODULE, "ofl_exp_openflow_map_queue: \n\r command :%s, port :%d, qos_group_id :%d, type: %s, queue array:  ", \
        cmd_str[msg->command], msg->port_id, msg->qos_group_id, type_str[msg->type]);
    for( i = 0; i<8; i++)
    {
        if( msg->queue_array[i] == 0xff)
            break;

        VLOG_DBG(LOG_MODULE, "%d, ", msg->queue_array[i]);
    }
    VLOG_DBG(LOG_MODULE, "\n\r");
}

ofl_err dp_handle_map_queue(struct datapath *dp, struct ofl_exp_openflow_map_queue *msg,
                            const struct sender *sender)
{
    int i;
    int num_of_no_shaping_group = 0;

    (void)sender;

    map_queue_infor(msg);

    switch( msg->command)
    {
        case qos_command_add:  // add;
            if( qos_group_num < QOS_GROUP_MAX)
            {
                memcpy( & qos_group_array[qos_group_num], msg, sizeof(struct ofl_exp_openflow_map_queue) );
                qos_group_num ++;
            }
            break;
        case qos_command_apply: // apply;
            num_of_no_shaping_group = 0;
            for( i=0; i< qos_group_num; i++)
            {
                if( qos_group_array[i].type != qos_group_shaping) // sharping;
                {
                    num_of_no_shaping_group ++;
                }
            }
            // preconf
            if( num_of_no_shaping_group != 0)
            {
                // 先注释掉
               // qos_preconf(qos_group_array[0].port_id, qos_group_array[0].type, num_of_no_shaping_group);
            }
            // map queue;
            for( i=0; i<qos_group_num; i++)
            {
                int queue_num;
                for( queue_num = 0; queue_num<8; queue_num++)
                {
                    if( qos_group_array[i].queue_array[queue_num] == 0xff)
                    {
                        break;
                    }
                }
                // 先注释掉
            /*    qos_mapping(qos_group_array[i].port_id, qos_group_array[i].qos_group_id, \
                    qos_group_array[i].type,  qos_group_array[i].queue_array,  queue_num);*/

                map_queue_infor(&qos_group_array[i]);
            }
            // post conf;
            if( num_of_no_shaping_group != 0)
            {
                // 先注释掉
               // qos_postconf(qos_group_array[0].port_id, qos_group_array[0].type);
            }
            // clear qos_group_array
            memset(qos_group_array, 0, sizeof(qos_group_array) );
            qos_group_num = 0;
            break;

         default:

            break;
    }

    // call wangtao's function;

    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);
    return 0;
}

ofl_err dp_handle_mod_port_conf(struct datapath *dp,
                                struct ofl_exp_openflow_mod_port_conf *msg,
                                const struct sender *sender)
{
    bool bEnabled ;

    if (msg->is_bool) {
       bEnabled = msg->value == 0 ? 0 : 1;
       // 先注释掉
       //set_port_attr(msg->port_id, msg->attr, &bEnabled);
    } else {
        // 先注释掉
       //set_port_attr(msg->port_id, msg->attr, &msg->value);
    }
    return 0;
}

ofl_err dp_handle_set_network(struct datapath *dp,
                      struct ofl_exp_openflow_network_conf *msg,
                      const struct sender *sender)
{
    struct netdev *netdev;
    struct in_addr in4, in4_msk, router;
    char *netdev_name = "eth0";
    int error;

    error = netdev_open(netdev_name, ETH_TYPE_IP, &netdev);
    if (error) {
        VLOG_ERR(LOG_MODULE, "could not open %s network device: %s\n",netdev_name, strerror(error));
        return 0;
    }

    if (msg->ipv4 != 0) {
        in4.s_addr = msg->ipv4;
        in4_msk.s_addr = msg->mask;
        netdev_set_in4(netdev, in4, in4_msk);
    }

    if (msg->gw != 0)  {
        router.s_addr = msg->gw;
        netdev_add_router(router);
    }

    netdev_close(netdev);
    return 0;
}

ofl_err dp_handle_mod_qos_group(struct datapath *dp,
                                struct ofl_exp_openflow_mod_qos_group *msg,
                                const struct sender *sender)
{

    VLOG_DBG(LOG_MODULE,
             "dp_handle_mod_qos_group: command: %s, port :%d, group_id :%d, type :%s, value: %lu\n\r",
             cmd_str[msg->command],
             msg->port_id,
             msg->qos_group_id,
             type_str[msg->type],
             msg->value);

//    msg->command = qos_command_mod;
    (void)sender;

    if (qos_command_apply == msg->command )
    {
        // 先注释掉
        //qos_postconf(msg->port_id, msg->type);
    }
    else if(qos_command_mod == msg->command)
    {
        // call wangtao's function;
        if (qos_group_shaping == msg->type)
        {
            msg->value = msg->value* 1000000;
            // 先注释掉
           // qos_conf(msg->port_id, msg->qos_group_id, msg->type, msg->value);
        }
        else if(qos_group_sp  == msg->type)
        {
            // 先注释掉
         //   qos_conf(msg->port_id, msg->qos_group_id, msg->type, msg->value);
        }
        else
        {
            // 先注释掉
         //   qos_conf(msg->port_id, msg->qos_group_id, msg->type, msg->value);
        }
    }
    else
    {
        // error;
    }

    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);
    return 0;
}

static ofl_err dp_check_generation_id(struct datapath *dp, unsigned long long int new_gen_id){

    if(dp->generation_is_defined == false)
    {
        dp->generation_id = new_gen_id;
        dp->generation_is_defined = true;
        return 0;
    }
    else
    {
        if((int64_t)(new_gen_id - dp->generation_id) > 0)
        {
            dp->generation_id = new_gen_id;
            return 0;
        }
        else
        {
            return ofl_error(OFPET_ROLE_REQUEST_FAILED, OFPRRFC_STALE);
        }
    }
}

ofl_err
dp_handle_role_request(struct datapath *dp, struct ofl_msg_role_request *msg,
                                            const struct sender *sender) {
    switch (msg->role) {
        case OFPCR_ROLE_MASTER: {
            struct remote *r;
            ofl_err error = dp_check_generation_id(dp,msg->generation_id);
            if (error) {
                VLOG_WARN_RL(LOG_MODULE, &rl, "Role message generation id is smaller than the current id!");
                return error;
            }
            /* Old master(s) must be changed to slave(s) */
            LIST_FOR_EACH (r, struct remote, node, &dp->remotes) {
                if (r->role == OFPCR_ROLE_MASTER) {
                    r->role = OFPCR_ROLE_SLAVE;
                }
            }
            sender->remote->role = OFPCR_ROLE_MASTER;
            break;
        }

        case OFPCR_ROLE_SLAVE: {
            ofl_err error = dp_check_generation_id(dp,msg->generation_id);
            if (error) {
                VLOG_WARN_RL(LOG_MODULE, &rl, "Role message generation id is smaller than the current id!");
                return error;
            }
            sender->remote->role = OFPCR_ROLE_SLAVE;
            break;
        }

        case OFPCR_ROLE_EQUAL: {
            sender->remote->role = OFPCR_ROLE_EQUAL;
            break;
        }

        case OFPCR_ROLE_NOCHANGE: {
            msg->role = sender->remote->role;
            break;
        }

        default: {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Role request with unknown role (%u).", msg->role);
            return ofl_error(OFPET_ROLE_REQUEST_FAILED, OFPRRFC_BAD_ROLE);
        }
    }

    {
    struct ofl_msg_role_request reply =
        {{.type = OFPT_ROLE_REPLY},
            .role = msg->role,
            .generation_id = dp->generation_id};

    dp_send_message(dp, (struct ofl_msg_header *)&reply, sender);
    }
    return 0;
}

ofl_err
dp_handle_async_request(struct datapath *dp, struct ofl_msg_async_config *msg,
                                            const struct sender *sender)
{
    int i;
    struct ofl_msg_async_config reply;
    unsigned short int async_type = msg->header.type;

    switch(async_type)
    {
        case (OFPT_GET_ASYNC_REQUEST):
        {
            reply.header.type = OFPT_GET_ASYNC_REPLY;
            reply.config = xmalloc(sizeof(struct ofl_async_config));

            for (i = 0; i < 2; i++)
            {
                reply.config->packet_in_mask[i] =  htonl(sender->remote->config.packet_in_mask[i]);
                reply.config->flow_removed_mask[i] =  htonl(sender->remote->config.flow_removed_mask[i]);
                reply.config->port_status_mask[i] = htonl(sender->remote->config.port_status_mask[i]);
            }

            dp_send_message(dp, (struct ofl_msg_header *)&reply, sender);

            ofl_msg_free((struct ofl_msg_header*)msg, dp->exp);
            free(reply.config);

            break;
        }
        case (OFPT_SET_ASYNC):
        {
            for (i = 0; i < 2; i++)
            {
                sender->remote->config.packet_in_mask[i] =  ntohl(msg->config->packet_in_mask[i]);
                sender->remote->config.flow_removed_mask[i] =  ntohl(msg->config->flow_removed_mask[i]);
                sender->remote->config.port_status_mask[i] = ntohl(msg->config->port_status_mask[i]);
            }
            break;
        }
    }
    return 0;
}

// add for brcm ports status change
#if defined(OF_HW_PLAT)
static int port_status_change(struct datapath *dp, struct rbuff *port_rbuff)
{
    ports_action *portsact;
    struct sw_port * port;
    struct ofl_msg_port_status msg;
    unsigned int flag = 1;

    while((portsact =(ports_action *) rbuff_get(port_rbuff)) != NULL)
    {
        LIST_FOR_EACH(port, struct sw_port, node, &dp->port_list)
        {
            if(port->conf->port_no <= ALTA_MAX_INDEX_NO && port->conf->port_no == portsact->port_no)
            {
                if(PORT_DOWN == portsact->port_flag)
                {
                    msg.header.type = OFPT_PORT_STATUS;
                    msg.reason      = OFPPR_MODIFY;
                    port->conf->state = OFPPS_LINK_DOWN;
                    msg.desc        = port->conf;
                }
                else if(PORT_UP == portsact->port_flag)
                {
                    msg.header.type = OFPT_PORT_STATUS;
                    msg.reason      = OFPPR_MODIFY;
                    port->conf->state = OFPPS_LIVE;
                    //先注释掉
                    //port->conf->curr = port_speed_features(port->conf->port_no);
                    port->conf->supported = port->conf->curr;
                    port->conf->advertised = port->conf->curr;
                    port->conf->curr_speed = port_speed(port->conf->curr);
                    port->conf->max_speed  = port_speed(port->conf->supported);
                    msg.desc        = port->conf;
                }
                else
                {
                    msg.header.type = OFPT_PORT_STATUS;
                    msg.reason      = OFPPR_MODIFY;
                    port->conf->state = OFPPS_BLOCKED;
                    msg.desc        = port->conf;
                }
                flag = (OFPPC_PORT_DOWN == port->conf->config) && OFPPS_LINK_DOWN != port->conf->state ? 0 : 1;
                if(flag)
                {
                    dp_send_message(dp, (struct ofl_msg_header *)&msg, NULL);
                }
                break;
            }
        }
        free(portsact);
    }
    return 0;
}
#endif
