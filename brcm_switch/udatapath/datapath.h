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
 */

#ifndef DATAPATH_H
#define DATAPATH_H 1

#define VOS_OK     0
#define VOS_ERR    1
#define VOS_NULL   0


#include <stdbool.h>
#include <stdint.h>

#include "util.h"
#include "dp_buffers.h"
#include "dp_ports.h"
#include "openflow/nicira-ext.h"
#include "ofpbuf.h"
#include "oflib/ofl.h"
#include "oflib/ofl-messages.h"
#include "oflib/ofl-structs.h"
#include "oflib-exp/ofl-exp-nicira.h"
#include "group_table.h"
#include "timeval.h"
#include "list.h"

#include "hlist.h"
#include "flow_table.h"

#include "pipeline.h"


struct rconn;
struct pvconn;
struct sender;

/****************************************************************************
 * The datapath
 ****************************************************************************/
#define INTERFACE_LEN            6
#define MAX_IP_V4_LEN            15
#define MAX_USER_NAME_LEN        253
#define MAX_PASSWORD_LEN         128
#define MAX_PORT_NO              104
#define ALTA_MAX_INDEX_NO        0xffffffff
#define DEFAULT_MAC_AGING_TIME   8

#define MAX_VLANS_RANGES_LEN     500    // 配置文件中VLAN行的最大长度
#define MAX_PORTS_RANGES_LEN     1000   // 配置文件中PORT行的最大长度
#define MAX_PVID_RANGES_LEN      200    // 配置文件中PVID行的最大长度
#define MAX_VLAN_NUMBER          4064   // 配置文件中允许写入的最大VLAN个数
#define MAX_VLANID_LEN           5      // 单个VLAN字符串的最大长度
#define MAX_PVID_LEN             5      // PVID的最大长度
#define MAX_PVID_NUMBER          4094   // 允许配置的PVID的最大个数
#define MAX_SEGMENT_LEN          100    // 单个VLAN段或PORT段的最大长度
#define MAX_VLAN                 4094   // 允许配置的最大VLAN值
#define MIN_VLAN                 2      // 允许配置的最小VLAN值
#define MAX_PARA_NUM             30     // 命令行中允许的参数的最大个数
#define MAX_OF_NEED_PARA_NUM     3      // Openflow使能命令行中必备的参数的个数
#define MAX_IP_VALUE             255    // 合法的ip的最大值
#define MAX_VLANS_BIT_LEN        512
#define MAX_PORT_NUMBER          1000   // 配置文件中允许写入的最大POTR个数
#define MAX_PORTNAME_LEN         30     // 单个PORT字符串的最大长度

#define PATH_MAX_ENTRIES (FLOW_TABLE_MAX_ENTRIES *10)
//#define AGEING_BUFFER_SIZE   50000

struct policer_config
{
    unsigned int cir_rate;    //kbit   k:1000
    unsigned int cir_capacity;  //kbyte   k:1024
    unsigned int cir_action;
    unsigned int eir_rate;
    unsigned int eir_capacity;
    unsigned int eir_action;
    unsigned int cir_dscp;
    unsigned int eir_dscp;
    int      flag;          //KBPS or PKTPS
};

/* Strings to describe the manufacturer, hardware, and software. This data
     * is queriable through switch stats request. */

struct datapath {    
    char                    *mfr_desc;
    char                    *hw_desc;
    char                    *sw_desc;
    char                    *dp_desc;
    char                    *serial_num;

    unsigned long long int  id;                     /* Unique identifier for this datapath. */

    struct list remotes;                            /* Remote connections. */

    unsigned long long int  generation_id;          /* Identifies a given mastership view */
    bool                    generation_is_defined;  /* If generation_id has been given by controller */

    /* Listeners. */
    struct pvconn **        listeners;
    size_t                  n_listeners;
    time_t                  last_timeout;

    struct dp_buffers *     buffers;
    struct data_buffers *   data_buffers;
    struct pipeline *       pipeline;               /* Pipeline with multi-tables. */
    struct group_table *    groups;                 /* Group tables */
    struct meter_table *    meters;                 /* Meter tables */
    unsigned int            start_group_id;
    struct ofl_config       config;                 /* Configuration, set from controller. */

    /* NOTE: ports are numbered starting at 1 in OF 1.1 */
    unsigned int            max_queues;             /* used when creating ports */
    struct sw_port          ports[DP_MAX_PORTS];
    struct sw_port *        local_port;             /* OFPP_LOCAL port, if any. */
    struct list             port_list;              /* All ports, including local_port. */
    size_t                  ports_num;

    struct ofl_exp *        exp;

#if defined(OF_HW_PLAT)
    /* Although the chain maintains the pointer to the HW driver
     * for flow operations, the datapath needs the port functions
     * in the driver structure
     */
    of_hw_driver_t *hw_drv;
    struct hw_pkt_q_entry *hw_pkt_list_head, *hw_pkt_list_tail;
#endif


    unsigned short int      vlan;

    struct meter_entry *    m_entry;
    unsigned short int      meter_choose_band;
    struct policer_config   pol_config;
    bool                    soft_switch;

    unsigned long long int  alta_queue[NETDEV_MAX_QUEUES];

    struct list             ofp_path;
    struct hlist_head *     path_buckets;           /* hash bucket  */
    unsigned int            enty_xid;

    unsigned char           flow_table_type;

    bool                    use_mac_table;
    bool                    use_exact_table;

    unsigned long long int  time_point[20];
    char *                  mng_netdev_name;
    bool                    packet_in_limit;
    unsigned int            delay_time;
    unsigned short int      mac_aging_time;
    pthread_rwlock_t        rw_lock;
    int                     flow_table_max_entries;
    bool                    no_del_flow_entry;
    bool                    vlan_ignore;
    char                    ip[MAX_IP_V4_LEN+1];
    char                    username[MAX_USER_NAME_LEN+1];
    unsigned char           vlanranges[MAX_VLANS_RANGES_LEN+1];
    char                    vlanBit[MAX_VLANS_BIT_LEN];
    char                    ifname[MAX_PORT_NUMBER][MAX_PORTNAME_LEN];
    unsigned int            ifindex[MAX_PORT_NUMBER];
    unsigned int            portnumber;

    unsigned int            vlans[MAX_VLAN_NUMBER];
    unsigned int            vlannumber;
    unsigned int            pvid[MAX_PVID_NUMBER];
    unsigned int            pvidnumber;

    bool                    openflowreset;

    }datapath_s;

/* The origin of a received OpenFlow message, to enable sending a reply. */
struct sender {
    struct remote *     remote;     /* The device that sent the message. */
    unsigned int        xid;        /* The OpenFlow transaction ID. */
};


#define TXQ_LIMIT 128               /* Max number of packets to queue for tx. */
/* A connection to a secure channel. */
struct remote {
    struct list         node;
    struct rconn *      rconn;
    int                 n_txq;      /* Number of packets queued for tx on rconn. */

    /* Support for reliable, multi-message replies to requests.
     *
     * If an incoming request needs to have a reliable reply that might
     * require multiple messages, it can use remote_start_dump() to set up
     * a callback that will be called as buffer space for replies. */
    int                 (*cb_dump)(struct datapath *, void *aux);
    void                (*cb_done)(void *aux);
    void *              cb_aux;

    unsigned int        role;       /* OpenFlow controller role. */
    struct ofl_async_config config; /* Asynchronous messages configuration,
                                     * set from controller*/
};



#define MAX_PORT_NO_dp 128

struct forwarding_context
{
    int in_port;
    int reason;
    unsigned char rx_cos;
    unsigned char untag_flag;
    void *buff;
};

unsigned int fwding_evt_handle
(
    unsigned int    ulNetID,       /*!<芯片号*/
    void       *pData,         /*!<数据报文指针*/
    unsigned int    ulLen,         /*!<报文长度*/
    void       *pstCtrlWord,   /*!<控制结构，见 FE_XGS_NI_CTRL_WORD_S*/
    unsigned char   **ppucBuf        /*!<该参数用于交换指针，先阶段不用，*/
);


/* Creates a new datapath */
struct datapath *dp_new(void);

void dp_new_table(struct datapath *dp);

void dp_add_pvconn(struct datapath *dp, struct pvconn *pvconn);

/* Executes the datapath. The datapath works if this function is run
 * repeatedly. */
void dp_run(struct datapath *dp);

/* This function should be called after dp_run. It sets up polling on all
 * event sources (listeners, remotes, ...), so that poll_block() will block
 * until an event occurs on any source. */
void dp_wait(struct datapath *dp);


/* Setter functions for various datapath fields */
void dp_set_dpid(struct datapath *dp, unsigned long long int dpid);

void dp_set_mfr_desc(struct datapath *dp, char *mfr_desc);

void dp_set_hw_desc(struct datapath *dp, char *hw_desc);

void dp_set_sw_desc(struct datapath *dp, char *sw_desc);

void dp_set_dp_desc(struct datapath *dp, char *dp_desc);

void dp_set_serial_num(struct datapath *dp, char *serial_num);

void dp_set_max_queues(struct datapath *dp, unsigned int max_queues);


/* Sends the given OFLib message to the connection represented by sender,
 * or to all open connections, if sender is null. */
int dp_send_message(struct datapath *dp, struct ofl_msg_header *msg,
                     const struct sender *sender);

/* wangxin 临时添加 */
int dp_send_message_asynchronism(struct datapath *dp, struct ofl_msg_header *msg,
                     unsigned int xid);

void * fwding_ctx(void);

unsigned int dp_is_ip_digit(char aDigit);
unsigned int dp_is_ip_formatvalid(char* paIP);
unsigned int dp_is_ip_valuevalid(char* paIP);
void dp_is_ip_valid(struct datapath *dp, char* paIP);
void dp_split_ranges(
    char *paRanges, 
    char paStorage[][MAX_SEGMENT_LEN+1], 
    unsigned int *puiSegNum);

void dp_parse_leftval(char *paStorage, char *paLeftval, unsigned int *puiLen);
void dp_parse_rightval(char *paStorage, char *paRightval, unsigned int *puiLen);
unsigned int dp_judge_illegal(char *paStorage);
void dp_split_vlan(
    char paStorage[][MAX_SEGMENT_LEN+1], 
    unsigned int *uiVlanSegNum, 
    struct datapath *dp);

void dp_parse_singleport(
    char *paPortStr, 
    char *paPortBegin, 
    char *paPortEnd, 
    unsigned int uiPortLen);

unsigned int dp_is_splitport(char *paStorage);

void dp_deal_commonport(
    char *paLeftval, 
    char *paRightval, 
    unsigned int *puiPortNum, 
    struct datapath *dp);

void dp_deal_splitport(
    char *paLeftval, 
    char *paRightval, 
    unsigned int *puiPortNum, 
    struct datapath *dp);

void dp_split_port(
    char paStorage[][MAX_SEGMENT_LEN+1], 
    unsigned int *PortSegNum, 
    struct datapath *dp);

void dp_parse_portgroup(
    char *paBegin, 
    char *paEnd, 
    unsigned int *puiLoop, 
    char aPortSegment[][MAX_PORTS_RANGES_LEN+1]);

void dp_parse_portbeforegroup(
    char *paBegin, 
    char *paEnd, 
    unsigned int *puiLoop, 
    char aPortSegment[][MAX_PORTS_RANGES_LEN+1]);

void dp_split_portgroups(
    char *paStorage,
    char aPortSegment[][MAX_PORTS_RANGES_LEN+1],
    char aPortStorage[][MAX_SEGMENT_LEN+1],
    unsigned int uiPvidFlag[MAX_PORT_NUMBER],
    unsigned int *puiPortGroupNum,
    struct datapath *dp);

void dp_split_pvid(
    char *paStorage, 
    unsigned int *uiPvidFlag, 
    unsigned int *uiPvidSegNum, 
    unsigned int *uiPortGroupNum, 
    struct datapath *dp);

void dp_set_vlan_port_pvid(struct datapath *dp, char *paSerialNum);


/* Handles a set description (openflow experimenter) message */
ofl_err dp_handle_set_desc(
    struct datapath *dp, 
    struct ofl_exp_openflow_msg_set_dp_desc *msg,
    const struct sender *sender);

/* Handles a role request message */
ofl_err dp_handle_show_perf(
    struct datapath *dp, 
    struct ofl_exp_openflow_msg_show_perf *msg,
    const struct sender *sender);

ofl_err dp_handle_hw_config(
    struct datapath *dp, 
    struct ofl_exp_openflow_msg_hw_config *msg, 
    const struct sender *sender);

/* Handles a role request message */
ofl_err dp_handle_role_request(
    struct datapath *dp, 
    struct ofl_msg_role_request *msg, 
    const struct sender *sender);

/* Handles an asynchronous configuration request message */
ofl_err dp_handle_async_request(
    struct datapath *dp, 
    struct ofl_msg_async_config *msg,
    const struct sender *sender);

ofl_err dp_handle_map_queue(
    struct datapath *dp, 
    struct ofl_exp_openflow_map_queue *msg,
    const struct sender *sender);

ofl_err dp_handle_mod_qos_group(
    struct datapath *dp, 
    struct ofl_exp_openflow_mod_qos_group *msg,
    const struct sender *sender);

ofl_err dp_handle_set_network(
    struct datapath *dp, 
    struct ofl_exp_openflow_network_conf *msg,
    const struct sender *sender);

int send_openflow_buffer(
    struct datapath *dp, 
    struct ofpbuf *buffer,
    const struct sender *sender);
#endif /* datapath.h */
