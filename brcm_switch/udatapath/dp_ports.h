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

#ifndef DP_PORTS_H
#define DP_PORTS_H 1

#include "list.h"
#include "netdev.h"
#include "dp_exp.h"
#include "oflib/ofl.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl-messages.h"
#include "oflib-exp/ofl-exp-openflow.h"


/****************************************************************************
 * Datapath port related functions.
 ****************************************************************************/
#define MNG_PORT_NUM        52

struct sender;

struct sw_queue {
    struct sw_port *port; /* reference to the parent port */
    unsigned short int class_id;    /* internal mapping from OF queue_id to tc class_id */
    unsigned long long int created;
    struct ofl_queue_stats *stats;
    struct ofl_packet_queue *props;
};

typedef struct of_packet_s {
    unsigned char *data;   /* Pointer to packet data */
    int length;            /* Length in bytes */
    void * os_pkt;       /* OS specific representation */
} of_packet_t;

struct sw_table
{
    char* packet_buffer;
};
typedef struct of_hw_driver of_hw_driver_t;


/* packet in callback function prototype */
typedef int (*of_packet_in_f)(unsigned int port,
                              of_packet_t *packet,
                              int reason,
                              void *cookie);

typedef void (*of_port_change_f)(unsigned int port,
                                 int state,
                                 void *cookie);

/* Hardware capabilities structure */
typedef struct of_hw_driver_caps {
    unsigned int flags;

    int max_flows;
    unsigned int wc_supported;       /* Bitmap of OFPFW_* supported wildcards */
    unsigned int actions_supported;  /* Bitmap of OFPAT_* supported actions */
    unsigned int ofpc_flags;         /* Bitmap of ofp_capabilities flags */
} of_hw_driver_caps_t;


struct of_hw_driver {
    struct sw_table* sw_table;

    of_hw_driver_caps_t* caps; //NULL

    int (*init)(of_hw_driver_t *hw_drv, unsigned int flags);

    int (*table_stats_get)(of_hw_driver_t *hw_drv, struct
                           ofp_table_stats *stats);
    int (*port_stats_get)(of_hw_driver_t *hw_drv, int of_port,
                          struct ofp_port_stats *stats);
    int (*flow_stats_get)(of_hw_driver_t *hw_drv, struct ofp_match,
                          struct ofp_flow_stats **stats, int *count);
    int (*aggregate_stats_get)(struct ofp_match,
                               struct ofp_aggregate_stats_reply *stats);

    int (*port_add)(of_hw_driver_t *hw_drv, int of_port, const char *hw_name);
    int (*port_remove)(of_hw_driver_t *hw_drv, unsigned int port);

    int (*port_link_get)(of_hw_driver_t *hw_drv, int of_port);
    int (*port_enable_set)(of_hw_driver_t *hw_drv, int of_port, int enable);
    int (*port_enable_get)(of_hw_driver_t *hw_drv, int of_port);

    int (*port_queue_config)(of_hw_driver_t *hw_drv, int of_port,
                             unsigned int qid, int min_bw);
    int (*port_queue_remove)(of_hw_driver_t *hw_drv, int of_port,
                             unsigned int qid);

    int (*port_change_register)(of_hw_driver_t *hw_drv,
                                of_port_change_f callback, void *cookie);

    int (*packet_send)(of_hw_driver_t *hw_drv, int of_port, of_packet_t *pkt,
                       unsigned int flags);

    int (*packet_receive_register)(of_hw_driver_t *hw_drv,
                                   of_packet_in_f callback, void *cookie);

    int (*ioctl)(of_hw_driver_t *hw_drv, unsigned int op, void **io_param,
                 int *io_len);

};


#define MAX_HW_NAME_LEN 32
enum sw_port_flags {
    SWP_USED             = 1 << 0,    /* Is port being used */
    SWP_HW_DRV_PORT      = 1 << 1,    /* Port controlled by HW driver */
};
#if defined(OF_HW_PLAT) && !defined(USE_NETDEV)
#define IS_HW_PORT(p) ((p)->flags & SWP_HW_DRV_PORT)
#else
#define IS_HW_PORT(p) 0
#endif

#define PORT_IN_USE(p) (((p) != NULL) && (p)->flags & SWP_USED)

struct sw_port {
    struct list node; /* Element in datapath.ports. */

    unsigned int flags;             /* SWP_* flags above */
    struct datapath *dp;
    struct netdev *netdev;
    struct ofl_port *conf;
    struct ofl_port_stats *stats;
    /* port queues */
    unsigned short int max_queues;
    unsigned short int num_queues;
    unsigned long long int created;
    struct sw_queue queues[NETDEV_MAX_QUEUES];
    unsigned int port_no;           /* ifIndex */
    unsigned int port_pvid;         /* port PVID */
};


#if defined(OF_HW_PLAT)
struct hw_pkt_q_entry {
    struct ofpbuf *buffer;
    struct hw_pkt_q_entry *next;
    unsigned int port_no;
    int reason;
};
#endif

typedef struct port_status_ref
{
    struct list node;
    unsigned int port;
    unsigned int status;
}PORT_STATUS_REF_S;

#define NULL_PORT         (0xFFFFFFFF)
#define NULL_PORT_STATUS   (0xFF)

#define DP_MAX_PORTS 128 /* Must be careful */
BUILD_ASSERT_DECL(DP_MAX_PORTS <= OFPP_MAX);


#if defined(OF_HW_PLAT) && !defined(USE_NETDEV)
int dp_ports_add(int port_index, struct datapath *dp);
#else
dp_ports_add(struct datapath *dp, const char *netdev);
#endif
/* Adds a local port to the datapath. */
int
dp_ports_add_local(struct datapath *dp, const char *netdev);

/* Receives datapath packets, and runs them through the pipeline. */
void
dp_ports_run(struct datapath *dp);

/* Returns the given port. */
struct sw_port *
dp_ports_lookup(struct datapath *, unsigned int);

/* Returns the given queue of the given port. */
struct sw_queue *
dp_ports_lookup_queue(struct sw_port *, unsigned int);

/* Outputs a datapath packet on the port. */
void
dp_ports_output(struct datapath *dp, struct ofpbuf *buffer, unsigned int out_port,
              unsigned int queue_id);

/* Outputs a datapath packet on all ports except for in_port. If flood is set,
 * packet is not sent out on ports with flooding disabled. */
int
dp_ports_output_all(struct datapath *dp, struct ofpbuf *buffer,
                    int in_port, bool flood, unsigned int queue_id);

/* Handles a port mod message. */
ofl_err
dp_ports_handle_port_mod(struct datapath *dp, struct ofl_msg_port_mod *msg,
                                               const struct sender *sender);

/* Handles a port stats request message. */
ofl_err
dp_ports_handle_stats_request_port(struct datapath *dp,
                                  struct ofl_msg_multipart_request_port *msg,
                                  const struct sender *sender);

/* Handles a port desc request message. */
ofl_err
dp_ports_handle_port_desc_request(struct datapath *dp,
                                  struct ofl_msg_multipart_request_header *msg UNUSED,
                                  const struct sender *sender UNUSED);

/* Handles a queue stats request message. */
ofl_err
dp_ports_handle_stats_request_queue(struct datapath *dp,
                                  struct ofl_msg_multipart_request_queue *msg,
                                  const struct sender *sender);

/* Handles a queue get config request message. */
ofl_err
dp_ports_handle_queue_get_config_request(struct datapath *dp,
                              struct ofl_msg_queue_get_config_request *msg,
                                                const struct sender *sender);

/* Handles a queue modify (OpenFlow experimenter) message. */
ofl_err
dp_ports_handle_queue_modify(struct datapath *dp, struct ofl_exp_openflow_msg_queue *msg,
        const struct sender *sender);

/* Handles a queue delete (OpenFlow experimenter) message. */
ofl_err
dp_ports_handle_queue_delete(struct datapath *dp, struct ofl_exp_openflow_msg_queue *msg,
        const struct sender *sender);

int dp_hw_drv_init(struct datapath *dp);
unsigned int port_speed(unsigned int conf);

bool check_port_link_status(struct sw_port *p);
int dp_port_init_queue(struct datapath *dp,int port_no);

//int dp_mng_port_snd(int sw, struct ofpbuf *buffer, unsigned short int dport, unsigned short int vlan);

//void *dp_mng_port_thread(void* arg);
int port_up(int port_no);

int Port_Statisitcs_put(void *recvdata, unsigned int revnum);
void * Port_Statisitcs_get(void);
unsigned int Port_State_Init(struct datapath *dp);
void port_evt_handle(int port, unsigned int linkst);
unsigned int Port_Ifindex_NotifyV8(struct datapath *dp);


#endif /* DP_PORTS_H */
