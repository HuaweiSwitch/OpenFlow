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

#include <config.h>
#include "secchan.h"
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <pwd.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>


#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "dirs.h"
#include "discovery.h"
#include "failover.h"
#include "fault.h"
#include "in-band.h"
#include "leak-checker.h"
#include "list.h"
#include "ofp.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "port-watcher.h"
#include "poll-loop.h"
#include "ratelimit.h"
#include "rconn.h"
#include "stp-secchan.h"
#include "status.h"
#include "timeval.h"
#include "util.h"
#include "vconn-ssl.h"
#include "vconn.h"
#include "vlog-socket.h"
#include "vlog.h"

#ifndef HAVE_OPENSSL
#define HAVE_OPENSSL 1
#endif
#define LOG_MODULE VLM_secchan
#define FIFO_NAME_M "/home/pipe_file_m"
#define FIFO_NAME_S "/home/pipe_file_s"
int pipe_fd_m = 0;
int pipe_fd_s = 0;
char ofprotocol_s[1] = {0};
char ofprotocol_new[1] = {0};

struct hook {
    const struct hook_class *class;
    void *aux;
};

struct secchan {
    struct hook *hooks;
    size_t n_hooks, allocated_hooks;
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

static void parse_options(int argc, char *argv[], struct settings *);
static void usage(void) NO_RETURN;
//void read_ctrl_param(struct settings *s);

static char *vconn_name_without_subscription(const char *);

#if 0
static struct pvconn *open_passive_vconn(const char *name);
static struct vconn *accept_vconn(struct pvconn *pvconn);
static void relay_wait(struct remote_half * premote, struct local_half * plocal);
#endif

static void relay_run(struct remote_half * premote, struct local_half * plocal);


#define XID_CHAIN_SIZE 10
#define XID_NONE 0xffffffff
#define XID_BITS   24


struct xid_node
{
    struct list node;
    unsigned int xid;
    unsigned int inter_xid;
};

struct list xid_chain  = LIST_INITIALIZER(&xid_chain);

static void xid_chain_init(void)
{
    //xid_chain = LIST_INITIALIZER(&xid_chain);
}

static unsigned int get_magic_xid(void)
{
    static unsigned int xid_magic_num = 0;

    xid_magic_num = (xid_magic_num + 1) % 0x00ffffff;
    if( xid_magic_num == 0)
    {
        xid_magic_num = 1;
    }

    return xid_magic_num;
}

static unsigned int push_xid_node(unsigned int conn_id, unsigned int xid)
{
    struct xid_node *node = xmalloc(sizeof *node);

    node->xid = xid;
    node->inter_xid = (conn_id << XID_BITS)+ get_magic_xid();
    list_push_back(&xid_chain, &node->node);

    if ( list_size(&xid_chain) >= XID_CHAIN_SIZE)
    {
        list_pop_front(&xid_chain);
    }

    return (node->inter_xid);
}

static unsigned int pop_xid_node(unsigned int inter_xid, bool del)
{
    struct xid_node *x, *n;
    unsigned int xid = XID_NONE;

    //for debug;
    if (VLOG_IS_DBG_ENABLED(LOG_MODULE))
    {
        VLOG_DBG(LOG_MODULE, "finding inter_xid: %08x, \r\n",inter_xid);
        LIST_FOR_EACH_SAFE (x, n, struct xid_node, node, &xid_chain)
        {
            VLOG_DBG(LOG_MODULE, "node  xid: %08x, inter_xid: %08x \r\n", x->xid, x->inter_xid);
        }
    }

    /* Do work. */
    LIST_FOR_EACH_SAFE (x, n, struct xid_node, node, &xid_chain)
    {
        if( x->inter_xid == inter_xid)
        {
            xid = x->xid;
            if( true == del)
            {
                list_remove(&x->node);
            }

            break;
        }
    }

    return xid;
}


int main(int argc, char *argv[])
{
    struct settings s;
    struct secchan secchan;

    struct remote_half r_half;
    struct local_half l_half;

    int i;
    int retval;
    int Ret = 0;
    /* 判断用户是否为root用户，如果不是，打印信息并返回*/
    struct passwd *pwd;
    pwd = getpwuid(getuid ());
    if (0 != strcmp(pwd->pw_name, "root"))
    {
        printf("Do not have enable proxy, because current user is not root user. Current User: %s\n", pwd->pw_name);
        return 0;
    }

    set_program_name(argv[0]);
    register_fault_handlers();
    time_init();
    vlog_init();
    //read_ctrl_param(&s);

    parse_options(argc, argv, &s);
    signal(SIGPIPE, SIG_IGN);

    secchan.hooks = NULL;
    secchan.n_hooks = 0;
    secchan.allocated_hooks = 0;

    /* Initialize switch status hook. */
    //switch_status_start(&secchan, &s, &switch_status);

    die_if_already_running();
    daemonize();

    //printf("%s: Set program to run in the background as system daemons.\n", program_name);    /* console output*/
    //fflush(stdout);
    //daemon(1, 0);

    VLOG_INFO(LOG_MODULE, "OpenFlow reference implementation version %s ", VERSION BUILDNR);
    VLOG_INFO(LOG_MODULE, "OpenFlow protocol version 0x%02x", OFP_VERSION);
    VLOG_INFO(LOG_MODULE, "Build time: %s %s", __DATE__, __TIME__);

    /* Check datapath name, to try to catch command-line invocation errors. */
    if (strncmp(s.dp_name, "nl:", 3) && strncmp(s.dp_name, "unix:", 5)
        && !s.controller_names[0]) {
        VLOG_WARN(LOG_MODULE, "Controller not specified and datapath is not nl: or "
                  "unix:.  (Did you forget to specify the datapath?)");
    }

    /* Connect to datapath without a subscription, for requests and replies. */
    l_half.n_txq = 0;
    l_half.rxbuf = NULL;
    l_half.name = vconn_name_without_subscription(s.dp_name);
    l_half.rconn = rconn_create(0, s.max_backoff);
    rconn_connect(l_half.rconn, l_half.name);
    free(l_half.name);
    //switch_status_register_category(switch_status, "local",
    //                                      rconn_status_cb, l_half.rconn);

    // set remote connection
    r_half.name[MAIN_REMOTE_ID] = vconn_name_without_subscription( s.controller_names[0]);

    /* main Connect to controller. */
    r_half.rconn[MAIN_REMOTE_ID]  = rconn_create(s.probe_interval, s.max_backoff);

    //r_half.rconn[MAIN_REMOTE_ID]  = rconn_create(0, s.max_backoff);
    if (r_half.name[MAIN_REMOTE_ID])
    {
        retval = rconn_connect(r_half.rconn[MAIN_REMOTE_ID], r_half.name[MAIN_REMOTE_ID]);
        if (retval == EAFNOSUPPORT)
        {
            ofp_fatal(0, "No support for %s vconn", r_half.name[MAIN_REMOTE_ID]);
        }

        r_half.rxbuf[MAIN_REMOTE_ID] = NULL;
        r_half.n_txq[MAIN_REMOTE_ID] = 0;
    }

    //switch_status_register_category(switch_status, "main_remote",
    //                                      rconn_status_cb, r_half.rconn[MAIN_REMOTE_ID]);
    // aux connection to controller
    r_half.conn_num = s.num_controllers > AUX_REMOTE_ID_BASE ?
                                            s.num_controllers : AUX_REMOTE_ID_BASE;

    for ( i = AUX_REMOTE_ID_BASE; i < r_half.conn_num; i++)
    {
        r_half.name[i] = s.controller_names[i];
        r_half.rconn[i] = rconn_create(s.probe_interval, s.max_backoff);
        r_half.rxbuf[i] = NULL;
        r_half.n_txq[i] = 0;
    }

    /* Set up hooks. */
    /* Start relaying. */
    xid_chain_init();

    if(access(FIFO_NAME_M,F_OK)==-1)            //文件是否存在
    {
        Ret = mkfifo(FIFO_NAME_M,0777);
        if(Ret != 0)
        {
            VLOG_DBG(LOG_MODULE, "Could not creat fifo %s,err is %s\n", FIFO_NAME_M, strerror(errno));
        }
        VLOG_DBG(LOG_MODULE, "Success to creat fifo %s\n",FIFO_NAME_M);
    }
    if(access(FIFO_NAME_S,F_OK)==-1)            //文件是否存在
    {
        Ret = mkfifo(FIFO_NAME_S,0777);
        if(Ret != 0)
        {
            VLOG_DBG(LOG_MODULE, "Could not creat fifo %s,err is %s\n", FIFO_NAME_S, strerror(errno));
        }
        VLOG_DBG(LOG_MODULE, "Success to creat fifo %s\n",FIFO_NAME_S);
    }

    VLOG_DBG(LOG_MODULE, "Process %d ready to open pipe file!\n",getpid());
    pipe_fd_m = open(FIFO_NAME_M,O_RDWR | O_NONBLOCK);
    if(pipe_fd_s != -1)
    {
        VLOG_DBG(LOG_MODULE, "The master file`s descriptor is %d\n",pipe_fd_m);
    }
    else
    {
        VLOG_DBG(LOG_MODULE, "Fail to open master file :%s\n",strerror(errno));
    }

    pipe_fd_s = open(FIFO_NAME_S,O_RDWR | O_NONBLOCK);
    if(pipe_fd_s != -1)
    {
        VLOG_DBG(LOG_MODULE, "The slave file`s descriptor is %d\n",pipe_fd_s);
    }
    else
    {
        VLOG_DBG(LOG_MODULE, "Fail to open slave file :%s\n",strerror(errno));
    }

    while( rconn_is_alive(r_half.rconn[MAIN_REMOTE_ID]) )
    {
        relay_run(&r_half, &l_half);
    }
    (void)close(pipe_fd_m);                //切记关闭文件描述符
    (void)close(pipe_fd_s);                //切记关闭文件描述符
    return 0;
}

void
add_hook(struct secchan *secchan, const struct hook_class *class, void *aux)
{
    struct hook *hook;

    if (secchan->n_hooks >= secchan->allocated_hooks) {
        secchan->hooks = x2nrealloc(secchan->hooks, &secchan->allocated_hooks,
                                    sizeof *secchan->hooks);
    }
    hook = &secchan->hooks[secchan->n_hooks++];
    hook->class = class;
    hook->aux = aux;
}

struct ofp_packet_in *
get_ofp_packet_in(struct relay *r)
{
    struct ofpbuf *msg = r->halves[HALF_LOCAL].rxbuf;
    struct ofp_header *oh = msg->data;
    if (oh->type == OFPT_PACKET_IN) {
         return msg->data;
    }
    return NULL;
}

/* Need to adapt 1.2 packet-in changes */
bool
get_ofp_packet_eth_header(struct relay *r, struct ofp_packet_in **opip,
                          struct eth_header **ethp)
{
    const int min_len = 0; //offsetof(struct ofp_packet_in, data) + ETH_HEADER_LEN;
    struct ofp_packet_in *opi = get_ofp_packet_in(r);
    if (opi && ntohs(opi->header.length) >= min_len) {
        *opip = opi;
        //*ethp = (void *) opi->data;
        *ethp = *ethp ;

        return true;
    }
    return false;
}

/* OpenFlow message relaying. */

/* Returns a malloc'd string containing a copy of 'vconn_name' modified not to
 * subscribe to asynchronous messages such as 'ofp_packet_in' events (if
 * possible). */
static char *
vconn_name_without_subscription(const char *vconn_name)
{
    int nl_index;
    if (sscanf(vconn_name, "nl:%d", &nl_index) == 1) {
        /* nl:123 or nl:123:1 opens a netlink connection to local datapath 123.
         * nl:123:0 opens a netlink connection to local datapath 123 without
         * obtaining a subscription for ofp_packet_in or ofp_flow_removed
         * messages. */
        return xasprintf("nl:%d:0", nl_index);
    } else {
        /* We don't have a way to specify not to subscribe to those messages
         * for other transports.  (That's a defect: really this should be in
         * the OpenFlow protocol, not the Netlink transport). */
        VLOG_WARN_RL(LOG_MODULE, &rl, "new management connection will receive "
                     "asynchronous messages");
        return xstrdup(vconn_name);
    }
}

static unsigned int select_hash(struct remote_half * premote, struct ofpbuf *rxbuf)
{
    struct ofp_packet_in *pi;
    unsigned int hash;
    unsigned int chanle;
    unsigned int aux_num;

    if( premote->conn_num <= 1)
        return 0;

    pi = (struct ofp_packet_in *) (rxbuf->data);
    if ( rxbuf->size != ntohs(pi->header.length) )
        return 0;

    hash = hash_bytes(pi->match.oxm_fields, ntohs(pi->match.length) - 4, 0);

    aux_num = premote->conn_num -1;
    chanle = hash % aux_num;
    return (chanle + AUX_REMOTE_ID_BASE);

}

static unsigned int select_aux(struct remote_half * premote, struct ofpbuf *rxbuf)
{
    unsigned int chanel;

    chanel = select_hash(premote, rxbuf);

    return chanel;
}


unsigned int g_lastreceived_xid = 0;

static void relay_run(struct remote_half * premote, struct local_half * plocal)
{
    int iteration;
    int i, retval;
//      char * name;

    // run rconn;
    rconn_run(plocal->rconn);
    rconn_run(premote->rconn[MAIN_REMOTE_ID]);
    if( rconn_is_connected (premote->rconn[MAIN_REMOTE_ID] ))
    {
        for( i = AUX_REMOTE_ID_BASE; i < premote->conn_num; i++)
        {
            if( !rconn_is_alive (premote->rconn[i]) ) // disconnected
            {
                retval = rconn_connect(premote->rconn[i], premote->name[i]);

                if (VLOG_IS_DBG_ENABLED(LOG_MODULE))
                {
                    VLOG_DBG(LOG_MODULE, "Aux connecting  %d name:%s", i, premote->name[i]);
                }

                if (retval == EAFNOSUPPORT)
                {
                     VLOG_ERR(LOG_MODULE, "No support for %s (auxiliary) vconn", premote->name[i]);
                }
            }
            else
            {
                rconn_run(premote->rconn[i]);
            }
        }
    }
    else
    {
        for (i = AUX_REMOTE_ID_BASE; i < premote->conn_num; i++)
        {
            if (VLOG_IS_DBG_ENABLED(LOG_MODULE))
            {
                VLOG_DBG(LOG_MODULE, "Aux disconnect  %d ", i);
            }
            rconn_disconnect(premote->rconn[i]);
            premote->n_txq[i] = 0;
            premote->rxbuf[i] = NULL;
        }
    }
    if( !rconn_is_connected (premote->rconn[MAIN_REMOTE_ID]) || !rconn_is_connected (plocal->rconn)) // disconnected
    {
        if(pipe_fd_s != -1)
        {
            if(-1 == read(pipe_fd_s,(void*)ofprotocol_s,sizeof(ofprotocol_s)))
            {
                VLOG_DBG(LOG_MODULE, "Disconnectted! Fail to read slave file %d:%s\n", pipe_fd_s, strerror(errno));
            }
        }
        else
        {
            VLOG_DBG(LOG_MODULE, "Disconnectted! Fail to read slave file ,the file is not open!\n");
        }
        ofprotocol_new[0] = PROTOCOL_DISCONNECT;
        if((PROTOCOL_MAX == ofprotocol_s[0]) || (ofprotocol_s[0] != ofprotocol_new[0]))
        {
            ofprotocol_s[0] = ofprotocol_new[0];
            (void)write(pipe_fd_m,(void*)ofprotocol_new,sizeof(ofprotocol_new));
        }
    }
    else
    {
        if(pipe_fd_s != -1)
        {
            if(-1 == read(pipe_fd_s,(void*)ofprotocol_s,sizeof(ofprotocol_s)))
            {
                VLOG_DBG(LOG_MODULE, "Fail to read slave file %d:%s\n", pipe_fd_s, strerror(errno));
            }
        }
        else
        {
            VLOG_DBG(LOG_MODULE, "Fail to read slave file ,the file is not open!\n");
        }
        ofprotocol_new[0] = PROTOCOL_CONNECTTED;
        if((PROTOCOL_MAX == ofprotocol_s[0]) || (ofprotocol_s[0] != ofprotocol_new[0]))
        {
            ofprotocol_s[0] = ofprotocol_new[0];
            (void)write(pipe_fd_m,(void*)ofprotocol_new,sizeof(ofprotocol_new));
        }
    }

    // processing data;
    for (iteration = 0; iteration < 1; iteration++)
    {
        bool progress = false;
        unsigned int conn_id = 0;

        // recive data from local;
        if (!plocal->rxbuf)
        {
            plocal->rxbuf = rconn_recv(plocal->rconn);
        }

        if (plocal->rxbuf)
        {
            struct ofp_header *h = (struct ofp_header *) (plocal->rxbuf->data);
            //check date length;
            switch(h->type)
            {
                case OFPT_PACKET_IN:
                {
                    conn_id = select_aux(premote, plocal->rxbuf );
                    //VLOG_DBG(LOG_MODULE, "Packetin with conn_id %d", conn_id);
                    break;
                }
                case OFPT_MULTIPART_REPLY:
                {
                    struct ofp_multipart_reply *mpr =  (struct ofp_multipart_reply *) (plocal->rxbuf->data);

                    conn_id = (h->xid >> 24) & 0x000000ff;
                    if ( ntohs(mpr->flags) & OFPMPF_REPLY_MORE)
                        h->xid = pop_xid_node(h->xid,false);
                    else
                        h->xid = pop_xid_node(h->xid,true);

                    break;
                }
                case OFPT_FEATURES_REPLY:
                case OFPT_ECHO_REPLY:
                case OFPT_GET_CONFIG_REPLY:
                case OFPT_BARRIER_REPLY:
                case OFPT_QUEUE_GET_CONFIG_REPLY:
                case OFPT_ROLE_REPLY:
                case OFPT_GET_ASYNC_REPLY:
                {
                    conn_id = (h->xid >> 24) & 0x000000ff;
                    h->xid = pop_xid_node(h->xid,true);
                    break;
                }
                case OFPT_ERROR:
                {
                    conn_id = (h->xid >> 24) & 0x000000ff;
                    h->xid = pop_xid_node(h->xid,true);

                    h->xid = g_lastreceived_xid;

                    {
                        char * print = (char *)h;

                        print[16] = print[4];
                        print[17] = print[5];
                        print[18] = print[6];
                        print[19] = print[7];
                    }
                    break;
                }
                default:
                    break;
            }

            conn_id = conn_id < premote->conn_num ? conn_id : 0;
            //VLOG_DBG(LOG_MODULE, "Send to controller with conn id %d", conn_id);

            if( premote->n_txq[conn_id] < 10000)
            {
                retval =  rconn_send(premote->rconn[conn_id], plocal->rxbuf, &(premote->n_txq[conn_id]));
            }
            else
            {
                retval = ENOTCONN;
                VLOG_DBG(LOG_MODULE, "Send queue %d number: %d", conn_id, premote->n_txq[conn_id]);
            }

            if( retval == ENOTCONN)
            {
                ofpbuf_delete(plocal->rxbuf);
            }
            plocal->rxbuf = NULL;
        }

        // receive from remote;
        for( i = 0; i< premote->conn_num; i++)
        {
            if (!premote->rxbuf[i] )
            {
                premote->rxbuf[i] = rconn_recv(premote->rconn[i] );
            }

            if (premote->rxbuf[i] )
            {
                struct ofp_header *h = (struct ofp_header *) (premote->rxbuf[i]->data);
                g_lastreceived_xid = h->xid;

                        h->xid = push_xid_node(i, h->xid);

                if (VLOG_IS_DBG_ENABLED(LOG_MODULE))
                {
                    VLOG_DBG(LOG_MODULE, "****************Remote msg from conn %d",i);
                }

                retval = rconn_send(plocal->rconn, premote->rxbuf[i], NULL);

                if( retval == ENOTCONN)
                {
                    ofpbuf_delete(premote->rxbuf[i]);
                }
                premote->rxbuf[i] = NULL;
            }
        }

        if(progress == false)
        break;
    }
}

/* User interface. */

static void
parse_options(int argc, char *argv[], struct settings *s)
{
    enum {
        OPT_ACCEPT_VCONN = UCHAR_MAX + 1,
        OPT_NO_RESOLV_CONF,
        OPT_INACTIVITY_PROBE,
        OPT_MAX_IDLE,
        OPT_MAX_BACKOFF,
        OPT_RATE_LIMIT,
        OPT_BURST_LIMIT,
        OPT_BOOTSTRAP_CA_CERT,
        OPT_STP,
        OPT_NO_STP,
        OPT_OUT_OF_BAND,
        OPT_IN_BAND,
        VLOG_OPTION_ENUMS,
        LEAK_CHECKER_OPTION_ENUMS
    };
    static struct option long_options[] = {
        /*{"accept-vconn", required_argument, 0, OPT_ACCEPT_VCONN},
        {"no-resolv-conf", no_argument, 0, OPT_NO_RESOLV_CONF},
        {"fail",        required_argument, 0, 'F'},
        {"inactivity-probe", required_argument, 0, OPT_INACTIVITY_PROBE},
        {"max-idle",    required_argument, 0, OPT_MAX_IDLE},
        {"max-backoff", required_argument, 0, OPT_MAX_BACKOFF},
        {"listen",      required_argument, 0, 'l'},
        {"monitor",     required_argument, 0, 'm'},
        {"rate-limit",  optional_argument, 0, OPT_RATE_LIMIT},
        {"burst-limit", required_argument, 0, OPT_BURST_LIMIT},
        {"stp",         no_argument, 0, OPT_STP},
        {"no-stp",      no_argument, 0, OPT_NO_STP},
        {"out-of-band", no_argument, 0, OPT_OUT_OF_BAND},
        {"in-band",     no_argument, 0, OPT_IN_BAND},
        {"verbose",     optional_argument, 0, 'v'},*/
        {"help",        no_argument, 0, 'h'},
        {"version",     no_argument, 0, 'V'},
        /*DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        LEAK_CHECKER_LONG_OPTIONS,*/
#ifdef HAVE_OPENSSL
        VCONN_SSL_LONG_OPTIONS
        {"bootstrap-ca-cert", required_argument, 0, OPT_BOOTSTRAP_CA_CERT},
#endif
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);
    char *accept_re = NULL;
    int retval;

    /* Set defaults that we can figure out before parsing options. */
    s->n_listeners = 0;
    s->monitor_name = NULL;
    s->max_idle = 15;
    s->probe_interval = 15;
    s->max_backoff = 4;
    s->update_resolv_conf = true;
    s->rate_limit = 0;
    s->burst_limit = 0;
    s->enable_stp = false;
    s->in_band = false;
    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        /*case OPT_ACCEPT_VCONN:
            accept_re = optarg[0] == '^' ? optarg : xasprintf("^%s", optarg);
            break;

        case OPT_NO_RESOLV_CONF:
            s->update_resolv_conf = false;
            break;

        case OPT_INACTIVITY_PROBE:
            s->probe_interval = atoi(optarg);
            if (s->probe_interval < 1) {
                ofp_fatal(0, "--inactivity-probe argument must be at least 1");
            }
            break;

        case OPT_MAX_IDLE:
            if (!strcmp(optarg, "permanent")) {
                s->max_idle = OFP_FLOW_PERMANENT;
            } else {
                s->max_idle = atoi(optarg);
                if (s->max_idle < 1 || s->max_idle > 65535) {
                    ofp_fatal(0, "--max-idle argument must be between 1 and "
                              "65535 or the word 'permanent'");
                }
            }
            break;

        case OPT_MAX_BACKOFF:
            s->max_backoff = atoi(optarg);
            if (s->max_backoff < 1) {
                ofp_fatal(0, "--max-backoff argument must be at least 1");
            } else if (s->max_backoff > 3600) {
                s->max_backoff = 3600;
            }
            break;*/
/*
        case OPT_RATE_LIMIT:
           if (optarg) {
               s->rate_limit = atoi(optarg);
               if (s->rate_limit < 1) {
                   ofp_fatal(0, "--rate-limit argument must be at least 1");
               }
           } else {
               s->rate_limit = 1000;
           }
           break;

       case OPT_BURST_LIMIT:
           s->burst_limit = atoi(optarg);
           if (s->burst_limit < 1) {
               ofp_fatal(0, "--burst-limit argument must be at least 1");
           }
           break;

       case OPT_STP:
           s->enable_stp = true;
           break;

       case OPT_NO_STP:
           s->enable_stp = false;
           break;

       case OPT_OUT_OF_BAND:
           s->in_band = false;
           break;

       case OPT_IN_BAND:
           s->in_band = true;
           break;

        case 'l':
            if (s->n_listeners >= MAX_MGMT) {
                ofp_fatal(0,
                          "-l or --listen may be specified at most %d times",
                          MAX_MGMT);
            }
            s->listener_names[s->n_listeners++] = optarg;
            break;

        case 'm':
            if (s->monitor_name) {
                ofp_fatal(0, "-m or --monitor may only be specified once");
            }
            s->monitor_name = optarg;
            break;*/

        case 'h':
            usage();

        case 'V':
            printf("%s %s compiled "__DATE__" "__TIME__"\n",
                   program_name, VERSION BUILDNR);
            exit(EXIT_SUCCESS);

        /*DAEMON_OPTION_HANDLERS

        VLOG_OPTION_HANDLERS

        LEAK_CHECKER_OPTION_HANDLERS*/

#ifdef HAVE_OPENSSL
        VCONN_SSL_OPTION_HANDLERS

        case OPT_BOOTSTRAP_CA_CERT:
            vconn_ssl_set_ca_cert_file(optarg, true);
            break;
#endif

        /*case '?':
            exit(EXIT_FAILURE);*/

        default:
            exit(EXIT_FAILURE);
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;
    //if (argc < 1 || argc > 2)
    if (argc < 1)
    {
        ofp_fatal(0, "need one or two non-option arguments; "
                  "use --help for usage");
    }

    /* Local and remote vconns. */
    s->dp_name = argv[0];
    {
        char *curr;
        char *save;
        int i;

       if (argv[1] != NULL) {
            s->num_controllers = 0;
            for (i = 0; i < MAX_CONTROLLERS; ++i)
                s->controller_names[i] = NULL;
            if (argc > 1) {
                for (curr = strtok_r(argv[1], ",,", &save), i = 0;  curr && i < MAX_CONTROLLERS;
                     curr = strtok_r(NULL, ",,", &save), ++i)
                {
                    s->controller_names[i] = xstrdup(curr);
                    ++s->num_controllers;
                }
            }
       }
    }

    /* Set accept_controller_regex. */
    if (!accept_re) {
        accept_re = vconn_ssl_is_configured() ? "^ssl:.*" : ".*";
    }
    retval = regcomp(&s->accept_controller_regex, accept_re,
                     REG_NOSUB | REG_EXTENDED);
    if (retval) {
        size_t length = regerror(retval, &s->accept_controller_regex, NULL, 0);
        char *buffer = xmalloc(length);
        regerror(retval, &s->accept_controller_regex, buffer, length);
        ofp_fatal(0, "%s: %s", accept_re, buffer);
    }
    s->accept_controller_re = accept_re;

    /* Mode of operation. */
    s->discovery = s->controller_names[0] == NULL;
    if (s->discovery && !s->in_band) {
        ofp_fatal(0, "Cannot perform discovery with out-of-band control");
    }

    /* Rate limiting. */
    if (s->rate_limit) {
        if (s->rate_limit < 100) {
            VLOG_WARN(LOG_MODULE, "Rate limit set to unusually low value %d",
                      s->rate_limit);
        }
        if (!s->burst_limit) {
            s->burst_limit = s->rate_limit / 4;
        }
        s->burst_limit = MAX(s->burst_limit, 1);
        s->burst_limit = MIN(s->burst_limit, INT_MAX / 1000);
    }
}

#define CTR_PARAM "ctrl_param"
#define KEY_VAL    "="

static void
usage(void)
{
    printf("%s: secure channel, a relay for OpenFlow messages.\n"
           "usage: %s [OPTIONS] DATAPATH [CONTROLLER]\n"
           "DATAPATH is an active connection method to a local datapath.\n"
           "CONTROLLER is an active OpenFlow connection method; if it is\n"
           "omitted, then secchan performs controller discovery.\n",
           program_name, program_name);
    vconn_usage(true, true, true);
    /*printf("\nController discovery options:\n"
           "  --accept-vconn=REGEX    accept matching discovered controllers\n"
           "  --no-resolv-conf        do not update /etc/resolv.conf\n"
           "\nNetworking options:\n"
           "  --inactivity-probe=SECS time between inactivity probes\n"
           "  --max-idle=SECS         max idle for flows set up by secchan\n"
           "  --max-backoff=SECS      max time between controller connection\n"
           "                          attempts (default: 15 seconds)\n"
           "  -l, --listen=METHOD     allow management connections on METHOD\n"
           "                          (a passive OpenFlow connection method)\n"
           "  -m, --monitor=METHOD    copy traffic to/from kernel to METHOD\n"
           "                          (a passive OpenFlow connection method)\n"
           "  --out-of-band           controller connection is out-of-band\n"
           "  --stp                   enable 802.1D Spanning Tree Protocol\n"
           "  --no-stp                disable 802.1D Spanning Tree Protocol\n"
           "\nRate-limiting of \"packet-in\" messages to the controller:\n"
           "  --rate-limit[=PACKETS]  max rate, in packets/s (default: 1000)\n"
           "  --burst-limit=BURST     limit on packet credit for idle time\n");
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"*/
    printf("\nConfiguration options:\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    /*leak_checker_usage();*/
    exit(EXIT_SUCCESS);
}

