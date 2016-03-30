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
 * Author: Zoltan Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <config.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pwd.h>

#include "command-line.h"
#include "daemon.h"
#include "dp_capabilities.h"
#include "datapath.h"
#include "fault.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "queue.h"
#include "util.h"
#include "rconn.h"
#include "timeval.h"
#include "vconn.h"
#include "dirs.h"
#include "vconn-ssl.h"
#include "vlog-socket.h"
#include "timer_wheel.h"
#include <pthread.h>
#include <unistd.h>

#include "oflib/oxm-match.h"
#include "common/port.h"
#include "udatapath/netconf_init.h"
#include "udatapath_socket.h"
#include "Hybrid_Framework_Linux.h"
#include "vlog.h"



#define TIMEWHEEL_NUM  10
#define TIMEWHEEL_SOLT 1

#define THIS_MODULE VLM_udatapath


extern int g_Socket_Thread_Alive_Flag;

int udatapath_cmd(int argc, char *argv[], struct datapath *dp);
int openflow_delete_cmd(int argc, char *argv[], struct datapath *dp);
void *udatapath_thread(void *arg);

bool g_use_mac_table = true;

static void parse_options(struct datapath *dp, int argc, char *argv[]);
static void usage(void) NO_RETURN;

#define LOG_MODULE VLM_udatapath
char *port_list = NULL;
char *port_1G_list = NULL;
char *local_port = "tap:";
bool g_net_link = false;
bool g_update_dscp_ttl = false;

#if defined(UDATAPATH_AS_LIB)
#define OFP_FATAL(_er, _str, args...) do {                \
        fprintf(stderr, _str, ## args);                   \
        return -1;                                        \
    } while (0)
#else
#define OFP_FATAL(_er, _str, args...) ofp_fatal(_er, _str, ## args)
#endif

#if !defined(UDATAPATH_AS_LIB)
int
main(int argc, char *argv[])
{
    struct passwd *pwd = NULL;
    struct datapath *dp = NULL;

    set_program_name(argv[0]);

    /* Check current user's privilege */
    pwd = getpwuid(getuid());
    if (strncmp(pwd->pw_name, "root", 4) != 0)
    {
        /* Only root can run ofdatapath */
        printf("%s: error: Permission denied, are you root?\n", program_name);
        return 0;
    }

    /* Parse input options */
    dp = dp_new();
    parse_options(dp, argc, argv);
    if (dp->openflowreset == true)
    {
        openflow_delete_cmd(argc, argv, dp);
    }
    else
    {
        udatapath_cmd(argc, argv, dp);
    }

    Socket_Close();

    return 0;
}
#endif

#if defined(OF_HW_PLAT)
static unsigned long long int
set_ports_ethmode(int top, int bottom)
{
    char *port_ptr;
    int  len, port_id = 0;
    unsigned long long int ports_flag = 0;

    if(!port_1G_list)
        return 0;

    len = strlen(port_1G_list);
    port_ptr = port_1G_list;
    if(len < 2)
    {
        VLOG_ERR(LOG_MODULE, "port_1G_list too short!\n");
        return 0;
    }

    while(port_ptr < (port_1G_list + len - 2))
    {
        if(*port_ptr != 'f')
        {
            port_ptr++;
        }
        else
        {
            port_ptr += 2;
            port_id = atoi(port_ptr);
            if (port_id < bottom || port_id > top || port_id == 0)
                VLOG_ERR(LOG_MODULE, "Error split port no(%d)!\n", port_id);
            else
                ports_flag |= 1 << (port_id - 1);
        }
    }

    return ports_flag;
}



static void add_ports(struct datapath *dp)
{
    int err, speed, port_id;
    unsigned int ifindex = 0xffffffff;

    if (dp->portnumber > MAX_PORT_NO)
    {
        VLOG_ERR(LOG_MODULE, "ERROR!  dp_ports portnumber is over MAX_PORT_NO!\n");
    }

    /* bitmap的0位表示CPU */
    for (port_id = 0; (port_id < MAX_PORT_NO) && (port_id < dp->portnumber); port_id++)
    {
        ///*修改原因:按照实际情况加入端口，而不是2012写死的方法*/
        ///*注意:下面的10M用来表示一个非法值，因为我们的设备上没有10M口*/
        ifindex = dp->ports[port_id].port_no;
        err = dp_ports_add(port_id, dp);
        if(err)
        {
            ofp_fatal(err, "failed to add port %d", port_id);
        }
        dp_port_init_queue(dp, ifindex);
    }
    VLOG_DBG(LOG_MODULE, "dp->ports_num = %d\n", dp->portnumber);
    return;
}
#else

static void
add_ports(struct datapath *dp, char *port_list)
{
    int i;
    char *port, *save_ptr;

    /* Glibc 2.7 has a bug in strtok_r when compiling with optimization that
     * can cause segfaults here:
     * http://sources.redhat.com/bugzilla/show_bug.cgi?id=5614.
     * Using ",," instead of the obvious "," works around it. */
    for (port = strtok_r(port_list, ",,", &save_ptr); port;
         port = strtok_r(NULL, ",,", &save_ptr)) {
        int error = dp_ports_add(dp, port);
        if (error) {
            ofp_fatal(error, "failed to add port %s", port);
        }
    }
}
#endif

unsigned int Port_Ifindex_NotifyV8(struct datapath *dp)
{
    int i = 0;
    unsigned int ret = VOS_OK;
    DPAL_MESSAGE_DATA_S stMSGData = {0};
    DPAL_CONFIG_DATA_S stConfig = {0};
    DPAL_INTERFACE_LIST_S stInterfaceList = {0};

    if (0 == dp->portnumber)
    {
        VLOG_DBG(LOG_MODULE, "notify V8 ifindex return ,portnum is 0.\n");
        return VOS_OK;
    }

    for (i = 0; i < dp->portnumber; i++)
    {
        stInterfaceList.astInterface[i].uiIfindex =
            dp->ports[i].port_no;
        stInterfaceList.uiPortnumber++;
    }

    stConfig.uiConfigType = DPAL_CONFIG_TYPE_PORTIFINDEX;
    stConfig.pData        = (void *)(&stInterfaceList);

    ret = DPAL_TranslatePkt(DPAL_MSG_TYPE_CONFIG, (void *)&stConfig, &stMSGData);
    if (VOS_OK != ret)
    {
        VLOG_ERR(LOG_MODULE,  "Portifindex packet phase failed.\n");
        return VOS_ERR;
    }
    ret = Hybrid_Chatwith_V8_new(&stMSGData);
    if (VOS_OK != ret)
    {
        VLOG_ERR(LOG_MODULE, "notify V8 ifindex return %d.\n", ret);
    }
    free(stMSGData.pData);
    return VOS_OK;
}


int
udatapath_cmd(int argc, char *argv[], struct datapath *dp)
{
    int n_listeners;
    int error;
    int i;
    pthread_t tid_datapath;
    pthread_t tid_timeout;

    unsigned int ret1;
    unsigned int ret = VOS_OK;

    DPAL_MESSAGE_DATA_S stMSGData;
    DPAL_CONFIG_DATA_S stConfig;

    signal(SIGPIPE, SIG_IGN);

    // 移动brcm_active前面，便于参数的传递
    VLOG_DBG(LOG_MODULE, "begin to enter to vlan_init 1 \n");

    // 用户输入用户名，并将用户名存储到dp->username
    printf("%s: Please input the username and password of your switch's netconf\n", program_name);
    printf("to establish a link to your switch's netconf server.\n");
    printf("username: ");    /* console output*/
    scanf("%s",dp->username);
    if (strlen(dp->username) > MAX_USER_NAME_LEN)
    {
        ofp_fatal(0, "argument to -u or --username: "
                      "the length  of username is over MAX_USER_NAME_LEN");
        return -1;
    }

    // 其中有netconf消息发送，必须放在 time_init() 前面
    ret = NETCONF_Init(dp);
    if (ret != VOS_OK)
    {
        printf("initializing netconf... fail\n");    /* console output*/
        VLOG_ERR(LOG_MODULE, "vlan_init error!\n");
        return -1;
    }

    printf("initializing netconf... done\n");    /* console output*/

    printf("initializing port status... ");    /* console output*/

    ret = Port_State_Init(dp);
    if (ret != VOS_OK)
    {
        printf("fail\n");    /* console output*/
        VLOG_ERR(LOG_MODULE, "Port_state_init error!\n");
        return -1;
    }

    printf("done\n");    /* console output*/

    /* run in the background */
    printf("%s: Set program to run in the background as system daemons.\n", program_name);    /* console output*/
    fflush(stdout);
    daemon(1, 0);

    Socket_Initial();

    // 使用新方式
    stConfig.uiConfigType = DPAL_CONFIG_TYPE_VLAN;
    stConfig.pData        = (void *)(dp->vlanBit);
    ret = DPAL_TranslatePkt(DPAL_MSG_TYPE_CONFIG, (void *)&stConfig, &stMSGData);
    if (0 != ret)
    {
        VLOG_ERR(LOG_MODULE, "VLAN packet phase failed.\n");
        return -1;
    }
    ret = Hybrid_Chatwith_V8_new(&stMSGData);
    if (0 != ret)
    {
        VLOG_ERR(LOG_MODULE, "ofdatapath enable failed.\n");
        return -1;
    }

    free(stMSGData.pData);

    ret = Port_Ifindex_NotifyV8(dp);
    if (ret != VOS_OK)
    {
        VLOG_ERR(LOG_MODULE, "Port state notify V8 error! \n");
        return -1;
    }

    VLOG_INFO(LOG_MODULE, "Port state notify V8 OK! \n");

    set_program_name(argv[0]);
    register_fault_handlers();
    time_init();
    vlog_init();
    oxm_match_init();

    /*修改原因:SDK初始化及驱动初始化在大包中已有，仅需保留设置MAC老化时间*/
    signal(SIGPIPE, SIG_IGN);

    if (argc - optind < 1) {
        OFP_FATAL(0, "at least one listener argument is required; "
          "use --help for usage");
    }
    dp_new_table(dp);

    n_listeners = 0;
    for (i = optind; i < argc; i++)
    {
        const char *pvconn_name = argv[i];
        struct pvconn *pvconn;
        int retval;

        retval = pvconn_open(pvconn_name, &pvconn);
        if (!retval || retval == EAGAIN)
        {
            dp_add_pvconn(dp, pvconn);
            n_listeners++;
        }
    }
    if (n_listeners == 0) {
        OFP_FATAL(0, "could not listen for any connections");
    }

    error = vlog_server_listen(NULL, NULL);
    if (error) {
        OFP_FATAL(error, "could not listen for vlog connections");
    }

    die_if_already_running();
    daemonize();

    if (pthread_create(&tid_datapath, NULL, udatapath_thread, (void*)dp))
    {
        VLOG_ERR(LOG_MODULE, "create free failed\n");
        return -1;
    }

    for (;;)
    {
        meter_table_add_tokens(dp->meters);
        sleep(1);
    }

    return 0;
}
int
openflow_delete_cmd(int argc, char *argv[], struct datapath *dp)
{
    int n_listeners;
    int error;
    int i;
    pthread_t tid_datapath;
    pthread_t tid_timeout;
    unsigned int ret1;
    unsigned int ret = VOS_OK;
    DPAL_MESSAGE_DATA_S stMSGData = {0};
    DPAL_CONFIG_DATA_S  stConfig  = {0};

    signal(SIGPIPE, SIG_IGN);

    // 初始化 socket
    // 是否需要判断下，datapath进程是否已经删除，否者会起两个socket，是否会有影响，
    Socket_Initial();

    VLOG_DBG(LOG_MODULE, "start to delete openflow resource\n");

    // 删除openflow 流表
    stConfig.uiConfigType = OPENFLOW_DELETE_ALL_RESOURCE;
    stConfig.pData        = VOS_NULL;
    ret = DPAL_TranslatePkt(DPAL_MSG_TYPE_RESET, (void *)&stConfig, &stMSGData);
    if (0 != ret)
    {
        VLOG_ERR(LOG_MODULE, "Openflow resouce delete msg construct failed.\n");
    }
    ret = Hybrid_Chatwith_V8_new(&stMSGData);

    // 删除openflow vlan
    stConfig.uiConfigType = OPENFLOW_DELETE_GLOBAL_VLAN;
    stConfig.pData        = VOS_NULL;
    ret = DPAL_TranslatePkt(DPAL_MSG_TYPE_RESET, (void *)&stConfig, &stMSGData);
    if (0 != ret)
    {
        VLOG_ERR(LOG_MODULE, "Openflow vlan delete msg construct failed.\n");
    }
    ret = Hybrid_Chatwith_V8_new(&stMSGData);

    free(stMSGData.pData);

    // 用户输入用户名，并将用户名存储到dp->username
    printf("%s: Please input the username and password of your switch's netconf\n", program_name);
    printf("to establish a link to your switch's netconf server.\n");
    printf("username: ");
    scanf("%s",dp->username);
    if (strlen(dp->username) > MAX_USER_NAME_LEN)
    {
        ofp_fatal(0, "argument to -u or --username: "
                      "the length  of username is over MAX_USER_NAME_LEN");
    }
    dp->username[MAX_USER_NAME_LEN] = 0x00;

    // 其中有netconf消息发送，必须放在 time_init() 前面
    ret = NETCONF_Del_Init(dp);
    if (ret != VOS_OK)
    {
        VLOG_ERR(LOG_MODULE, "Delete error!\n");
    }

    g_Socket_Thread_Alive_Flag = 0;

    VLOG_DBG(LOG_MODULE, "openflow delete success!\n");
    set_program_name(argv[0]);
    register_fault_handlers();
    time_init();
    vlog_init();
    oxm_match_init();

    signal(SIGPIPE, SIG_IGN);

    if (argc - optind < 1) {
        OFP_FATAL(0, "at least one listener argument is required; "
          "use --help for usage");
    }
    dp_new_table(dp);

    return 0;
}

void initial_DPAL(struct datapath *dp)
{
    int i = 0;
    DPAL_INTERFACE_LIST_S stInterfaceList = {0};

    for (i = 0; i < dp->portnumber; i++)
    {
        stInterfaceList.astInterface[stInterfaceList.uiPortnumber].uiIfindex =
            dp->ports[i].port_no;
        stInterfaceList.astInterface[stInterfaceList.uiPortnumber].uiPVID =
            dp->ports[i].port_pvid;
        stInterfaceList.uiPortnumber++;
    }

    (void)DPAL_Active(&stInterfaceList);

    return;
}

void* udatapath_thread(void* arg)
{
    time_t last_timeout = time_now_sec();
    bool pass = true;
    time_t now;
    struct datapath *dp = (struct datapath *)arg;

    while(1)
    {
        if (pass)
        {
            now = time_now_sec();
            if ((now -last_timeout > dp->delay_time))
            {
                initial_DPAL(dp);
                add_ports(dp);
                pass = false;
            }
        }
        dp_run(dp);
    }
    pthread_rwlock_destroy(&dp->rw_lock);

    return 0;
}

static void
parse_options(struct datapath *dp, int argc, char *argv[])
{
    enum {
        OPT_MFR_DESC = UCHAR_MAX + 1,
        OPT_HW_DESC,
        OPT_SW_DESC,
        OPT_DP_DESC,
        OPT_SERIAL_NUM,
        OPT_BOOTSTRAP_CA_CERT,
        OPT_NO_LOCAL_PORT,
        OPT_NO_SLICING,
        VLOG_OPTION_ENUMS
    };

    // ./ofdatapath ptcp:6677 -d 000000000030 中，后面跟的参数，如 -d
    // 包括大参数和小参数，如"interfaces"是大参数，用法为 --interfaces，和小参数， 如 -i
    static struct option long_options[] =
    {

        {"datapath-id",       required_argument, 0, 'd'},
        {"help",              no_argument,       0, 'h'},
        {"version",           no_argument,       0, 'V'},
        {"run-mode",          no_argument,       0, 'm'},
        {"ip",                required_argument, 0, 'I'},
        {"conffile",          required_argument, 0, 'f'},  
                                                            /* 添加参数f，表示存储vlan和对应端口的配置文件 */
        {"reset",             no_argument,       0, 'r'},   
                                                            /* 添加参数r，表示是否删除配置 */
        {"verbose",           required_argument, 0, 'v'},
        {"log-file",          required_argument, 0, 'a'},   
        {0, 0, 0, 0},
    };

    char     aParaArry[MAX_PARA_NUM] = {0};
    unsigned int uiParaNum               = 0;
    unsigned int uiLoop                  = 0;
    unsigned int uiCount                 = 0;

    // 解析长参数为短参数
    char *short_options = long_options_to_short_options(long_options);
    int count = 1;

    for (;;)
    {
        int indexptr;
        int c;

        // 第三个参数为0，此函数得到的还是短参数。
        c = getopt_long(argc, argv, short_options, long_options, &indexptr);
        if ((-1 == c) && (1 == count))
        {
            ofp_fatal(0, "need one or more arguments; "
                          "use --help for usage");
        }
        else if ((-1 == c) && (1 != count))
        {
            break;
        }
        count++;
        // 将解析到的参数存放至数组中
        aParaArry[uiParaNum++] = c;

        switch (c) {
        case 'd': {
            unsigned long long int dpid;
            if (strlen(optarg) != 12
                || strspn(optarg, "0123456789abcdefABCDEF") != 12) {
                ofp_fatal(0, "argument to -d or --datapath-id must be "
                          "exactly 12 hex digits");
            }
            dpid = strtoll(optarg, NULL, 16);
            if (!dpid) {
                ofp_fatal(0, "argument to -d or --datapath-id must "
                          "be nonzero");
            }
            dp_set_dpid(dp, dpid);
            break;
        }
        case 'h':
            usage();    // 此函数解释了各个参数的作用

        case 'V':
            printf("%s %s compiled "__DATE__" "__TIME__"\n",
                   program_name, VERSION BUILDNR);
            exit(EXIT_SUCCESS);
        case 'm':
            dp->soft_switch = true;
            break;
        case 'I': {
            dp_is_ip_valid(dp, optarg);
            break;
        }
        case 'f':       
        {
            dp_set_vlan_port_pvid(dp, optarg);
            break;
        }               
        case 'r':      
        {
            dp->openflowreset = true;
            break;
        }               
        case 'v':
        {
            vlog_set_verbosity(optarg);
            break;
        }
        case 'a':
        {
            vlog_set_log_file(optarg);
            break;
        }
        default:
            exit(EXIT_FAILURE);
        }
    }

    // 判断-d,-I,-f参数是否存在
    while (uiLoop < uiParaNum)
    {
        if ('d' == aParaArry[uiLoop] || 'I' == aParaArry[uiLoop] || 'f' == aParaArry[uiLoop])
        {
            uiCount++;
        }
        uiLoop++;
    }
    if (!(MAX_OF_NEED_PARA_NUM == uiCount || 0 == uiCount))
    {
        ofp_fatal(0, "[ERROR]The number of paramaters is less than 3, -d -I -f must be present");
    }

    free(short_options);
}


static void
usage(void)
{
    printf("%s: OpenFlow datapath\n"
           "usage: %s [OPTIONS] LISTEN...\n"
           "where LISTEN is a passive OpenFlow connection method on which\n"
           "to listen for incoming connections from the secure channel.\n",
           program_name, program_name);
    vconn_usage(false, true, false);
    printf("\nConfiguration options:\n"

           "  -d, --datapath-id=ID    Use ID as the OpenFlow switch ID\n"
           "                          (ID must consist of 12 hex digits)\n"
           "  -h, --help              display this help message\n"
           "  -I, --ip                ip for netconf\n"
           "  -f, --conffile          configure file contains vlan and port message\n"
           "  -r, --reset             reset configurations\n"
           "  -v, --verbose=MODULE[:FACILITY[:LEVEL]]  set logging levels\n"
           "  -a, --file[=FILE]       enable logging to specified FILE\n"
           );

    exit(EXIT_SUCCESS);
}

