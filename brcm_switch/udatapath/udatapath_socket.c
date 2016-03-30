#include <config.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "vlog.h"
#include "Hybrid_Framework_Common.h"
#include "udatapath_socket.h"

#define LOG_MODULE VLM_socket

/* V8-datapath的socket fd */
int g_uiListenfd = -1;

char g_RcvBuf[MAX_SOCKET_MSG_SIZE];     /* OPENFLOW报文接收缓冲区*/

int g_SockFd = 0;   //linux与FEI通信申请的SockFd，是个全局变量，初始化时申请一次，如果断链重新建链需要更新
int g_RevData_Len=0;  //接收到数据报文的长度，最大值为65495
int g_Socket_Thread_Alive_Flag = 1;       //socket 起的线程退出标志

extern HYBRID_INFOCHANGE_BUFFER_S g_ua_info_buf[HYBRID_INFOCHANGE_BUFFER_LENGTH];

int udatapath_GetLocalMac(char *pucMac)
{
    int iIfreqFd = 0;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(ifr));

    /* 循环判断，等待vethof端口创建 */
    if ((iIfreqFd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        VLOG_ERR(LOG_MODULE, "fail to open socket.");
        return -1;
     }

    (void)strncpy(ifr.ifr_name, "eth0", strlen("eth0")+1);
    if ((ioctl(iIfreqFd, SIOCGIFHWADDR, &ifr) < 0))
    {
        VLOG_ERR(LOG_MODULE, "fail to read vethof: %s\n", strerror(errno));
        (void)close(iIfreqFd);
        return -1;
    }

    (void)memcpy(pucMac, ifr.ifr_hwaddr.sa_data, SOCKET_MAC_LEN);
    (void)close(iIfreqFd);
    return 0;
}

int send_socket_msg(char* pcMsg, unsigned short usMsgLen)
{
    char*              pcSendBuff  = NULL;
    struct ifreq       ifr;
    struct sockaddr_ll stServaddr;
    int recv_len = 0;
    openflow_socket_mac_head *pstMacHead = NULL;
    char aucSrcMac[SOCKET_MAC_LEN] = {0};

    memset(&ifr, 0, sizeof(ifr));

    if (-1 == udatapath_GetLocalMac(aucSrcMac))
    {
        VLOG_ERR(LOG_MODULE, "get mac failed.");
        return -1;
    }

    pcSendBuff = malloc(usMsgLen + sizeof(openflow_socket_mac_head));
    if(NULL == pcSendBuff)
    {
        VLOG_ERR(LOG_MODULE, "Apply Memory SendBuff Error!\n");
        return -1;
    }
    memset(pcSendBuff, 0, (usMsgLen + sizeof(openflow_socket_mac_head)));
    pstMacHead = (openflow_socket_mac_head *)(void *)pcSendBuff;
    memset(pstMacHead->aucDMac, 0xFF, SOCKET_MAC_LEN);
    (void)memcpy(pstMacHead->aucSMac, aucSrcMac, SOCKET_MAC_LEN);
    pstMacHead->usEthType = (unsigned short)htons(OPENFLOW_ETH_TYPE);

    (void)memcpy(pcSendBuff + sizeof(openflow_socket_mac_head), pcMsg, usMsgLen);

    /* 绑定vethof端口 */
    memset(&stServaddr, 0, sizeof(stServaddr));
    stServaddr.sll_family   = AF_PACKET;
    stServaddr.sll_protocol = (unsigned short)htons(OPENFLOW_ETH_TYPE);
    stServaddr.sll_ifindex  = if_nametoindex("eth0");
    (void)memcpy(stServaddr.sll_addr, pstMacHead->aucDMac, SOCKET_MAC_LEN);

    /* 判断RAW模式socket是否存在 */
    if (-1 == g_uiListenfd)
    {
        VLOG_ERR(LOG_MODULE, "Listen ID is illegal.");
        (void)free(pcSendBuff);
        return -1;
    }

    recv_len = sendto(g_uiListenfd, pcSendBuff, usMsgLen + sizeof(openflow_socket_mac_head), MSG_DONTWAIT,
                      (struct sockaddr *)&stServaddr, sizeof(stServaddr));
    if(0 >= recv_len)
    {
        VLOG_ERR(LOG_MODULE, "openflow send socket fail!\n");
        (void)free(pcSendBuff);
        return -1;
    }

    (void)free(pcSendBuff);
    return 0;
}

/* V8数据发送函数 */
int Sock_Sendto_V8(void *recvdata, unsigned short revnum, unsigned int uiReverse)
{
    int iRet =0;
    char* pBuf = NULL;
    MLA_FRAME_SOCKET_TLV_HEAD_S* ptmp = NULL;

    // 添加一个消息头
    pBuf = malloc(revnum + sizeof(MLA_FRAME_SOCKET_TLV_HEAD_S));
    if(NULL == pBuf)
    {
        VLOG_ERR(LOG_MODULE, "Apply Memory pBuf Error for Sock_Sendto_V8\n");
        return -1;
    }
    memset(pBuf, 0, (revnum + sizeof(MLA_FRAME_SOCKET_TLV_HEAD_S)));

    ptmp = (MLA_FRAME_SOCKET_TLV_HEAD_S*)pBuf;

    ptmp->uiIndex = 0;
    ptmp->uiPid = 1;
    ptmp->usProgram = 0;
    ptmp->uiReverse = uiReverse;
    ptmp->usDataLength = revnum;
    ptmp->usLength = sizeof(MLA_FRAME_SOCKET_TLV_HEAD_S) + revnum;
    memcpy(pBuf + sizeof(MLA_FRAME_SOCKET_TLV_HEAD_S), recvdata, revnum);

    iRet = send_socket_msg(pBuf, ptmp->usLength);

    free(pBuf);

    if(iRet < 0)
    {
        VLOG_ERR(LOG_MODULE, "SOCK Send to V8 Fail\n");
        return -1;
    }
    VLOG_DBG(LOG_MODULE, "SOCK Send to V8 success\n");

    return 0;

}


int SockRecv_Find_WaitBuf(unsigned int uiIdentifier, unsigned int *uiBufId)
{
    unsigned int iLoop = 0;
    for (iLoop=0; iLoop<HYBRID_INFOCHANGE_BUFFER_LENGTH; iLoop++)
    {
        if ((uiIdentifier == g_ua_info_buf[iLoop].ui_identifier) &&
            (g_ua_info_buf[iLoop].wait_v8reply_flag == HYBRID_INFOCHANGE_WAITV8REPLY))
        {
            *uiBufId = iLoop;
            return FOUND;
        }
    }

    return NOTFOUND;
}

/*V8数据处理函数*/
int SOCK_Recvdata_Process(char *recvdata, unsigned int revnum)
{
    openflow_socket_mac_head    *pstMsgMacHead = NULL;
    HYBRID_INFO_CHANGE_S        *pstSendDate  = NULL;
    unsigned int uiIdentifier = 0;
    unsigned int uiBufId = 0;
    unsigned int uiProcessRet = 0;

    if(revnum < sizeof(MLA_FRAME_SOCKET_TLV_HEAD_S) +
            sizeof(HYBRID_INFO_CHANGE_S) + sizeof(openflow_socket_mac_head))
    {
        VLOG_ERR(LOG_MODULE, "SOCK Receive Invalid Data");
        return -1;
    }

    /*判断消息头是否是openflow的消息头，如果不是则返回错误*/
    pstMsgMacHead = (openflow_socket_mac_head*)recvdata;
    if(OPENFLOW_ETH_TYPE !=  pstMsgMacHead->usEthType)
    {
        VLOG_ERR(LOG_MODULE, "SOCK Receive not openflow Data");
        return -1;
    }
    // 消息头偏移，之后，recvdata指针不再指向原始报文头了
    pstSendDate = (HYBRID_INFO_CHANGE_S *)(recvdata + sizeof(openflow_socket_mac_head) +
                sizeof(MLA_FRAME_SOCKET_TLV_HEAD_S));

    revnum = revnum - sizeof(MLA_FRAME_SOCKET_TLV_HEAD_S) - sizeof(openflow_socket_mac_head);

    // 收到的信息必须带  ui_identifier 字段
    uiIdentifier = pstSendDate->ui_identifier;

    // 判断是否为需要等待响应的报文
    // 没有缓存区，只处理event报文
    if(NOTFOUND == SockRecv_Find_WaitBuf(uiIdentifier, &uiBufId))
    {
        // Hybrid框架处理V8发送的EVENT报文，包括Packet in，LLDP,端口信息，端口状态四类报文
        uiProcessRet = Hybird_Frame_Process_UnknownIdentifier_Packet((char *)pstSendDate, revnum);
        if(VOS_OK == uiProcessRet)
        {
            return 0;
        }
        else
        {
            return -1;
        }
    }
    // 对需要等待响应的消息，才处理
    else
    {
        g_ua_info_buf[uiBufId].pst_info = pstSendDate;
        g_ua_info_buf[uiBufId].data_len = revnum;

        /*这时候框架应该在死等，数据拷贝完成后，释放信号量，通知框架去取*/
        sem_post(&(g_ua_info_buf[uiBufId].sem_isused));

        /*等待框架将数据卸载下来,释放信号量，死等，SOCK线程不做其他事情*/
        // 这个不能等吧，event报文都不接受了
        // 你收你的就是了，没有不是这个报文不会处理的，用select后更没问题了
        //sem_wait(&g_sem_waitframe_restordata);
        return 0;
    }
}

/*V8数据接收线程*/
void openflow_recvdata(void *pArg)

{
    int                iRet        = 0;
    int                iIfreqFd    = 0;
    int                recv_len    = 0;
    int                uiListenfd  = -1;
    struct ifreq       ifr;
    struct timespec    stTime;
    struct sockaddr_ll stServaddr;
    fd_set sockFds;

    stTime.tv_sec  = 0;
    stTime.tv_nsec = 100000 * 1000;

    memset(&ifr, 0, sizeof(ifr));
    memset(&stServaddr, 0, sizeof(stServaddr));
    memset(g_RcvBuf, 0, MAX_SOCKET_MSG_SIZE);

    /* 循环判断，等待vethof端口创建 */
    if ((iIfreqFd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        VLOG_ERR(LOG_MODULE, "fail to open socket.");
        return;
    }

    (void)strncpy(ifr.ifr_name, "eth0", strlen("eth0")+1);
    while ((ioctl(iIfreqFd, SIOCGIFMTU, &ifr) < 0))
    {
        VLOG_ERR(LOG_MODULE, "fail to read vethof: %s\n", strerror(errno));
        (void)nanosleep(&stTime, &stTime);
    }

    (void)close(iIfreqFd);

    /* 创建RAW模式socket */
    if ((uiListenfd = socket(AF_PACKET, SOCK_RAW, htons(OPENFLOW_ETH_TYPE))) == -1 )
    {
        VLOG_ERR(LOG_MODULE, "create socket error: %s\n", strerror(errno));
        return;
    }

    /* 绑定vethof端口 */
    stServaddr.sll_family   = AF_PACKET;
    stServaddr.sll_protocol = htons(OPENFLOW_ETH_TYPE);
    stServaddr.sll_ifindex  = if_nametoindex("eth0");
    if(bind(uiListenfd, (struct sockaddr *)&stServaddr, sizeof(stServaddr)) != 0)
    {
        VLOG_ERR(LOG_MODULE, "bind socket error: %s\n", strerror(errno));
        (void)close(uiListenfd);
        return;
    }

    for (;;)
    {
        FD_ZERO(&sockFds);
        FD_SET(uiListenfd, &sockFds);

        if (select(uiListenfd + 1, &sockFds, NULL, NULL, NULL) > 0)
        {
            if (FD_ISSET(uiListenfd, &sockFds))
            {
                VLOG_DBG(LOG_MODULE, "receive a packet!\n");
                /*接口板与网板接收主控板的响应报文*/
                memset(g_RcvBuf, 0, MAX_SOCKET_MSG_SIZE);
                recv_len = recvfrom(uiListenfd, g_RcvBuf,
                                    MAX_SOCKET_MSG_SIZE, MSG_DONTWAIT, NULL, NULL);
                if(0 < recv_len)
                {
                    VLOG_DBG(LOG_MODULE, "receive data from v8\n");
                    iRet = SOCK_Recvdata_Process(g_RcvBuf, (unsigned int)recv_len);
                    if (0 != iRet)
                    {
                        VLOG_ERR(LOG_MODULE, "Recvdata process fail\n");
                    }
                }
            }
        }
    }

    (void)close(uiListenfd);
    return;
}

/*V8-Linux SOCKET初始化函数*/
void Socket_Create()
{
    g_uiListenfd = socket(AF_PACKET, SOCK_RAW, htons(OPENFLOW_ETH_TYPE));
    if (-1 == g_uiListenfd)
    {
        VLOG_ERR(LOG_MODULE, "create send socket error: %s\n", strerror(errno));
        return;
    }
}

int Socket_Initial()
{
    pthread_t  tid_socketFEI = 0;
    void*      temppoint     = NULL;

    Socket_Create();

    if (pthread_create(&tid_socketFEI, NULL, (void*)openflow_recvdata, (void*)temppoint))
    {
        VLOG_ERR(LOG_MODULE, "Create Thread Failed\n");
        exit(1);
    }
    return 0;
}

void Socket_Close()
{
    (void)close(g_uiListenfd);

    g_uiListenfd = -1;

    return 0;
}


/*The end*/
