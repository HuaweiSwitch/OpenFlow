
#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

#include <semaphore.h>
#include "Hybrid_Framework_Common.h"
#include "Hybrid_Framework_Linux.h"
#include "common/port.h"
#include "datapath.h"
#include "dpal_pub.h"
#include "vlog.h"

#define LOG_MODULE VLM_frame


unsigned int g_ui_identifier = 1;
HYBRID_INFOCHANGE_BUFFER_S g_ua_info_buf[HYBRID_INFOCHANGE_BUFFER_LENGTH];


#define hybird_get_identifier() (g_ui_identifier++)


FEI_OPENFLOW_FEIFRAME_MSG_PROC_FUNC_P  g_ast_openflow_event_proc[] =
{
    Hybird_Frame_Process_PacketIn,
    NULL,
    NULL,
    Hybird_Frame_Process_PortInfo,
    NULL,
    NULL,
    NULL,
    NULL,
    Hybird_Frame_Process_PortStatus,
};


UINT32 Hybrid_Chatwith_V8(HYBRID_INFO_CHANGE_S *pdata, unsigned short len, HYBRID_INFO_CHANGE_S **prevdata,UINT32* rcvLen)
{
    UINT32 uiLoop = 0;
    int iRet = 0;
    VOID *pMsg =NULL;
    UINT32 uiRcvLen = 0;

    /*2.查找空缓冲区*/
    // 最后一个1表示新接口
    iRet = Sock_Sendto_V8((VOID *)pdata, len, 0);
    if (0 != iRet)
    {
        return VOS_ERR;
    }

    // 需要定哪些类型的消息需要响应
    // 通过消息类型判断是否要等待消息响应，这样实际上是没起作用，以后修改为 HYBRID_ACTION_GET
    if (HYBRID_ACTION_COMMON == ((Hybrid_FEI_Send_Head_Struct *)pdata)->head.ui_action)
    {
        g_ua_info_buf[uiLoop].ui_identifier = pdata->ui_identifier;
        g_ua_info_buf[uiLoop].wait_v8reply_flag = HYBRID_INFOCHANGE_WAITV8REPLY;
        VLOG_DBG(LOG_MODULE, "Sock Send OK\n");
    }
    else
    {
        VLOG_DBG(LOG_MODULE, "no need to wait response!\n");
        return VOS_OK;
    }

    /*6.等待返回*/
    VLOG_DBG(LOG_MODULE, "Wait V8 Reply\n");
    sem_wait(&(g_ua_info_buf[uiLoop].sem_isused));

    /*7.将V8返回的数据复制一份，返回给上层，此处申请的内存请上层务必释放*/
    VLOG_DBG(LOG_MODULE, "Sock Recv Success\n");

    uiRcvLen = (UINT32) g_ua_info_buf[uiLoop].data_len;

    // 关注，可能造成重大内存泄露，每次调用都会申请一块内存
    pMsg = malloc(uiRcvLen);
    if(NULL == pMsg)
    {
        //信号量等资源释放
        VLOG_ERR(LOG_MODULE, "Apply Memory Error\n");
        return VOS_ERR;
    }
    (void)memset(pMsg,0,uiRcvLen);

    // 申请保存消息的内存
    (void)memcpy(pMsg, g_ua_info_buf[uiLoop].pst_info, uiRcvLen);

    *prevdata = pMsg;
    *rcvLen = uiRcvLen;

    /*8.数据拷贝结束，释放BUF*/
    g_ua_info_buf[uiLoop].pst_info = NULL;
    g_ua_info_buf[uiLoop].data_len = 0;
    g_ua_info_buf[uiLoop].wait_v8reply_flag = 0;
    g_ua_info_buf[uiLoop].ui_identifier = 0;

    return VOS_OK;
}



UINT32 Hybrid_Chatwith_V8_new(DPAL_MESSAGE_DATA_S *pdata)
{
    UINT32 uiLoop = 0;
    int iRet = 0;
    VOID *pMsg =NULL;
    UINT32 uiRcvLen = 0;
    unsigned short len = pdata->usDataLength;

    // 最后一个1表示新接口
    iRet = Sock_Sendto_V8(pdata->pData, len, 1);
    if (0 != iRet)
    {
        VLOG_ERR(LOG_MODULE, "Sock_Sendto_V8 error, ret = %d.\n", iRet);
        return VOS_ERR;
    }

    // 先不做消息响应，以后做
    return VOS_OK;

}


UINT32 Hybrid_Frame_NotifyV8_Vlan(struct datapath *dp)
{
    HYBRID_INFO_CHANGE_S_T *pPKT = VOS_NULL;
    UCHAR *pDataPKT = VOS_NULL;
    HYBRID_INFO_CHANGE_S * pRevMsg = NULL;
    Hybrid_VlanData_Reply *pVlanReply = NULL;
    UINT32 uiRcvLen = 0;
    UINT32 uiSendLen = 0;
    UINT32 uiRet = VOS_OK;

    VLOG_DBG(LOG_MODULE, "Start NotifyV8 Vlan\n");

    uiSendLen = sizeof(HYBRID_INFO_CHANGE_S_T) + MAX_VLANS_BIT_LEN;
    pPKT = malloc(uiSendLen);
    if(NULL == pPKT)
    {
        VLOG_ERR(LOG_MODULE, "[Apply Memory Error][Hybrid_Frame_NotifyV8_Vlan]\n");
        return VOS_ERR;
    }
    (void)memset(pPKT,0,uiSendLen);

    VLOG_DBG(LOG_MODULE, "Memory Apply Success\n");

    pPKT->ui_length = uiSendLen;
    pPKT->ui_action = HYBRID_ACTION_SET;
    pPKT->ui_method = HYBRID_METHOD_RESOURCE;
    pPKT->ui_module = HYBRID_RESOURCE_VLAN;
    pPKT->ui_ver = HYBRID_INFOCHANGE_VERSION;

    pDataPKT = (UCHAR*)Hybrid_MSG_PAYLOAD_HYBRIDHEAD(pPKT);

    (VOID)memcpy(pDataPKT, dp->vlanBit, MAX_VLANS_BIT_LEN);
    VLOG_DBG(LOG_MODULE, "pPKT ui_identifier:%d, ui_length:%d, ui_action:%d\n"\
                         "pPKT ui_method:%d, ui_module:%d, ui_ver:%d\n",
                         pPKT->ui_identifier, pPKT->ui_length, pPKT->ui_action,
                         pPKT->ui_method, pPKT->ui_module, pPKT->ui_ver);

    uiRet = Hybrid_Chatwith_V8((VOID*)pPKT, (INT32)uiSendLen, &pRevMsg,&uiRcvLen);
    if(VOS_OK != uiRet)
    {
        free(pPKT);
        VLOG_ERR(LOG_MODULE, "Send to V8 Fail, ret = %d.\n", uiRet);
        return VOS_ERR;
    }

    VLOG_DBG(LOG_MODULE, "Send to V8 Success\n");

    if (NULL != pPKT)
    {
        free(pPKT);
        pPKT = NULL;
    }

    if (NULL != pRevMsg)
    {
        free(pRevMsg);
        pRevMsg = NULL;
    }

    return uiRet;
}


UINT32 Hybird_Frame_Process_PacketIn(CHAR *recvdata, UINT32 revnum)
{
    UINT32 uiRet = VOS_OK;
    CHAR * pPacketIn = VOS_NULL;
    OPENFLOW_CtlWord_Sendtolinux_Linux_S_T *pstCtrlWord = VOS_NULL;
    OPENFLOW_CtlWord_Sendtolinux_Linux_S_T stCtrlWord = {0};
    UINT32 uiLoop = 0;
    UCHAR **ppucBuf = VOS_NULL;

    if(revnum < sizeof(OPENFLOW_CtlWord_Sendtolinux_Linux_S_T))
    {
        VLOG_ERR(LOG_MODULE, "Invalid Length = %d\n", revnum);
        return VOS_ERR;
    }

    pstCtrlWord = (OPENFLOW_CtlWord_Sendtolinux_Linux_S_T*)recvdata;

    (void)memcpy(&stCtrlWord, pstCtrlWord, sizeof(OPENFLOW_CtlWord_Sendtolinux_Linux_S_T));

    pPacketIn = recvdata + sizeof(OPENFLOW_CtlWord_Sendtolinux_Linux_S_T);
    revnum = revnum - sizeof(OPENFLOW_CtlWord_Sendtolinux_Linux_S_T);

    //PKT In报文上送给Openflow处理BUF
    uiRet = fwding_evt_handle(0, (VOID*)pPacketIn, revnum, (VOID*)&stCtrlWord, ppucBuf);
    if(VOS_OK != uiRet)
    {
        VLOG_ERR(LOG_MODULE, "Hybrid Process PacketIn Fail Code =%d\n", uiRet);
        return VOS_ERR;
    }

    return VOS_OK;

}


UINT32 Hybird_Frame_Process_PortInfo(CHAR *recvdata, UINT32 revnum)
{
    UINT32 uiRet = VOS_OK;

    VLOG_DBG(LOG_MODULE, "Enter Hybrid Process Port Info\n");
    if(VOS_NULL == recvdata)
    {
        VLOG_ERR(LOG_MODULE, "[Point NULL][Hybird_Frame_Process_PortInfo]\n");
        return VOS_ERR;
    }

    if(revnum <= 0)
    {
        VLOG_ERR(LOG_MODULE, "[DataLen Zero][Hybird_Frame_Process_PortInfo]\n");
        return VOS_ERR;
    }

    //PKT In报文上送给Openflow处理BUF
    (void)Port_Statisitcs_put(recvdata, revnum);

    VLOG_DBG(LOG_MODULE, "Hybrid Process PacketIn Success\n");
    return VOS_OK;

}



UINT32 Hybird_Frame_Process_PortStatus(CHAR *recvdata,UINT32 revnum)
{
    UINT32 uiRet = VOS_OK;
    FEI_OFA_PORT_LINUX_S* pData = VOS_NULL;

    //PKT In报文上送给Openflow处理BUF

    if(revnum < sizeof(FEI_OFA_PORT_LINUX_S)+ 4)
    {
        VLOG_ERR(LOG_MODULE, "Invalid Length = %d\n", revnum);
        return VOS_ERR;
    }

    pData = (FEI_OFA_PORT_LINUX_S*)(recvdata + 4);//需要偏过MLA_OPENFLOW_MESSAGE_TLV_HEAD_S

    VLOG_DBG(LOG_MODULE, "uiIfIndex = %d\n",pData->uiIfIndex);
    VLOG_DBG(LOG_MODULE, "uiPortState = %d\n", pData->uiState);

    port_evt_handle((int)(pData->uiIfIndex), (unsigned int)(pData->uiState));

    return VOS_OK;

}



UINT32 Hybird_Frame_Process_Event_Packet(HYBRID_INFO_CHANGE_S *recvdata, UINT32 revnum)
{
    CHAR * pEventPkt = VOS_NULL;
    UINT32 uiEventPktLen = 0;
    UINT32 uiRet = VOS_OK;

    VLOG_DBG(LOG_MODULE, "Enter Hybrid Process Event Packet! \n");

    pEventPkt =(UCHAR*)Hybrid_MSG_PAYLOAD_HYBRIDHEAD(recvdata);
    uiEventPktLen = revnum - sizeof(HYBRID_INFO_CHANGE_S);

    if(VOS_NULL == pEventPkt)
    {
        VLOG_ERR(LOG_MODULE, "[Point NULL][Hybird_Frame_Process_Event_Packet]\n");
        return VOS_ERR;
    }

    if (NULL != (UINT32)g_ast_openflow_event_proc[recvdata->ui_module])
    {
        uiRet = (UINT32)g_ast_openflow_event_proc[recvdata->ui_module](pEventPkt, uiEventPktLen);
        if (VOS_OK != uiRet)
        {
            VLOG_ERR(LOG_MODULE, "Hybird Process Event Packet Err, ret=%d, module=%d\n", uiRet, recvdata->ui_module);
        }
        else
        {
            VLOG_INFO(LOG_MODULE, "Port state notify V8 OK, module=%d\n", recvdata->ui_module);
        }
    }
    else
    {
        VLOG_WARN(LOG_MODULE, "Hybird Process Event do not find pro function, module=%d\n", recvdata->ui_module);
    }

    return uiRet;
}


UINT32 Hybird_Frame_Process_UnknownIdentifier_Packet(CHAR *recvdata, UINT32 revnum)
{
    HYBRID_INFO_CHANGE_S * pMsgHead = VOS_NULL;
    UINT32 uiRet = VOS_OK;

    VLOG_DBG(LOG_MODULE, "Enter Hybrid Rcv UnknownIdentifier Packet! \n");

    //报文数据合法性检查
    if(VOS_NULL == recvdata)
    {
        VLOG_ERR(LOG_MODULE, "[NoId]Pointer NULL\n");
        return VOS_ERR;
    }

    if(revnum < sizeof(HYBRID_INFO_CHANGE_S))
    {
        VLOG_ERR(LOG_MODULE, "InValid PktLen, revnum=%d\n", revnum);
        return VOS_ERR;
    }

    pMsgHead = (HYBRID_INFO_CHANGE_S *)recvdata;

    if(pMsgHead->ui_ver != HYBRID_INFOCHANGE_VERSION)
    {
        VLOG_ERR(LOG_MODULE, "Unknown Version=%d\n", pMsgHead->ui_ver);
        return VOS_ERR;
    }

    if(pMsgHead->ui_method == HYBRID_METHOD_EVENT)
    {
        // Hybrid框架处理V8发送的EVENT报文，包括Packet in，LLDP,端口信息，端口状态四类报文
        uiRet = Hybird_Frame_Process_Event_Packet((HYBRID_INFO_CHANGE_S *)recvdata, revnum);
        if(VOS_OK != uiRet)
        {
            VLOG_ERR(LOG_MODULE, "Hybird Process Event Err,Ret=%d\n", uiRet);
        }
    }
    else
    {
        VLOG_ERR(LOG_MODULE, "Unknown Method=%d\n", pMsgHead->ui_method);
        uiRet = VOS_ERR;
    }

    return uiRet;

}


#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */
