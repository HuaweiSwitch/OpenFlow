
#ifndef __HYBRID_FRAMEWORK_LINUX_H_
#define __HYBRID_FRAMEWORK_LINUX_H_


#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif

#include "Hybrid_Framework_Common.h"
#include "Hybrid_Framework_Linux.h"
#include "dpal_pub.h"


/*-----------------------------------------------*/
/*             1、常量宏和枚举定义               */
/*-----------------------------------------------*/

#define FUNCTYPEVLANCREAT 1
#define FUNCTYPEVLANDELETE 2
#define FUNCTYPEVLANOPENFLOWSET 3


typedef  UINT32  (* FEI_OPENFLOW_FEIFRAME_MSG_PROC_FUNC_P)(CHAR *recvdata,UINT32 revnum);


/*result*/
typedef enum tagHybridFrameworkResultModuleId
{
    HYBRID_RESULT_COMMON,
    HYBRID_RESULT_OK,
    HYBRID_RESULT_ERROR,
    HYBRID_RESULT_FULL,
    HYBRID_RESULT_NOT_EXIST,
    HYBRID_RESULT_TIMEOUT,
    HYBRID_RESULT_OTHER,
    HYBRID_RESULT_MAX,
}HYBRID_FRAMEWORK_RESULT_MODULE_E;

/*Method*/
typedef enum tagHybridFrameworkMethodModuleId
{
    HYBRID_METHOD_COMMON,
    HYBRID_METHOD_RESOURCE,
    HYBRID_METHOD_TRANSACT,
    HYBRID_METHOD_RESPONSE,
    HYBRID_METHOD_LIST,
    HYBRID_METHOD_ECHO,
    HYBRID_METHOD_EVENT,
    HYBRID_METHOD_RESPONSE_LINUX,
    HYBRID_METHOD_MAX,
}HYBRID_FRAMEWORK_METHOD_MODULE_E;

/*Action*/
typedef enum tagHybridFrameworkActionModuleId
{
    HYBRID_ACTION_COMMON,
    HYBRID_ACTION_ALLOCATE,
    HYBRID_ACTION_RELEASE,
    HYBRID_ACTION_GET,
    HYBRID_ACTION_SET,
    HYBRID_ACTION_DELETE,
    HYBRID_ACTION_SEND,
    HYBRID_ACTION_RECEIVE,
    HYBRID_ACTION_MAX,
}HYBRID_FRAMEWORK_ACTION_MODULE_E;

/*resource*/
typedef enum tagHybridFrameworkResourceModuleId
{
    HYBRID_RESOURCE_PACKET,
    HYBRID_RESOURCE_INTERFACE,
    HYBRID_RESOURCE_PORT,
    HYBRID_RESOURCE_VLAN,
    HYBRID_RESOURCE_MAC,
    HYBRID_RESOURCE_L3,
    HYBRID_RESOURCE_ACL,
    HYBRID_RESOURCE_QOS,
    HYBRID_RESOURCE_IPMC,
    HYBRID_RESOURCE_DEVICE,
    HYBRID_RESOURCE_MAX
}HYBRID_FRAMEWORK_RESOURCE_MODULE_E;

/*event*/
typedef enum tagHybridFrameworkEventModuleId
{
    HYBRID_EVENT_COMMON,
    HYBRID_EVENT_PORTUP,
    HYBRID_EVENT_PORTDOWN,
    HYBRID_EVENT_MAX,
}HYBRID_FRAMEWORK_EVENT_MODULE_E;




/*-----------------------------------------------*/
/*             2、数据结构定义                   */
/*-----------------------------------------------*/


/*VLAN数据结构定义*/
typedef struct tagHybrid_VlanData_Struct
{
    unsigned short usAction;
    unsigned short usVlan;
    unsigned int ulUnit;
}Hybrid_VlanData;

typedef struct tagHybrid_VlanData_Reply_Struct
{
    unsigned int  ulRet;
}Hybrid_VlanData_Reply;

typedef struct tagHybrid_Info_Change_T
{
    unsigned int ui_identifier;
    unsigned int ui_ver;
    unsigned int ui_method;     // 废除，在dpal中封装
    unsigned int ui_module;     // 废除，在dpal中封装
    unsigned int ui_action;     // 废除，在dpal中封装
    unsigned int ui_length;
}HYBRID_INFO_CHANGE_S_T;

typedef struct tagHybrid_FEI_Send_Head_Struct
{
    HYBRID_INFO_CHANGE_S_T head;
    unsigned int ulType;        // 废除，在dpal中封装
    unsigned int uiLength;
}Hybrid_FEI_Send_Head_Struct;

typedef struct tagHybrid_FEI_Reply_Head_Struct
{
    HYBRID_INFO_CHANGE_S_T head;
    unsigned int ulType;
    unsigned int uiLength;
}Hybrid_FEI_Reply_Head_Struct;

typedef struct tag_OPENFLOW_CtlWord_Sendtolinux_Linux_T
{
    unsigned int   uiPktLen;
    unsigned int   ulIfIndex;                  /*!< 端口的ifindex索引 */
    unsigned int   ulRecvReason;
    unsigned char  ucUntagFlag;
    unsigned char  ucCos;
    unsigned char  ucRes[10];
}OPENFLOW_CtlWord_Sendtolinux_Linux_S_T;

typedef struct tagFE_XGS_NI_VLAN_INFO_Linux
{
    USHORT usPriority     : 3;   /* VLAN 优先级 */
    USHORT usCFI          : 1;   /* CFI */
    USHORT usVlanID       : 12;  /* VLAN ID */
} FE_XGS_NI_VLAN_INFO_Linux_S;  /* 主机序 */

typedef struct
{
            UINT32 u32_w[16]; /*!< 位图 */

} FE_PBMP_LINUX;

 /*端口信息*/
/*typedef struct tagFEI_OFA_PORT_LINUX_S
{
    UINT32 uiUnitID;
    UINT32 uiPortID;
    UINT32 uiPortState;
}FEI_OFA_PORT_LINUX_S;*/

typedef struct tagFEI_OFA_PORT_LINUX_S
{
    UINT32   uiIfIndex;
    USHORT   usTb;
    USHORT   usTp;
    UINT32   uiState;
}FEI_OFA_PORT_LINUX_S;

typedef struct
{
    UINT32 linkst;                                  /*!< */
    UINT32 TB;                                      /*!< */
    UINT32 TP;                                      /*!< */
    UINT32 FeiID;                                   /*!< */
}PIC_CALLBACK_INFO_FRAME_S;




/*-----------------------------------------------*/
/*             3、公共操作宏定义                 */
/*-----------------------------------------------*/
#define OPENFLOW_TS_MSG_PAYLOAD_Linux(pMsg) ((OPENFLOW_CtlWord_Sendtolinux_Linux_S_T*)(pMsg) + 1)
#define Hybrid_MSG_PAYLOAD_HYBRIDHEAD(pMsg) ((HYBRID_INFO_CHANGE_S_T*)(pMsg) + 1)
#define Hybrid_MSG_PAYLOAD(pMsg) ((Hybrid_FEI_Send_Head_Struct*)(pMsg) + 1)
#define Hybrid_MSG_VLANDATA_PAYLOAD(pMsg) ((Hybrid_FEI_Reply_Head_Struct*)(pMsg) + 1)



/*-----------------------------------------------*/
/*             4、函数声明                       */
/*-----------------------------------------------*/
UINT32 Hybird_Frame_Process_PacketIn(CHAR *recvdata,UINT32 revnum);
UINT32 Hybird_Frame_Process_PortInfo(CHAR *recvdata,UINT32 revnum);
UINT32 Hybird_Frame_Process_PortStatus(CHAR *recvdata,UINT32 revnum);

UINT32 Hybrid_Chatwith_V8(HYBRID_INFO_CHANGE_S *pdata, unsigned short len, HYBRID_INFO_CHANGE_S **prevdata,UINT32* rcvLen);

UINT32 Hybrid_Chatwith_V8_new(DPAL_MESSAGE_DATA_S *pdata);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif     /* #ifndef __HYBRID_FRAMEWORK_LINUX_H_ */
