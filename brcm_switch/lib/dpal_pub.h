
#ifndef __DPAL_PUB_H__
#define __DPAL_PUB_H__

/* 宏定义 */


/* 枚举定义 */
typedef enum tagDPAL_MSG_TYPE
{
    DPAL_MSG_TYPE_PKT,
    DPAL_MSG_TYPE_CONFIG,
    DPAL_MSG_TYPE_RESET,
    DPAL_MSG_TYPE_STATISTICS,
    DPAL_MSG_TYPE_FLOWTABLE_ADD,
    DPAL_MSG_TYPE_FLOWTABLE_DELETE,
    DPAL_MSG_TYPE_FLOWTABLE_EXIST,
    DPAL_MSG_TYPE_FLOWTABLE_STATISTCS,

    DPAL_MSG_TYPE_MAX
}DPAL_MSG_TYPE_E;

typedef enum tagDPAL_CONFIG_TYPE
{
    DPAL_CONFIG_TYPE_VLAN,
    DPAL_CONFIG_TYPE_INTERFACE,
    DPAL_CONFIG_TYPE_PORTIFINDEX,
    DPAL_CONFIG_TYPE_MAX
}DPAL_CONFIG_TYPE_E;

typedef enum tagOPENFLOW_DEL_TYPE
{
    OPENFLOW_DELETE_GLOBAL_VLAN,
    OPENFLOW_DELETE_ALL_RESOURCE,

    OPENFLOW_DELETE_MAX,
} OPENFLOW_DEL_TYPE_E;

/* 结构体定义 */
#ifndef MAX_VLANS_BIT_LEN
#define MAX_VLANS_BIT_LEN 512
#endif

#ifndef MAX_PORT_NUMBER
#define MAX_PORT_NUMBER 1000
#endif

typedef struct tagDPAL_INTERFACE
{
    unsigned int uiIfindex;
    unsigned int uiPVID;
}DPAL_INTERFACE_S;

typedef struct tagDPAL_INTERFACE_LIST
{
    DPAL_INTERFACE_S astInterface[MAX_PORT_NUMBER];
    unsigned int     uiPortnumber;
}DPAL_INTERFACE_LIST_S;

typedef struct tagDPAL_CONFIG_DATA
{
    unsigned int uiConfigType;
    void *       pData;
}DPAL_CONFIG_DATA_S, DPAL_QUERY_DATA_S;

typedef struct tagDPAL_MESSAGE_PKT
{
    unsigned short usIfNum;
    unsigned short usPktLength;
    unsigned int * puiIfIndex;
    void * pPKT;
}DPAL_MESSAGE_PKT_S;

typedef struct tagDPAL_MESSAGE_CONFIG
{
    unsigned short usType;
    unsigned short usAct;
    unsigned short usDataLength;
    unsigned short usRes;
    void * pData;
}DPAL_MESSAGE_CONFIG_S;

typedef struct tagDPAL_MESSAGE_DATA
{
    unsigned short usTLVNum;
    unsigned short usDataLength;
    void * pData;
}DPAL_MESSAGE_DATA_S;

typedef struct tagDPAL_PROC_DATA
{
    unsigned short usType;
    unsigned short usAct;
    void * pData;
}DPAL_PROC_DATA_S;

typedef struct tagDPAL_PROC
{
    unsigned int uiProNUM;
    DPAL_PROC_DATA_S *pstProcData;
}DPAL_PROC_S;

#define DPAL_DEBUG_LOG_PUB(szfmt, args...)\
{\
    DPAL_LOG_WriteLog("dpal_pub.log",\
                      "func: %s, line: %d. "szfmt,\
                      __FUNCTION__, __LINE__, ##args);\
}
void DPAL_LOG_WriteLog(char *pcFileName, const char *pcFmt, ...);


unsigned int DPAL_Active(DPAL_INTERFACE_LIST_S * pstInterfaceList);

unsigned int DPAL_TranslatePkt(DPAL_MSG_TYPE_E eType, void *param, DPAL_MESSAGE_DATA_S *pstMSGData);

unsigned int DPAL_TranslateData(DPAL_MESSAGE_DATA_S *pstMSGData, DPAL_PROC_S *pstProc);


void DPAL_DestroyData(DPAL_PROC_S *pstProc);

unsigned int DPAL_TranslatePortStat(void *msg, unsigned int revnum, DPAL_PROC_S * pstProc);

#endif /* __DPAL_PUB_H__ */

