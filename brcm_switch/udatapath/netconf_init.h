#ifndef NETCONF_INIT_H


#define BRCM_VLAN_H 1

#define DATAPATH_ERR            1
#define DATAPATH_OK             0

#define NETCONF_SEND_DATA_LEN 2501

#define NETCONF_VLANBIT_LEN 512
#define NETCONF_VLANBIT_LEN_STR 1024

#define NETCONF_IFNAME_LEN_MAX 30   /* 与dp结构体里的ifname长度保持一致 */
#define NETCONF_PORT_NUM       10   /* 一次设置端口个数 */
#define NETCONF_BUF_PORT_VLAN_MAX (23*1024)

#define DATAPATH_ERR            1
#define DATAPATH_OK             0

#define NETCONF_PORT            22

#define NETCONF_NULL_BREAK(p) if(p == NULL){ return DATAPATH_ERR;}

#define NETCONF_NUM_TO_STR(num, str)    \
if ((num >= 0) && (num <=9))            \
{                                       \
    str = num + '0';                    \
}                                       \
else if ((num >= 10) && (num <= 15))    \
{                                       \
    str = num + 'a' - 10;               \
}                                       \
else                                    \
{                                       \
    str = 0;                            \
}

#define NETCONF_STR_TO_NUM(str, num)    \
if ((str >= '0') && (str <= '9'))       \
{                                       \
    str = str - '0';                    \
}                                       \
else if ((str >= 'a') && (str <= 'f'))  \
{                                       \
    num = str - 'a' + 10;               \
}                                       \
else if ((str >= 'A') && (str <= 'F'))  \
{                                       \
    num = str - 'A' + 10;               \
}                                       \
else                                    \
{                                       \
    num = 0;                            \
}

#define NETCONF_BIT_REVERSE(bitVlaue, bit)      \
    (((bitVlaue & (1<<bit)) >> bit) << (8 - bit - 1))

unsigned int NETCONF_Init(struct datapath *dp);
void NETCONF_Vlanbit2NetVlanBit(char aucVlanBit[], char aucNetVlanBitStr[]);

void NETCONF_Get_Confbit(unsigned int auiVlans[], unsigned int uiVlanNum, char *netconfBit);
unsigned int NETCONF_Create_SingleVlan(struct nc_session * netconf_session, unsigned int uiVlanId);
unsigned int NETCONF_Delete_SingleVlan(struct nc_session * netconf_session, unsigned int uiVlanId);
unsigned int NETCONF_Create_Vlanbit(struct nc_session * netconf_session, char netconfBit[]);
unsigned int NETCONF_Des_SingleVlan(struct nc_session * netconf_session, unsigned int uiVlanId);
unsigned int NETCONF_Delete_Vlanbit(struct nc_session * netconf_session, char netconfBit[]);
unsigned int NETCONF_Set_Port_Trunk(struct nc_session * netconf_session, char ifName[]);
unsigned int NETCONF_Create_Port_Vlan(struct nc_session * netconf_session, char ifName[], unsigned int pvid, char netconfBit[], char send_data[]);
void NETCONF_Create_Vlan_Description_All(struct nc_session * netconf_session, unsigned int auiVlans [ ], unsigned int uiVlanNum);
unsigned int NETCONF_Delete_Port_Vlan(struct nc_session * netconf_session, char ifName[], char netconfBit[]);
void NETCONF_Delete_All_Port_Vlan(struct nc_session * netconf_session, unsigned int uiPortNum, char *pucIfName);
unsigned int NETCONF_Get_Ifindex_FromMsg(char *pData, char aIfName[], unsigned int *puiIfIndex);
unsigned int NETCONF_Get_Ifindex_ByIfname(struct nc_session * netconf_session, char ifName[], unsigned int *puiIfIndex);
unsigned int NETCONF_Get_Vlanbit_FromMsg(char *pData, char aucIfName[], char *pVlanBitStr);
unsigned int NETCONF_Get_Vlanbit_ByIfname(struct nc_session * netconf_session, char ifName[], char netconfBit[]);
unsigned int NETCONF_Clear_Config(struct nc_session * netconf_session, char aucVlanBit[], unsigned int uiPortNum, char *pucIfName);
void NETCONF_Get_Confbit_Tmp(unsigned int auiVlanId[], unsigned int uivlannumber, char *netconfBit, char aucvlanBit[]);
unsigned int NETCONF_Check_Port(struct nc_session * netconf_session, char *pucIfName, unsigned int uiPortNum, unsigned int *pifIndex);
unsigned int NETCONF_Get_VlanInfo_ByVlanId(struct nc_session * netconf_session, unsigned int uiVlanId);
unsigned int NETCONF_Check_Vlan(struct nc_session * netconf_session, unsigned int auiVlans[], unsigned int uiVlanNum);
unsigned int NETCONF_Del_Init(struct datapath *dp);
unsigned int NETCONF_Create_Port_Vlan_all(struct nc_session * netconf_session, unsigned int uiPortNum, char *pucIfName, unsigned int pvid[], char netconfBit[]);
unsigned int NETCONF_Create_Port_access(struct nc_session * netconf_session, char ifName[]);
unsigned int NETCONF_Create_Port_access_all(struct nc_session * netconf_session, unsigned int uiPortNum, char *pucIfName);
unsigned int NETCONF_Create_Vlan_Description(struct nc_session * netconf_session, unsigned int auiVlans [ ], unsigned int uiVlanNum, unsigned int uiLoop);
unsigned int NETCONF_Send_Data(struct nc_session * netconf_session, char send_data[]);
#endif

