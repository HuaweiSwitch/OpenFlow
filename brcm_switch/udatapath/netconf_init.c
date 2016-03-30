#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <math.h>

#include "list.h"
#include "vlog.h"
//****#include "fm_sdk_int.h"
//#include "fe/fe_common_pub.h"
//#include "fe/fe_xgs_pub.h"

//#include "udatapath/Hybrid_SDK_Function.h"
#include "datapath.h"
#include "netconf/libnetconf.h"

#include "netconf_init.h"

#define LOG_MODULE VLM_netconf

#define MAX_VLAN_NUM  20
#define MAX_VLAN_LEN  10


unsigned int NETCONF_Init(struct datapath *dp)
{
    unsigned int    i                            = 0;
    unsigned int    uiRet                        = 0;
    unsigned int    uiloop                       = 0;
    nc_rpc          *rpc                         = NULL;
    nc_reply        * reply = NULL;
    char            netconfBit[NETCONF_VLANBIT_LEN_STR + 1] = {0};

    struct nc_cpblts    * cpblts = NULL;
    struct nc_session   * netconf_session = NULL;

    /* Set libnetconf's debug level as error */
    nc_verbosity(NC_VERB_ERROR);

    VLOG_DBG(LOG_MODULE, "netconf init: ip:%s, username:%s\n", dp->ip, dp->username);
    cpblts = nc_cpblts_new(NULL);
    if (cpblts == NULL)
    {
        return DATAPATH_ERR;
    }

    nc_cpblts_add(cpblts, "urn:ietf:params:netconf:base:1.0");
    nc_cpblts_add(cpblts, "urn:ietf:params:netconf:capability:writable-running:1.0");
    nc_cpblts_add(cpblts, "urn:ietf:params:netconf:capability:candidate:1.0");
    nc_cpblts_add(cpblts, "urn:ietf:params:netconf:capability:confirmed-commit:1.0");
    nc_cpblts_add(cpblts, "http://www.huawei.com/netconf/capability/discard-commit/1.0");

    nc_cpblts_add(cpblts, "urn:ietf:params:netconf:capability:startup:1.0");
    nc_cpblts_add(cpblts, "urn:ietf:params:netconf:capability:rollback-on-error:1.0");
    nc_cpblts_add(cpblts, "http://www.huawei.com/netconf/capability/sync/1.1");
    nc_cpblts_add(cpblts, "http://www.huawei.com/netconf/capability/sync/1.0");
    nc_cpblts_add(cpblts, "http://www.huawei.com/netconf/capability/exchange/1.0");

    nc_cpblts_add(cpblts, "http://www.huawei.com/netconf/capability/active/1.0");
    nc_cpblts_add(cpblts, "http://www.huawei.com/netconf/capability/action/1.0");
    nc_cpblts_add(cpblts, "http://www.huawei.com/netconf/capability/execute-cli/1.0");
    nc_cpblts_add(cpblts, "http://www.huawei.com/netconf/capability/update/1.0");
    nc_cpblts_add(cpblts, "http://www.huawei.com/netconf/capability/commit-description/1.0");

    nc_cpblts_add(cpblts, "urn:ietf:params:netconf:capability:notification:1.0");
    nc_cpblts_add(cpblts, "urn:ietf:params:netconf:capability:interleave:1.0");

    netconf_session = nc_session_connect(dp->ip, NETCONF_PORT, dp->username, cpblts);
    if (netconf_session == NULL)
    {
        nc_cpblts_free(cpblts);
        cpblts = NULL;
        ofp_fatal(0, "session connect failed. ");
    }
/*
    uiRet = NETCONF_Check_Vlan(netconf_session, cpblts, dp->vlans, dp->vlannumber);
    if (uiRet != DATAPATH_OK)
    {
        nc_session_free(netconf_session);
        nc_cpblts_free(cpblts);
        cpblts = NULL;
        ofp_fatal(0, "There are some vlans that have been created.");
    }
*/
/* for test
    dp->portnumber = 2;
    strncpy(dp->ifname[0], "40GE1/0/3", 10);
    strncpy(dp->ifname[1], "40GE2/0/3", 10);
*/
    uiRet = NETCONF_Check_Port(netconf_session, (char *)(dp->ifname), dp->portnumber, dp->ifindex);
    if (uiRet != DATAPATH_OK)
    {
        nc_session_free(netconf_session);
        nc_cpblts_free(cpblts);
        cpblts = NULL;
        ofp_fatal(0, "There are some ports that do not exist.");
    }

    for (uiloop = 0; uiloop < dp->portnumber; uiloop++)
    {
        dp->ports[uiloop].port_no   = dp->ifindex[uiloop];
        dp->ports[uiloop].port_pvid = dp->pvid[uiloop];
    }

    /* 获取ofdatapath.cfg中所配置vlan的vlanBit */
    NETCONF_Get_Confbit(dp->vlans, dp->vlannumber, dp->vlanBit);
    NETCONF_Vlanbit2NetVlanBit(dp->vlanBit, netconfBit);

    /* 设置vlan */

    uiRet = NETCONF_Create_Vlanbit(netconf_session, netconfBit);
    if (uiRet != NC_REPLY_OK)
    {
        nc_session_free(netconf_session);
        nc_cpblts_free(cpblts);
        cpblts = NULL;
        ofp_fatal(0, "create vlans failed.");
    }

    NETCONF_Create_Vlan_Description_All(netconf_session, dp->vlans, dp->vlannumber);

    /* 清除端口所加vlan */
    uiRet = NETCONF_Create_Port_access_all(netconf_session, dp->portnumber, (char *)(dp->ifname));
    if (uiRet != DATAPATH_OK)
    {
        nc_session_free(netconf_session);
        nc_cpblts_free(cpblts);
        ofp_fatal(0, "the ports clear config failed.");
        return DATAPATH_ERR;
    }

    /* 端口加VLAN */
    uiRet = NETCONF_Create_Port_Vlan_all(netconf_session, dp->portnumber, (char *)(dp->ifname), dp->pvid, netconfBit);

    nc_cpblts_free(cpblts);
    nc_session_free(netconf_session);

    if (uiRet != DATAPATH_OK)
    {
        ofp_fatal(0, "the ports add vlan failed.");
        return DATAPATH_ERR;
    }

    VLOG_DBG(LOG_MODULE, "Info: Vlan init successfully.\n");
    return DATAPATH_OK;
}


void NETCONF_Vlanbit2NetVlanBit(char aucVlanBit[], char aucNetVlanBitStr[])
{
    unsigned int i           = 0;
    unsigned int j           = 0;
    unsigned int k           = 0;
    char         ucVlanValue = 0;

    for (i = 0; (i < NETCONF_VLANBIT_LEN) && (k < NETCONF_VLANBIT_LEN_STR); i++)
    {
        ucVlanValue = 0;
        for (j = 0; j < 8; j++)
        {
            ucVlanValue += NETCONF_BIT_REVERSE(aucVlanBit[i], j);
        }

        NETCONF_NUM_TO_STR((ucVlanValue & 0xf), aucNetVlanBitStr[k+1]);
        NETCONF_NUM_TO_STR(((ucVlanValue & 0xf0)>>4), aucNetVlanBitStr[k]);
        k += 2;
    }
}


void NETCONF_Get_Confbit(unsigned int auiVlans[], unsigned int uiVlanNum, char *netconfBit)
{
    int    i           = 0;
    int    uiVlanValue = 0;

/*  auiVlans[0] = 2;
    auiVlans[1] = 3;
    auiVlans[2] = 4;
    auiVlans[3] = 5;
    auiVlans[4] = 6;
    auiVlans[5] = 7;
    auiVlans[6] = 8;
    uiVlanNum = 7;*/

    for (i = 0; i < uiVlanNum; i++)
    {
        uiVlanValue = auiVlans[i];
        netconfBit[(uiVlanValue >> 3)] |= (1 << (uiVlanValue & 0x07));
    }
}


void NETCONF_Get_Confbit_Tmp(unsigned int auiVlanId[], unsigned int uivlannumber, char *netconfBit, char aucvlanBit[])
{
    int    i           = 0;
    int    uiVlanValue = 0;
/*
    dp->vlans[0] = 2;
    dp->vlans[1] = 3;
    dp->vlans[2] = 4;
    dp->vlans[3] = 5;
    dp->vlans[4] = 6;
    dp->vlans[5] = 7;
    dp->vlans[6] = 8;
    dp->vlannumber = 7;*/

    for (i = 0; i < uivlannumber; i++)
    {
        uiVlanValue = auiVlanId[i];

        if (uiVlanValue/sizeof(int) >= NETCONF_VLANBIT_LEN_STR)
        {
            return;
        }
        netconfBit[uiVlanValue/sizeof(int)] += (int)pow(2, (3 - (uiVlanValue % sizeof(int))));
    }

    for (i = 0; i < NETCONF_VLANBIT_LEN; i++)
    {
        aucvlanBit[i] = ((netconfBit[2*i] << 4)|netconfBit[2*i+1]);
    }

    for (i = 0; i < NETCONF_VLANBIT_LEN_STR; i++)
    {
        if (netconfBit[i] > 9)
        {
            netconfBit[i] += 'A' - 10;
        }
        else
        {
            netconfBit[i] += '0';
        }
    }
    netconfBit[NETCONF_VLANBIT_LEN_STR] = 0;
}


unsigned int NETCONF_Create_SingleVlan(struct nc_session * netconf_session, unsigned int uiVlanId)
{
    unsigned int    uiRet       = 0;
    unsigned int    uiLength    = 0;
    char            send_data[NETCONF_SEND_DATA_LEN] = {0};
    nc_rpc          *rpc                         = NULL;
    nc_reply        * reply = NULL;

    snprintf(send_data, NETCONF_SEND_DATA_LEN,
        "<edit-config>"\
          "<target><running/></target>"\
          "<default-operation>merge</default-operation>"\
          "<error-option>rollback-on-error</error-option>"\
          "<config>"\
            "<vlan xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<vlans>"\
                "<vlan operation=\"create\">"\
                  "<vlanId>%d</vlanId>"\
                  "<vlanName/>"\
                  "<vlanDesc/>"\
                  "<vlanType>super</vlanType>"\
                  "<subVlans/>"\
                "</vlan>"\
              "</vlans>"\
            "</vlan>"\
          "</config>"\
        "</edit-config>", uiVlanId);
    rpc = nc_rpc_generic(send_data);
    nc_session_send_recv(netconf_session, rpc, &reply);

    nc_rpc_free(rpc);
    rpc = NULL;

    uiRet = nc_reply_get_type(reply);
    if (uiRet != NC_REPLY_OK)
    {
        VLOG_ERR(LOG_MODULE, "[create_single_vlan]vlanId: %d\n", uiVlanId);
        VLOG_ERR(LOG_MODULE, "[create_single_vlan]err: %s\n", nc_reply_get_errormsg(reply));
    }

    nc_reply_free(reply);

    return uiRet;

}


unsigned int NETCONF_Des_SingleVlan(struct nc_session * netconf_session, unsigned int uiVlanId)
{
    unsigned int    uiRet       = 0;
    unsigned int    uiLength    = 0;
    char            send_data[NETCONF_SEND_DATA_LEN] = {0};
    nc_rpc          *rpc                         = NULL;
    nc_reply        * reply = NULL;

    snprintf(send_data, NETCONF_SEND_DATA_LEN,
        "<edit-config>"\
            "<target><running/></target>"\
            "<default-operation>merge</default-operation>"\
            "<error-option>rollback-on-error</error-option>"\
            "<config>"\
                "<vlan xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
                    "<vlans>"\
                        "<vlan operation=\"merge\">"\
                            "<vlanId>%d</vlanId>"\
                                "<vlanDesc>openflow</vlanDesc>"\
                        "</vlan>"\
                    "</vlans>"\
                "</vlan>"\
            "</config>"\
        "</edit-config>", uiVlanId);
    rpc = nc_rpc_generic(send_data);
    nc_session_send_recv(netconf_session, rpc, &reply);

    nc_rpc_free(rpc);
    rpc = NULL;

    uiRet = nc_reply_get_type(reply);
    if (uiRet != NC_REPLY_OK)
    {
        VLOG_ERR(LOG_MODULE, "[Des_SingleVlan]vlanId: %d\n", uiVlanId);
        VLOG_ERR(LOG_MODULE, "[Des_SingleVlan]err: %s\n", nc_reply_get_errormsg(reply));
    }

    nc_reply_free(reply);

    return uiRet;

}


void NETCONF_Create_Vlan_Description_All
(
    struct nc_session * netconf_session,
    unsigned int auiVlans[],
    unsigned int uiVlanNum
)
{
    unsigned int uiLoop = 0;

    for (uiLoop = 0; uiLoop < uiVlanNum; uiLoop++)
    {
        uiLoop = NETCONF_Create_Vlan_Description(netconf_session, auiVlans, uiVlanNum, uiLoop);
    }
}


unsigned int NETCONF_Create_Vlan_Description
(
    struct nc_session * netconf_session,
    unsigned int auiVlans[],
    unsigned int uiVlanNum,
    unsigned int uiLoop
)
{
    unsigned int    uiRet       = 0;
    unsigned int    uiLength    = 0;
    char            send_data[NETCONF_SEND_DATA_LEN] = {0};
    nc_rpc         *rpc         = NULL;
    nc_reply       *reply       = NULL;

    uiLength = sprintf(send_data,
        "<edit-config>"\
            "<target><running/></target>"\
            "<default-operation>merge</default-operation>"\
            "<error-option>rollback-on-error</error-option>"\
            "<config>"\
                "<vlan xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
                    "<vlans>\n");
    for (uiLoop = uiLoop; uiLoop < uiVlanNum; uiLoop++)
    {
        uiLength += sprintf(send_data + uiLength,
                        "<vlan operation=\"merge\">"\
                            "<vlanId>%d</vlanId>"\
                                "<vlanDesc>openflow</vlanDesc>"\
                        "</vlan>\n", auiVlans[uiLoop]);
        if(uiLength > (NETCONF_SEND_DATA_LEN - 200))
        {
            break;
        }
    }

    uiLength += sprintf(send_data+uiLength,
                    "</vlans>"\
                "</vlan>"\
            "</config>"\
        "</edit-config>");
    rpc = nc_rpc_generic(send_data);
    nc_session_send_recv(netconf_session, rpc, &reply);

    nc_rpc_free(rpc);
    rpc = NULL;

    uiRet = nc_reply_get_type(reply);
    if (uiRet != NC_REPLY_OK)
    {
        VLOG_ERR(LOG_MODULE, "[Des_SingleVlan]vlanId: %d\n", auiVlans[uiLoop]);
        VLOG_ERR(LOG_MODULE, "[Des_SingleVlan]err: %s\n", nc_reply_get_errormsg(reply));
    }

    nc_reply_free(reply);

    return uiLoop;

}


 unsigned int NETCONF_Delete_SingleVlan(struct nc_session * netconf_session, unsigned int uiVlanId)
{
    unsigned int    uiRet       = 0;
    unsigned int    uiLength    = 0;
    char            send_data[NETCONF_SEND_DATA_LEN] = {0};
    nc_rpc          *rpc                         = NULL;
    nc_reply        * reply = NULL;

    snprintf(send_data, NETCONF_SEND_DATA_LEN,
        "<edit-config>"\
          "<target><running/></target>"\
          "<default-operation>merge</default-operation>"\
          "<error-option>rollback-on-error</error-option>"\
          "<config>"\
            "<vlan xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<vlans>"\
                "<vlan operation=\"delete\">"\
                  "<vlanId>%d</vlanId>"\
                "</vlan>"\
              "</vlans>"\
            "</vlan>"\
          "</config>"\
        "</edit-config>", uiVlanId);
    rpc = nc_rpc_generic(send_data);
    nc_session_send_recv(netconf_session, rpc, &reply);

    nc_rpc_free(rpc);
    rpc = NULL;

    uiRet = nc_reply_get_type(reply);
    if (uiRet != NC_REPLY_OK)
    {
        VLOG_ERR(LOG_MODULE, "[del_single_vlan]vlanId: %d\n", uiVlanId);
        VLOG_ERR(LOG_MODULE, "[del_single_vlan]err: %s\n", nc_reply_get_errormsg(reply));
    }

    nc_reply_free(reply);

    return uiRet;

}


unsigned int NETCONF_Create_Vlanbit(struct nc_session * netconf_session, char netconfBit[])
{
    unsigned int    uiRet       = 0;
    unsigned int    uiLength    = 0;
    char            send_data[NETCONF_SEND_DATA_LEN] = {0};
    nc_rpc          *rpc                         = NULL;
    nc_reply        * reply = NULL;

    snprintf(send_data, NETCONF_SEND_DATA_LEN,
        "<execute-action xmlns=\"http://www.huawei.com/netconf/capability/base/1.0\">"\
          "<action>"\
            "<vlan xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
              "<shVlanBatchCrt>"\
                "<vlans>%s:%s</vlans>"\
              "</shVlanBatchCrt>"\
            "</vlan>"\
          "</action>"\
        "</execute-action>", netconfBit, netconfBit);

    rpc = nc_rpc_generic(send_data);
    nc_session_send_recv(netconf_session, rpc, &reply);

    nc_rpc_free(rpc);
    rpc = NULL;

    uiRet = nc_reply_get_type(reply);
    if (uiRet != NC_REPLY_OK)
    {
        VLOG_ERR(LOG_MODULE, "[create_vlanbit]VlanBit: %s\n", netconfBit);
        VLOG_ERR(LOG_MODULE, "[create_vlanbit]err: %s\n", nc_reply_get_errormsg(reply));
    }

    nc_reply_free(reply);

    return uiRet;

}


unsigned int NETCONF_Delete_Vlanbit(struct nc_session * netconf_session, char netconfBit[])
{
    unsigned int    uiRet       = 0;
    unsigned int    uiLength    = 0;
    char            send_data[NETCONF_SEND_DATA_LEN] = {0};
    nc_rpc          *rpc                         = NULL;
    nc_reply        * reply = NULL;

    snprintf(send_data, NETCONF_SEND_DATA_LEN,
        "<execute-action xmlns=\"http://www.huawei.com/netconf/capability/base/1.0\">"\
            "<action>"\
              "<vlan xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
                "<shVlanBatchDel>"\
                  "<vlans>%s:%s</vlans>"\
                "</shVlanBatchDel>"\
              "</vlan>"\
            "</action>"\
          "</execute-action>", netconfBit, netconfBit);
    rpc = nc_rpc_generic(send_data);
    nc_session_send_recv(netconf_session, rpc, &reply);

    nc_rpc_free(rpc);
    rpc = NULL;

    uiRet = nc_reply_get_type(reply);
    if (uiRet != NC_REPLY_OK)
    {
        VLOG_ERR(LOG_MODULE, "[del_vlanbit]VlanBit: %s\n", netconfBit);
        VLOG_ERR(LOG_MODULE, "[del_vlanbit]err: %s\n", nc_reply_get_errormsg(reply));
    }

    nc_reply_free(reply);

    return uiRet;

}


unsigned int NETCONF_Set_Port_Trunk(struct nc_session * netconf_session, char ifName[])
{
    unsigned int    uiRet       = 0;
    unsigned int    uiLength    = 0;
    char            send_data[NETCONF_SEND_DATA_LEN] = {0};
    nc_rpc          *rpc                         = NULL;
    nc_reply        * reply = NULL;

    snprintf(send_data, NETCONF_SEND_DATA_LEN,
        "<edit-config>"\
          "<target><running/></target>"\
          "<default-operation>merge</default-operation>"\
          "<error-option>rollback-on-error</error-option>"\
          "<config>"\
          "<ethernet xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
            "<ethernetIfs>"\
              "<ethernetIf operation=\"merge\">"\
              "<ifName>%s</ifName>"\
              "<l2Attribute>"\
                "<linkType>trunk</linkType>"\
                "<trunkVlans></trunkVlans>"\
              "</l2Attribute>"\
              "</ethernetIf>"\
            "</ethernetIfs>"\
          "</ethernet>"\
          "</config>"\
        "</edit-config>", ifName);

    rpc = nc_rpc_generic(send_data);
    nc_session_send_recv(netconf_session, rpc, &reply);

    nc_rpc_free(rpc);
    rpc = NULL;

    uiRet = nc_reply_get_type(reply);
    if (uiRet != NC_REPLY_OK)
    {
        VLOG_ERR(LOG_MODULE, "[create_port_trunk]Port:%s\n", ifName);
        VLOG_ERR(LOG_MODULE, "[create_port_trunk]err: %s\n", nc_reply_get_errormsg(reply));
    }

    nc_reply_free(reply);

    return uiRet;
}


unsigned int NETCONF_Create_Port_Vlan(struct nc_session * netconf_session, char ifName[], unsigned int pvid, char netconfBit[], char send_data[])
{
    unsigned int    uiLen       = 0;
    unsigned int    i           = 0;
    char            netconfBitTmp[1024] = {0};

    sprintf(netconfBitTmp, "%s", netconfBit);
    netconfBitTmp[0] = netconfBitTmp[0] + 4;

    uiLen = sprintf(send_data,
               "<ethernetIf operation=\"merge\">"\
                "<ifName>%s</ifName>"\
                "<l2Attribute>"\
                  "<linkType>trunk</linkType>"\
                  "<pvid>%d</pvid>"
                  "<trunkVlans>%s:%s</trunkVlans>"\
                "</l2Attribute>"\
              "</ethernetIf>", ifName, pvid, netconfBit, netconfBitTmp);

    return uiLen;

}

unsigned int NETCONF_Create_Port_Vlan_all(struct nc_session * netconf_session, unsigned int uiPortNum, char *pucIfName, unsigned int pvid[], char netconfBit[])
{
    unsigned int uiloop   = 0;
    unsigned int uiIndex  = 0;
    unsigned int uiPortIndex = 0;
    unsigned int uiRet    = 0;
    unsigned int uiLen    = 0;
    unsigned int uiEndLen    = 0;
    char         send_head[] = {"<edit-config>"\
                                "<target><running/></target>"\
                                "<default-operation>merge</default-operation>"\
                                "<error-option>rollback-on-error</error-option>"\
                                "<config>"\
                                "<ethernet xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
                                "<ethernetIfs>"};
    char         send_end[] = {"</ethernetIfs>"\
                                "</ethernet>"\
                                "</config>"\
                                "</edit-config>"};
    char         *send_data = NULL;

    send_data = malloc(NETCONF_BUF_PORT_VLAN_MAX);
    if (send_data == NULL)
    {
        VLOG_ERR(LOG_MODULE, "NETCONF_Create_Port_Vlan_all xmalloc failed.\n");
        return DATAPATH_ERR;
    }

    uiLen = strlen(send_head);
    uiEndLen = strlen(send_end);

    /* 端口加VLAN 1 */
    for(uiloop = 0; uiloop < uiPortNum/NETCONF_PORT_NUM; uiloop++)
    {
        memset(send_data, 0, NETCONF_BUF_PORT_VLAN_MAX);
        uiLen = sprintf(send_data,"%s", send_head);
        for (uiIndex = 0; uiIndex < NETCONF_PORT_NUM; uiIndex++)
        {
            uiPortIndex = uiIndex + NETCONF_PORT_NUM*uiloop;
            uiLen += NETCONF_Create_Port_Vlan(netconf_session, pucIfName+uiPortIndex*NETCONF_IFNAME_LEN_MAX, pvid[uiPortIndex], netconfBit, send_data + uiLen);
        }

        memcpy(send_data + uiLen, send_end, uiEndLen);

        uiRet = NETCONF_Send_Data(netconf_session, send_data);
        if (uiRet != NC_REPLY_OK)
        {
            //VLOG_ERR(LOG_MODULE, "[port add vlan] failed. send_data:%s", send_data);
            free(send_data);
            return DATAPATH_ERR;
        }
    }

    if (uiPortNum%NETCONF_PORT_NUM == 0)
    {
        free (send_data);
        return DATAPATH_OK;
    }

    memset(send_data, 0, NETCONF_BUF_PORT_VLAN_MAX);
    uiPortIndex = NETCONF_PORT_NUM * (uiPortNum/NETCONF_PORT_NUM);

    uiLen = sprintf(send_data,"%s", send_head);

    for (uiIndex = 0; uiIndex < (uiPortNum%NETCONF_PORT_NUM); uiIndex++)
    {
        //VLOG_ERR(LOG_MODULE, "uiIndex:%d, ifname:%s, pvid:%d\n", uiPortIndex, pucIfName+uiPortIndex*NETCONF_IFNAME_LEN_MAX, pvid[uiPortIndex]);
        uiLen += NETCONF_Create_Port_Vlan(netconf_session, pucIfName+uiPortIndex*NETCONF_IFNAME_LEN_MAX, pvid[uiPortIndex], netconfBit, send_data + uiLen);
        uiPortIndex ++;
    }

    memcpy(send_data + uiLen, send_end, uiEndLen);
    uiRet = NETCONF_Send_Data(netconf_session, send_data);
    if (uiRet != NC_REPLY_OK)
    {
        //VLOG_ERR(LOG_MODULE, "[port add vlan] failed. send_data:%s", send_data);
        free(send_data);
        return DATAPATH_ERR;
    }

    free (send_data);

    return DATAPATH_OK;
}


void NETCONF_Delete_All_Port_Vlan(struct nc_session * netconf_session, unsigned int uiPortNum, char *pucIfName)
{
    unsigned int uiLoop = 0;
    char         aucVlanBit[NETCONF_VLANBIT_LEN_STR+1] = {0};

    /* 清vlan+port */
    for (uiLoop = 0; uiLoop < uiPortNum; uiLoop++)
    {
        //VLOG_ERR(LOG_MODULE, "uiLoop = %d, ifname:%s\n", uiLoop, pucIfName+uiLoop*NETCONF_IFNAME_LEN_MAX);
        (void)NETCONF_Get_Vlanbit_ByIfname(netconf_session, pucIfName+uiLoop*NETCONF_IFNAME_LEN_MAX, aucVlanBit);
        (void)NETCONF_Delete_Port_Vlan(netconf_session, pucIfName+uiLoop*NETCONF_IFNAME_LEN_MAX, aucVlanBit);
    }
}


unsigned int NETCONF_Delete_Port_Vlan(struct nc_session * netconf_session, char ifName[], char netconfBit[])
{
    unsigned int    uiRet       = 0;
    unsigned int    uiLength    = 0;
    char            aucVlanBitZero[NETCONF_VLANBIT_LEN_STR+1] = {0};
    char            send_data[NETCONF_SEND_DATA_LEN] = {0};
    nc_rpc          *rpc        = NULL;
    nc_reply        * reply     = NULL;

    memset(aucVlanBitZero, '0', NETCONF_VLANBIT_LEN_STR);

    snprintf(send_data, NETCONF_SEND_DATA_LEN,
        "<edit-config>"\
          "<target><running/></target>"\
          "<default-operation>merge</default-operation>"\
          "<error-option>rollback-on-error</error-option>"\
          "<config>"\
          "<ethernet xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
            "<ethernetIfs>"\
              "<ethernetIf operation=\"merge\">"\
                "<ifName>%s</ifName>"\
                "<l2Attribute>"\
                  "<linkType>trunk</linkType>"\
                  "<trunkVlans>%s:%s</trunkVlans>"\
                "</l2Attribute>"\
              "</ethernetIf>"\
            "</ethernetIfs>"\
          "</ethernet>"\
          "</config>"\
        "</edit-config>", ifName, aucVlanBitZero, netconfBit);
    rpc = nc_rpc_generic(send_data);
    nc_session_send_recv(netconf_session, rpc, &reply);

    nc_rpc_free(rpc);
    rpc = NULL;

    uiRet = nc_reply_get_type(reply);
    if (uiRet != NC_REPLY_OK)
    {
        VLOG_ERR(LOG_MODULE, "[del_port_vlan]Port:%s\n", ifName);
        VLOG_ERR(LOG_MODULE, "[del_port_vlan]err: %s\n", nc_reply_get_errormsg(reply));
    }

    nc_reply_free(reply);

    return uiRet;
}


unsigned int NETCONF_Get_Ifindex_FromMsg(char *pData, char aIfName[], unsigned int *puiIfIndex)
{
    char *pLeft  = NULL;
    char *pRight = NULL;
    char aifIndexLeft[]  = "<ifIndex>";
    char aifIndexRight[] = "</ifIndex>";
    char ch[] = ">";
    unsigned int uiIfIndex = 0;

    if(pData == NULL || strlen(pData) == 0)
    {
        return DATAPATH_ERR ;
    }

    NETCONF_NULL_BREAK(strstr(pData,aIfName));

    pLeft=strstr(pData,aifIndexLeft);

    NETCONF_NULL_BREAK(pLeft);
    pLeft = pLeft + strlen(aifIndexLeft);

    NETCONF_NULL_BREAK(pLeft);

    pRight=strstr(pData,aifIndexRight);

    NETCONF_NULL_BREAK(pRight);

    while (pLeft != pRight)
    {
        if ((*pLeft < '0') || (*pLeft > '9'))
        {
            return DATAPATH_ERR;
        }

        uiIfIndex = (uiIfIndex * 10) + *pLeft - '0';
        pLeft++;
    }

    if (uiIfIndex == 0)
    {
        return DATAPATH_ERR;
    }

    *puiIfIndex = uiIfIndex;

    return DATAPATH_OK;
}


unsigned int NETCONF_Get_Ifindex_ByIfname(struct nc_session * netconf_session, char ifName[], unsigned int *puiIfIndex)
{
    unsigned int    uiRet       = 0;
    unsigned int    uiLength    = 0;
    char            send_data[NETCONF_SEND_DATA_LEN] = {0};
    nc_rpc          *rpc                         = NULL;
    nc_reply        * reply = NULL;

    snprintf(send_data, NETCONF_SEND_DATA_LEN,
        "<get>"\
           "<filter type=\"subtree\">"\
           "<ifm xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
           "<interfaces>"\
           "<interface>"\
           "<ifName>%s</ifName>"\
           "<ifIndex></ifIndex>"\
           "</interface>"\
           "</interfaces>"\
           "</ifm>"\
           "</filter>"\
         "</get>", ifName);
    rpc = nc_rpc_generic(send_data);
    nc_session_send_recv(netconf_session, rpc, &reply);
    nc_rpc_free(rpc);
    rpc = NULL;

    if (nc_reply_get_type(reply) != NC_REPLY_DATA)
    {
        VLOG_ERR(LOG_MODULE, "[get_ifindex]Port:%s\n", ifName);
        VLOG_ERR(LOG_MODULE, "[get_ifindex]err: %s\n", nc_reply_get_errormsg(reply));
        nc_reply_free(reply);

        return DATAPATH_ERR;
    }

    uiRet = NETCONF_Get_Ifindex_FromMsg(nc_reply_get_data(reply), ifName, puiIfIndex);
    nc_reply_free(reply);

    return uiRet;
}


unsigned int NETCONF_Get_VlanInfo_ByVlanId(struct nc_session * netconf_session, unsigned int uiVlanId)
{
    unsigned int    uiRet       = 0;
    unsigned int    uiLength    = 0;
    //unsigned int    uiIfIndex     = 0;
    char            send_data[NETCONF_SEND_DATA_LEN] = {0};
    char            *pdata      = NULL;
    nc_rpc          *rpc                         = NULL;
    nc_reply        * reply = NULL;

    snprintf(send_data, NETCONF_SEND_DATA_LEN,
        "<get>"\
          "<filter type=\"subtree\">"\
          "<vlan xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
            "<vlans>"\
              "<vlan>"\
                "<vlanId>%d</vlanId>"\
                "<vlanName></vlanName>"\
                "<vlanDesc></vlanDesc>"\
                "<vlanType></vlanType>"\
                "<adminStatus></adminStatus>"\
                "<subVlans></subVlans>"\
                "<superVlan></superVlan>"\
              "</vlan>"\
            "</vlans>"\
          "</vlan>"\
          "</filter>"\
        "</get>", uiVlanId);
    rpc = nc_rpc_generic(send_data);
    nc_session_send_recv(netconf_session, rpc, &reply);
    nc_rpc_free(rpc);
    rpc = NULL;

    if (nc_reply_get_type(reply) != NC_REPLY_DATA)
    {
        VLOG_ERR(LOG_MODULE, "[get_ifindex]vlan:%d\n", uiVlanId);
        VLOG_ERR(LOG_MODULE, "[get_ifindex]err: %s\n", nc_reply_get_errormsg(reply));
        nc_reply_free(reply);

        return DATAPATH_ERR;
    }

    pdata = nc_reply_get_data(reply);

    if (pdata == NULL || strlen(pdata) == 0)
    {
        nc_reply_free(reply);
        return DATAPATH_ERR;
    }

    return DATAPATH_OK;
}


unsigned int NETCONF_Get_Vlanbit_FromMsg(char *pData, char aucIfName[], char *pVlanBitStr)
{
    char *pLeft  = NULL;
    char *pRight = NULL;
    char aifIndexLeft[]  = "<trunkVlans>";
    char aifIndexRight[] = "</trunkVlans>";
    char ch[] = ">";
    unsigned int i = 0;
    unsigned int uiIfIndex = 0;

    if(pData == NULL || strlen(pData) == 0)
    {
        return DATAPATH_ERR ;
    }

    NETCONF_NULL_BREAK(strstr(pData,aucIfName));

    pLeft=strstr(pData,aifIndexLeft);
    pLeft = pLeft + strlen(aifIndexLeft);
    NETCONF_NULL_BREAK(pLeft);

    pRight=strstr(pData,aifIndexRight);
    NETCONF_NULL_BREAK(pRight);

    strncpy(pVlanBitStr, pLeft, NETCONF_VLANBIT_LEN_STR);

    return DATAPATH_OK;
}


unsigned int NETCONF_Get_Vlanbit_ByIfname(struct nc_session * netconf_session, char ifName[], char netconfBit[])
{
    unsigned int    uiRet       = 0;
    unsigned int    uiLength    = 0;
    char            send_data[NETCONF_SEND_DATA_LEN] = {0};
    nc_rpc          *rpc                         = NULL;
    nc_reply        * reply = NULL;
    char            ucKeyDtat[]  = "trunkVlans";

    snprintf(send_data, NETCONF_SEND_DATA_LEN,
        "<get>"\
            "<filter type=\"subtree\">"\
                "<ethernet xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
                    "<ethernetIfs>"\
                        "<ethernetIf>"\
                            "<ifName>%s</ifName>"\
                            "<l2Enable></l2Enable>"\
                            "<vlanAssigns></vlanAssigns>"\
                            "<l2Attribute>"\
                                "<linkType></linkType>"\
                                "<pvid></pvid>"\
                                "<trunkVlans></trunkVlans>"\
                                "<untagVlans></untagVlans>"\
                                "<portBridgEnable></portBridgEnable>"\
                                "<taggedPacketDiscard></taggedPacketDiscard>"\
                                "<muxVlanEna>"\
                                    "<enableVlans></enableVlans>"\
                                "</muxVlanEna>"\
                            "</l2Attribute>"\
                        "</ethernetIf>"\
                    "</ethernetIfs>"\
                "</ethernet>"\
            "</filter>"\
        "</get>", ifName);

    rpc = nc_rpc_generic(send_data);
    nc_session_send_recv(netconf_session, rpc, &reply);

    nc_rpc_free(rpc);
    rpc = NULL;

    uiRet = nc_reply_get_type(reply);
    if (nc_reply_get_type(reply) != NC_REPLY_DATA)
    {
        VLOG_ERR(LOG_MODULE, "[get_vlanbit]Port:%s\n", ifName);
        VLOG_ERR(LOG_MODULE, "[get_vlanbit]err: %s\n", nc_reply_get_errormsg(reply));
        nc_reply_free(reply);

        return DATAPATH_ERR;
    }

    //pData = nc_reply_get_data(reply);

    uiRet = NETCONF_Get_Vlanbit_FromMsg(nc_reply_get_data(reply), ifName, netconfBit);
    nc_reply_free(reply);

    return uiRet;

}



unsigned int NETCONF_Clear_Config(struct nc_session * netconf_session, char aucVlanBit[], unsigned int uiPortNum, char *pucIfName)
{
    unsigned int uiRet = DATAPATH_ERR;

    /* 清vlan+port */
    NETCONF_Delete_All_Port_Vlan(netconf_session, uiPortNum, pucIfName);

    /* 清vlan */
    uiRet = NETCONF_Delete_Vlanbit(netconf_session, aucVlanBit);
    if (uiRet != NC_REPLY_OK)
    {
        ofp_fatal(0, "[port+vlan] delete port and vlan failed, ret = %d.", uiRet);
    }

    return DATAPATH_OK;
}


unsigned int NETCONF_Check_Port(struct nc_session * netconf_session, char *pucIfName, unsigned int uiPortNum, unsigned int *pifIndex)
{
    unsigned int uiLoop = 0;
    unsigned int uiRet  = 0;
    unsigned int uiIfIndex = 0;

    for(uiLoop = 0; uiLoop < uiPortNum; uiLoop++)
    {
        //(void)NETCONF_Set_Port_Trunk(netconf_session, pucIfName+uiLoop*NETCONF_IFNAME_LEN_MAX);
        uiRet = NETCONF_Get_Ifindex_ByIfname(netconf_session, pucIfName+uiLoop*NETCONF_IFNAME_LEN_MAX, &(pifIndex[uiLoop]));
        if (uiRet != DATAPATH_OK)
        {
            return DATAPATH_ERR;
        }
    }

    return DATAPATH_OK;
}


unsigned int NETCONF_Check_Vlan(struct nc_session * netconf_session, unsigned int auiVlans[], unsigned int uiVlanNum)
{
    unsigned int uiLoop = 0;
    unsigned int uiRet  = 0;
    unsigned int uiIfIndex = 0;

    for(uiLoop = 0; uiLoop < uiVlanNum; uiLoop++)
    {
        uiRet = NETCONF_Get_VlanInfo_ByVlanId(netconf_session, auiVlans[uiLoop]);
        if (uiRet == DATAPATH_OK)
        {
            VLOG_ERR(LOG_MODULE, "vlan%d has been created.", auiVlans[uiLoop]);
            return DATAPATH_ERR;
        }
    }

    return DATAPATH_OK;
}


unsigned int NETCONF_Send_Data(struct nc_session * netconf_session, char send_data[])
{
    nc_rpc          *rpc    = NULL;
    nc_reply        * reply = NULL;
    unsigned int    uiRet   = 0;

    rpc = nc_rpc_generic(send_data);
    nc_session_send_recv(netconf_session, rpc, &reply);

    nc_rpc_free(rpc);
    rpc = NULL;

    uiRet = nc_reply_get_type(reply);
    if (uiRet != NC_REPLY_OK)
    {
        VLOG_ERR(LOG_MODULE, "err_reply:%s\n", nc_reply_get_errormsg(reply));
    }

    nc_reply_free(reply);

    return uiRet;
}


unsigned int NETCONF_Del_Init(struct datapath *dp)
{
    unsigned int    i                                     = 0;
    unsigned int    uiRet                                 = 0;
    unsigned int    uiloop                                = 0;
    nc_rpc         *rpc                                   = NULL;
    nc_reply       *reply                                 = NULL;
    char            send_data[NETCONF_SEND_DATA_LEN]      = {0};
    char            netconfBit[NETCONF_VLANBIT_LEN_STR+1] = {0};

    struct nc_cpblts    * cpblts = NULL;
    struct nc_session   * netconf_session = NULL;

    VLOG_DBG(LOG_MODULE, "netconf init: ip:%s, username:%s\n", dp->ip, dp->username);
    cpblts = nc_cpblts_new(NULL);
    if (cpblts == NULL)
    {
        return DATAPATH_ERR;
    }

    nc_cpblts_add(cpblts, "urn:ietf:params:netconf:base:1.0");
    nc_cpblts_add(cpblts, "urn:ietf:params:netconf:capability:writable-running:1.0");
    nc_cpblts_add(cpblts, "urn:ietf:params:netconf:capability:candidate:1.0");
    nc_cpblts_add(cpblts, "urn:ietf:params:netconf:capability:confirmed-commit:1.0");
    nc_cpblts_add(cpblts, "http://www.huawei.com/netconf/capability/discard-commit/1.0");

    nc_cpblts_add(cpblts, "urn:ietf:params:netconf:capability:startup:1.0");
    nc_cpblts_add(cpblts, "urn:ietf:params:netconf:capability:rollback-on-error:1.0");
    nc_cpblts_add(cpblts, "http://www.huawei.com/netconf/capability/sync/1.1");
    nc_cpblts_add(cpblts, "http://www.huawei.com/netconf/capability/sync/1.0");
    nc_cpblts_add(cpblts, "http://www.huawei.com/netconf/capability/exchange/1.0");

    nc_cpblts_add(cpblts, "http://www.huawei.com/netconf/capability/active/1.0");
    nc_cpblts_add(cpblts, "http://www.huawei.com/netconf/capability/action/1.0");
    nc_cpblts_add(cpblts, "http://www.huawei.com/netconf/capability/execute-cli/1.0");
    nc_cpblts_add(cpblts, "http://www.huawei.com/netconf/capability/update/1.0");
    nc_cpblts_add(cpblts, "http://www.huawei.com/netconf/capability/commit-description/1.0");

    nc_cpblts_add(cpblts, "urn:ietf:params:netconf:capability:notification:1.0");
    nc_cpblts_add(cpblts, "urn:ietf:params:netconf:capability:interleave:1.0");

    netconf_session = nc_session_connect(dp->ip, NETCONF_PORT, dp->username, cpblts);
    if (netconf_session == NULL)
    {
        nc_cpblts_free(cpblts);
        cpblts = NULL;
        ofp_fatal(0, "session connect failed. ");
    }
/*
    uiRet = NETCONF_Check_Vlan(netconf_session, cpblts, dp->vlans, dp->vlannumber);
    if (uiRet != DATAPATH_OK)
    {
        nc_session_free(netconf_session);
        nc_cpblts_free(cpblts);
        cpblts = NULL;
        ofp_fatal(0, "There are some vlans that have been created.");
    }
*/
/* for test
    dp->portnumber = 2;
    strncpy(dp->ifname[0], "40GE1/0/3", 10);
    strncpy(dp->ifname[1], "40GE2/0/3", 10);
*/
    uiRet = NETCONF_Check_Port(netconf_session, (char *)(dp->ifname), dp->portnumber, dp->ifindex);
    /*if (uiRet != DATAPATH_OK)
    {
        nc_session_free(netconf_session);
        nc_cpblts_free(cpblts);
        cpblts = NULL;
        ofp_fatal(0, "There are some ports that do not exist.");
    }*/

    for (uiloop = 0; uiloop < dp->portnumber; uiloop++)
    {
        dp->ports[uiloop].port_no = dp->ifindex[uiloop];
    }

    NETCONF_Get_Confbit(dp->vlans, dp->vlannumber, dp->vlanBit);
    NETCONF_Vlanbit2NetVlanBit(dp->vlanBit, netconfBit);


    /* 删除vlan */
    uiRet = NETCONF_Delete_Vlanbit(netconf_session, netconfBit);
    if (uiRet != NC_REPLY_OK)
    {
        VLOG_ERR(LOG_MODULE, "[Error]: Failed to delete openflow vlan.\n");
        //nc_session_free(netconf_session);
        //nc_cpblts_free(cpblts);
        //cpblts = NULL;
        //ofp_fatal(0, "[vlan] reply_get failed.");
    }

    /* 端口退出VLAN并删除vlan*/

    memset(send_data,0,NETCONF_SEND_DATA_LEN);

    //uiRet = NETCONF_Clear_Config(netconf_session, cpblts, netconfBit, dp->portnumber, dp->ifname);

    //VLOG_DBG(LOG_MODULE, "Info: start to set port mode access\n");
    uiRet = NETCONF_Create_Port_access_all(netconf_session, dp->portnumber, (char *)(dp->ifname));

    // close NETCONF session
    nc_rpc_free(rpc);
    nc_reply_free(reply);
    nc_cpblts_free(cpblts);
    nc_session_free(netconf_session);
    //VLOG_DBG(LOG_MODULE, "Info: Vlan delete successfully.\n");
    return DATAPATH_OK;
}



unsigned int NETCONF_Create_Port_access_all(struct nc_session * netconf_session, unsigned int uiPortNum, char *pucIfName)
{
    unsigned int uiloop   = 0;
    unsigned int uiRet    = 0;

    /* 端口恢复access 模式 */
    for(uiloop = 0; uiloop < uiPortNum; uiloop++)
    {
        uiRet = NETCONF_Create_Port_access(netconf_session, pucIfName+uiloop*NETCONF_IFNAME_LEN_MAX);
    }
    return uiRet;
}

unsigned int NETCONF_Create_Port_access(struct nc_session * netconf_session, char ifName[])
{
    unsigned int    uiRet       = 0;
    unsigned int    uiLength    = 0;
    nc_rpc         *rpc         = NULL;
    nc_reply       *reply       = NULL;
    char            send_data[NETCONF_SEND_DATA_LEN] = {0};

    snprintf(send_data, NETCONF_SEND_DATA_LEN,
        "<edit-config>"\
          "<target><running/></target>"\
          "<default-operation>merge</default-operation>"\
          "<error-option>rollback-on-error</error-option>"\
          "<config>"\
          "<ethernet xmlns=\"http://www.huawei.com/netconf/vrp\" content-version=\"1.0\" format-version=\"1.0\">"\
            "<ethernetIfs>"\
              "<ethernetIf operation=\"merge\">"\
                "<ifName>%s</ifName>"\
                "<l2Attribute>"\
                  "<linkType>access</linkType>"\
                  "<pvid>1</pvid>"\
                "</l2Attribute>"\
              "</ethernetIf>"\
            "</ethernetIfs>"\
          "</ethernet>"\
          "</config>"\
        "</edit-config>", ifName);
    rpc = nc_rpc_generic(send_data);
    nc_session_send_recv(netconf_session, rpc, &reply);

    nc_rpc_free(rpc);
    rpc = NULL;

    uiRet = nc_reply_get_type(reply);
    if (uiRet != NC_REPLY_OK)
    {
        VLOG_ERR(LOG_MODULE, "[create_port_acess]Port:%s", ifName);
        VLOG_ERR(LOG_MODULE, "[create_port_acess]err: %s\n", nc_reply_get_errormsg(reply));
        nc_reply_free(reply);

        return DATAPATH_ERR;
    }

    nc_reply_free(reply);

    return DATAPATH_OK;

}

