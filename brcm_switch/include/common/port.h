#ifndef __PORT_H__
#define __PORT_H__

#define PORT_MAX 72

#define MCAST_TABLE_MAX 1024

#define LBG_TABLE_MAX 1024

#define PORT_NUM_MAX 128

typedef struct port_action{
    unsigned int  port_flag;
    unsigned int  port_no;
} ports_action;


enum PORT_STATUS
{
    PORT_DOWN    = 0,
    PORT_UP      = 1,
    PORT_NO_RECV = 2,
    PORT_BLOCK  = 3,
    PORT_ADD     = 4
};

enum PORT_DUPLEX
{
    PORT_HALF = 0,
    PORT_FULL = 1
};

enum PORT_ETH_MODE
{
    PORT_10M  = 10,
    PORT_100M = 100,
    PORT_1G   = 1000,
    PORT_10G  = 10000,
    PORT_40G  = 40000,
    PORT_100G = 100000
};

struct port_stats {
    unsigned int   port_no;
    unsigned long long int   rx_packets;   /* Number of received packets. */
    unsigned long long int   tx_packets;   /* Number of transmitted packets. */
    unsigned long long int   rx_bytes;     /* Number of received bytes. */
    unsigned long long int   tx_bytes;     /* Number of transmitted bytes. */
    unsigned long long int   rx_dropped;   /* Number of packets dropped by RX. */
    unsigned long long int   tx_dropped;   /* Number of packets dropped by TX. */
    unsigned long long int   rx_errors;    /* Number of receive errors. This is a super-set
                               of more specific receive errors and should be
                               greater than or equal to the sum of all
                               rx_*_err values. */
    unsigned long long int   tx_errors;    /* Number of transmit errors. This is a super-set
                               of more specific transmit errors and should be
                               greater than or equal to the sum of all
                               tx_*_err values (none currently defined.) */
    unsigned long long int   rx_frame_err; /* Number of frame alignment errors. */
    unsigned long long int   rx_over_err;  /* Number of packets with RX overrun. */
    unsigned long long int   rx_crc_err;   /* Number of CRC errors. */
    unsigned long long int   collisions;   /* Number of collisions. */
    unsigned int   duration_sec; /* Time port has been alive in seconds */
    unsigned int   duration_nsec; /* Time port has been alive in nanoseconds
                                 beyond duration_sec */
};

struct rbuff *port_rbuff;

extern struct rbuff *port_rbuff;
//
#define BRCM_PLATFORM
#ifdef BRCM_PLATFORM
#define CALL(fun) brcm_##fun
#else
#define CALL(fun) fun
#endif

#endif/*__PORT_H__*/
