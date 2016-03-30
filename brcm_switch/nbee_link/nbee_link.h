/*
 * nbee_link.h 
 *
 *  Created on: Jul 18, 2011
 *      Author: rdenicol
 */

#ifndef NBEE_LINK_H_
#define NBEE_LINK_H_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "lib/hmap.h"
#include "lib/ofpbuf.h"
#include "lib/packets.h"

#define ETHADDLEN 6
#define IPV6ADDLEN 16
#define ETHTYPELEN 2
#define ERRBUF_SIZE 256


typedef struct pcap_pkthdr {	/* needed to make Nbee happy */
	struct timeval ts;	/* time stamp */
	unsigned int caplen;	/* length of portion present */
	unsigned int len;	/* length this packet (off wire) */
}pcap_pkthdr_t;

// List used to store more than 1 value on the hash map... maybe we'll use it again on the future
//typedef struct field_values {
//       struct list list_node;
//	unsigned int len;
//        unsigned int pos;
//        unsigned char* value;
//}field_values_t;

struct packet_fields {
       struct hmap_node hmap_node;
       unsigned int header;                  /* OXM_* value. */
       unsigned int pos;
       unsigned char *value;              /* List of field values (In one packet, there may be more than one value per field) */
};

#ifdef __cplusplus
extern "C"
#endif
int nblink_initialize(void);

#ifdef __cplusplus
extern "C"
#endif
int nblink_packet_parse(struct ofpbuf * pktin, struct hmap * pktout, struct protocols_std * pkt_proto);

#endif /* NBEE_LINK_H_ */
