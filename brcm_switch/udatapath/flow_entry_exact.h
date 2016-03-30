#ifndef FLOW_ENTRY_EXACT_H
#define FLOW_ENTRY_EXACT_H 1

#include <stdbool.h>
#include <sys/types.h>
#include "datapath.h"
#include "list.h"
#include "flow_entry.h"
#include "flow_table.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl-messages.h"
#include "jhash.h"


#define EXACT_FLOW_TABLE_MAX_ENTRIES 143360  //  140k
#define EXACT_TABLE_CLASH_COUNT 40           // ³åÍ»Á´±íÊý
#define EXACT_FLOW_TABLE_MAX_ENTRIES_MODE  143357

void free_flow_key(unsigned char *ptr);
unsigned char *malloc_flow_key(int len);

struct hlist_head *exact_flow_entry_pos(unsigned int hash,struct flow_table *table);
unsigned int exact_flow_entry_hash(unsigned char *dst,unsigned long long int tbl_match,
                               struct ofl_match *match,int *key_len);
struct flow_entry *exact_flow_entry_lookup(struct flow_table *table,struct ofl_match  *match);
bool exact_flow_entry_overlaps(struct flow_table *table, struct ofl_msg_flow_mod *mod);


struct flow_entry *exact_flow_entry_create(struct datapath *dp,
                                                 struct flow_table *table,
                                                 struct ofl_msg_flow_mod *mod,
                                                 unsigned int hash,
                                                 unsigned char *key,
                                                 int  key_len);
void exact_flow_entry_timeout(struct flow_entry *entry);

#endif

