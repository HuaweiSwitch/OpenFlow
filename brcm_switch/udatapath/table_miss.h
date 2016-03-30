#ifndef TABLE_MISS_H
#define TABLE_MISS_H

struct flow_table *miss_table_create(struct datapath *dp, unsigned char table_id);

ofl_err miss_table_add(struct flow_table *table,
                       struct ofl_msg_flow_mod *mod,
                       bool *match_kept, bool *insts_kept);

ofl_err miss_table_modify(struct flow_table *table,
                          struct ofl_msg_flow_mod *mod,
                          bool strict, bool *insts_kept);

ofl_err miss_table_delete(struct flow_table *table,
                          struct ofl_msg_flow_mod *mod, bool strict);

struct ofl_flow_stats*
miss_table_lookup_stats(struct flow_table *table);

struct flow_table *miss_table_create(struct datapath *dp,
                                         unsigned char table_id);
#endif