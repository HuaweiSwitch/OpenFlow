/*-
 * Copyright (c) 2008, 2009
 *      The Board of Trustees of The Leland Stanford Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation that
 * others will use, modify and enhance the Software and contribute those
 * enhancements back to the community. However, since we would like to make the
 * Software available for broadest use, with as few restrictions as possible
 * permission is hereby granted, free of charge, to any person obtaining a copy
 * of this Software to deal in the Software under the copyrights without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any derivatives
 * without specific, written prior permission.
 */

#ifndef OFPSTAT_H_
#define OFPSTAT_H_

struct ofp_header;

struct ofpstat {
	unsigned long long int ofps_total;
	unsigned long long int ofps_unknown;

	unsigned long long int ofps_hello;
	unsigned long long int ofps_error;
	struct {
		unsigned long long int hello_fail;
		unsigned long long int bad_request;
		unsigned long long int bad_action;
		unsigned long long int flow_mod_fail;
		unsigned long long int unknown;
	} ofps_error_type;
	struct {
		unsigned long long int hf_incompat;
		unsigned long long int hf_eperm;
		unsigned long long int br_bad_version;
		unsigned long long int br_bad_type;
		unsigned long long int br_bad_stat;
		unsigned long long int br_bad_vendor;
		unsigned long long int br_eperm;
		unsigned long long int ba_bad_type;
		unsigned long long int ba_bad_len;
		unsigned long long int ba_bad_vendor;
		unsigned long long int ba_bad_vendor_type;
		unsigned long long int ba_bad_out_port;
		unsigned long long int ba_bad_argument;
		unsigned long long int ba_eperm;
		unsigned long long int fmf_all_tables_full;
		unsigned long long int fmf_overlap;
		unsigned long long int fmf_eperm;
		unsigned long long int fmf_emerg;
		unsigned long long int unknown;
	} ofps_error_code;
	unsigned long long int ofps_echo_request;
	unsigned long long int ofps_echo_reply;
	unsigned long long int ofps_vendor;
	unsigned long long int ofps_feats_request;
	unsigned long long int ofps_feats_reply;
	unsigned long long int ofps_get_config_request;
	unsigned long long int ofps_get_config_reply;
	unsigned long long int ofps_set_config;
	unsigned long long int ofps_packet_in;
	unsigned long long int ofps_flow_removed;
	unsigned long long int ofps_port_status;
	unsigned long long int ofps_packet_out;
	unsigned long long int ofps_flow_mod;
	struct {
		unsigned long long int add;
		unsigned long long int modify;
		unsigned long long int modify_strict;
		unsigned long long int delete;
		unsigned long long int delete_strict;
		unsigned long long int unknown;
	} ofps_flow_mod_ops;
	unsigned long long int ofps_port_mod;
	unsigned long long int ofps_stats_request;
	unsigned long long int ofps_stats_reply;
	unsigned long long int ofps_barrier_request;
	unsigned long long int ofps_barrier_reply;
};

void ofpstat_inc_protocol_stat(struct ofpstat *, struct ofp_header *);

#endif
