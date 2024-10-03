/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2025 by Paolo Lucente
*/

/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* includes */
#include "pmacct.h"
#include "bgp/bgp.h"
#include "bmp.h"
#include "pmacct_gauze_lib/pmacct_gauze_lib.h"

#if defined WITH_RABBITMQ
#include "amqp_common.h"
#endif
#ifdef WITH_KAFKA
#include "kafka_common.h"
#endif

#ifndef PMACCT_GAUZE_BUILD
static Opaque_ContextCache *bmp_context_cache = NULL;

extern Opaque_ContextCache *bmp_context_cache_get() {
  if (!bmp_context_cache)
    bmp_context_cache = netgauze_make_Opaque_ContextCache();

  return bmp_context_cache;
}

Opaque_BmpParsingContext *bmp_parsing_context_get(struct bmp_peer *bmp_peer) {
  Opaque_ContextCache *context_cache = bmp_context_cache_get();
  Opaque_BmpParsingContext *ctx = netgauze_context_cache_get(context_cache, bmp_peer);
  if (ctx) return ctx;

  return netgauze_context_cache_set(context_cache, bmp_peer, netgauze_make_Opaque_BmpParsingContext());
}

void bmp_parsing_context_clear(struct bmp_peer *bmp_peer) {
  if (bmp_context_cache)
    netgauze_context_cache_delete(bmp_context_cache, bmp_peer);
}
#endif

u_int32_t bmp_process_packet(char *bmp_packet, u_int32_t len, struct bmp_peer *bmpp, int *do_term) {

  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;
  char *bmp_packet_ptr = bmp_packet;
  u_int32_t pkt_remaining_len, msg_start_len;

  struct bmp_common_hdr *bch = NULL;

  if (do_term) (*do_term) = FALSE;
  if (!bmpp) return FALSE;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return FALSE;

  for (msg_start_len = pkt_remaining_len = len; pkt_remaining_len; msg_start_len = pkt_remaining_len) {
    BmpParseResult parse_result = netgauze_bmp_parse_packet_with_context(bmp_packet_ptr, pkt_remaining_len,
                                                                         bmp_parsing_context_get(bmpp));

    if (parse_result.tag == CResult_Err) {
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] packet discarded: %s\n", config.name, bms->log_str, peer->addr_str,
          bmp_parse_error_str(parse_result.err));
      bmp_parse_result_free(parse_result);
      return msg_start_len;
    }

    ParsedBmp parsed_bmp = parse_result.ok;
    bch = &parsed_bmp.common_header;

    Log(LOG_INFO, "INFO ( %s/%s ): [%s] packet received version %u, length %u, type %u\n", config.name, bms->log_str,
        peer->addr_str, bch->version, bch->len, bch->type);

    peer->version = bch->version;

    if (bch->type <= BMP_MSG_TYPE_MAX) {
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%s] [common] type: %s (%u)\n",
          config.name, bms->log_str, peer->addr_str, bmp_msg_types[bch->type], bch->type);
    }

    switch (bch->type) {
      case BMP_MSG_ROUTE_MONITOR:
        bmp_process_msg_route_monitor(bmpp, &parsed_bmp);
        break;
      case BMP_MSG_STATS:
        bmp_process_msg_stats(bmpp, &parsed_bmp);
        break;
      case BMP_MSG_PEER_DOWN:
        bmp_process_msg_peer_down(bmpp, &parsed_bmp);
        break;
      case BMP_MSG_PEER_UP:
        bmp_process_msg_peer_up(bmpp, &parsed_bmp);
        break;
      case BMP_MSG_INIT:
        bmp_process_msg_init(bmpp, &parsed_bmp);
        break;
      case BMP_MSG_TERM:
        bmp_process_msg_term(bmpp, &parsed_bmp);
        if (do_term) (*do_term) = TRUE;
        break;
      case BMP_MSG_ROUTE_MIRROR:
        bmp_process_msg_route_mirror(bmpp);
        break;

      default:
        Log(LOG_INFO, "INFO ( %s/%s ): [%s] packet discarded: unknown message type (%u)\n",
            config.name, bms->log_str, peer->addr_str, bch->type);
        break;
    }

    /* move forward to next bmp message in the packet */
    bmp_jump_offset(&bmp_packet_ptr, &pkt_remaining_len, parsed_bmp.read_bytes);

    bmp_parse_result_free(parse_result);
  }
  return FALSE;
}

void bmp_process_msg_init(struct bmp_peer *bmpp, ParsedBmp *parsed_bmp) {
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;
  struct bmp_data bdata = { 0 };

  /* TLV vars */
  struct bmp_tlv_hdr *bth;
  u_int16_t bmp_tlv_type, bmp_tlv_len;
  char *bmp_tlv_value;
  struct cdada_list_t *tlvs = NULL;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  memset(&bdata, 0, sizeof(bdata));

  tlvs = bmp_tlv_list_new_v2();
  if (!tlvs) return;

  BmpTlvListResult tlv_result = netgauze_bmp_get_tlvs(parsed_bmp->message);
  if (tlv_result.tag == CResult_Err) {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] [init] netgauze_bmp_get_tlvs failed.\n", config.name, bms->log_str,
        peer->addr_str);
    return;
  }

  CSlice_bmp_log_tlv tlv_slice = tlv_result.ok;

  for (struct bmp_log_tlv *tlv = tlv_slice.base_ptr; tlv && tlv < tlv_slice.end_ptr; tlv += 1) {
    if (bmp_tlv_list_add(tlvs, tlv->pen, tlv->type, tlv->len, tlv->val) == ERR) {
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] [init] bmp_tlv_list_add() failed.\n", config.name, bms->log_str,
          peer->addr_str);
      exit_gracefully(1);
    }
  }

  /* Init message does not contain a timestamp */
  gettimeofday(&bdata.tstamp_arrival, NULL);
  memset(&bdata.tstamp, 0, sizeof(struct timeval));

  if (bms->msglog_backend_methods) {
    char event_type[] = "log";

    bmp_log_msg(peer, &bdata, tlvs, &bmp_logdump_tag, NULL, bgp_peer_log_seq_get(&bms->log_seq), event_type,
                config.bmp_daemon_msglog_output, BMP_LOG_TYPE_INIT);
  }

  if (bms->dump_backend_methods) bmp_dump_se_ll_append(peer, &bdata, tlvs, NULL, BMP_LOG_TYPE_INIT);

  if (bms->msglog_backend_methods || bms->dump_backend_methods) bgp_peer_log_seq_increment(&bms->log_seq);

  if (!cdada_list_size(tlvs) || !bms->dump_backend_methods) bmp_tlv_list_destroy_v2(tlvs);
}

void bmp_process_msg_term(struct bmp_peer *bmpp, const ParsedBmp *parsed_bmp) {
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;
  struct bmp_data bdata = { 0 };

  /* TLV vars */
  struct bmp_tlv_hdr *bth;
  u_int16_t bmp_tlv_type, bmp_tlv_len;
  char *bmp_tlv_value;
  struct cdada_list_t *tlvs = NULL;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  memset(&bdata, 0, sizeof(bdata));

  tlvs = bmp_tlv_list_new_v2();
  if (!tlvs) return;

  /* Term message does not contain a timestamp */
  gettimeofday(&bdata.tstamp_arrival, NULL);
  memset(&bdata.tstamp, 0, sizeof(struct timeval));

  tlvs = bmp_tlv_list_new(NULL, bmp_tlv_list_node_del);
  if (!tlvs) return;

  BmpTlvListResult tlv_result = netgauze_bmp_get_tlvs(parsed_bmp->message);
  if (tlv_result.tag == CResult_Err) {
    Log(LOG_ERR, "ERROR ( %s/%s ): [%s] [init] netgauze_bmp_get_tlvs failed.\n", config.name, bms->log_str,
        peer->addr_str);
    return;
  }

  CSlice_bmp_log_tlv tlv_slice = tlv_result.ok;

  for (struct bmp_log_tlv *tlv = tlv_slice.base_ptr; tlv && tlv < tlv_slice.end_ptr; tlv += 1) {
    if (bmp_tlv_list_add(tlvs, tlv->pen, tlv->type, tlv->len, tlv->val) == ERR) {
      Log(LOG_ERR, "ERROR ( %s/%s ): [%s] [init] bmp_tlv_list_add() failed.\n", config.name, bms->log_str,
          peer->addr_str);
      exit_gracefully(1);
    }
  }

  if (bms->msglog_backend_methods) {
    char event_type[] = "log";

    bmp_log_msg(peer, &bdata, tlvs, &bmp_logdump_tag, NULL, bgp_peer_log_seq_get(&bms->log_seq), event_type,
                config.bmp_daemon_msglog_output, BMP_LOG_TYPE_TERM);
  }

  if (bms->dump_backend_methods) bmp_dump_se_ll_append(peer, &bdata, tlvs, NULL, BMP_LOG_TYPE_TERM);

  if (bms->msglog_backend_methods || bms->dump_backend_methods) bgp_peer_log_seq_increment(&bms->log_seq);

  if (!cdada_list_size(tlvs) || !bms->dump_backend_methods) bmp_tlv_list_destroy_v2(tlvs);

  CSlice_free_bmp_log_tlv(tlv_slice);

  /* BGP peers are deleted as part of bmp_peer_close() */
}

void
bmp_process_msg_peer_up(struct bmp_peer *bmpp, const ParsedBmp *netgauze_parsed) {
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  BmpPeerHdrDataResult bdata_res = netgauze_bmp_peer_hdr_get_data(netgauze_parsed->message);
  if (bdata_res.tag == CResult_Err) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] netgauze could not get bmp peer header data\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }
  struct bmp_data bdata = bdata_res.ok;

  if (!bdata.family) return;

  gettimeofday(&bdata.tstamp_arrival, NULL);

  struct bgp_peer bgp_peer_loc = { 0 }, bgp_peer_rem = { 0 }, *bmpp_bgp_peer;
  struct bmp_chars bmed_bmp = { 0 };
  void *ret = NULL;

  BmpPeerUpHdrResult peer_up_hdr_res = netgauze_bmp_peer_up_get_hdr(netgauze_parsed->message);
  if (peer_up_hdr_res.tag == CResult_Err) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] netgauze could not get bmp peer up header\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }
  struct bmp_log_peer_up blpu = peer_up_hdr_res.ok;

  bgp_peer_loc.type = FUNC_TYPE_BMP;
  bgp_msg_data_set_data_bmp(&bmed_bmp, &bdata);

  BmpPeerUpOpenResult peer_up_open_tx = netgauze_bmp_peer_up_get_open_tx(netgauze_parsed->message);
  if (peer_up_open_tx.tag == CResult_Err) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] netgauze could not get bmp open tx\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }

  netgauze_bgp_process_open(peer_up_open_tx.ok.message, &bgp_peer_loc);

  memcpy(&bmpp->self.id, &bgp_peer_loc.id, sizeof(struct host_addr));
  memcpy(&bgp_peer_loc.addr, &blpu.local_ip, sizeof(struct host_addr));

  bgp_peer_rem.type = FUNC_TYPE_BMP;

  BmpPeerUpOpenResult peer_up_open_rx = netgauze_bmp_peer_up_get_open_rx(netgauze_parsed->message);
  if (peer_up_open_rx.tag == CResult_Err) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] netgauze could not get bmp open rx\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }

  netgauze_bgp_process_open(peer_up_open_rx.ok.message, &bgp_peer_rem);

  memcpy(&bgp_peer_rem.addr, &bdata.peer_ip, sizeof(struct host_addr));

  /* sync capabilities between loc/rem and remote->id becomes remote->addr */
  bmpp_bgp_peer = bmp_sync_loc_rem_peers(&bgp_peer_loc, &bgp_peer_rem);
  bmpp_bgp_peer->log = bmpp->self.log;
  bmpp_bgp_peer->bmp_se = bmpp; /* using bmp_se field to back-point a BGP peer to its parent BMP peer */
  bmpp_bgp_peer->peer_distinguisher = bdata.chars.rd;

  /* Search (or create if not existing) the BGP peer structure for this peer_up msg */if (bdata.family == AF_INET) {
    ret = pm_tsearch(bmpp_bgp_peer, &bmpp->bgp_peers_v4, bgp_peer_cmp_bmp, sizeof(struct bgp_peer));
  } else if (bdata.family == AF_INET6) {
    ret = pm_tsearch(bmpp_bgp_peer, &bmpp->bgp_peers_v6, bgp_peer_cmp_bmp, sizeof(struct bgp_peer));
  }

  if (!ret)
        Log(LOG_WARNING, "WARN ( %s/%s ): [%s] [peer up] tsearch() unable to insert.\n", config.name, bms->log_str,
            peer->addr_str);

  BmpTlvListResult tlv_result = netgauze_bmp_get_tlvs(netgauze_parsed->message);
  if (tlv_result.tag == CResult_Err) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] netgauze could not get bmp peer up tlvs\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }

  struct pm_list *tlvs = bmp_tlv_list_new(NULL, bmp_tlv_list_node_del);
  if (!tlvs) return;

  CSlice_bmp_log_tlv tlv_list = tlv_result.ok;
  for (struct bmp_log_tlv *tlv = tlv_list.base_ptr; tlv && tlv < tlv_list.end_ptr; tlv += 1) {
      if (bmp_tlv_list_add(tlvs, tlv->pen, tlv->type, tlv->len, tlv->val) == ERR) {
        Log(LOG_ERR, "INFO ( %s/%s ): [%s] [peer up] bmp_tlv_list_add failed\n",
            config.name, bms->log_str, peer->addr_str);
        bmp_tlv_list_destroy_v2(tlvs);
        return;
      }

      bmp_tlv_hdr_get_type(bth, &bmp_tlv_type);
      bmp_tlv_hdr_get_len(bth, &bmp_tlv_len);
      if (bmp_tlv_handle_ebit(&bmp_tlv_type)) {
        if (!(bmp_tlv_get_pen(bmp_packet, len, &bmp_tlv_len, &pen))) {
          Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer up] packet discarded: failed bmp_tlv_get_pen()\n",
              config.name, bms->log_str, peer->addr_str);
          bmp_tlv_list_destroy_v2(tlvs);
          return;
        }
      }

      if (!(bmp_tlv_value = bmp_get_and_check_length(bmp_packet, len, bmp_tlv_len))) {
        Log(LOG_INFO,
            "INFO ( %s/%s ): [%s] [peer up] packet discarded: failed bmp_get_and_check_length() BMP TLV info\n",
            config.name, bms->log_str, peer->addr_str);
        bmp_tlv_list_destroy_v2(tlvs);
        return;
      }

      ret2 = bmp_tlv_list_add(tlvs, pen, bmp_tlv_type, bmp_tlv_len, bmp_tlv_value);
      if (ret2 == ERR) {
        Log(LOG_ERR, "ERROR ( %s/%s ): [%s] [peer up] bmp_tlv_list_add() failed.\n", config.name, bms->log_str,
            peer->addr_str);
        exit_gracefully(1);
      }
  }

  if (bms->msglog_backend_methods) {
    char event_type[] = "log";

    bmp_log_msg(peer, &bdata, tlvs, &bmp_logdump_tag, &blpu, bgp_peer_log_seq_get(&bms->log_seq), event_type,
                    config.bmp_daemon_msglog_output, BMP_LOG_TYPE_PEER_UP);
  }

  if (bms->dump_backend_methods) bmp_dump_se_ll_append(peer, &bdata, tlvs, &blpu, BMP_LOG_TYPE_PEER_UP);

  if (bms->msglog_backend_methods || bms->dump_backend_methods) bgp_peer_log_seq_increment(&bms->log_seq);

  if (!cdada_list_size(tlvs) || !bms->dump_backend_methods) bmp_tlv_list_destroy_v2(tlvs);
}

void bmp_process_msg_peer_down(struct bmp_peer *bmpp, const ParsedBmp *parsed_bmp) {
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer, *bmpp_bgp_peer;
  void *ret = NULL;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  BmpPeerHdrDataResult peer_hdr_result = netgauze_bmp_peer_hdr_get_data(parsed_bmp->message);
  if (peer_hdr_result.tag == CResult_Err) {
    Log(LOG_INFO,
        "INFO ( %s/%s ): [%s] [peer down] packet discarded: pmacct-gauze could not convert peer header\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }
  struct bmp_data bdata = peer_hdr_result.ok;

  if (!bdata.family) return;

  gettimeofday(&bdata.tstamp_arrival, NULL);

  BmpPeerDownInfoResult peer_down_result = netgauze_bmp_peer_down_get_info(parsed_bmp->message);
  if (peer_down_result.tag == CResult_Err) {
    Log(LOG_INFO,
        "INFO ( %s/%s ): [%s] [peer down] packet discarded: pmacct-gauze could not get peer down info\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }
  struct bmp_log_peer_down blpd = peer_down_result.ok;

  /* TLV vars */
  struct pm_list *tlvs = NULL;
  /* draft-ietf-grow-bmp-tlv */
  if (peer->version == BMP_V4) {
    // TODO handle when netgauze supports bmpv4
  }

  if (bms->msglog_backend_methods) {
    char event_type[] = "log";

    bmp_log_msg(peer, &bdata, tlvs, &bmp_logdump_tag, &blpd, bgp_peer_log_seq_get(&bms->log_seq), event_type,
                config.bmp_daemon_msglog_output, BMP_LOG_TYPE_PEER_DOWN);
  }

  if (bms->dump_backend_methods) bmp_dump_se_ll_append(peer, &bdata, tlvs, &blpd, BMP_LOG_TYPE_PEER_DOWN);

  if (bms->msglog_backend_methods || bms->dump_backend_methods) bgp_peer_log_seq_increment(&bms->log_seq);

  if (tlvs && (!pm_listcount(tlvs) || !bms->dump_backend_methods)) bmp_tlv_list_destroy(tlvs);

  /* Find the relevant BGP peer (matching peer_ip and peer_distinguisher) */
  if (bdata.family == AF_INET) {
    ret = pm_tfind(&bdata, &bmpp->bgp_peers_v4, bgp_peer_host_addr_peer_dist_cmp);
  } else if (bdata.family == AF_INET6) {
    ret = pm_tfind(&bdata, &bmpp->bgp_peers_v6, bgp_peer_host_addr_peer_dist_cmp);
  }

  if (ret) {
    bmpp_bgp_peer = (*(struct bgp_peer **) ret);

    bgp_peer_info_delete(bmpp_bgp_peer);

    if (bdata.family == AF_INET) {
      pm_tdelete(&bdata, &bmpp->bgp_peers_v4, bgp_peer_host_addr_peer_dist_cmp);
    } else if (bdata.family == AF_INET6) {
      pm_tdelete(&bdata, &bmpp->bgp_peers_v6, bgp_peer_host_addr_peer_dist_cmp);
    }
  }
  /* missing BMP peer up message, ie. case of replay/replication of BMP messages */
  else {
    char peer_ip[INET6_ADDRSTRLEN];

    addr_to_str(peer_ip, &bdata.peer_ip);

    if (!log_notification_isset(&bmpp->missing_peer_up, bdata.tstamp_arrival.tv_sec)) {
      log_notification_set(&bmpp->missing_peer_up, bdata.tstamp_arrival.tv_sec, BMP_MISSING_PEER_UP_LOG_TOUT);
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] [peer down] packet discarded: missing peer up BMP message for peer %s\n",
          config.name, bms->log_str, peer->addr_str, peer_ip);

    }
  }
}

void bmp_process_msg_route_monitor(struct bmp_peer *bmpp, const ParsedBmp *netgauze_parsed) {
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer, *bmpp_bgp_peer;
  void *ret = NULL;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  BmpPeerHdrDataResult bdata_result = netgauze_bmp_peer_hdr_get_data(netgauze_parsed->message);
  if (bdata_result.tag == CResult_Err) {
    Log(LOG_INFO,
        "INFO ( %s/%s ): [%s] [route monitor] netgauze could not get bmp peer up header\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }
  struct bmp_data bdata = bdata_result.ok;

  if (!bdata.family) return;

  gettimeofday(&bdata.tstamp_arrival, NULL);

  /* Find the relevant BGP peer (matching peer_ip and peer_distinguisher) */
  if (bdata.family == AF_INET) {
    ret = pm_tfind(&bdata, &bmpp->bgp_peers_v4, bgp_peer_host_addr_peer_dist_cmp);
  } else if (bdata.family == AF_INET6) {
    ret = pm_tfind(&bdata, &bmpp->bgp_peers_v6, bgp_peer_host_addr_peer_dist_cmp);
  }

  /* missing BMP peer up message, ie. case of replay/replication of BMP messages */
  if (!ret) {
    if (!log_notification_isset(&bmpp->missing_peer_up, bdata.tstamp_arrival.tv_sec)) {
      char peer_ip[INET6_ADDRSTRLEN];

      addr_to_str(peer_ip, &bdata.peer_ip);

      log_notification_set(&bmpp->missing_peer_up, bdata.tstamp_arrival.tv_sec, BMP_MISSING_PEER_UP_LOG_TOUT);
      Log(LOG_INFO, "INFO ( %s/%s ): [%s] [route monitor] packet discarded: missing peer up BMP message for peer %s\n",
          config.name, bms->log_str, peer->addr_str, peer_ip);
    }
    return;
  }

  /* peer up found -> parse route monitoring data */

  struct bmp_chars bmed_bmp = { 0 };
  struct bgp_msg_data bmd = { 0 };

  struct cdada_list_t *tlvs = NULL;
  char **bgp_pdu_ptrptr = NULL, *bgp_pdu_ptr = NULL;
  u_int32_t *bgp_pdu_lenptr = NULL, bgp_pdu_len;

  bmpp_bgp_peer = (*(struct bgp_peer **) ret);

  bmd.peer = bmpp_bgp_peer;
  bmd.extra.id = BGP_MSG_EXTRA_DATA_BMP;
  bmd.extra.len = sizeof(bmed_bmp);
  bmd.extra.data = &bmed_bmp;
  bgp_msg_data_set_data_bmp(&bmed_bmp, &bdata);

  compose_timestamp(bms->log_tstamp_str, SRVBUFLEN, &bdata.tstamp, TRUE,
                    config.timestamps_since_epoch, config.timestamps_rfc3339,
                    config.timestamps_utc);

  encode_tstamp_arrival(bms->log_tstamp_str, SRVBUFLEN, &bdata.tstamp_arrival, TRUE);

  BgpUpdateResult bgp_result = netgauze_bgp_update_get_updates(&bmpp->self, netgauze_parsed->message);

  if (bgp_result.tag == CResult_Err) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [route monitor] packet discarded: could not read BGP PDUs from Netgauze code=%d\n",
        config.name, bms->log_str, peer->addr_str, bgp_result.err.tag);
    return;
  }

  ParsedBgpUpdate bgp_parsed = bgp_result.ok;

  ProcessPacket *pkt = NULL;
  for (int i = 0; i < bgp_parsed.packets.len; i += 1) {
    pkt = &bgp_parsed.packets.base_ptr[i];

    switch (pkt->update_type) {
      case BGP_NLRI_UPDATE:
        bgp_process_update(&bmd, &pkt->prefix, &pkt->attr, &pkt->attr_extra, pkt->afi, pkt->safi, i);
        break;
      case BGP_NLRI_WITHDRAW:
        bgp_process_withdraw(&bmd, &pkt->prefix, &pkt->attr, &pkt->attr_extra, pkt->afi, pkt->safi, i);
        break;
      case BGP_NLRI_EOR: {
        // this is EoR
        struct bgp_info ri = { 0 };
        ri.bmed = bmd.extra;
        ri.peer = bmd.peer;
        bgp_peer_log_msg(NULL, &ri, pkt->afi, pkt->safi, bms->tag, "log", bms->msglog_output, NULL, BGP_LOG_TYPE_EOR);
        break;
      }
      default: {
        Log(LOG_INFO,
            "INFO ( %s/%s ): [%s] [route monitor] packet discarded: unknown update type received from pmacct-gauze\n",
            config.name, bms->log_str, peer->addr_str);
      }
    }
  }

  // Unintern all temporary structures
  if (pkt) {
    if (pkt->attr.community) community_unintern(peer, pkt->attr.community);
    if (pkt->attr.lcommunity) lcommunity_unintern(peer, pkt->attr.lcommunity);
    if (pkt->attr.ecommunity) ecommunity_unintern(peer, pkt->attr.ecommunity);
    if (pkt->attr.aspath) aspath_unintern(peer, pkt->attr.aspath);
  }

  CSlice_free_ProcessPacket(bgp_parsed.packets);

  bmp_tlv_list_destroy_v2(bmed_bmp.tlvs);
}

void bmp_process_msg_route_mirror(struct bmp_peer *bmpp) {
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  Log(LOG_INFO,
      "INFO ( %s/%s ): [%s] [route mirror] packet discarded: Unicorn! Message type currently not supported.\n",
      config.name, bms->log_str, peer->addr_str);

  // XXX: maybe support route mirroring
}

void bmp_process_msg_stats(struct bmp_peer *bmpp, const ParsedBmp *parsed_bmp) {
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer;

  /* unknown stats TLVs */
  char *cnt_value;
  struct cdada_list_t *tlvs = NULL;

  if (!bmpp) return;

  peer = &bmpp->self;
  bms = bgp_select_misc_db(peer->type);

  if (!bms) return;

  BmpPeerHdrDataResult bdata_result = netgauze_bmp_peer_hdr_get_data(parsed_bmp->message);
  if (bdata_result.tag == CResult_Err) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [stats] netgauze could not get bmp peer header data\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }
  struct bmp_data bdata = bdata_result.ok;

  BmpStatsResult stats_result = netgauze_bmp_stats_get_stats(parsed_bmp->message);
  if (stats_result.tag == CResult_Err) {
    Log(LOG_INFO, "INFO ( %s/%s ): [%s] [stats] netgauze could not get stats count\n",
        config.name, bms->log_str, peer->addr_str);
    return;
  }

  CSlice_bmp_log_stats stats = stats_result.ok;

  if (!bdata.family) goto cleanup;

  gettimeofday(&bdata.tstamp_arrival, NULL);

  for (int index = 0; index < stats.len; index++) {
    // TODO handle tlvs when bmpv4 is supported by netgauze
    tlvs = NULL;
    struct bmp_log_stats stat = stats.base_ptr[index];

    if (bms->msglog_backend_methods)
      bmp_log_msg(peer, &bdata, tlvs, &bmp_logdump_tag, &stat, bgp_peer_log_seq_get(&bms->log_seq), "log",
                  config.bmp_daemon_msglog_output, BMP_LOG_TYPE_STATS);

    if (bms->dump_backend_methods&& !config.bmp_dump_exclude_stats) bmp_dump_se_ll_append(peer, &bdata, tlvs, &stat, BMP_LOG_TYPE_STATS);

    if (bms->msglog_backend_methods || bms->dump_backend_methods) bgp_peer_log_seq_increment(&bms->log_seq);

    if (tlvs && (!pm_listcount(tlvs) || !bms->dump_backend_methods)) bmp_tlv_list_destroy_v2(tlvs);
  }

cleanup:
  CSlice_free_bmp_log_stats(stats);
}

void bmp_common_hdr_get_len(struct bmp_common_hdr *bch, u_int32_t *len) {
  if (bch && len) (*len) = ntohl(bch->len);
}

void bmp_tlv_hdr_get_type(struct bmp_tlv_hdr *bth, u_int16_t *type) {
  if (bth && type) (*type) = ntohs(bth->type);
}

void bmp_tlv_hdr_get_len(struct bmp_tlv_hdr *bth, u_int16_t *len) {
  if (bth && len) (*len) = ntohs(bth->len);
}

void bmp_tlv_hdr_get_index(char *idx_ptr, u_int16_t *idx)
{
  if (idx_ptr && idx) (*idx) = ntohs((u_int16_t) *idx_ptr);
}

void bmp_term_hdr_get_reason_type(char **bmp_packet, u_int32_t *pkt_size, u_int16_t *type)
{
  char *ptr;

  if (bmp_packet && (*bmp_packet) && pkt_size && type) {
    ptr = bmp_get_and_check_length(bmp_packet, pkt_size, 2);

    if (ptr) {
      memcpy(type, ptr, 2);
      (*type) = ntohs((*type));
    }
  }
}

void bmp_peer_hdr_get_v_flag(struct bmp_peer_hdr *bph, u_int8_t *family) {
  u_int8_t version;

  if (bph && family) {
    version = (bph->flags & BMP_PEER_FLAGS_ARI_V);
    (*family) = FALSE;

    if (version == 0) (*family) = AF_INET;
    else (*family) = AF_INET6;
  }
}

void bmp_peer_hdr_get_l_flag(struct bmp_peer_hdr *bph, u_int8_t *is_post) {
  if (bph && is_post) {
    if (bph->flags & BMP_PEER_FLAGS_ARI_L) (*is_post) = TRUE;
    else (*is_post) = FALSE;
  }
}

void bmp_peer_hdr_get_a_flag(struct bmp_peer_hdr *bph, u_int8_t *is_2b_asn) {
  if (bph && is_2b_asn) {
    if (bph->flags & BMP_PEER_FLAGS_ARI_A) (*is_2b_asn) = TRUE;
    else (*is_2b_asn) = FALSE;
  }
}

void bmp_peer_hdr_get_f_flag(struct bmp_peer_hdr *bph, u_int8_t *is_filtered) {
  if (bph && is_filtered) {
    if (bph->flags & BMP_PEER_FLAGS_LR_F) (*is_filtered) = TRUE;
    else (*is_filtered) = FALSE;
  }
}

void bmp_peer_hdr_get_o_flag(struct bmp_peer_hdr *bph, u_int8_t *is_out) {
  if (bph && is_out) {
    if (bph->flags & BMP_PEER_FLAGS_ARO_O) (*is_out) = TRUE;
    else (*is_out) = FALSE;
  }
}

void bmp_peer_hdr_get_peer_ip(struct bmp_peer_hdr *bph, struct host_addr *a, u_int8_t *family) {
  if (bph && a) {
    if ((*family) == AF_INET) a->address.ipv4.s_addr = bph->addr[3];
    else if ((*family) == AF_INET6) memcpy(&a->address.ipv6, &bph->addr, 16);
    else {
      memset(a, 0, sizeof(struct host_addr));
      if (!bph->addr[0] && !bph->addr[1] && !bph->addr[2] && !bph->addr[3]) {
        (*family) = AF_INET; /* we just set this up to something non-zero */
      }
    }

    a->family = (*family);
  }
}

void bmp_peer_hdr_get_bgp_id(struct bmp_peer_hdr *bph, struct host_addr *a) {
  if (bph && a) {
    a->family = AF_INET;
    a->address.ipv4.s_addr = bph->bgp_id;
  }
}

void bmp_peer_hdr_get_rd(struct bmp_peer_hdr *bph, rd_t *rd) {
  if (bph && rd) {
    if (bph->type == BMP_PEER_TYPE_L3VPN || bph->type == BMP_PEER_TYPE_LOC_RIB) {
      memcpy(rd, bph->rd, RD_LEN);
      bgp_rd_ntoh(rd);

      if (!is_empty_256b(rd, RD_LEN)) {
        bgp_rd_origin_set(rd, RD_ORIGIN_BMP);
      }
    }
  }
}

void bmp_peer_hdr_get_tstamp(struct bmp_peer_hdr *bph, struct timeval *tv) {
  u_int32_t sec, usec;

  if (bph && tv) {
    if (bph->tstamp_sec) {
      sec = ntohl(bph->tstamp_sec);
      usec = ntohl(bph->tstamp_usec);

      tv->tv_sec = sec;
      tv->tv_usec = usec;
    }
  }
}

void bmp_peer_hdr_get_peer_asn(struct bmp_peer_hdr *bph, u_int32_t *asn) {
  if (bph && asn) (*asn) = ntohl(bph->asn);
}

void bmp_peer_hdr_get_peer_type(struct bmp_peer_hdr *bph, u_int8_t *type) {
  if (bph && type) (*type) = bph->type;
}

void bmp_peer_up_hdr_get_local_ip(struct bmp_peer_up_hdr *bpuh, struct host_addr *a, u_int8_t family) {
  if (bpuh && a && family) {
    a->family = family;

    if (family == AF_INET) a->address.ipv4.s_addr = bpuh->loc_addr[3];
    else if (family == AF_INET6) memcpy(&a->address.ipv6, &bpuh->loc_addr, 16);
  }
}

void bmp_peer_up_hdr_get_loc_port(struct bmp_peer_up_hdr *bpuh, u_int16_t *port) {
  if (bpuh && port) (*port) = ntohs(bpuh->loc_port);
}

void bmp_peer_up_hdr_get_rem_port(struct bmp_peer_up_hdr *bpuh, u_int16_t *port) {
  if (bpuh && port) (*port) = ntohs(bpuh->rem_port);
}

void bmp_peer_down_hdr_get_reason(struct bmp_peer_down_hdr *bpdh, u_char *reason) {
  if (bpdh && reason) (*reason) = bpdh->reason;
}

void bmp_peer_down_hdr_get_loc_code(char **bmp_packet, u_int32_t *pkt_size, u_int16_t *code) {
  char *ptr;

  if (bmp_packet && (*bmp_packet) && pkt_size && code) {
    ptr = bmp_get_and_check_length(bmp_packet, pkt_size, 2);
    memcpy(code, ptr, 2);
    (*code) = ntohs((*code));
  }
}

void bmp_stats_hdr_get_count(struct bmp_stats_hdr *bsh, u_int32_t *count) {
  if (bsh && count) (*count) = ntohl(bsh->count);
}

void bmp_stats_cnt_hdr_get_type(struct bmp_stats_cnt_hdr *bsch, u_int16_t *type) {
  if (bsch && type) (*type) = ntohs(bsch->type);
}

void bmp_stats_cnt_hdr_get_len(struct bmp_stats_cnt_hdr *bsch, u_int16_t *len) {
  if (bsch && len) (*len) = ntohs(bsch->len);
}

void bmp_stats_cnt_get_data32(char **bmp_packet, u_int32_t *pkt_size, u_int32_t *data) {
  char *ptr;

  if (bmp_packet && (*bmp_packet) && pkt_size && data) {
    ptr = bmp_get_and_check_length(bmp_packet, pkt_size, 4);
    memcpy(data, ptr, 4);
    (*data) = ntohl((*data));
  }
}

void bmp_stats_cnt_get_data64(char **bmp_packet, u_int32_t *pkt_size, u_int64_t *data) {
  char *ptr;

  if (bmp_packet && (*bmp_packet) && pkt_size && data) {
    ptr = bmp_get_and_check_length(bmp_packet, pkt_size, 8);
    memcpy(data, ptr, 8);
    (*data) = pm_ntohll((*data));
  }
}

void
bmp_stats_cnt_get_afi_safi_data64(char **bmp_packet, u_int32_t *pkt_size, afi_t *afi, safi_t *safi, u_int64_t *data) {
  char *ptr;

  if (bmp_packet && (*bmp_packet) && pkt_size && afi && safi && data) {
    ptr = bmp_get_and_check_length(bmp_packet, pkt_size, 2);
    memcpy(afi, ptr, 2);
    (*afi) = ntohs((*afi));

    ptr = bmp_get_and_check_length(bmp_packet, pkt_size, 1);
    memcpy(safi, ptr, 1);

    ptr = bmp_get_and_check_length(bmp_packet, pkt_size, 8);
    memcpy(data, ptr, 8);
    (*data) = pm_ntohll((*data));
  }
}
