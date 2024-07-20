/*  
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2023 by Paolo Lucente
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
#include "bgp.h"
#include "bgp_blackhole.h"


int bgp_parse_msg(struct bgp_peer *peer, time_t now, int online) {
  struct bgp_misc_structs *bms;
  struct bgp_msg_data bmd;
  char *bgp_packet_ptr;
  int bgp_len;

  if (!peer || !peer->buf.base) return ERR;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return ERR;

  memset(&bmd, 0, sizeof(bmd));
  bmd.peer = peer;

  for (bgp_packet_ptr = peer->buf.base; peer->msglen > 0; peer->msglen -= bgp_len, bgp_packet_ptr += bgp_len) {
    BgpParseResult parse_result = netgauze_bgp_parse_packet_with_context(bgp_packet_ptr, peer->msglen, bgp_parsing_context_get(peer));

    if (parse_result.tag == CResult_Err) {
      Log(LOG_INFO, "netgauze parse error: %s\n", netgauze_bgp_parse_error_str(parse_result.err));
      if (parse_result.err.tag == BgpParseError_NetgauzeBgpError) {
        netgauze_bgp_parse_result_free(parse_result);
        return parse_result.err.netgauze_bgp_error.pmacct_error_code;
      }
    }

    int err = SUCCESS;
    ParsedBgp *parsed_bgp = &parse_result.ok;

    struct bgp_header* bhdr = &parsed_bgp->header;
    bgp_len = bhdr->bgpo_len;

    switch (bhdr->bgpo_type) {
      case BGP_OPEN:
        if (bgp_process_msg_open(&bmd, parsed_bgp->message, now, online) < 0)
          err = BGP_NOTIFY_OPEN_ERR;
        break;
      case BGP_NOTIFICATION: {
        err = bgp_process_msg_notif(&bmd, parsed_bgp->message);
        break;
      }
      case BGP_KEEPALIVE:
        err = bgp_process_msg_keepalive(&bmd, parsed_bgp->message, now, online);
        break;
      case BGP_UPDATE:
        err = bgp_process_msg_update(&bmd, parsed_bgp->message);
        break;
      case BGP_ROUTE_REFRESH:
        /* just ignore */
        break;
      default: {
        char bgp_peer_str[INET6_ADDRSTRLEN];
        bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
        Log(LOG_INFO, "INFO ( %s/%s ): [%s] Received malformed BGP packet (unsupported message type).\n",
            config.name, bms->log_str, bgp_peer_str);
        err = BGP_NOTIFY_HEADER_ERR;
      }
    }

    netgauze_bgp_parse_result_free(parse_result);

    if (err != SUCCESS)
      return err;
  }

  return SUCCESS;
}

int bgp_process_msg_open(struct bgp_msg_data *bmd, const Opaque_BgpMessage *bgp_msg, time_t now, int online) {
  struct bgp_peer *peer = bmd->peer;
  struct bgp_misc_structs *bms;
  if (!peer || !bgp_msg) return ERR;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return ERR;

  BgpOpenProcessResult proc_res = netgauze_bgp_process_open(bgp_msg, peer, 5, online);
  if (proc_res.tag == CResult_Err) {
    Log(LOG_INFO, "netgauze could not process bgp open for error code %d\n", proc_res.err.tag);
    return ERR;
  }

  /* Check: duplicate Router-IDs; BGP only, ie. no BMP */
  if (!config.bgp_disable_router_id_check && bms->bgp_msg_open_router_id_check) {
    int check_ret;

    check_ret = bms->bgp_msg_open_router_id_check(bmd);
    if (check_ret) return check_ret;
  }

  if (online) {
    char bgp_reply_pkt[BGP_BUFFER_SIZE], *bgp_reply_ptr = bgp_reply_pkt;

    /* Replying to OPEN message */
    if (!config.bgp_daemon_as) peer->myas = peer->as;
    else peer->myas = config.bgp_daemon_as;

    bgp_reply_ptr += bgp_write_open_msg(bgp_reply_pkt, BGP_BUFFER_SIZE, peer, bgp_msg);
    /* sticking a KEEPALIVE to it */
    bgp_reply_ptr += bgp_write_keepalive_msg(bgp_reply_ptr);
    peer->last_keepalive = now;
    return send(peer->fd, bgp_reply_pkt, bgp_reply_ptr - bgp_reply_pkt, 0);
  }

  return SUCCESS;
}

int bgp_max_msglen_check(u_int32_t length) {
  if (length <= BGP_MAX_MSGLEN) return SUCCESS;
  else return ERR;
}

/* Marker check. */
int bgp_marker_check(struct bgp_header *bhdr, int length) {
  int i;

  for (i = 0; i < length; i++)
    if (bhdr->bgpo_marker[i] != 0xff)
      return ERR;

  return SUCCESS;
}

/* write BGP KEEPALIVE msg */
int bgp_write_keepalive_msg(char *msg) {
  struct bgp_header bhdr;

  memset(&bhdr.bgpo_marker, 0xff, BGP_MARKER_SIZE);
  bhdr.bgpo_type = BGP_KEEPALIVE;
  bhdr.bgpo_len = htons(BGP_HEADER_SIZE);
  memcpy(msg, &bhdr, sizeof(bhdr));

  return BGP_HEADER_SIZE;
}

/* write BGP OPEN msg */
int bgp_write_open_msg(char *msg, int buff_len, struct bgp_peer *peer, const Opaque_BgpMessage *open_rx) {
  char my_id_static[] = "1.2.3.4";
  struct host_addr my_id_addr, bgp_ip, bgp_id;

  if (config.bgp_daemon_ip) str_to_addr(config.bgp_daemon_ip, &bgp_ip);
  else memset(&bgp_ip, 0, sizeof(bgp_ip));

  if (config.bgp_daemon_id) str_to_addr(config.bgp_daemon_id, &bgp_id);
  else memset(&bgp_id, 0, sizeof(bgp_id));

  /* set BGP router-ID trial #1 */
  memset(&my_id_addr, 0, sizeof(my_id_addr));

  if (config.bgp_daemon_id && !is_any(&bgp_id) && !my_id_addr.family) {
    str_to_addr(config.bgp_daemon_id, &my_id_addr);
    if (my_id_addr.family != AF_INET) memset(&my_id_addr, 0, sizeof(my_id_addr));
  }

  /* set BGP router-ID trial #2 */
  if (config.bgp_daemon_ip && !is_any(&bgp_ip) && !my_id_addr.family) {
    str_to_addr(config.bgp_daemon_ip, &my_id_addr);
    if (my_id_addr.family != AF_INET) memset(&my_id_addr, 0, sizeof(my_id_addr));
  }

  /* set BGP router-ID trial #3 */
  if (!my_id_addr.family) {
    str_to_addr(my_id_static, &my_id_addr);
  }

  BgpOpenWriteResult write_result = netgauze_bgp_open_write_reply(peer, open_rx, msg, buff_len, my_id_addr.address.ipv4);
  if (write_result.tag == CResult_Err) {
    Log(LOG_INFO, "netgauze error while crafting bgp open reply %s\n", netgauze_bgp_open_write_result_err_str(write_result.err));
    netgauze_bgp_open_write_result_free(write_result);
    return ERR;
  }

  return write_result.ok;
}

int bgp_write_notification_msg(char *msg, int msglen, u_int8_t n_major, u_int8_t n_minor, char *shutdown_msg) {
  struct bgp_notification *bn_reply = (struct bgp_notification *) msg;
  struct bgp_notification_shutdown_msg *bnsm_reply;
  u_int16_t shutdown_msglen;
  int ret = FALSE;
  char *reply_msg_ptr;

  if (bn_reply && msglen >= BGP_MIN_NOTIFICATION_MSG_SIZE) {
    memset(bn_reply->bgpn_marker, 0xff, BGP_MARKER_SIZE);

    bn_reply->bgpn_len = ntohs(BGP_MIN_NOTIFICATION_MSG_SIZE);
    bn_reply->bgpn_type = BGP_NOTIFICATION;

    if (!n_major) bn_reply->bgpn_major = BGP_NOTIFY_CEASE;
    else bn_reply->bgpn_major = n_major;

    if (!n_minor) bn_reply->bgpn_minor = BGP_NOTIFY_CEASE_ADMIN_SHUTDOWN;
    else bn_reply->bgpn_minor = n_minor;

    ret += BGP_MIN_NOTIFICATION_MSG_SIZE;

    /* rfc8203 */
    if (shutdown_msg) {
      shutdown_msglen = strlen(shutdown_msg);

      if (shutdown_msglen <= BGP_NOTIFY_CEASE_SM_LEN) {
        if (msglen >= (BGP_MIN_NOTIFICATION_MSG_SIZE + shutdown_msglen)) {
          reply_msg_ptr = (char *) (msg + BGP_MIN_NOTIFICATION_MSG_SIZE);
          memset(reply_msg_ptr, 0, (msglen - BGP_MIN_NOTIFICATION_MSG_SIZE));
          bnsm_reply = (struct bgp_notification_shutdown_msg *) reply_msg_ptr;

          bnsm_reply->bgpnsm_len = shutdown_msglen;
          strncpy(bnsm_reply->bgpnsm_data, shutdown_msg, shutdown_msglen);
          bn_reply->bgpn_len = htons(BGP_MIN_NOTIFICATION_MSG_SIZE + shutdown_msglen + 1 /* bgpnsm_len */);
          ret += (shutdown_msglen + 1 /* bgpnsm_len */);
        }
      }
    }
  }

  return ret;
}

/* process bgp messages */
int bgp_process_msg_notif(struct bgp_msg_data *bmd, const Opaque_BgpMessage *bgp_msg) {

  struct bgp_peer *peer = bmd->peer;
  struct bgp_misc_structs *bms = bgp_select_misc_db(peer->type);

  BgpNotificationResult notif_result = netgauze_bgp_notification(bgp_msg);
  if (notif_result.tag == CResult_Err) {
    Log(LOG_INFO, "netgauze could not process bgp notification correctly: bad msg type %d\n",
        notif_result.err._0);
    return notif_result.err._0;
  }

  // get shutdown message
  BgpNotification *notif = &notif_result.ok;
  char shutdown_msg[notif->value_len + 1];
  memcpy(shutdown_msg, notif->value, notif->value_len);
  shutdown_msg[notif->value_len] = 0; // ensure we have a zero-terminated string

  char bgp_peer_str[INET6_ADDRSTRLEN];
  bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
  Log(LOG_INFO, "INFO ( %s/%s ): [%s] BGP_NOTIFICATION received (%u, %u). Shutdown Message: '%s'\n",
      config.name, bms->log_str, bgp_peer_str, notif->code, notif->subcode, shutdown_msg);

  return ERR;
}

int bgp_process_msg_keepalive(struct bgp_msg_data *bmd, const Opaque_BgpMessage *bgp_msg, time_t now, bool online) {

  struct bgp_peer *peer = bmd->peer;
  struct bgp_misc_structs *bms = bgp_select_misc_db(peer->type);

  char bgp_peer_str[INET6_ADDRSTRLEN];
  bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
  Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%s] BGP_KEEPALIVE received\n", config.name, bms->log_str, bgp_peer_str);

  /* If we didn't pass through a successful BGP OPEN exchange just yet
     let's temporarily silently discard BGP KEEPALIVEs */
  if (peer->status >= OpenSent) {
    if (peer->status < Established) peer->status = Established;
    if (online) {
      char bgp_reply_pkt[BGP_BUFFER_SIZE], *bgp_reply_pkt_ptr;

      memset(bgp_reply_pkt, 0, BGP_BUFFER_SIZE);
      bgp_reply_pkt_ptr = bgp_reply_pkt;
      bgp_reply_pkt_ptr += bgp_write_keepalive_msg(bgp_reply_pkt_ptr);
      send(peer->fd, bgp_reply_pkt, bgp_reply_pkt_ptr - bgp_reply_pkt, 0);
      peer->last_keepalive = now;

      bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
      Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%s] BGP_KEEPALIVE sent\n", config.name, bms->log_str, bgp_peer_str);
    }
  }

  return SUCCESS;
}

int bgp_process_msg_update(struct bgp_msg_data *bmd, const Opaque_BgpMessage *bgp_msg) {
  struct bgp_misc_structs *bms;
  struct bgp_peer *peer = bmd->peer;

  if (peer->status < Established) {
    char bgp_peer_str[INET6_ADDRSTRLEN];
    bgp_peer_print(peer, bgp_peer_str, INET6_ADDRSTRLEN);
    Log(LOG_DEBUG, "DEBUG ( %s/%s ): [%s] BGP UPDATE received (no neighbor). Discarding.\n",
        config.name, bms->log_str, bgp_peer_str);
    return BGP_NOTIFY_FSM_ERR;
  }

  if (!peer || !bgp_msg) return BGP_NOTIFY_UPDATE_ERR;

  bms = bgp_select_misc_db(peer->type);

  if (!bms) return BGP_NOTIFY_UPDATE_ERR;

  // TODO move this logic into one function so that bgp and bmp behaviour is shared
  BgpUpdateResult bgp_update_res = netgauze_bgp_update_get_updates(peer, bgp_msg);
  if (bgp_update_res.tag == CResult_Err) {
    Log(LOG_INFO, "netgauze bad bgp message type %d in %s\n", bgp_update_res.err._0, __func__);
    return BGP_NOTIFY_UPDATE_ERR;
  }

  ParsedBgpUpdate bgp_parsed = bgp_update_res.ok;

  ProcessPacket *pkt = NULL;
  for (int i = 0; i < bgp_parsed.packets.len; i += 1) {
    pkt = &bgp_parsed.packets.base_ptr[i];

    // TODO handle process_update/withdraw error ? they were not handled before...
    switch (pkt->update_type) {
      case BGP_NLRI_UPDATE:
        bgp_process_update(bmd, &pkt->prefix, &pkt->attr, &pkt->attr_extra, pkt->afi, pkt->safi, i);
        break;
      case BGP_NLRI_WITHDRAW:
        bgp_process_withdraw(bmd, &pkt->prefix, &pkt->attr, &pkt->attr_extra, pkt->afi, pkt->safi, i);
        break;
      case BGP_NLRI_UNDEFINED: {
        // this is EoR
        struct bgp_info ri = { 0 };
        ri.bmed = bmd->extra;
        ri.peer = bmd->peer;
        bgp_peer_log_msg(NULL, &ri, pkt->afi, pkt->safi, bms->tag, "log", bms->msglog_output, NULL, BGP_LOG_TYPE_EOR);
        break;
      }
      default: {
        Log(LOG_INFO,
            "INFO ( %s/%s ): [%s] [bgp_parse_update] packet discarded: unknown update type received from pmacct-gauze\n",
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

  return SUCCESS;
}


int
bgp_process_update(struct bgp_msg_data *bmd, struct prefix *p, void *attr, struct bgp_attr_extra *attr_extra, afi_t afi,
                   safi_t safi, int idx) {
  struct bgp_peer *peer = bmd->peer;
  struct bgp_rt_structs *inter_domain_routing_db;
  struct bgp_misc_structs *bms;
  struct bgp_node *route = NULL, route_local;
  struct bgp_info *ri = NULL, *new = NULL, ri_local;
  struct bgp_attr *attr_new = NULL;
  u_int32_t modulo;

  if (!peer) return ERR;

  inter_domain_routing_db = bgp_select_routing_db(peer->type);
  bms = bgp_select_misc_db(peer->type);

  if (!inter_domain_routing_db || !bms) return ERR;

  if (!bms->skip_rib) {
    modulo = bms->route_info_modulo(peer, &attr_extra->rd, &attr_extra->path_id, &bmd->extra,
                                    bms->table_per_peer_buckets);
    route = bgp_node_get(peer, inter_domain_routing_db->rib[afi][safi], p);

    /* Check previously received route. */
    for (ri = route->info[modulo]; ri; ri = ri->next) {
      if (ri->peer == peer) {
        if (safi == SAFI_MPLS_VPN) {
          if (ri->attr_extra && !memcmp(&ri->attr_extra->rd, &attr_extra->rd, sizeof(rd_t)));
          else continue;
        }

        if (peer->cap_add_paths.cap[afi][safi]) {
          if (ri->attr_extra && (attr_extra->path_id == ri->attr_extra->path_id));
          else continue;
        }

        if (ri->bmed.id) {
          if (bms->bgp_extra_data_cmp && !(*bms->bgp_extra_data_cmp)(&bmd->extra, &ri->bmed));
          else continue;
        }

        break;
      }
    }

    attr_new = bgp_attr_intern(peer, attr);

    if (ri) {
      /* Received same information */
      if (attrhash_cmp(ri->attr, attr_new)) {
        bgp_unlock_node(peer, route);
        bgp_attr_unintern(peer, attr_new);

        if (bms->msglog_backend_methods)
          goto log_update;

        return SUCCESS;
      } else {
        /* Update to new attribute.  */
        bgp_attr_unintern(peer, ri->attr);
        ri->attr = attr_new;
        bgp_attr_extra_process(peer, ri, afi, safi, attr_extra);
        if (bms->bgp_extra_data_process) (*bms->bgp_extra_data_process)(&bmd->extra, ri, idx, BGP_NLRI_UPDATE);

        bgp_unlock_node(peer, route);

        if (bms->msglog_backend_methods)
          goto log_update;

        return SUCCESS;
      }
    }

    /* Make new BGP info. */
    new = bgp_info_new(peer);
    if (new) {
      new->peer = peer;
      new->attr = attr_new;
      bgp_attr_extra_process(peer, new, afi, safi, attr_extra);
      if (bms->bgp_extra_data_process) (*bms->bgp_extra_data_process)(&bmd->extra, new, idx, BGP_NLRI_UPDATE);
    } else return ERR;

    /* Register new BGP information. */
    bgp_info_add(peer, route, new, modulo);

    /* route_node_get lock */
    bgp_unlock_node(peer, route);

    if (bms->msglog_backend_methods) {
      ri = new;
      goto log_update;
    }
  } else {
    if (bms->msglog_backend_methods) {
      route = &route_local;
      memset(&route_local, 0, sizeof(struct bgp_node));
      memcpy(&route_local.p, p, sizeof(struct prefix));

      ri = &ri_local;
      memset(&ri_local, 0, sizeof(struct bgp_info));

      ri->peer = peer;
      ri->attr = bgp_attr_intern(peer, attr);
      bgp_attr_extra_process(peer, ri, afi, safi, attr_extra);
      if (bms->bgp_extra_data_process) (*bms->bgp_extra_data_process)(&bmd->extra, ri, idx, BGP_NLRI_UPDATE);

      goto log_update;
    }
  }

  return SUCCESS;

  log_update:
  {
    char event_type[] = "log";

    bgp_peer_log_msg(route, ri, afi, safi, bms->tag, event_type, bms->msglog_output, NULL, BGP_LOG_TYPE_UPDATE);
  }

  if (bms->skip_rib) {
    if (ri->attr_extra) bgp_attr_extra_free(peer, &ri->attr_extra);
    if (bms->bgp_extra_data_free) (*bms->bgp_extra_data_free)(&ri->bmed);
    bgp_attr_unintern(peer, ri->attr);
  }

  return SUCCESS;
}

int bgp_process_withdraw(struct bgp_msg_data *bmd, struct prefix *p, void *attr, struct bgp_attr_extra *attr_extra,
                         afi_t afi, safi_t safi, int idx) {
  struct bgp_peer *peer = bmd->peer;
  struct bgp_rt_structs *inter_domain_routing_db;
  struct bgp_misc_structs *bms;
  struct bgp_node *route = NULL, route_local;
  struct bgp_info *ri = NULL, ri_local;
  u_int32_t modulo = 0;

  if (!peer) return ERR;

  inter_domain_routing_db = bgp_select_routing_db(peer->type);
  bms = bgp_select_misc_db(peer->type);

  if (!inter_domain_routing_db || !bms) return ERR;

  if (!bms->skip_rib) {
    modulo = bms->route_info_modulo(peer, &attr_extra->rd, &attr_extra->path_id, &bmd->extra,
                                    bms->table_per_peer_buckets);

    /* Lookup node. */
    route = bgp_node_get(peer, inter_domain_routing_db->rib[afi][safi], p);

    /* Check previously received route. */
    for (ri = route->info[modulo]; ri; ri = ri->next) {
      if (ri->peer == peer) {
        if (safi == SAFI_MPLS_VPN) {
          if (ri->attr_extra && !memcmp(&ri->attr_extra->rd, &attr_extra->rd, sizeof(rd_t)));
          else continue;
        }

        if (peer->cap_add_paths.cap[afi][safi]) {
          if (ri->attr_extra && (attr_extra->path_id == ri->attr_extra->path_id));
          else continue;
        }

        if (ri->bmed.id) {
          if (bms->bgp_extra_data_cmp && !(*bms->bgp_extra_data_cmp)(&bmd->extra, &ri->bmed));
          else continue;
        }

        break;
      }
    }
  } else {
    if (bms->msglog_backend_methods) {
      route = &route_local;
      memset(&route_local, 0, sizeof(struct bgp_node));
      memcpy(&route_local.p, p, sizeof(struct prefix));

      ri = &ri_local;
      memset(&ri_local, 0, sizeof(struct bgp_info));

      ri->peer = peer;
      bgp_attr_extra_process(peer, ri, afi, safi, attr_extra);
      if (bms->bgp_extra_data_process) (*bms->bgp_extra_data_process)(&bmd->extra, ri, idx, BGP_NLRI_WITHDRAW);
    }
  }

  if (ri && bms->msglog_backend_methods) {
    char event_type[] = "log";

    bgp_peer_log_msg(route, ri, afi, safi, bms->tag, event_type, bms->msglog_output, NULL, BGP_LOG_TYPE_WITHDRAW);
  }

  if (!bms->skip_rib) {
    /* Withdraw specified route from routing table. */
    if (ri) bgp_info_delete(peer, route, ri, modulo);

    /* Unlock bgp_node_get() lock. */
    bgp_unlock_node(peer, route);
  } else {
    if (bms->msglog_backend_methods) {
      if (ri->attr_extra) bgp_attr_extra_free(peer, &ri->attr_extra);
      if (bms->bgp_extra_data_free) (*bms->bgp_extra_data_free)(&ri->bmed);
    }
  }

  return SUCCESS;
}
