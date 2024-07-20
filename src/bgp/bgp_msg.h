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

#ifndef _BGP_MSG_H_
#define _BGP_MSG_H_

/* prototypes */
extern int bgp_max_msglen_check(u_int32_t);
extern int bgp_marker_check(struct bgp_header *, int);
extern int bgp_parse_msg(struct bgp_peer *, time_t, int);
extern int bgp_write_keepalive_msg(char *);
extern int bgp_write_notification_msg(char *, int, u_int8_t, u_int8_t, char *);
extern int bgp_process_update(struct bgp_msg_data *, struct prefix *, void *, struct bgp_attr_extra *, afi_t, safi_t, int);
extern int bgp_process_withdraw(struct bgp_msg_data *, struct prefix *, void *, struct bgp_attr_extra *, afi_t, safi_t, int);

#ifndef PMACCT_GAUZE_BUILD
#include "bgp.h"
extern int process_update_packets(struct bgp_msg_data *, struct bgp_misc_structs *, struct bgp_peer *, ParsedBgpUpdate);
extern int bgp_process_msg_update(struct bgp_msg_data *, const Opaque_BgpMessage *);
extern int bgp_process_msg_notif(struct bgp_msg_data *, const Opaque_BgpMessage *);
extern int bgp_process_msg_open(struct bgp_msg_data *, const Opaque_BgpMessage *, time_t, int);
extern int bgp_process_msg_keepalive(struct bgp_msg_data*, const Opaque_BgpMessage *, time_t, bool);
extern int bgp_write_open_msg(char *msg, int buff_len, struct bgp_peer *peer, const Opaque_BgpMessage *open_rx);
#endif

#endif 
