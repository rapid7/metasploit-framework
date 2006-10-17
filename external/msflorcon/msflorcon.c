#include <msflorcon.h>

/*
    This is a derivative of the tx.c sample included with lorcon

    lorcon is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    lorcon is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with lorcon; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    Copyright (c) 2005 dragorn and Joshua Wright
	Copyright (c) 2006 H D Moore
*/

/* This is quick and ugly code I wrote as PoC */

int msflorcon_in_tx_size(void) {
	return(sizeof(struct tx80211));
}

int msflorcon_send(struct tx80211 *in_tx, char *buff, int len, int cnt, int delay) {
	struct tx80211_packet in_packet;
	int ret = 0;
	int c = cnt;
	
	in_packet.packet = buff;
	in_packet.plen = len;
	
	for (; c > 0; c--) {
		ret = tx80211_txpacket(in_tx, &in_packet);
		if (ret < 0) 
			return(ret);
		if (delay > 0)
			usleep(delay);
	}
	
	return(cnt);
}

		
int msflorcon_open(struct tx80211 *in_tx, char *iface, char *driver, int channel) {
	int ret = 0;
	int drivertype = INJ_NODRIVER;

	drivertype = tx80211_resolvecard(driver);
	if (drivertype == INJ_NODRIVER) {
		fprintf(stderr, "Driver name not recognized.\n");
		return(0);
	}
	
	if (tx80211_init(in_tx, iface, drivertype) < 0) {
		perror("tx80211_init");
		return(0);
	}
		
	ret = tx80211_setmode(in_tx, IW_MODE_MONITOR);
	if (ret != 0) {
		fprintf(stderr, "Error setting mode, returned %d.\n", ret);
		return(0);
	}

	/* Switch to the given channel */
	ret = tx80211_setchannel(in_tx, channel);
	if (ret < 0) {
		fprintf(stderr, "Error setting channel, returned %d.\n", ret);
		return(0);
	}

	/* Open the interface to get a socket */
	ret = tx80211_open(in_tx);
	if (ret < 0) {
		fprintf(stderr, "Unable to open interface %s.\n", in_tx->ifname);
		return(0);
	}
	
	return(1);		
}

void msflorcon_close(struct tx80211 *in_tx) {
	tx80211_close(in_tx);
}

int msflorcon_driverlist(char *buff, int len) {
	struct tx80211_cardlist *cardlist = NULL;
	int i,l,r;

	if (buff == NULL)
		return(0);
	
	cardlist = tx80211_getcardlist();
	if (cardlist == NULL) {
		free(buff);
		return(0);
	}
	
	r = len;
	for (i = 1; i < cardlist->num_cards; i++) {
		
		l = strlen(cardlist->cardnames[i]);
		
		if (l + 1 > r)
			return(0);
		
		strcat(buff, cardlist->cardnames[i]);
		if (i + 1 < cardlist->num_cards)
			strcat(buff, ",");

		r -= l + 1;
	}

	return(1);
}
