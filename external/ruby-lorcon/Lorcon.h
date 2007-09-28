#ifndef _MSFLORCON_H
#define _MSFLORCON_H

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <tx80211.h>
#include <tx80211_packet.h>


struct rldev {
	struct tx80211 in_tx;
	struct tx80211_packet in_packet;
};


#endif
