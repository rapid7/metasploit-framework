#include "Lorcon.h"
#include "ruby.h"

/*
	self.license = GPLv2;
*/

/*
    This is a derivative of the tx.c sample included with lorcon:
		http://802.11ninja.net/lorcon/

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
	
*/

/*
	Lots of code borrowed from Tom Wambold's pylorcon:
		http://pylorcon.googlecode.com/ - tom5760[at]gmail.com
*/

/*	
	All ruby-lorcon/rubyisms are by Rapid7, Inc (C) 2006-2007
		http://metasploit.com/ - msfdev[at]metasploit.com
*/

VALUE mLorcon;
VALUE cDevice;

VALUE lorcon_get_version(VALUE self) {
	return INT2NUM(tx80211_getversion());
}

VALUE lorcon_cap_to_list(int cap) {
	VALUE list;
	list = rb_ary_new();
	
	if ((cap & TX80211_CAP_SNIFF) != 0) 
		rb_ary_push(list, rb_str_new2("SNIFF"));
	
	if ((cap & TX80211_CAP_TRANSMIT) != 0)
		rb_ary_push(list, rb_str_new2("TRANSMIT"));
	
	if ((cap & TX80211_CAP_SEQ) != 0)
		rb_ary_push(list, rb_str_new2("SEQ"));
	
	if ((cap & TX80211_CAP_BSSTIME) != 0)
		rb_ary_push(list, rb_str_new2("BSSTIME"));
	
	if ((cap & TX80211_CAP_FRAG) != 0)
		rb_ary_push(list, rb_str_new2("FRAG"));
	
	if ((cap & TX80211_CAP_CTRL) != 0)
		rb_ary_push(list, rb_str_new2("CTRL"));
	
	if ((cap & TX80211_CAP_DURID) != 0)
		rb_ary_push(list, rb_str_new2("DURID"));
	
	if ((cap & TX80211_CAP_SNIFFACK) != 0)
		rb_ary_push(list, rb_str_new2("SNIFFACK"));
	
	if ((cap & TX80211_CAP_SELFACK) != 0)
		rb_ary_push(list, rb_str_new2("SELFACK"));
	
	if ((cap & TX80211_CAP_TXNOWAIT) != 0)
		rb_ary_push(list, rb_str_new2("TXNOWAIT"));
	
	if ((cap & TX80211_CAP_DSSSTX) != 0)
		rb_ary_push(list, rb_str_new2("DSSSTX"));
	
	if ((cap & TX80211_CAP_OFDMTX) != 0)
		rb_ary_push(list, rb_str_new2("OFDMTX"));
	
	if ((cap & TX80211_CAP_MIMOTX) != 0)
		rb_ary_push(list, rb_str_new2("MIMOTX"));
	
	if ((cap & TX80211_CAP_SETRATE) != 0)
		rb_ary_push(list, rb_str_new2("SETRATE"));
	
	if ((cap & TX80211_CAP_SETMODULATION) != 0)
		rb_ary_push(list, rb_str_new2("SETMODULATION"));
	
	if ((cap & TX80211_CAP_NONE) != 0)
		rb_ary_push(list, rb_str_new2("NONE"));

	return list;
}


static VALUE lorcon_driver_list(VALUE self) {	
	VALUE list;
	VALUE hash;

	struct tx80211_cardlist *cards = NULL;
	int i;

	list  = rb_hash_new();
	cards = tx80211_getcardlist();
	if (cards == NULL) {
		return(Qnil);
	}
	
	for (i = 1; i < cards->num_cards; i++) {
		hash = rb_hash_new();
		rb_hash_aset(hash, rb_str_new2("name"), rb_str_new2(cards->cardnames[i]));
		rb_hash_aset(hash, rb_str_new2("description"), rb_str_new2(cards->descriptions[i]));
		rb_hash_aset(hash, rb_str_new2("capabilities"), lorcon_cap_to_list(cards->capabilities[i]));
		rb_hash_aset(list, rb_str_new2(cards->cardnames[i]), hash);
	}

	tx80211_freecardlist(cards);	
	return(list);
}

static VALUE lorcon_device_get_channel(VALUE self) {
	struct rldev *rld;
	Data_Get_Struct(self, struct rldev, rld);
	return INT2NUM(tx80211_getchannel(&rld->in_tx));
}

static VALUE lorcon_device_set_channel(VALUE self, VALUE channel) {
	struct rldev *rld;
	Data_Get_Struct(self, struct rldev, rld);
	tx80211_setchannel(&rld->in_tx, NUM2INT(channel));
	return INT2NUM(tx80211_getchannel(&rld->in_tx));
}

void lorcon_device_free(struct rldev *rld) {
	if (tx80211_getmode(&rld->in_tx) >= 0) {
		tx80211_close(&rld->in_tx);
	}
	free(&rld->in_tx);
}


static VALUE lorcon_device_get_mode(VALUE self) {
	struct rldev *rld;
	int mode;
	Data_Get_Struct(self, struct rldev, rld);
	

	mode = tx80211_getmode(&rld->in_tx);
	if (mode < 0) {
		rb_raise(rb_eArgError, "Lorcon could not determine the mode of this device: %s", tx80211_geterrstr(&rld->in_tx));
		return(Qnil);
	}
	
	switch (mode) {
		case TX80211_MODE_AUTO:
			return rb_str_new2("AUTO");
			break;
		case TX80211_MODE_ADHOC:
			return rb_str_new2("ADHOC");
			break;
		case TX80211_MODE_INFRA:
			return rb_str_new2("INFRA");
			break;
		case TX80211_MODE_MASTER:
			return rb_str_new2("MASTER");
			break;
		case TX80211_MODE_REPEAT:
			return rb_str_new2("REPEAT");
			break;
		case TX80211_MODE_SECOND:
			return rb_str_new2("SECOND");
			break;
		case TX80211_MODE_MONITOR:
			return rb_str_new2("MONITOR");
			break;
		default:
			return Qnil;
			break;
	}
}

static VALUE lorcon_device_set_mode(VALUE self, VALUE rmode) {
	struct rldev *rld;
	char *setmode = StringValuePtr(rmode);
	int mode = -1;

	Data_Get_Struct(self, struct rldev, rld);
	
	if (strcmp(setmode, "AUTO") == 0) {
		mode = TX80211_MODE_AUTO;
	} else if (strcmp(setmode, "ADHOC") == 0) {
		mode = TX80211_MODE_ADHOC;
	} else if (strcmp(setmode, "INFRA") == 0) {
		mode = TX80211_MODE_INFRA;
	} else if (strcmp(setmode, "MASTER") == 0) {
		mode = TX80211_MODE_MASTER;
	} else if (strcmp(setmode, "REPEAT") == 0) {
		mode = TX80211_MODE_REPEAT;
	} else if (strcmp(setmode, "SECOND") == 0) {
		mode = TX80211_MODE_SECOND;
	} else if (strcmp(setmode, "MONITOR") == 0) {
		mode = TX80211_MODE_MONITOR;
	} else {
		rb_raise(rb_eArgError, "Invalid mode specified: %s", tx80211_geterrstr(&rld->in_tx));
		return(Qnil);
	}

	return INT2NUM(tx80211_setmode(&rld->in_tx, mode));
}

	
static VALUE lorcon_device_set_functional_mode(VALUE self, VALUE rmode) {
	struct rldev *rld;
	char *funcmode = StringValuePtr(rmode);
	int mode = -1;

	Data_Get_Struct(self, struct rldev, rld);
		
	if (strcmp(funcmode, "RFMON") == 0) {
		mode = TX80211_FUNCMODE_RFMON;
	} else if (strcmp(funcmode, "INJECT") == 0) {
		mode = TX80211_FUNCMODE_INJECT;
	} else if (strcmp(funcmode, "INJMON") == 0) {
		mode = TX80211_FUNCMODE_INJMON;
	} else {
		rb_raise(rb_eArgError, "Invalid mode specified: %s", tx80211_geterrstr(&rld->in_tx));
		return(Qnil);
	}

	if (tx80211_setfunctionalmode(&rld->in_tx, mode) != 0) {
		rb_raise(rb_eArgError, "Lorcon could not set the functional mode: %s", tx80211_geterrstr(&rld->in_tx));
		return(Qnil);
	}
	return Qtrue;
}


static VALUE lorcon_device_get_txrate(VALUE self) {
	struct rldev *rld;
	int txrate;
	
	txrate = tx80211_gettxrate(&rld->in_packet);
	Data_Get_Struct(self, struct rldev, rld);

	switch (txrate) {
		case TX80211_RATE_DEFAULT:
			return UINT2NUM(0);
			break;
		case TX80211_RATE_1MB:
			return UINT2NUM(1);
			break;
		case TX80211_RATE_2MB:
			return UINT2NUM(2);
			break;
		case TX80211_RATE_5_5MB:
			return UINT2NUM(5);
			break;
		case TX80211_RATE_6MB:
			return UINT2NUM(6);
			break;
		case TX80211_RATE_9MB:
			return UINT2NUM(9);
			break;
		case TX80211_RATE_11MB:
			return UINT2NUM(11);
			break;
		case TX80211_RATE_24MB:
			return UINT2NUM(24);
			break;
		case TX80211_RATE_36MB:
			return UINT2NUM(36);
			break;
		case TX80211_RATE_48MB:
			return UINT2NUM(48);
			break;
		case TX80211_RATE_108MB:
			return UINT2NUM(108);
			break;
		default:
			rb_raise(rb_eArgError, "Lorcon could not determine the tx rate: %s", tx80211_geterrstr(&rld->in_tx));
			return(Qnil);
	}
	
	return Qnil;
}


static VALUE lorcon_device_set_txrate(VALUE self, VALUE rrate) {
	struct rldev *rld;
	float settxrate = -1;
	int txrate = -1;
	
	Data_Get_Struct(self, struct rldev, rld);


	if ((tx80211_getcapabilities(&rld->in_tx) & TX80211_CAP_SETRATE) == 0) {
		rb_raise(rb_eArgError, "Lorcon does not support setting the tx rate for this card");
		return(Qnil);
	}

	settxrate = NUM2DBL(rrate);
	
	if (settxrate == -1) {
		txrate = TX80211_RATE_DEFAULT;
	} else if (settxrate == 1) {
		txrate = TX80211_RATE_1MB;
	} else if (settxrate == 2) {
		txrate = TX80211_RATE_2MB;
	} else if (settxrate == 5.5) {
		txrate = TX80211_RATE_5_5MB;
	} else if (settxrate == 6) {
		txrate = TX80211_RATE_6MB;
	} else if (settxrate == 9) {
		txrate = TX80211_RATE_9MB;
	} else if (settxrate == 11) {
		txrate = TX80211_RATE_11MB;
	} else if (settxrate == 24) {
		txrate = TX80211_RATE_24MB;
	} else if (settxrate == 36) {
		txrate = TX80211_RATE_36MB;
	} else if (settxrate == 48) {
		txrate = TX80211_RATE_48MB;
	} else if (settxrate == 108) {
		txrate = TX80211_RATE_108MB;
	} else {
		rb_raise(rb_eArgError, "Lorcon does not support this rate setting");
		return(Qnil);
	}

	if (tx80211_settxrate(&rld->in_tx, &rld->in_packet, txrate) < 0) {
		rb_raise(rb_eArgError, "Lorcon could not set the tx rate: %s", tx80211_geterrstr(&rld->in_tx));
		return(Qnil);
	}

	return INT2NUM(txrate);
}

static VALUE lorcon_device_get_modulation(VALUE self) {
	struct rldev *rld;
	int mod;
	
	Data_Get_Struct(self, struct rldev, rld);

	mod = tx80211_getmodulation(&rld->in_packet);
	switch (mod) {
		case TX80211_MOD_DEFAULT:
			return rb_str_new2("DEFAULT");
			break;
		case TX80211_MOD_FHSS:
			return rb_str_new2("FHSS");
			break;
		case TX80211_MOD_DSSS:
			return rb_str_new2("DSSS");
			break;
		case TX80211_MOD_OFDM:
			return rb_str_new2("OFDM");
			break;
		case TX80211_MOD_TURBO:
			return rb_str_new2("TURBO");
			break;
		case TX80211_MOD_MIMO:
			return rb_str_new2("MIMO");
			break;
		case TX80211_MOD_MIMOGF:
			return rb_str_new2("MIMOGF");
			break;
		default:
		rb_raise(rb_eArgError, "Lorcon could not get the modulation value");
		return(Qnil);
	}
	return(Qnil);
}

static VALUE lorcon_device_set_modulation(VALUE self, VALUE rmod) {
	struct rldev *rld;
	char *setmod = NULL;
	int mod;
	
	Data_Get_Struct(self, struct rldev, rld);

	if ((tx80211_getcapabilities(&rld->in_tx) & TX80211_CAP_SETMODULATION) == 0) {
		rb_raise(rb_eArgError, "Lorcon does not support setting the modulation for this card");
		return(Qnil);
	}

	setmod = StringValuePtr(rmod);

	if (strcmp(setmod, "DEFAULT") == 0) {
		mod = TX80211_MOD_DEFAULT;
	} else if (strcmp(setmod, "FHSS") == 0) {
		mod = TX80211_MOD_FHSS;
	} else if (strcmp(setmod, "DSSS") == 0) {
		mod = TX80211_MOD_DSSS;
	} else if (strcmp(setmod, "OFDM") == 0) {
		mod = TX80211_MOD_OFDM;
	} else if (strcmp(setmod, "TURBO") == 0) {
		mod = TX80211_MOD_TURBO;
	} else if (strcmp(setmod, "MIMO") == 0) {
		mod = TX80211_MOD_MIMO;
	} else if (strcmp(setmod, "MIMOGF") == 0) {
		mod = TX80211_MOD_MIMOGF;
	} else {
		rb_raise(rb_eArgError, "Lorcon does not support this modulation setting");
		return(Qnil);
	}

	if (tx80211_setmodulation(&rld->in_tx, &rld->in_packet, mod) < 0) {
		rb_raise(rb_eArgError, "Lorcon could not set the modulation: %s", tx80211_geterrstr(&rld->in_tx));
		return(Qnil);
	}
	
	return INT2NUM(mod);
}

static VALUE lorcon_device_get_capabilities(VALUE self) {
	struct rldev *rld;
	Data_Get_Struct(self, struct rldev, rld);
	return(lorcon_cap_to_list(tx80211_getcapabilities(&rld->in_tx)));
}

static VALUE lorcon_device_open(int argc, VALUE *argv, VALUE self) {
	struct rldev *rld;
	int ret = 0;
	int drivertype = INJ_NODRIVER;
	char *driver, *intf;
	VALUE rbdriver, rbintf;
	VALUE obj;

	rb_scan_args(argc, argv, "2", &rbintf, &rbdriver);
	
	driver = STR2CSTR(rbdriver);
	intf   = STR2CSTR(rbintf);

	obj = Data_Make_Struct(cDevice, struct rldev, 0, lorcon_device_free, rld);

	drivertype = tx80211_resolvecard(driver);
	if (drivertype == INJ_NODRIVER) {
		rb_raise(rb_eArgError, "Lorcon did not recognize the specified driver");
		return(Qnil);
	}
	
	if (tx80211_init(&rld->in_tx, intf, drivertype) < 0) {
		rb_raise(rb_eRuntimeError, "Lorcon could not initialize the interface: %s", tx80211_geterrstr(&rld->in_tx));
		return(Qnil);
	}

	/* Open the interface to get a socket */
	ret = tx80211_open(&rld->in_tx);
	if (ret < 0) {
		rb_raise(rb_eRuntimeError, "Lorcon could not open the interface: %s", tx80211_geterrstr(&rld->in_tx));
		return(Qnil);
	}	

	rb_obj_call_init(obj, 0, 0);	
	return(obj);
}

static VALUE lorcon_device_write(int argc, VALUE *argv, VALUE self) {
	struct rldev *rld;
	int ret = 0;
	int cnt = 0;
	int dly = 0;
	
	VALUE rbbuff, rbcnt, rbdelay;
	
	Data_Get_Struct(self, struct rldev, rld);	
		
	switch(rb_scan_args(argc, argv, "12", &rbbuff, &rbcnt, &rbdelay)) {	
		case 1:
			rbdelay = INT2NUM(0);
		case 2:	
			rbcnt = INT2NUM(1);
		default:
			break;
	}

	cnt = NUM2INT(rbcnt);
	dly = NUM2INT(rbdelay);

	rld->in_packet.packet = StringValuePtr(rbbuff);
	rld->in_packet.plen = RSTRING(rbbuff)->len;

	for (; cnt > 0; cnt--) {
		ret = tx80211_txpacket(&rld->in_tx, &rld->in_packet);
		if (ret < 0) {
			rb_raise(rb_eRuntimeError, "Lorcon could not transmit packet: %s", tx80211_geterrstr(&rld->in_tx));			
			return(INT2NUM(ret));
		}
		if (dly > 0)
#ifdef _MSC_VER
			Sleep(dly);
#else
			usleep(dly);
#endif
	}

	return (rbcnt);
}

void Init_Lorcon() {	
	mLorcon = rb_define_module("Lorcon");
	rb_define_module_function(mLorcon, "drivers", lorcon_driver_list, 0);
	rb_define_module_function(mLorcon, "version", lorcon_get_version, 0);
		
	cDevice = rb_define_class_under(mLorcon, "Device", rb_cObject);
	rb_define_singleton_method(cDevice, "new", lorcon_device_open, -1);
	rb_define_method(cDevice, "channel", lorcon_device_get_channel, 0);
	rb_define_method(cDevice, "channel=", lorcon_device_set_channel, 1);
	rb_define_method(cDevice, "write", lorcon_device_write, -1);
	rb_define_method(cDevice, "mode",  lorcon_device_get_mode, 0);
	rb_define_method(cDevice, "mode=",  lorcon_device_set_mode, 1);
	rb_define_method(cDevice, "fmode=",  lorcon_device_set_functional_mode, 1);
	rb_define_method(cDevice, "txrate",  lorcon_device_get_txrate, 0);
	rb_define_method(cDevice, "txrate=",  lorcon_device_set_txrate, 1);
	rb_define_method(cDevice, "modulation",  lorcon_device_get_modulation, 0);
	rb_define_method(cDevice, "modulation=",  lorcon_device_set_modulation, 1);	
	rb_define_method(cDevice, "capabilities",  lorcon_device_get_capabilities, 0);
}
