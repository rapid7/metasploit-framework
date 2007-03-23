#include "Lorcon.h"
#include "ruby.h"

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
*/

/*	
	Ruby-Lorcon specifics are Copyright (c) 2006 Metasploit LLC
*/

VALUE mLorcon;
VALUE cDevice;

static VALUE lorcon_driver_list(VALUE self) {	
	VALUE list;
	struct tx80211_cardlist *cards = NULL;
	int i;

	list  = rb_ary_new();
	cards = tx80211_getcardlist();
	if (cards == NULL) {
		return(Qnil);
	}
	
	for (i = 1; i < cards->num_cards; i++)
		rb_ary_push(list, rb_str_new2(cards->cardnames[i]));
	
	return(list);
}

static VALUE lorcon_driver_get_channel(VALUE self) {
	struct tx80211 *in_tx;
	Data_Get_Struct(self, struct tx80211, in_tx);
	return INT2NUM(tx80211_getchannel(in_tx));
}

static VALUE lorcon_driver_set_channel(VALUE self, VALUE channel) {
	struct tx80211 *in_tx;
	Data_Get_Struct(self, struct tx80211, in_tx);
	tx80211_setchannel(in_tx, NUM2INT(channel));
	return INT2NUM(tx80211_getchannel(in_tx));
}

void lorcon_driver_free(struct tx80211 *in_tx) {
	tx80211_close(in_tx);
	free(in_tx);
}

static VALUE lorcon_driver_open(int argc, VALUE *argv, VALUE self) {
	struct tx80211 *in_tx;
	int ret = 0;
	int drivertype = INJ_NODRIVER;
	char *driver, *intf;
	VALUE rbdriver, rbintf, rbchannel;
	VALUE obj;
		
	if (rb_scan_args(argc, argv, "21", &rbintf, &rbdriver, &rbchannel) == 2) {
		rbchannel = INT2NUM(11);		
	}

	driver = STR2CSTR(rbdriver);
	intf = STR2CSTR(rbintf);
	
	obj = Data_Make_Struct(cDevice, struct tx80211, 0, lorcon_driver_free, in_tx);

	drivertype = tx80211_resolvecard(driver);
	if (drivertype == INJ_NODRIVER) {
		rb_raise(rb_eArgError, "Lorcon did not recognize the specified driver");
		return(Qnil);
	}
	
	if (tx80211_init(in_tx, intf, drivertype) < 0) {
		rb_raise(rb_eRuntimeError, "Lorcon could not initialize the interface");
		return(Qnil);
	}
		
	/*
	 *FUNCMODE_INJ_MON gets us injection -and- monitor mode if supported 
	 *This seems like a good default, but i havent tried it on any cards
	 *other than atheros with madwifi-old 
	 */
	//ret = tx80211_setmode(in_tx, IW_MODE_MONITOR); 
	ret = tx80211_setfunctionalmode(in_tx, TX80211_FUNCMODE_INJMON);
	if (ret != 0) {
		//rb_raise(rb_eRuntimeError, "Lorcon could not place the card into monitor mode");
		rb_raise(rb_eRuntimeError, "Lorcon could not place the card into injection + monitor mode");
		return(Qnil);
	}

	/* Switch to the given channel */
	ret = tx80211_setchannel(in_tx, NUM2INT(rbchannel));
	if (ret < 0) {
		rb_raise(rb_eRuntimeError, "Lorcon could not set the channel");
		return(Qnil);
	}

	/* Open the interface to get a socket */
	ret = tx80211_open(in_tx);
	if (ret < 0) {
		rb_raise(rb_eRuntimeError, "Lorcon could not open the interface");
		return(Qnil);
	}	

	rb_obj_call_init(obj, 0, 0);	
	return(obj);
}

static VALUE lorcon_driver_write(int argc, VALUE *argv, VALUE self) {
	struct tx80211_packet in_packet;
	struct tx80211 *in_tx;
	int ret = 0;
	int cnt = 0;
	int dly = 0;
	
	VALUE rbbuff, rbcnt, rbdelay;
	
	Data_Get_Struct(self, struct tx80211, in_tx);	
		
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
	
	in_packet.packet = StringValuePtr(rbbuff);
	in_packet.plen = RSTRING(rbbuff)->len;

	for (; cnt > 0; cnt--) {
		ret = tx80211_txpacket(in_tx, &in_packet);
		if (ret < 0) 
			return(INT2NUM(ret));
		if (dly > 0)
			usleep(dly);
	}

	return (rbcnt);
}

void Init_Lorcon() {	
	mLorcon = rb_define_module("Lorcon");
	rb_define_module_function(mLorcon, "drivers", lorcon_driver_list, 0);
	
	cDevice = rb_define_class_under(mLorcon, "Device", rb_cObject);
	rb_define_singleton_method(cDevice, "new", lorcon_driver_open, -1);
	rb_define_method(cDevice, "channel", lorcon_driver_get_channel, 0);
	rb_define_method(cDevice, "channel=", lorcon_driver_set_channel, 1);
	rb_define_method(cDevice, "write", lorcon_driver_write, -1);
}
