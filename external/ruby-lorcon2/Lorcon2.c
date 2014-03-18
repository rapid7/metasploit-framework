#include "Lorcon2.h"
#include "ruby.h"

#ifndef RUBY_19
#include "rubysig.h"
#endif

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
	All ruby-lorcon/rubyisms are by Rapid7, Inc. (C) 2006-2007
		http://metasploit.com/ - msfdev[at]metasploit.com
*/

VALUE mLorcon;
VALUE cDevice;
VALUE cPacket;

VALUE Lorcon_get_version(VALUE self) {
	return INT2NUM(lorcon_get_version());
}

static VALUE Lorcon_list_drivers(VALUE self) {
	VALUE list;
	VALUE hash;

	lorcon_driver_t *drvlist, *dri;

	list = rb_hash_new();

	dri = drvlist = lorcon_list_drivers();

	if (dri == NULL)
		return Qnil;

	while (dri) {
		hash = rb_hash_new();
		rb_hash_aset(hash, rb_str_new2("name"), rb_str_new2(dri->name));
		rb_hash_aset(hash, rb_str_new2("description"), rb_str_new2(dri->details));
		rb_hash_aset(list, rb_str_new2(dri->name),hash);
		dri = dri->next;
	}

	lorcon_free_driver_list(drvlist);

	return(list);
}

static VALUE Lorcon_find_driver(VALUE self, VALUE driver) {
	VALUE hash;
	lorcon_driver_t *dri;
	char *drivert = RSTRING_PTR(driver);

	dri = lorcon_find_driver(drivert);

	if (dri == NULL)
		return Qnil;

	hash = rb_hash_new();

	rb_hash_aset(hash, rb_str_new2("name"), rb_str_new2(dri->name));
	rb_hash_aset(hash, rb_str_new2("description"), rb_str_new2(dri->details));

	lorcon_free_driver_list(dri);

	return(hash);
}

static VALUE Lorcon_auto_driver(VALUE self, VALUE interface) {
	VALUE hash;
	lorcon_driver_t *dri;
	char *intf = RSTRING_PTR(interface);

	dri = lorcon_auto_driver(intf);

	if (dri == NULL)
		return Qnil;

	hash = rb_hash_new();
	rb_hash_aset(hash, rb_str_new2("name"), rb_str_new2(dri->name));
	rb_hash_aset(hash, rb_str_new2("description"), rb_str_new2(dri->details));

	lorcon_free_driver_list(dri);

	return hash;
}

void Lorcon_free(struct rldev *rld) {
	if (rld->context != NULL)
		lorcon_free(rld->context);
}

static VALUE Lorcon_create(int argc, VALUE *argv, VALUE self) {
	struct rldev *rld;
	char *intf = NULL, *driver = NULL;
	VALUE rbdriver, rbintf, obj;
	lorcon_driver_t *dri;

	if (argc == 2) {
		rb_scan_args(argc, argv, "2", &rbintf, &rbdriver);
		intf = StringValuePtr(rbintf);
		driver = StringValuePtr(rbdriver);
	} else {
		rb_scan_args(argc, argv, "1", &rbintf);
		intf = StringValuePtr(rbintf);
	}
	
	if (driver == NULL) {
		if ((dri = lorcon_auto_driver(intf)) == NULL) {
			rb_raise(rb_eRuntimeError,
					 "LORCON could not detect a driver and none specified");
			return (Qnil);
		}
	} else {
		if ((dri = lorcon_find_driver(driver)) == NULL) {
			rb_raise(rb_eArgError,
					 "LORCON could not recognize the specified driver");
			return (Qnil);
		}
	}

	obj = Data_Make_Struct(cDevice, struct rldev, 0, Lorcon_free, rld);

	rld->context = lorcon_create(intf, dri);
	
	// Obsolete: XXX
	// lorcon_set_timeout(rld->context, 100);
		
	if (rld->context == NULL) {
		rb_raise(rb_eRuntimeError,
				 "LORCON could not create context");
		return (Qnil);
	}

	lorcon_free_driver_list(dri);

	rb_obj_call_init(obj, 0, 0);	
	return(obj);
}


static VALUE Lorcon_open_inject(VALUE self) {
	struct rldev *rld;

	Data_Get_Struct(self, struct rldev, rld);

	if (lorcon_open_inject(rld->context) < 0)
		return Qfalse;

	return Qtrue;
}

static VALUE Lorcon_open_monitor(VALUE self) {
	struct rldev *rld;

	Data_Get_Struct(self, struct rldev, rld);

	if (lorcon_open_monitor(rld->context) < 0)
		return Qfalse;

	return Qtrue;
}

static VALUE Lorcon_open_injmon(VALUE self) {
	struct rldev *rld;

	Data_Get_Struct(self, struct rldev, rld);

	if (lorcon_open_injmon(rld->context) < 0)
		return Qfalse;

	return Qtrue;
}

static VALUE Lorcon_get_error(VALUE self) {
	struct rldev *rld;

	Data_Get_Struct(self, struct rldev, rld);

	return rb_str_new2(lorcon_get_error(rld->context));
}

static VALUE Lorcon_get_capiface(VALUE self) {
	struct rldev *rld;
	Data_Get_Struct(self, struct rldev, rld);

	return rb_str_new2(lorcon_get_capiface(rld->context));
}

void Lorcon_packet_free(struct rlpack *rlp) {
	if (rlp->packet != NULL) {
		lorcon_packet_free(rlp->packet);
		rlp->packet = NULL;
		free(rlp);
	}
}

static VALUE Lorcon_packet_create(int argc, VALUE *argv, VALUE self) {
	struct rlpack *rlp;
	VALUE obj;

	obj = Data_Make_Struct(cPacket, struct rlpack, 0, Lorcon_packet_free, rlp);

	rlp->packet = (struct lorcon_packet *) malloc(sizeof(struct lorcon_packet));
	memset(rlp->packet, 0, sizeof(struct lorcon_packet));

	rlp->bssid = NULL;
	rlp->dot3 = NULL;
	rlp->len = 0;
	rlp->dir = 0;

	rb_obj_call_init(obj, 0, 0);	
	return(obj);
}

static VALUE Lorcon_packet_get_channel(VALUE self) {
	struct rlpack *rlp;
	Data_Get_Struct(self, struct rlpack, rlp);

	return INT2FIX(rlp->packet->channel);
}

static VALUE Lorcon_packet_set_channel(VALUE self, VALUE channel) {
	struct rlpack *rlp;

	Data_Get_Struct(self, struct rlpack, rlp);

	lorcon_packet_set_channel(rlp->packet, NUM2INT(channel));

	return channel;
}

static VALUE Lorcon_packet_get_dlt(VALUE self) {
	struct rlpack *rlp;
	Data_Get_Struct(self, struct rlpack, rlp);

	return INT2FIX(rlp->packet->dlt);
}

static VALUE Lorcon_packet_get_bssid(VALUE self) {
	struct rlpack *rlp;
	struct lorcon_dot11_extra *extra;
	Data_Get_Struct(self, struct rlpack, rlp);

	if (rlp->packet->extra_info == NULL ||
		rlp->packet->extra_type != LORCON_PACKET_EXTRA_80211)
		return Qnil;

	extra = (struct lorcon_dot11_extra *) rlp->packet->extra_info;

	if (extra->bssid_mac == NULL)
		return Qnil;

	return rb_str_new((char *)extra->bssid_mac, 6);
}

static VALUE Lorcon_packet_get_source(VALUE self) {
	struct rlpack *rlp;
	struct lorcon_dot11_extra *extra;
	Data_Get_Struct(self, struct rlpack, rlp);

	if (rlp->packet->extra_info == NULL ||
		rlp->packet->extra_type != LORCON_PACKET_EXTRA_80211)
		return Qnil;

	extra = (struct lorcon_dot11_extra *) rlp->packet->extra_info;

	if (extra->source_mac == NULL)
		return Qnil;

	return rb_str_new((char *)extra->source_mac, 6);
}

static VALUE Lorcon_packet_get_dest(VALUE self) {
	struct rlpack *rlp;
	struct lorcon_dot11_extra *extra;
	Data_Get_Struct(self, struct rlpack, rlp);

	if (rlp->packet->extra_info == NULL ||
		rlp->packet->extra_type != LORCON_PACKET_EXTRA_80211)
		return Qnil;

	extra = (struct lorcon_dot11_extra *) rlp->packet->extra_info;

	if (extra->dest_mac == NULL)
		return Qnil;

	return rb_str_new((char *)extra->dest_mac, 6);
}

static VALUE Lorcon_packet_get_rawdata(VALUE self) {
	struct rlpack *rlp;
	Data_Get_Struct(self, struct rlpack, rlp);

	if (rlp->packet->packet_raw == NULL)
		return Qnil;

	return rb_str_new((char *)rlp->packet->packet_raw, rlp->packet->length);
}

static VALUE Lorcon_packet_get_headerdata(VALUE self) {
	struct rlpack *rlp;
	Data_Get_Struct(self, struct rlpack, rlp);

	if (rlp->packet->packet_header == NULL)
		return Qnil;

	return rb_str_new((char *)rlp->packet->packet_header, rlp->packet->length_header);
}

static VALUE Lorcon_packet_get_data(VALUE self) {
	struct rlpack *rlp;
	Data_Get_Struct(self, struct rlpack, rlp);

	if (rlp->packet->packet_data == NULL)
		return Qnil;

	return rb_str_new((char *)rlp->packet->packet_data, rlp->packet->length_data);
}


static VALUE Lorcon_packet_getdot3(VALUE self) {
	struct rlpack *rlp;
	u_char *pdata;
	int len;
	VALUE ret;
	
	Data_Get_Struct(self, struct rlpack, rlp);

	if (rlp->packet->packet_data == NULL)
		return Qnil;

	len = lorcon_packet_to_dot3(rlp->packet, &pdata);

	ret = rb_str_new((char *)pdata, len);

	free(pdata);

	return ret;
}

static VALUE Lorcon_packet_prepdot3(VALUE self, VALUE dot3) {
	struct rlpack *rlp;
	Data_Get_Struct(self, struct rlpack, rlp);

	rlp->dot3 = (unsigned char *) RSTRING_PTR(dot3);
	rlp->len = RSTRING_LEN(dot3);

	return dot3;
}

static VALUE Lorcon_packet_prepbssid(VALUE self, VALUE bssid) {
	struct rlpack *rlp;
	Data_Get_Struct(self, struct rlpack, rlp);

	rlp->bssid = (unsigned char *)RSTRING_PTR(bssid);

	return bssid;
}

static VALUE Lorcon_packet_prepdir(VALUE self, VALUE dir) {
	struct rlpack *rlp;
	Data_Get_Struct(self, struct rlpack, rlp);

	rlp->dir = NUM2INT(dir);

	return dir;
}

static VALUE Lorcon_packet_getdir(VALUE self) {
	struct rlpack *rlp;
	struct lorcon_dot11_extra *extra;
	Data_Get_Struct(self, struct rlpack, rlp);

	if (rlp->dir != 0)
		return INT2FIX(rlp->dir);

	if (rlp->packet == NULL)
		return Qnil;

	if (rlp->packet->extra_info == NULL ||
		rlp->packet->extra_type != LORCON_PACKET_EXTRA_80211)
		return Qnil;

	extra = (struct lorcon_dot11_extra *) rlp->packet->extra_info;

	if (extra->from_ds && !extra->to_ds)
		return INT2FIX(LORCON_DOT11_DIR_FROMDS);
	else if (!extra->from_ds && extra->to_ds)
		return INT2FIX(LORCON_DOT11_DIR_TODS);
	else if (!extra->from_ds && !extra->to_ds)
		return INT2FIX(LORCON_DOT11_DIR_ADHOCDS);
	else if (extra->from_ds && extra->to_ds)
		return INT2FIX(LORCON_DOT11_DIR_INTRADS);

	return Qnil;
}

static VALUE Lorcon_packet_get_rawlength(VALUE self) {
	struct rlpack *rlp;
	Data_Get_Struct(self, struct rlpack, rlp);

	return INT2FIX(rlp->packet->length);
}

static VALUE Lorcon_packet_get_headerlength(VALUE self) {
	struct rlpack *rlp;
	Data_Get_Struct(self, struct rlpack, rlp);

	return INT2FIX(rlp->packet->length_header);
}

static VALUE Lorcon_packet_get_datalength(VALUE self) {
	struct rlpack *rlp;
	Data_Get_Struct(self, struct rlpack, rlp);

	return INT2FIX(rlp->packet->length_data);
}

VALUE new_lorcon_packet(struct lorcon_packet **packet) {
	struct rlpack *rlp;
	VALUE obj;

	obj = Data_Make_Struct(cPacket, struct rlpack, 0, Lorcon_packet_free, rlp);

	rlp->packet = *packet;
	rb_obj_call_init(obj, 0, 0);	
	return(obj);
}

static VALUE Lorcon_inject_packet(VALUE self, VALUE packet) {
	struct rldev *rld;
	struct rlpack *rlp;
	lorcon_packet_t *pack = NULL;
	int ret;

	if (rb_obj_is_kind_of(packet, cPacket) == 0) {
		rb_raise(rb_eTypeError, "wrong type expected %s", rb_class2name(cPacket));
		return Qnil;
	}
		
	Data_Get_Struct(self, struct rldev, rld);
	Data_Get_Struct(packet, struct rlpack, rlp);

	if (rlp->bssid != NULL && rlp->dot3 != NULL) {
		pack = lorcon_packet_from_dot3(rlp->bssid, rlp->dir, rlp->dot3, rlp->len);
		ret = lorcon_inject(rld->context, pack);
		lorcon_packet_free(pack);
	} else {
		ret = lorcon_inject(rld->context, rlp->packet);
	}

	return INT2FIX(ret);
}

static VALUE Lorcon_write_raw(VALUE self, VALUE rpacket) {
	struct rldev *rld;
	int ret;
	
	Data_Get_Struct(self, struct rldev, rld);
	
    if(TYPE(rpacket) != T_STRING) {
    	rb_raise(rb_eArgError, "packet data must be a string");
		return Qnil;
	}
	
	ret = lorcon_send_bytes(rld->context, RSTRING_LEN(rpacket), (unsigned char *)RSTRING_PTR(rpacket));
	return INT2FIX(ret);
}

static VALUE Lorcon_set_filter(VALUE self, VALUE filter) {
	struct rldev *rld;
	Data_Get_Struct(self, struct rldev, rld);
	return INT2FIX(lorcon_set_filter(rld->context, RSTRING_PTR(filter)));
}

static VALUE Lorcon_set_channel(VALUE self, VALUE channel) {
	struct rldev *rld;
	Data_Get_Struct(self, struct rldev, rld);
	return INT2FIX(lorcon_set_channel(rld->context, NUM2INT(channel)));
}

static VALUE Lorcon_get_channel(VALUE self) {
	struct rldev *rld;
	Data_Get_Struct(self, struct rldev, rld);
	return INT2FIX(lorcon_get_channel(rld->context));
}

static void rblorcon_pcap_handler(rblorconjob_t *job, struct pcap_pkthdr *hdr, u_char *pkt){
	job->pkt = (unsigned char *)pkt;
	job->hdr = *hdr;
}

static VALUE Lorcon_capture_next(VALUE self) {
	struct rldev *rld;
	int ret = 0;
	struct lorcon_packet *packet;
	unsigned char *raw;
	pcap_t *pd;
	rblorconjob_t job;
	Data_Get_Struct(self, struct rldev, rld);

	pd = lorcon_get_pcap(rld->context);
	
#ifndef RUBY_19
	TRAP_BEG;
#endif
	ret = pcap_dispatch(pd, 1, (pcap_handler) rblorcon_pcap_handler, (u_char *)&job);
#ifndef RUBY_19
	TRAP_END;
#endif
		
	if (ret == 0)
		return(Qnil);

	if (ret < 0 || job.hdr.caplen <= 0)
		return INT2FIX(ret);

	raw = malloc(job.hdr.caplen);
	if(! raw) return Qnil;
	
	memcpy(raw, job.pkt, job.hdr.caplen);
	packet = lorcon_packet_from_pcap(rld->context, &job.hdr, raw);
	lorcon_packet_set_freedata(packet, 1);
			
	return new_lorcon_packet(&packet);
}


static VALUE Lorcon_capture_loop(int argc, VALUE *argv, VALUE self) {
	struct rldev *rld;
	int count = 0;
	int p = 0;
	VALUE v_cnt;
	VALUE ret;
	int fd;
	
	Data_Get_Struct(self, struct rldev, rld);

	if (rb_scan_args(argc, argv, "01", &v_cnt) >= 1) {
		count = FIX2INT(v_cnt);
	} else {
		count = -1;
	}

	fd = lorcon_get_selectable_fd(rld->context);
	if(fd < 0 ) {
		rb_raise(rb_eRuntimeError,
				 "LORCON context could not provide a pollable descriptor "
				 "and we need one for the threaded dispatch loop");
	}
	
	while (p < count || count <= 0) {
		ret = Lorcon_capture_next(self);
		if(TYPE(ret) == T_FIXNUM) return(ret);
		if(ret == Qnil) {
			rb_thread_wait_fd(fd);
		} else {
			rb_yield(ret);
			p++;
		}
	}
	
	return INT2FIX(p);
}


void Init_Lorcon2() {	
	mLorcon = rb_define_module("Lorcon");

	cPacket = rb_define_class_under(mLorcon, "Packet", rb_cObject);

	rb_define_const(cPacket, "LORCON_FROM_DS", INT2NUM(LORCON_DOT11_DIR_FROMDS));
	rb_define_const(cPacket, "LORCON_TO_DS", INT2NUM(LORCON_DOT11_DIR_TODS));
	rb_define_const(cPacket, "LORCON_INTRA_DS", INT2NUM(LORCON_DOT11_DIR_INTRADS));
	rb_define_const(cPacket, "LORCON_ADHOC_DS", INT2NUM(LORCON_DOT11_DIR_ADHOCDS));

	rb_define_singleton_method(cPacket, "new", Lorcon_packet_create, -1);
	rb_define_method(cPacket, "bssid", Lorcon_packet_get_bssid, 0);
	rb_define_method(cPacket, "source", Lorcon_packet_get_source, 0);
	rb_define_method(cPacket, "dest", Lorcon_packet_get_dest, 0);

	rb_define_method(cPacket, "channel", Lorcon_packet_get_channel, 0);
	rb_define_method(cPacket, "channel=", Lorcon_packet_set_channel, 1);
	rb_define_method(cPacket, "dlt", Lorcon_packet_get_dlt, 0);

	rb_define_method(cPacket, "rawdata", Lorcon_packet_get_rawdata, 0);
	rb_define_method(cPacket, "headerdata", Lorcon_packet_get_headerdata, 0);
	rb_define_method(cPacket, "data", Lorcon_packet_get_data, 0);

	rb_define_method(cPacket, "dot3", Lorcon_packet_getdot3, 0);

	rb_define_method(cPacket, "dot3=", Lorcon_packet_prepdot3, 1);
	rb_define_method(cPacket, "bssid=", Lorcon_packet_prepbssid, 1);
	rb_define_method(cPacket, "direction=", Lorcon_packet_prepdir, 1);
	rb_define_method(cPacket, "direction", Lorcon_packet_getdir, 0);

	rb_define_method(cPacket, "size", Lorcon_packet_get_rawlength, 0);
	rb_define_method(cPacket, "linesize", Lorcon_packet_get_rawlength, 0);
	rb_define_method(cPacket, "headersize", Lorcon_packet_get_headerlength, 0);
	rb_define_method(cPacket, "datasize", Lorcon_packet_get_datalength, 0);

	cDevice = rb_define_class_under(mLorcon, "Device", rb_cObject);
	rb_define_singleton_method(cDevice, "new", Lorcon_create, -1);
	rb_define_method(cDevice, "openinject", Lorcon_open_inject, 0);
	rb_define_method(cDevice, "openmonitor", Lorcon_open_monitor, 0);
	rb_define_method(cDevice, "openinjmon", Lorcon_open_injmon, 0);
	rb_define_method(cDevice, "error", Lorcon_get_error, 0);
	rb_define_method(cDevice, "capiface", Lorcon_get_capiface, 0);

	rb_define_method(cDevice, "filter=", Lorcon_set_filter, 1);
	rb_define_method(cDevice, "channel=", Lorcon_set_channel, 1);
	rb_define_method(cDevice, "channel", Lorcon_get_channel, 0);

	rb_define_method(cDevice, "loop", Lorcon_capture_loop, -1);
	rb_define_method(cDevice, "each", Lorcon_capture_loop, -1);
	rb_define_method(cDevice, "each_packet", Lorcon_capture_loop, -1);
	rb_define_method(cDevice, "write", Lorcon_write_raw, 1);
	rb_define_method(cDevice, "inject", Lorcon_inject_packet, 1);
	rb_define_module_function(mLorcon, "drivers", Lorcon_list_drivers, 0);
	rb_define_module_function(mLorcon, "version", Lorcon_get_version, 0);
	rb_define_module_function(mLorcon, "find_driver", Lorcon_find_driver, 1);
	rb_define_module_function(mLorcon, "auto_driver", Lorcon_auto_driver, 1);
}


