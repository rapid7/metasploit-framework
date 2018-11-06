/*****************************************************************************

$Id: rubymain.cpp 4529 2007-07-04 11:32:22Z francis $

File:     rubymain.cpp
Date:     02Jul07

Copyright (C) 2007 by Francis Cianfrocca. All Rights Reserved.
Gmail: garbagecat10

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/



#include <iostream>
#include <stdexcept>

#include <ruby.h>
#include "mapper.h"

static VALUE EmModule;
static VALUE FastFileReader;
static VALUE Mapper;



/*********
mapper_dt
*********/

static void mapper_dt (void *ptr)
{
	if (ptr)
		delete (Mapper_t*) ptr;
}

/**********
mapper_new
**********/

static VALUE mapper_new (VALUE self, VALUE filename)
{
	Mapper_t *m = new Mapper_t (StringValueCStr (filename));
	if (!m)
		rb_raise (rb_eStandardError, "No Mapper Object");
	VALUE v = Data_Wrap_Struct (Mapper, 0, mapper_dt, (void*)m);
	return v;
}


/****************
mapper_get_chunk
****************/

static VALUE mapper_get_chunk (VALUE self, VALUE start, VALUE length)
{
	Mapper_t *m = NULL;
	Data_Get_Struct (self, Mapper_t, m);
	if (!m)
		rb_raise (rb_eStandardError, "No Mapper Object");

	// TODO, what if some moron sends us a negative start value?
	unsigned _start = NUM2INT (start);
	unsigned _length = NUM2INT (length);
	if ((_start + _length) > m->GetFileSize())
		rb_raise (rb_eStandardError, "Mapper Range Error");

	const char *chunk = m->GetChunk (_start);
	if (!chunk)
		rb_raise (rb_eStandardError, "No Mapper Chunk");
	return rb_str_new (chunk, _length);
}

/************
mapper_close
************/

static VALUE mapper_close (VALUE self)
{
	Mapper_t *m = NULL;
	Data_Get_Struct (self, Mapper_t, m);
	if (!m)
		rb_raise (rb_eStandardError, "No Mapper Object");
	m->Close();
	return Qnil;
}

/***********
mapper_size
***********/

static VALUE mapper_size (VALUE self)
{
	Mapper_t *m = NULL;
	Data_Get_Struct (self, Mapper_t, m);
	if (!m)
		rb_raise (rb_eStandardError, "No Mapper Object");
	return INT2NUM (m->GetFileSize());
}


/**********************
Init_fastfilereaderext
**********************/

extern "C" void Init_fastfilereaderext()
{
	EmModule = rb_define_module ("EventMachine");
	FastFileReader = rb_define_class_under (EmModule, "FastFileReader", rb_cObject);
	Mapper = rb_define_class_under (FastFileReader, "Mapper", rb_cObject);

	rb_define_module_function (Mapper, "new", (VALUE(*)(...))mapper_new, 1);
	rb_define_method (Mapper, "size", (VALUE(*)(...))mapper_size, 0);
	rb_define_method (Mapper, "close", (VALUE(*)(...))mapper_close, 0);
	rb_define_method (Mapper, "get_chunk", (VALUE(*)(...))mapper_get_chunk, 2);
}



