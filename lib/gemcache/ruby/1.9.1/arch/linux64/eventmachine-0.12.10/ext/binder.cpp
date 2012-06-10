/*****************************************************************************

$Id$

File:     binder.cpp
Date:     07Apr06

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/

#include "project.h"

#define DEV_URANDOM "/dev/urandom"


map<unsigned long, Bindable_t*> Bindable_t::BindingBag;


/********************************
STATIC Bindable_t::CreateBinding
********************************/

unsigned long Bindable_t::CreateBinding()
{
	// XXX use atomic_t to prevent thread-safety issues
	static unsigned long num = 0;
	while(BindingBag[++num]);
	return num;
}

#if 0
string Bindable_t::CreateBinding()
{
	static int index = 0;
	static string seed;

	if ((index >= 1000000) || (seed.length() == 0)) {
		#ifdef OS_UNIX
		int fd = open (DEV_URANDOM, O_RDONLY);
		if (fd < 0)
			throw std::runtime_error ("No entropy device");

		unsigned char u[16];
		size_t r = read (fd, u, sizeof(u));
		if (r < sizeof(u))
			throw std::runtime_error ("Unable to read entropy device");

		unsigned char *u1 = (unsigned char*)u;
		char u2 [sizeof(u) * 2 + 1];

		for (size_t i=0; i < sizeof(u); i++)
			sprintf (u2 + (i * 2), "%02x", u1[i]);

		seed = string (u2);
		#endif


		#ifdef OS_WIN32
		UUID uuid;
		UuidCreate (&uuid);
		unsigned char *uuidstring = NULL;
		UuidToString (&uuid, &uuidstring);
		if (!uuidstring)
			throw std::runtime_error ("Unable to read uuid");
		seed = string ((const char*)uuidstring);

		RpcStringFree (&uuidstring);
		#endif

		index = 0;


	}

	stringstream ss;
	ss << seed << (++index);
	return ss.str();
}
#endif

/*****************************
STATIC: Bindable_t::GetObject
*****************************/

Bindable_t *Bindable_t::GetObject (const unsigned long binding)
{
  map<unsigned long, Bindable_t*>::const_iterator i = BindingBag.find (binding);
  if (i != BindingBag.end())
    return i->second;
  else
    return NULL;
}


/**********************
Bindable_t::Bindable_t
**********************/

Bindable_t::Bindable_t()
{
	Binding = Bindable_t::CreateBinding();
	BindingBag [Binding] = this;
}



/***********************
Bindable_t::~Bindable_t
***********************/

Bindable_t::~Bindable_t()
{
	BindingBag.erase (Binding);
}


