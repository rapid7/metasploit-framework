/*****************************************************************************

$Id$

File:     binder.h
Date:     07Apr06

Copyright (C) 2006-07 by Francis Cianfrocca. All Rights Reserved.
Gmail: blackhedd

This program is free software; you can redistribute it and/or modify
it under the terms of either: 1) the GNU General Public License
as published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version; or 2) Ruby's License.

See the file COPYING for complete licensing information.

*****************************************************************************/

#ifndef __ObjectBindings__H_
#define __ObjectBindings__H_


class Bindable_t
{
	public:
		static unsigned long CreateBinding();
		static Bindable_t *GetObject (const unsigned long);
		static map<unsigned long, Bindable_t*> BindingBag;

	public:
		Bindable_t();
		virtual ~Bindable_t();

		const unsigned long GetBinding() {return Binding;}

	private:
		unsigned long Binding;
};





#endif // __ObjectBindings__H_

