/* Copyright (C) 2002-2005 RealVNC Ltd.  All Rights Reserved.
 * Copyright (C) 2007 Constantin Kaplinsky.  All Rights Reserved.
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 * USA.
 */

// Helper class managing dynamic linkage to DLL functions.

#ifndef __RFB_WIN32_DYNAMICFN_H__
#define __RFB_WIN32_DYNAMICFN_H__

#include "stdhdrs.h"

class DynamicFnBase {
public:
	DynamicFnBase(const TCHAR* dllName, const char* fnName);
	~DynamicFnBase();
	bool isValid() const {return fnPtr != 0;}
protected:
	void* fnPtr;
	HMODULE dllHandle;
private:
	DynamicFnBase(const DynamicFnBase&);
	DynamicFnBase operator=(const DynamicFnBase&);
};

template<class T> class DynamicFn : public DynamicFnBase {
public:
	DynamicFn(const TCHAR* dllName, const char* fnName) : DynamicFnBase(dllName, fnName) {}
	T operator *() const {return (T)fnPtr;};
};

#endif
