//				Package : omnithread
// omnithread/nt.h		Created : 6/95 tjr
//
//    Copyright (C) 1999 AT&T Laboratories Cambridge. All Rights Reserved.
//
//    This file is part of the omnithread library
//
//    The omnithread library is free software; you can redistribute it and/or
//    modify it under the terms of the GNU Library General Public
//    License as published by the Free Software Foundation; either
//    version 2 of the License, or (at your option) any later version.
//
//    This library is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//    Library General Public License for more details.
//
//    You should have received a copy of the GNU Library General Public
//    License along with this library; if not, write to the Free
//    Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  
//    02111-1307, USA
//
//
// OMNI thread implementation classes for NT threads.
//

#ifndef __omnithread_nt_h_
#define __omnithread_nt_h_

#include <windows.h>

#define OMNI_THREAD_WRAPPER \
    unsigned __stdcall omni_thread_wrapper(LPVOID ptr)

extern "C" OMNI_THREAD_WRAPPER;

#define OMNI_MUTEX_IMPLEMENTATION			\
    CRITICAL_SECTION crit;

#define OMNI_CONDITION_IMPLEMENTATION			\
    CRITICAL_SECTION crit;				\
    omni_thread* waiting_head;				\
    omni_thread* waiting_tail;

#define OMNI_SEMAPHORE_IMPLEMENTATION			\
    HANDLE nt_sem;

#define OMNI_THREAD_IMPLEMENTATION			\
    HANDLE handle;					\
    DWORD nt_id;					\
    void* return_val;					\
    HANDLE cond_semaphore;				\
    omni_thread* cond_next;				\
    omni_thread* cond_prev;				\
    BOOL cond_waiting;					\
    static int nt_priority(priority_t);			\
    friend class omni_condition;			\
    friend OMNI_THREAD_WRAPPER;

#endif
