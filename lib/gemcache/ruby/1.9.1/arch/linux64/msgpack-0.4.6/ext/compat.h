/*
 * MessagePack for Ruby
 *
 * Copyright (C) 2008-2010 FURUHASHI Sadayuki
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
#ifndef COMPAT_H__
#define COMPAT_H__


#ifdef HAVE_RUBY_ENCODING_H
#include "ruby/encoding.h"
#define COMPAT_HAVE_ENCODING
extern int s_enc_utf8;
extern int s_enc_ascii8bit;
extern int s_enc_usascii;
extern VALUE s_enc_utf8_value;
#endif

/* MRI 1.9 */
#if defined(RUBY_VM)
#define COMPAT_RERAISE rb_exc_raise(rb_errinfo())

/* JRuby */
#elif defined(JRUBY)
#define COMPAT_RERAISE rb_exc_raise(rb_gv_get("$!"))

/* MRI 1.8 and Rubinius */
#else
#define COMPAT_RERAISE rb_exc_raise(ruby_errinfo)
#endif


#ifndef RBIGNUM_POSITIVE_P

/* Rubinius */
#if defined(RUBINIUS)
#define RBIGNUM_POSITIVE_P(b) (rb_funcall(b, rb_intern(">="), 1, INT2FIX(0)) == Qtrue)

/* JRuby */
#elif defined(JRUBY)
#define RBIGNUM_POSITIVE_P(b) (rb_funcall(b, rb_intern(">="), 1, INT2FIX(0)) == Qtrue)
#define rb_big2ull(b) rb_num2ull(b)
/*#define rb_big2ll(b) rb_num2ll(b)*/

/* MRI 1.8 */
#else
#define RBIGNUM_POSITIVE_P(b) (RBIGNUM(b)->sign)

#endif
#endif


/* Rubinius */
#if defined(RUBINIUS)
static inline void rb_gc_enable() { return; }
static inline void rb_gc_disable() { return; }

/* JRuby */
#elif defined(JRUBY)
static inline void rb_gc_enable() { return; }
static inline void rb_gc_disable() { return; }
#endif


/* MRI 1.8.5 */
#ifndef RSTRING_PTR
#define RSTRING_PTR(s) (RSTRING(s)->ptr)
#endif

/* MRI 1.8.5 */
#ifndef RSTRING_LEN
#define RSTRING_LEN(s) (RSTRING(s)->len)
#endif

/* MRI 1.8.5 */
#ifndef RARRAY_PTR
#define RARRAY_PTR(s) (RARRAY(s)->ptr)
#endif

/* MRI 1.8.5 */
#ifndef RARRAY_LEN
#define RARRAY_LEN(s) (RARRAY(s)->len)
#endif


#endif /* compat.h */

