/*
 * MessagePack for Ruby packing routine
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
#include "ruby.h"
#include "compat.h"

#include "msgpack/pack_define.h"

static ID s_to_msgpack;
static ID s_append;

#define msgpack_pack_inline_func(name) \
	static inline void msgpack_pack ## name

#define msgpack_pack_inline_func_cint(name) \
	static inline void msgpack_pack ## name

#define msgpack_pack_user VALUE

#define msgpack_pack_append_buffer(user, buf, len) \
	((TYPE(user) == T_STRING) ? \
		rb_str_buf_cat(user, (const void*)buf, len) : \
		rb_funcall(user, s_append, 1, rb_str_new((const void*)buf,len)))

#include "msgpack/pack_template.h"


#ifndef RUBY_VM
#include "st.h"  // ruby hash
#endif

#define ARG_BUFFER(name, argc, argv) \
	VALUE name; \
	if(argc == 1) { \
		name = argv[0]; \
	} else if(argc == 0) { \
		name = rb_str_buf_new(0); \
	} else { \
		rb_raise(rb_eArgError, "wrong number of arguments (%d for 0)", argc); \
	}


/*
 * Document-method: NilClass#to_msgpack
 *
 * call-seq:
 *   nil.to_msgpack(out = '') -> String
 *
 * Serializes the nil into raw bytes.
 */
static VALUE MessagePack_NilClass_to_msgpack(int argc, VALUE *argv, VALUE self)
{
	ARG_BUFFER(out, argc, argv);
	msgpack_pack_nil(out);
	return out;
}


/*
 * Document-method: TrueClass#to_msgpack
 *
 * call-seq:
 *   true.to_msgpack(out = '') -> String
 *
 * Serializes the true into raw bytes.
 */
static VALUE MessagePack_TrueClass_to_msgpack(int argc, VALUE *argv, VALUE self)
{
	ARG_BUFFER(out, argc, argv);
	msgpack_pack_true(out);
	return out;
}


/*
 * Document-method: FalseClass#to_msgpack
 *
 * call-seq:
 *   false.to_msgpack(out = '') -> String
 *
 * Serializes false into raw bytes.
 */
static VALUE MessagePack_FalseClass_to_msgpack(int argc, VALUE *argv, VALUE self)
{
	ARG_BUFFER(out, argc, argv);
	msgpack_pack_false(out);
	return out;
}


/*
 * Document-method: Fixnum#to_msgpack
 *
 * call-seq:
 *   fixnum.to_msgpack(out = '') -> String
 *
 * Serializes the Fixnum into raw bytes.
 */
static VALUE MessagePack_Fixnum_to_msgpack(int argc, VALUE *argv, VALUE self)
{
	ARG_BUFFER(out, argc, argv);
#ifdef JRUBY
	msgpack_pack_long(out, FIXNUM_P(self) ? FIX2LONG(self) : rb_num2ll(self));
#else
	msgpack_pack_long(out, FIX2LONG(self));
#endif
	return out;
}


/*
 * Document-method: Bignum#to_msgpack
 *
 * call-seq:
 *   bignum.to_msgpack(out = '') -> String
 *
 * Serializes the Bignum into raw bytes.
 */
static VALUE MessagePack_Bignum_to_msgpack(int argc, VALUE *argv, VALUE self)
{
	ARG_BUFFER(out, argc, argv);
	if(RBIGNUM_POSITIVE_P(self)) {
		msgpack_pack_uint64(out, rb_big2ull(self));
	} else {
		msgpack_pack_int64(out, rb_big2ll(self));
	}
	return out;
}


/*
 * Document-method: Float#to_msgpack
 *
 * call-seq:
 *   float.to_msgpack(out = '') -> String
 *
 * Serializes the Float into raw bytes.
 */
static VALUE MessagePack_Float_to_msgpack(int argc, VALUE *argv, VALUE self)
{
	ARG_BUFFER(out, argc, argv);
	msgpack_pack_double(out, rb_num2dbl(self));
	return out;
}


/*
 * Document-method: String#to_msgpack
 *
 * call-seq:
 *   string.to_msgpack(out = '') -> String
 *
 * Serializes the String into raw bytes.
 */
static VALUE MessagePack_String_to_msgpack(int argc, VALUE *argv, VALUE self)
{
	ARG_BUFFER(out, argc, argv);
#ifdef COMPAT_HAVE_ENCODING
	int enc = ENCODING_GET(self);
	if(enc != s_enc_utf8 && enc != s_enc_ascii8bit && enc != s_enc_usascii) {
		if(!ENC_CODERANGE_ASCIIONLY(self)) {
			self = rb_str_encode(self, s_enc_utf8_value, 0, Qnil);
		}
	}
#endif
	msgpack_pack_raw(out, RSTRING_LEN(self));
	msgpack_pack_raw_body(out, RSTRING_PTR(self), RSTRING_LEN(self));
	return out;
}


/*
 * Document-method: Symbol#to_msgpack
 *
 * call-seq:
 *   symbol.to_msgpack(out = '') -> String
 *
 * Serializes the Symbol into raw bytes.
 */
static VALUE MessagePack_Symbol_to_msgpack(int argc, VALUE *argv, VALUE self)
{
#ifdef COMPAT_HAVE_ENCODING
	return MessagePack_String_to_msgpack(argc, argv, rb_id2str(SYM2ID(self)));
#else
	ARG_BUFFER(out, argc, argv);
	const char* name = rb_id2name(SYM2ID(self));
	size_t len = strlen(name);
	msgpack_pack_raw(out, len);
	msgpack_pack_raw_body(out, name, len);
	return out;
#endif
}


/*
 * Document-method: Array#to_msgpack
 *
 * call-seq:
 *   array.to_msgpack(out = '') -> String
 *
 * Serializes the Array into raw bytes.
 * This calls to_msgpack method reflectively for internal elements.
 */
static VALUE MessagePack_Array_to_msgpack(int argc, VALUE *argv, VALUE self)
{
	ARG_BUFFER(out, argc, argv);
	// FIXME check sizeof(long) > sizeof(unsigned int) && RARRAY_LEN(self) > UINT_MAX
	msgpack_pack_array(out, (unsigned int)RARRAY_LEN(self));
	VALUE* p = RARRAY_PTR(self);
	VALUE* const pend = p + RARRAY_LEN(self);
	for(;p != pend; ++p) {
		rb_funcall(*p, s_to_msgpack, 1, out);
	}
	return out;
}


#ifndef RHASH_SIZE  // Ruby 1.8
#define RHASH_SIZE(h) (RHASH(h)->tbl ? RHASH(h)->tbl->num_entries : 0)
#endif

static int MessagePack_Hash_to_msgpack_foreach(VALUE key, VALUE value, VALUE out)
{
	if (key == Qundef) { return ST_CONTINUE; }
	rb_funcall(key, s_to_msgpack, 1, out);
	rb_funcall(value, s_to_msgpack, 1, out);
	return ST_CONTINUE;
}

/*
 * Document-method: Hash#to_msgpack
 *
 * call-seq:
 *   hash.to_msgpack(out = '') -> String
 *
 * Serializes the Hash into raw bytes.
 * This calls to_msgpack method reflectively for internal keys and values.
 */
static VALUE MessagePack_Hash_to_msgpack(int argc, VALUE *argv, VALUE self)
{
	ARG_BUFFER(out, argc, argv);
	// FIXME check sizeof(st_index_t) > sizeof(unsigned int) && RARRAY_LEN(self) > UINT_MAX
	msgpack_pack_map(out, (unsigned int)RHASH_SIZE(self));
	rb_hash_foreach(self, MessagePack_Hash_to_msgpack_foreach, out);
	return out;
}


/**
 * Document-method: MessagePack.pack
 *
 * call-seq:
 *   MessagePack.pack(object, out = '') -> String
 *
 * Serializes the object into raw bytes. The encoding of the string is ASCII-8BIT on Ruby 1.9.
 * This method is same as object.to_msgpack(out = '').
 *
 * _out_ is an object that implements *<<* method like String or IO.
 */
static VALUE MessagePack_pack(int argc, VALUE* argv, VALUE self)
{
	VALUE out;
	if(argc == 1) {
		out = rb_str_buf_new(0);
	} else if(argc == 2) {
		out = argv[1];
	} else {
		rb_raise(rb_eArgError, "wrong number of arguments (%d for 1)", argc);
	}
	return rb_funcall(argv[0], s_to_msgpack, 1, out);
}


void Init_msgpack_pack(VALUE mMessagePack)
{
	s_to_msgpack = rb_intern("to_msgpack");
	s_append = rb_intern("<<");

	rb_define_method(rb_cNilClass,   "to_msgpack", MessagePack_NilClass_to_msgpack, -1);
	rb_define_method(rb_cTrueClass,  "to_msgpack", MessagePack_TrueClass_to_msgpack, -1);
	rb_define_method(rb_cFalseClass, "to_msgpack", MessagePack_FalseClass_to_msgpack, -1);
	rb_define_method(rb_cFixnum, "to_msgpack", MessagePack_Fixnum_to_msgpack, -1);
	rb_define_method(rb_cBignum, "to_msgpack", MessagePack_Bignum_to_msgpack, -1);
	rb_define_method(rb_cFloat,  "to_msgpack", MessagePack_Float_to_msgpack, -1);
	rb_define_method(rb_cString, "to_msgpack", MessagePack_String_to_msgpack, -1);
	rb_define_method(rb_cArray,  "to_msgpack", MessagePack_Array_to_msgpack, -1);
	rb_define_method(rb_cHash,   "to_msgpack", MessagePack_Hash_to_msgpack, -1);
	rb_define_method(rb_cSymbol, "to_msgpack", MessagePack_Symbol_to_msgpack, -1);

	/**
	 * MessagePack module is defined in rbinit.c file.
	 * mMessagePack = rb_define_module("MessagePack");
	 */
	rb_define_module_function(mMessagePack, "pack", MessagePack_pack, -1);
}

