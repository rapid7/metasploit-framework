/*
 * MessagePack for Ruby unpacking routine
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

#include "msgpack/unpack_define.h"

static ID s_sysread;
static ID s_readpartial;

struct unpack_buffer {
	size_t used;
	size_t free;
	char* ptr;
};

typedef struct {
	int finished;
	VALUE source;
	size_t offset;
	struct unpack_buffer buffer;
	VALUE stream;
	VALUE streambuf;
	ID stream_append_method;
	size_t buffer_free_size;
} unpack_user;


#define msgpack_unpack_struct(name) \
	struct template ## name

#define msgpack_unpack_func(ret, name) \
	ret template ## name

#define msgpack_unpack_callback(name) \
	template_callback ## name

#define msgpack_unpack_object VALUE

#define msgpack_unpack_user unpack_user


struct template_context;
typedef struct template_context msgpack_unpack_t;

static void template_init(msgpack_unpack_t* u);

static VALUE template_data(msgpack_unpack_t* u);

static int template_execute(msgpack_unpack_t* u,
		const char* data, size_t len, size_t* off);


static inline VALUE template_callback_root(unpack_user* u)
{ return Qnil; }

static inline int template_callback_uint8(unpack_user* u, uint8_t d, VALUE* o)
{ *o = INT2FIX(d); return 0; }

static inline int template_callback_uint16(unpack_user* u, uint16_t d, VALUE* o)
{ *o = INT2FIX(d); return 0; }

static inline int template_callback_uint32(unpack_user* u, uint32_t d, VALUE* o)
{ *o = UINT2NUM(d); return 0; }

static inline int template_callback_uint64(unpack_user* u, uint64_t d, VALUE* o)
{ *o = rb_ull2inum(d); return 0; }

static inline int template_callback_int8(unpack_user* u, int8_t d, VALUE* o)
{ *o = INT2FIX((long)d); return 0; }

static inline int template_callback_int16(unpack_user* u, int16_t d, VALUE* o)
{ *o = INT2FIX((long)d); return 0; }

static inline int template_callback_int32(unpack_user* u, int32_t d, VALUE* o)
{ *o = INT2NUM((long)d); return 0; }

static inline int template_callback_int64(unpack_user* u, int64_t d, VALUE* o)
{ *o = rb_ll2inum(d); return 0; }

static inline int template_callback_float(unpack_user* u, float d, VALUE* o)
{ *o = rb_float_new(d); return 0; }

static inline int template_callback_double(unpack_user* u, double d, VALUE* o)
{ *o = rb_float_new(d); return 0; }

static inline int template_callback_nil(unpack_user* u, VALUE* o)
{ *o = Qnil; return 0; }

static inline int template_callback_true(unpack_user* u, VALUE* o)
{ *o = Qtrue; return 0; }

static inline int template_callback_false(unpack_user* u, VALUE* o)
{ *o = Qfalse; return 0;}

static inline int template_callback_array(unpack_user* u, unsigned int n, VALUE* o)
{ *o = rb_ary_new2(n); return 0; }

static inline int template_callback_array_item(unpack_user* u, VALUE* c, VALUE o)
{ rb_ary_push(*c, o); return 0; }  // FIXME set value directry RARRAY_PTR(obj)[RARRAY_LEN(obj)++]

static inline int template_callback_map(unpack_user* u, unsigned int n, VALUE* o)
{ *o = rb_hash_new(); return 0; }

static inline int template_callback_map_item(unpack_user* u, VALUE* c, VALUE k, VALUE v)
{ rb_hash_aset(*c, k, v); return 0; }

#ifdef RSTRING_EMBED_LEN_MAX
#define COW_MIN_SIZE RSTRING_EMBED_LEN_MAX
#else
#define COW_MIN_SIZE ((sizeof(VALUE)*3)/sizeof(char)-1)
#endif

static inline int template_callback_raw(unpack_user* u, const char* b, const char* p, unsigned int l, VALUE* o)
{
	if(u->source == Qnil || l <= COW_MIN_SIZE) {
		*o = rb_str_new(p, l);
	} else {
		*o = rb_str_substr(u->source, p - b, l);
	}
#ifdef COMPAT_HAVE_ENCODING
	ENCODING_SET(*o, s_enc_utf8);
#endif
	return 0;
}


#include "msgpack/unpack_template.h"


#define UNPACKER(from, name) \
	msgpack_unpack_t *name = NULL; \
	Data_Get_Struct(from, msgpack_unpack_t, name); \
	if(name == NULL) { \
		rb_raise(rb_eArgError, "NULL found for " # name " when shouldn't be."); \
	}

#define CHECK_STRING_TYPE(value) \
	value = rb_check_string_type(value); \
	if( NIL_P(value) ) { \
		rb_raise(rb_eTypeError, "instance of String needed"); \
	}


static VALUE template_execute_rescue(VALUE nouse)
{
	rb_gc_enable();
	COMPAT_RERAISE;
}

static VALUE template_execute_do(VALUE argv)
{
	VALUE* args = (VALUE*)argv;

	msgpack_unpack_t* mp = (msgpack_unpack_t*)args[0];
	char* dptr   = (char*)args[1];
	size_t dlen  = (size_t)args[2];
	size_t* from = (size_t*)args[3];

	int ret = template_execute(mp, dptr, dlen, from);

	return (VALUE)ret;
}

static int template_execute_wrap(msgpack_unpack_t* mp,
		VALUE str, size_t dlen, size_t* from)
{
	VALUE args[4] = {
		(VALUE)mp,
		(VALUE)RSTRING_PTR(str),
		(VALUE)dlen,
		(VALUE)from,
	};

	// FIXME execute実行中はmp->topが更新されないのでGC markが機能しない
	rb_gc_disable();

	mp->user.source = str;

	int ret = (int)rb_rescue(template_execute_do, (VALUE)args,
			template_execute_rescue, Qnil);

	rb_gc_enable();

	return ret;
}

static int template_execute_wrap_each(msgpack_unpack_t* mp,
		const char* ptr, size_t dlen, size_t* from)
{
	VALUE args[4] = {
		(VALUE)mp,
		(VALUE)ptr,
		(VALUE)dlen,
		(VALUE)from,
	};

	// FIXME execute実行中はmp->topが更新されないのでGC markが機能しない
	rb_gc_disable();

	mp->user.source = Qnil;

	int ret = (int)rb_rescue(template_execute_do, (VALUE)args,
			template_execute_rescue, Qnil);

	rb_gc_enable();

	return ret;
}


static VALUE cUnpacker;


/**
 * Document-module: MessagePack::UnpackerError
 *
 */
static VALUE eUnpackError;


#ifndef MSGPACK_UNPACKER_BUFFER_INIT_SIZE
#define MSGPACK_UNPACKER_BUFFER_INIT_SIZE (32*1024)
#endif

#ifndef MSGPACK_UNPACKER_BUFFER_RESERVE_SIZE
#define MSGPACK_UNPACKER_BUFFER_RESERVE_SIZE (8*1024)
#endif

/*
#ifndef MSGPACK_BUFFER_FREE_SIZE
#define MSGPACK_BUFFER_FREE_SIZE (1024*1024)
#endif
*/
#define MSGPACK_BUFFER_FREE_SIZE 0

static void MessagePack_Unpacker_free(void* data)
{
	if(data) {
		msgpack_unpack_t* mp = (msgpack_unpack_t*)data;
		free(mp->user.buffer.ptr);
		free(mp);
	}
}

static void MessagePack_Unpacker_mark(msgpack_unpack_t *mp)
{
	unsigned int i;
	rb_gc_mark(mp->user.stream);
	rb_gc_mark(mp->user.streambuf);
	rb_gc_mark_maybe(template_data(mp));
	for(i=0; i < mp->top; ++i) {
		rb_gc_mark(mp->stack[i].obj);
		rb_gc_mark_maybe(mp->stack[i].map_key);
	}
}

static VALUE MessagePack_Unpacker_alloc(VALUE klass)
{
	VALUE obj;
	msgpack_unpack_t* mp = ALLOC_N(msgpack_unpack_t, 1);

	// rb_gc_mark (not _maybe) is used for following member objects.
	mp->user.stream = Qnil;
	mp->user.streambuf = Qnil;

	mp->user.finished = 0;
	mp->user.offset = 0;
	mp->user.buffer.used = 0;
	mp->user.buffer.free = 0;
	mp->user.buffer.ptr = NULL;

	obj = Data_Wrap_Struct(klass, MessagePack_Unpacker_mark,
			MessagePack_Unpacker_free, mp);
	return obj;
}

static ID append_method_of(VALUE stream)
{
	if(rb_respond_to(stream, s_sysread)) {
		return s_sysread;
	} else {
		return s_readpartial;
	}
}

/**
 * Document-method: MessagePack::Unpacker#initialize
 *
 * call-seq:
 *   MessagePack::Unpacker.new(stream = nil)
 *
 * Creates instance of MessagePack::Unpacker.
 *
 * You can specify a _stream_ for input stream.
 * It is required to implement *sysread* or *readpartial* method.
 *
 * With the input stream, buffers will be feeded into the deserializer automatically.
 *
 * Without the input stream, use *feed* method manually. Or you can manage the buffer manually
 * with *execute*, *finished?*, *data* and *reset* methods.
 */
static VALUE MessagePack_Unpacker_initialize(int argc, VALUE *argv, VALUE self)
{
	VALUE stream;
	switch(argc) {
	case 0:
		stream = Qnil;
		break;
	case 1:
		stream = argv[0];
		break;
	default:
		rb_raise(rb_eArgError, "wrong number of arguments (%d for 0)", argc);
	}

	UNPACKER(self, mp);
	template_init(mp);
	mp->user.stream = stream;
	mp->user.streambuf = rb_str_buf_new(MSGPACK_UNPACKER_BUFFER_RESERVE_SIZE);
	mp->user.stream_append_method = append_method_of(stream);
	mp->user.buffer_free_size = MSGPACK_BUFFER_FREE_SIZE;

	return self;
}


/**
 * Document-method: MessagePack::Unpacker#stream
 *
 * call-seq:
 *   unpacker.stream
 *
 * Gets the input stream.
 */
static VALUE MessagePack_Unpacker_stream_get(VALUE self)
{
	UNPACKER(self, mp);
	return mp->user.stream;
}

/**
 * Document-method: MessagePack::Unpacker#stream=
 *
 * call-seq:
 *   unpacker.stream = stream
 *
 * Resets the input stream. You can set nil not to use input stream.
 */
static VALUE MessagePack_Unpacker_stream_set(VALUE self, VALUE val)
{
	UNPACKER(self, mp);
	mp->user.stream = val;
	mp->user.stream_append_method = append_method_of(val);
	return val;
}


static void reserve_buffer(msgpack_unpack_t* mp, size_t require)
{
	struct unpack_buffer* buffer = &mp->user.buffer;

	if(buffer->used == 0) {
		if(require <= buffer->free) {
			/* enough free space */
			return;
		}
		/* no used buffer: realloc only */
		size_t nsize = buffer->free == 0 ?
			MSGPACK_UNPACKER_BUFFER_INIT_SIZE : buffer->free*2;
		while(nsize < require) {
			nsize *= 2;
		}
		char* tmp = REALLOC_N(buffer->ptr, char, nsize);
		buffer->free = nsize;
		buffer->ptr = tmp;
		return;
	}

	if(buffer->used <= mp->user.offset) {
		/* clear buffer and rewind offset */
		buffer->free += buffer->used;
		buffer->used = 0;
		mp->user.offset = 0;
	}

	if(require <= buffer->free) {
		/* enough free space */
		return;
	}

	size_t nsize = (buffer->used + buffer->free) * 2;

	if(mp->user.offset <= buffer->used / 2) {
		/* parsed less than half: realloc only */
		while(nsize < buffer->used + require) {
			nsize *= 2;
		}
		char* tmp = REALLOC_N(buffer->ptr, char, nsize);
		buffer->free = nsize - buffer->used;
		buffer->ptr = tmp;

	} else {
		/* parsed more than half: realloc and move */
		size_t not_parsed = buffer->used - mp->user.offset;
		while(nsize < not_parsed + require) {
			nsize *= 2;
		}
		char* tmp = REALLOC_N(buffer->ptr, char, nsize);
		memcpy(tmp, tmp + mp->user.offset, not_parsed);
		buffer->free = nsize - not_parsed;
		buffer->used = not_parsed;
		buffer->ptr = tmp;
		mp->user.offset = 0;
	}
}

static inline void try_free_buffer(msgpack_unpack_t* mp, size_t require)
{
	if(mp->user.buffer_free_size == 0) {
		return;
	}

	struct unpack_buffer* buffer = &mp->user.buffer;
	size_t csize = buffer->used + buffer->free;

	if(csize <= mp->user.buffer_free_size) {
		return;
	}

	if(mp->user.offset <= buffer->used / 2) {
		/* parsed less than half: do nothing */

	} else if(mp->user.offset < buffer->used) {
		/* parsed more than half but not all: realloc and move */
		size_t nsize = MSGPACK_UNPACKER_BUFFER_INIT_SIZE;
		size_t not_parsed = buffer->used - mp->user.offset;
		while(nsize < not_parsed + require) {
			nsize *= 2;
		}

		if(nsize >= csize) {
			return;
		}

		char* tmp;
		if(mp->user.offset == 0) {
			tmp = ALLOC_N(char, nsize);
			memcpy(tmp, buffer->ptr + mp->user.offset, not_parsed);
			free(buffer->ptr);
		} else {
			tmp = REALLOC_N(buffer->ptr, char, nsize);
		}
		buffer->free = nsize - not_parsed;
		buffer->used = not_parsed;
		buffer->ptr = tmp;
		mp->user.offset = 0;

	} else {
		/* all parsed: free all */
		free(buffer->ptr);
		buffer->free = 0;
		buffer->used = 0;
		buffer->ptr = NULL;
		mp->user.offset = 0;
	}
}

static void feed_buffer(msgpack_unpack_t* mp, const char* ptr, size_t len)
{
	struct unpack_buffer* buffer = &mp->user.buffer;

	reserve_buffer(mp, len);

	memcpy(buffer->ptr + buffer->used, ptr, len);
	buffer->used += len;
	buffer->free -= len;
}

/**
 * Document-method: MessagePack::Unpacker#feed
 *
 * call-seq:
 *   unpacker.feed(data)
 *
 * Fills the internal buffer with the specified buffer.
 */
static VALUE MessagePack_Unpacker_feed(VALUE self, VALUE data)
{
	UNPACKER(self, mp);
	StringValue(data);
	feed_buffer(mp, RSTRING_PTR(data), RSTRING_LEN(data));
	return Qnil;
}

/**
 * Document-method: MessagePack::Unpacker#fill
 *
 * call-seq:
 *   unpacker.fill -> length of read data
 *
 * Fills the internal buffer using the input stream.
 *
 * If the input stream is not specified, it returns nil.
 * You can set it on *initialize* or *stream=* methods.
 *
 * This methods raises exceptions that _stream.sysread_ or
 * _stream.readpartial_ method raises.
 */
static VALUE MessagePack_Unpacker_fill(VALUE self)
{
	UNPACKER(self, mp);

	if(mp->user.stream == Qnil) {
		return Qnil;
	}

	rb_funcall(mp->user.stream, mp->user.stream_append_method, 2,
			LONG2FIX(MSGPACK_UNPACKER_BUFFER_RESERVE_SIZE),
			mp->user.streambuf);

	size_t len = RSTRING_LEN(mp->user.streambuf);
	feed_buffer(mp, RSTRING_PTR(mp->user.streambuf), len);

	return LONG2FIX(len);
}


/**
 * Document-method: MessagePack::Unpacker#each
 *
 * call-seq:
 *   unpacker.each {|object| }
 *
 * Deserializes objects repeatedly. This calls *fill* method automatically.
 *
 * UnpackError is throw when parse error is occured.
 * This method raises exceptions that *fill* method raises.
 */
static VALUE MessagePack_Unpacker_each(VALUE self)
{
	UNPACKER(self, mp);
	int ret;

#ifdef RETURN_ENUMERATOR
	RETURN_ENUMERATOR(self, 0, 0);
#endif

	while(1) {
		if(mp->user.buffer.used <= mp->user.offset) {
			do_fill:
			{
				VALUE len = MessagePack_Unpacker_fill(self);
				if(len == Qnil || FIX2LONG(len) == 0) {
					break;
				}
			}
		}

		ret = template_execute_wrap_each(mp,
				mp->user.buffer.ptr, mp->user.buffer.used,
				&mp->user.offset);

		if(ret < 0) {
			rb_raise(eUnpackError, "parse error.");

		} else if(ret > 0) {
			VALUE data = template_data(mp);
			template_init(mp);
			rb_yield(data);

		} else {
			goto do_fill;
		}
	}

	try_free_buffer(mp, 0);

	return Qnil;
}

static VALUE feed_each_impl(VALUE args)
{
	VALUE self = ((VALUE*)args)[0];
	VALUE data = ((VALUE*)args)[1];
	size_t* pconsumed = (size_t*)((VALUE*)args)[2];

	UNPACKER(self, mp);
	int ret;
	const char* ptr = RSTRING_PTR(data);
	size_t len = RSTRING_LEN(data);

	if(mp->user.buffer.used > 0) {
		while(1) {
			ret = template_execute_wrap_each(mp,
					mp->user.buffer.ptr, mp->user.buffer.used,
					&mp->user.offset);

			if(ret < 0) {
				rb_raise(eUnpackError, "parse error.");

			} else if(ret > 0) {
				VALUE data = template_data(mp);
				template_init(mp);
				rb_yield(data);

			} else {
				break;
			}
		}
	}

	if(len <= 0) {
		return Qnil;
	}

	if(mp->user.buffer.used <= mp->user.offset) {
		// wrap & execute & feed
		while(1) {
			ret = template_execute_wrap_each(mp,
					ptr, len, pconsumed);

			if(ret < 0) {
				rb_raise(eUnpackError, "parse error.");

			} else if(ret > 0) {
				VALUE data = template_data(mp);
				template_init(mp);
				rb_yield(data);

			} else {
				break;
			}
		}

	} else {
		// feed & execute
		feed_buffer(mp, ptr, len);
		*pconsumed = len;

		while(1) {
			ret = template_execute_wrap_each(mp,
					mp->user.buffer.ptr, mp->user.buffer.used,
					&mp->user.offset);

			if(ret < 0) {
				rb_raise(eUnpackError, "parse error.");

			} else if(ret > 0) {
				VALUE data = template_data(mp);
				template_init(mp);
				rb_yield(data);

			} else {
				break;
			}
		}
	}

	return Qnil;
}

static VALUE feed_each_ensure(VALUE args) {
	VALUE self = ((VALUE*)args)[0];
	VALUE data = ((VALUE*)args)[1];
	size_t* pconsumed = (size_t*)((VALUE*)args)[2];

	const char* dptr = RSTRING_PTR(data) + *pconsumed;
	size_t dlen = RSTRING_LEN(data) - *pconsumed;

	if(dlen > 0) {
		UNPACKER(self, mp);
		try_free_buffer(mp, dlen);
		feed_buffer(mp, dptr, dlen);
	}

	return Qnil;
}

/**
 * Document-method: MessagePack::Unpacker#feed_each
 *
 * call-seq:
 *   unpacker.feed_each(data) {|object| }
 *
 * Same as feed(data) + each {|object| }, but tries to avoid copying of the buffer.
 */
static VALUE MessagePack_Unpacker_feed_each(VALUE self, VALUE data)
{
	size_t consumed = 0;
	StringValue(data);

	VALUE args[3];
	args[0] = self;
	args[1] = data;
	args[2] = (VALUE)&consumed;

	return rb_ensure(feed_each_impl, (VALUE)args,
			feed_each_ensure, (VALUE)args);
}


static inline VALUE MessagePack_unpack_impl(VALUE self, VALUE data, unsigned long dlen)
{
	msgpack_unpack_t mp;
	template_init(&mp);

	mp.user.finished = 0;

	size_t from = 0;
	int ret = template_execute_wrap(&mp, data, dlen, &from);

	if(ret < 0) {
		rb_raise(eUnpackError, "parse error.");

	} else if(ret == 0) {
		rb_raise(eUnpackError, "insufficient bytes.");

	} else {
		if(from < dlen) {
			rb_raise(eUnpackError, "extra bytes.");
		}
		return template_data(&mp);
	}
}

/**
 * Document-method: MessagePack::Unpacker.unpack_limit
 *
 * call-seq:
 *   MessagePack::Unpacker.unpack_limit(data, limit) -> object
 *
 * Deserializes one object over the specified buffer upto _limit_ bytes.
 *
 * UnpackError is throw when parse error is occured, the buffer is insufficient
 * to deserialize one object or there are extra bytes.
 */
static VALUE MessagePack_unpack_limit(VALUE self, VALUE data, VALUE limit)
{
	CHECK_STRING_TYPE(data);
	return MessagePack_unpack_impl(self, data, NUM2ULONG(limit));
}

/**
 * Document-method: MessagePack::Unpacker.unpack
 *
 * call-seq:
 *   MessagePack::Unpacker.unpack(data) -> object
 *
 * Deserializes one object over the specified buffer.
 *
 * UnpackError is throw when parse error is occured, the buffer is insufficient
 * to deserialize one object or there are extra bytes.
 */
static VALUE MessagePack_unpack(VALUE self, VALUE data)
{
	CHECK_STRING_TYPE(data);
	return MessagePack_unpack_impl(self, data, RSTRING_LEN(data));
}


static VALUE MessagePack_Unpacker_execute_impl(VALUE self, VALUE data,
		size_t from, size_t limit)
{
	UNPACKER(self, mp);

	if(from >= limit) {
		rb_raise(eUnpackError, "offset is bigger than data buffer size.");
	}

	int ret = template_execute_wrap(mp, data, limit, &from);

	if(ret < 0) {
		rb_raise(eUnpackError, "parse error.");
	} else if(ret > 0) {
		mp->user.finished = 1;
		return ULONG2NUM(from);
	} else {
		mp->user.finished = 0;
		return ULONG2NUM(from);
	}
}

/**
 * Document-method: MessagePack::Unpacker#execute_limit
 *
 * call-seq:
 *   unpacker.execute_limit(data, offset, limit) -> next offset
 *
 * Deserializes one object over the specified buffer from _offset_ bytes upto _limit_ bytes.
 *
 * This method doesn't use the internal buffer.
 *
 * Call *reset* method before calling this method again.
 *
 * UnpackError is throw when parse error is occured.
 */
static VALUE MessagePack_Unpacker_execute_limit(VALUE self, VALUE data,
		VALUE off, VALUE limit)
{
	CHECK_STRING_TYPE(data);
	return MessagePack_Unpacker_execute_impl(self, data,
			(size_t)NUM2ULONG(off), (size_t)NUM2ULONG(limit));
}

/**
 * Document-method: MessagePack::Unpacker#execute
 *
 * call-seq:
 *   unpacker.execute(data, offset) -> next offset
 *
 * Deserializes one object over the specified buffer from _offset_ bytes.
 *
 * This method doesn't use the internal buffer.
 *
 * Call *reset* method before calling this method again.
 *
 * This returns offset that was parsed to.
 * Use *finished?* method to check an object is deserialized and call *data*
 * method if it returns true.
 *
 * UnpackError is throw when parse error is occured.
 */
static VALUE MessagePack_Unpacker_execute(VALUE self, VALUE data, VALUE off)
{
	CHECK_STRING_TYPE(data);
	return MessagePack_Unpacker_execute_impl(self, data,
			(size_t)NUM2ULONG(off), (size_t)RSTRING_LEN(data));
}

/**
 * Document-method: MessagePack::Unpacker#finished?
 *
 * call-seq:
 *   unpacker.finished?
 *
 * Returns true if an object is ready to get with data method.
 *
 * Use this method with execute method.
 */
static VALUE MessagePack_Unpacker_finished_p(VALUE self)
{
	UNPACKER(self, mp);
	if(mp->user.finished) {
		return Qtrue;
	}
	return Qfalse;
}

/**
 * Document-method: MessagePack::Unpacker#data
 *
 * call-seq:
 *   unpacker.data
 *
 * Gets the object deserialized by execute method.
 *
 * Use this method with execute method.
 */
static VALUE MessagePack_Unpacker_data(VALUE self)
{
	UNPACKER(self, mp);
	return template_data(mp);
}

/**
 * Document-method: MessagePack::Unpacker#reset
 *
 * call-seq:
 *   unpacker.reset
 *
 * Resets the internal state of the unpacker.
 */
static VALUE MessagePack_Unpacker_reset(VALUE self)
{
	UNPACKER(self, mp);
	template_init(mp);
	mp->user.finished = 0;
	try_free_buffer(mp, 0);
	return self;
}


void Init_msgpack_unpack(VALUE mMessagePack)
{
	s_sysread = rb_intern("sysread");
	s_readpartial = rb_intern("readpartial");

	eUnpackError = rb_define_class_under(mMessagePack, "UnpackError", rb_eStandardError);
	cUnpacker = rb_define_class_under(mMessagePack, "Unpacker", rb_cObject);
	rb_define_alloc_func(cUnpacker, MessagePack_Unpacker_alloc);

	rb_define_method(cUnpacker, "initialize", MessagePack_Unpacker_initialize, -1);

	/* Buffered API */
	rb_define_method(cUnpacker, "feed", MessagePack_Unpacker_feed, 1);
	rb_define_method(cUnpacker, "fill", MessagePack_Unpacker_fill, 0);
	rb_define_method(cUnpacker, "each", MessagePack_Unpacker_each, 0);
	rb_define_method(cUnpacker, "stream", MessagePack_Unpacker_stream_get, 0);
	rb_define_method(cUnpacker, "stream=", MessagePack_Unpacker_stream_set, 1);
	rb_define_method(cUnpacker, "feed_each", MessagePack_Unpacker_feed_each, 1);

	/* Unbuffered API */
	rb_define_method(cUnpacker, "execute", MessagePack_Unpacker_execute, 2);
	rb_define_method(cUnpacker, "execute_limit", MessagePack_Unpacker_execute_limit, 3);
	rb_define_method(cUnpacker, "finished?", MessagePack_Unpacker_finished_p, 0);
	rb_define_method(cUnpacker, "data", MessagePack_Unpacker_data, 0);
	rb_define_method(cUnpacker, "reset", MessagePack_Unpacker_reset, 0);

	/**
	 * MessagePack module is defined in rbinit.c file.
	 * mMessagePack = rb_define_module("MessagePack");
	 */
	rb_define_module_function(mMessagePack, "unpack", MessagePack_unpack, 1);
	rb_define_module_function(mMessagePack, "unpack_limit", MessagePack_unpack_limit, 2);
}

/**
 * Document-module: MessagePack::Unpacker
 *
 * Deserializer class that includes Buffered API and Unbuffered API.
 *
 *
 * Buffered API uses the internal buffer of the Unpacker.
 * Following code uses Buffered API with an input stream:
 *
 *   # create an unpacker with input stream.
 *   pac = MessagePack::Unpacker.new(STDIN)
 *   
 *   # deserialize object one after another.
 *   pac.each {|obj|
 *     # ...
 *   }
 *
 *
 * Following code doesn't use the input stream and feeds buffer
 * manually. This is useful to use special stream or with
 * event-driven I/O library.
 *
 *   # create an unpacker without input stream.
 *   pac = MessagePack::Unpacker.new()
 *   
 *   # feed buffer to the internal buffer.
 *   pac.feed(input_bytes)
 *   
 *   # deserialize object one after another.
 *   pac.each {|obj|
 *     # ...
 *   }
 *
 *
 * You can manage the buffer manually with the combination of
 * *execute*, *finished?*, *data* and *reset* method.
 *
 *   # create an unpacker.
 *   pac = MessagePack::Unpacker.new()
 *   
 *   # manage buffer and offset manually.
 *   offset = 0
 *   buffer = ''
 *   
 *   # read some data into the buffer.
 *   buffer << [1,2,3].to_msgpack
 *   buffer << [4,5,6].to_msgpack
 *   
 *   while true
 *     offset = pac.execute(buffer, offset)
 *   
 *     if pac.finished?
 *       obj = pac.data
 *   
 *       buffer.slice!(0, offset)
 *       offset = 0
 *       pac.reset
 *   
 *       # do something with the object
 *       # ...
 *
 *       # repeat execution if there are more data.
 *       next unless buffer.empty?
 *     end
 *
 *     break
 *   end
 */

