/*
 * MessagePack unpacking routine template
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

#ifndef msgpack_unpack_func
#error msgpack_unpack_func template is not defined
#endif

#ifndef msgpack_unpack_callback
#error msgpack_unpack_callback template is not defined
#endif

#ifndef msgpack_unpack_struct
#error msgpack_unpack_struct template is not defined
#endif

#ifndef msgpack_unpack_struct_decl
#define msgpack_unpack_struct_decl(name) msgpack_unpack_struct(name)
#endif

#ifndef msgpack_unpack_object
#error msgpack_unpack_object type is not defined
#endif

#ifndef msgpack_unpack_user
#error msgpack_unpack_user type is not defined
#endif

#ifndef USE_CASE_RANGE
#if !defined(_MSC_VER)
#define USE_CASE_RANGE
#endif
#endif

msgpack_unpack_struct_decl(_stack) {
	msgpack_unpack_object obj;
	size_t count;
	unsigned int ct;
	msgpack_unpack_object map_key;
};

msgpack_unpack_struct_decl(_context) {
	msgpack_unpack_user user;
	unsigned int cs;
	unsigned int trail;
	unsigned int top;
	/*
	msgpack_unpack_struct(_stack)* stack;
	unsigned int stack_size;
	msgpack_unpack_struct(_stack) embed_stack[MSGPACK_EMBED_STACK_SIZE];
	*/
	msgpack_unpack_struct(_stack) stack[MSGPACK_EMBED_STACK_SIZE];
};


msgpack_unpack_func(void, _init)(msgpack_unpack_struct(_context)* ctx)
{
	ctx->cs = CS_HEADER;
	ctx->trail = 0;
	ctx->top = 0;
	/*
	ctx->stack = ctx->embed_stack;
	ctx->stack_size = MSGPACK_EMBED_STACK_SIZE;
	*/
	ctx->stack[0].obj = msgpack_unpack_callback(_root)(&ctx->user);
}

/*
msgpack_unpack_func(void, _destroy)(msgpack_unpack_struct(_context)* ctx)
{
	if(ctx->stack_size != MSGPACK_EMBED_STACK_SIZE) {
		free(ctx->stack);
	}
}
*/

msgpack_unpack_func(msgpack_unpack_object, _data)(msgpack_unpack_struct(_context)* ctx)
{
	return (ctx)->stack[0].obj;
}


msgpack_unpack_func(int, _execute)(msgpack_unpack_struct(_context)* ctx, const char* data, size_t len, size_t* off)
{
	assert(len >= *off);

	const unsigned char* p = (unsigned char*)data + *off;
	const unsigned char* const pe = (unsigned char*)data + len;
	const void* n = NULL;

	unsigned int trail = ctx->trail;
	unsigned int cs = ctx->cs;
	unsigned int top = ctx->top;
	msgpack_unpack_struct(_stack)* stack = ctx->stack;
	/*
	unsigned int stack_size = ctx->stack_size;
	*/
	msgpack_unpack_user* user = &ctx->user;

	msgpack_unpack_object obj;
	msgpack_unpack_struct(_stack)* c = NULL;

	int ret;

#define push_simple_value(func) \
	if(msgpack_unpack_callback(func)(user, &obj) < 0) { goto _failed; } \
	goto _push
#define push_fixed_value(func, arg) \
	if(msgpack_unpack_callback(func)(user, arg, &obj) < 0) { goto _failed; } \
	goto _push
#define push_variable_value(func, base, pos, len) \
	if(msgpack_unpack_callback(func)(user, \
		(const char*)base, (const char*)pos, len, &obj) < 0) { goto _failed; } \
	goto _push

#define again_fixed_trail(_cs, trail_len) \
	trail = trail_len; \
	cs = _cs; \
	goto _fixed_trail_again
#define again_fixed_trail_if_zero(_cs, trail_len, ifzero) \
	trail = trail_len; \
	if(trail == 0) { goto ifzero; } \
	cs = _cs; \
	goto _fixed_trail_again

#define start_container(func, count_, ct_) \
	if(top >= MSGPACK_EMBED_STACK_SIZE) { goto _failed; } /* FIXME */ \
	if(msgpack_unpack_callback(func)(user, count_, &stack[top].obj) < 0) { goto _failed; } \
	if((count_) == 0) { obj = stack[top].obj; goto _push; } \
	stack[top].ct = ct_; \
	stack[top].count = count_; \
	++top; \
	/*printf("container %d count %d stack %d\n",stack[top].obj,count_,top);*/ \
	/*printf("stack push %d\n", top);*/ \
	/* FIXME \
	if(top >= stack_size) { \
		if(stack_size == MSGPACK_EMBED_STACK_SIZE) { \
			size_t csize = sizeof(msgpack_unpack_struct(_stack)) * MSGPACK_EMBED_STACK_SIZE; \
			size_t nsize = csize * 2; \
			msgpack_unpack_struct(_stack)* tmp = (msgpack_unpack_struct(_stack)*)malloc(nsize); \
			if(tmp == NULL) { goto _failed; } \
			memcpy(tmp, ctx->stack, csize); \
			ctx->stack = stack = tmp; \
			ctx->stack_size = stack_size = MSGPACK_EMBED_STACK_SIZE * 2; \
		} else { \
			size_t nsize = sizeof(msgpack_unpack_struct(_stack)) * ctx->stack_size * 2; \
			msgpack_unpack_struct(_stack)* tmp = (msgpack_unpack_struct(_stack)*)realloc(ctx->stack, nsize); \
			if(tmp == NULL) { goto _failed; } \
			ctx->stack = stack = tmp; \
			ctx->stack_size = stack_size = stack_size * 2; \
		} \
	} \
	*/ \
	goto _header_again

#define NEXT_CS(p) \
	((unsigned int)*p & 0x1f)

#ifdef USE_CASE_RANGE
#define SWITCH_RANGE_BEGIN     switch(*p) {
#define SWITCH_RANGE(FROM, TO) case FROM ... TO:
#define SWITCH_RANGE_DEFAULT   default:
#define SWITCH_RANGE_END       }
#else
#define SWITCH_RANGE_BEGIN     { if(0) {
#define SWITCH_RANGE(FROM, TO) } else if(FROM <= *p && *p <= TO) {
#define SWITCH_RANGE_DEFAULT   } else {
#define SWITCH_RANGE_END       } }
#endif

	if(p == pe) { goto _out; }
	do {
		switch(cs) {
		case CS_HEADER:
			SWITCH_RANGE_BEGIN
			SWITCH_RANGE(0x00, 0x7f)  // Positive Fixnum
				push_fixed_value(_uint8, *(uint8_t*)p);
			SWITCH_RANGE(0xe0, 0xff)  // Negative Fixnum
				push_fixed_value(_int8, *(int8_t*)p);
			SWITCH_RANGE(0xc0, 0xdf)  // Variable
				switch(*p) {
				case 0xc0:  // nil
					push_simple_value(_nil);
				//case 0xc1:  // string
				//	again_terminal_trail(NEXT_CS(p), p+1);
				case 0xc2:  // false
					push_simple_value(_false);
				case 0xc3:  // true
					push_simple_value(_true);
				//case 0xc4:
				//case 0xc5:
				//case 0xc6:
				//case 0xc7:
				//case 0xc8:
				//case 0xc9:
				case 0xca:  // float
				case 0xcb:  // double
				case 0xcc:  // unsigned int  8
				case 0xcd:  // unsigned int 16
				case 0xce:  // unsigned int 32
				case 0xcf:  // unsigned int 64
				case 0xd0:  // signed int  8
				case 0xd1:  // signed int 16
				case 0xd2:  // signed int 32
				case 0xd3:  // signed int 64
					again_fixed_trail(NEXT_CS(p), 1 << (((unsigned int)*p) & 0x03));
				//case 0xd4:
				//case 0xd5:
				//case 0xd6:  // big integer 16
				//case 0xd7:  // big integer 32
				//case 0xd8:  // big float 16
				//case 0xd9:  // big float 32
				case 0xda:  // raw 16
				case 0xdb:  // raw 32
				case 0xdc:  // array 16
				case 0xdd:  // array 32
				case 0xde:  // map 16
				case 0xdf:  // map 32
					again_fixed_trail(NEXT_CS(p), 2 << (((unsigned int)*p) & 0x01));
				default:
					goto _failed;
				}
			SWITCH_RANGE(0xa0, 0xbf)  // FixRaw
				again_fixed_trail_if_zero(ACS_RAW_VALUE, ((unsigned int)*p & 0x1f), _raw_zero);
			SWITCH_RANGE(0x90, 0x9f)  // FixArray
				start_container(_array, ((unsigned int)*p) & 0x0f, CT_ARRAY_ITEM);
			SWITCH_RANGE(0x80, 0x8f)  // FixMap
				start_container(_map, ((unsigned int)*p) & 0x0f, CT_MAP_KEY);

			SWITCH_RANGE_DEFAULT
				goto _failed;
			SWITCH_RANGE_END
			// end CS_HEADER


		_fixed_trail_again:
			++p;

		default:
			if((size_t)(pe - p) < trail) { goto _out; }
			n = p;  p += trail - 1;
			switch(cs) {
			//case CS_
			//case CS_
			case CS_FLOAT: {
					union { uint32_t i; float f; } mem;
					mem.i = _msgpack_load32(uint32_t,n);
					push_fixed_value(_float, mem.f); }
			case CS_DOUBLE: {
					union { uint64_t i; double f; } mem;
					mem.i = _msgpack_load64(uint64_t,n);
					push_fixed_value(_double, mem.f); }
			case CS_UINT_8:
				push_fixed_value(_uint8, *(uint8_t*)n);
			case CS_UINT_16:
				push_fixed_value(_uint16, _msgpack_load16(uint16_t,n));
			case CS_UINT_32:
				push_fixed_value(_uint32, _msgpack_load32(uint32_t,n));
			case CS_UINT_64:
				push_fixed_value(_uint64, _msgpack_load64(uint64_t,n));

			case CS_INT_8:
				push_fixed_value(_int8, *(int8_t*)n);
			case CS_INT_16:
				push_fixed_value(_int16, _msgpack_load16(int16_t,n));
			case CS_INT_32:
				push_fixed_value(_int32, _msgpack_load32(int32_t,n));
			case CS_INT_64:
				push_fixed_value(_int64, _msgpack_load64(int64_t,n));

			//case CS_
			//case CS_
			//case CS_BIG_INT_16:
			//	again_fixed_trail_if_zero(ACS_BIG_INT_VALUE, _msgpack_load16(uint16_t,n), _big_int_zero);
			//case CS_BIG_INT_32:
			//	again_fixed_trail_if_zero(ACS_BIG_INT_VALUE, _msgpack_load32(uint32_t,n), _big_int_zero);
			//case ACS_BIG_INT_VALUE:
			//_big_int_zero:
			//	// FIXME
			//	push_variable_value(_big_int, data, n, trail);

			//case CS_BIG_FLOAT_16:
			//	again_fixed_trail_if_zero(ACS_BIG_FLOAT_VALUE, _msgpack_load16(uint16_t,n), _big_float_zero);
			//case CS_BIG_FLOAT_32:
			//	again_fixed_trail_if_zero(ACS_BIG_FLOAT_VALUE, _msgpack_load32(uint32_t,n), _big_float_zero);
			//case ACS_BIG_FLOAT_VALUE:
			//_big_float_zero:
			//	// FIXME
			//	push_variable_value(_big_float, data, n, trail);

			case CS_RAW_16:
				again_fixed_trail_if_zero(ACS_RAW_VALUE, _msgpack_load16(uint16_t,n), _raw_zero);
			case CS_RAW_32:
				again_fixed_trail_if_zero(ACS_RAW_VALUE, _msgpack_load32(uint32_t,n), _raw_zero);
			case ACS_RAW_VALUE:
			_raw_zero:
				push_variable_value(_raw, data, n, trail);

			case CS_ARRAY_16:
				start_container(_array, _msgpack_load16(uint16_t,n), CT_ARRAY_ITEM);
			case CS_ARRAY_32:
				/* FIXME security guard */
				start_container(_array, _msgpack_load32(uint32_t,n), CT_ARRAY_ITEM);

			case CS_MAP_16:
				start_container(_map, _msgpack_load16(uint16_t,n), CT_MAP_KEY);
			case CS_MAP_32:
				/* FIXME security guard */
				start_container(_map, _msgpack_load32(uint32_t,n), CT_MAP_KEY);

			default:
				goto _failed;
			}
		}

_push:
	if(top == 0) { goto _finish; }
	c = &stack[top-1];
	switch(c->ct) {
	case CT_ARRAY_ITEM:
		if(msgpack_unpack_callback(_array_item)(user, &c->obj, obj) < 0) { goto _failed; }
		if(--c->count == 0) {
			obj = c->obj;
			--top;
			/*printf("stack pop %d\n", top);*/
			goto _push;
		}
		goto _header_again;
	case CT_MAP_KEY:
		c->map_key = obj;
		c->ct = CT_MAP_VALUE;
		goto _header_again;
	case CT_MAP_VALUE:
		if(msgpack_unpack_callback(_map_item)(user, &c->obj, c->map_key, obj) < 0) { goto _failed; }
		if(--c->count == 0) {
			obj = c->obj;
			--top;
			/*printf("stack pop %d\n", top);*/
			goto _push;
		}
		c->ct = CT_MAP_KEY;
		goto _header_again;

	default:
		goto _failed;
	}

_header_again:
		cs = CS_HEADER;
		++p;
	} while(p != pe);
	goto _out;


_finish:
	stack[0].obj = obj;
	++p;
	ret = 1;
	/*printf("-- finish --\n"); */
	goto _end;

_failed:
	/*printf("** FAILED **\n"); */
	ret = -1;
	goto _end;

_out:
	ret = 0;
	goto _end;

_end:
	ctx->cs = cs;
	ctx->trail = trail;
	ctx->top = top;
	*off = p - (const unsigned char*)data;

	return ret;
}


#undef msgpack_unpack_func
#undef msgpack_unpack_callback
#undef msgpack_unpack_struct
#undef msgpack_unpack_object
#undef msgpack_unpack_user

#undef push_simple_value
#undef push_fixed_value
#undef push_variable_value
#undef again_fixed_trail
#undef again_fixed_trail_if_zero
#undef start_container

#undef NEXT_CS

