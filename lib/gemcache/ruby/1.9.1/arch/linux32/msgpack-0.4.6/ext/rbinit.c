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
#include "pack.h"
#include "unpack.h"
#include "compat.h"

static VALUE mMessagePack;

#ifdef COMPAT_HAVE_ENCODING
int s_enc_utf8;
int s_enc_ascii8bit;
int s_enc_usascii;
VALUE s_enc_utf8_value;
#endif

/**
 * Document-module: MessagePack
 *
 * MessagePack is a binary-based efficient object serialization library.
 * It enables to exchange structured objects between many languages like JSON.
 * But unlike JSON, it is very fast and small.
 *
 * You can install MessagePack with rubygems.
 *
 *   gem install msgpack
 *
 * Simple usage is as follows:
 *
 *   require 'msgpack'
 *   msg = [1,2,3].to_msgpack  #=> "\x93\x01\x02\x03"
 *   MessagePack.unpack(msg)   #=> [1,2,3]
 *
 * Use Unpacker class for streaming deserialization.
 *
 */
void Init_msgpack(void)
{
	mMessagePack = rb_define_module("MessagePack");

	rb_define_const(mMessagePack, "VERSION", rb_str_new2(MESSAGEPACK_VERSION));

#ifdef COMPAT_HAVE_ENCODING
	s_enc_ascii8bit = rb_ascii8bit_encindex();
	s_enc_utf8 = rb_utf8_encindex();
	s_enc_usascii = rb_usascii_encindex();
	s_enc_utf8_value = rb_enc_from_encoding(rb_utf8_encoding());
#endif

	Init_msgpack_unpack(mMessagePack);
	Init_msgpack_pack(mMessagePack);
}
