#!/usr/bin/env ruby
require File.dirname(__FILE__)+'/test_helper'

if RUBY_VERSION < "1.9"
	exit
end

class MessagePackTestEncoding < Test::Unit::TestCase
	def self.it(name, &block)
		define_method("test_#{name}", &block)
	end

	it "US-ASCII" do
		check_unpack "abc".force_encoding("US-ASCII")
	end

	it "UTF-8 ascii" do
		check_unpack "abc".force_encoding("UTF-8")
	end

	it "UTF-8 mbstr" do
		check_unpack "\xE3\x81\x82".force_encoding("UTF-8")
	end

	it "UTF-8 invalid" do
		check_unpack "\xD0".force_encoding("UTF-8")
	end

	it "ASCII-8BIT" do
		check_unpack "\xD0".force_encoding("ASCII-8BIT")
	end

	it "EUC-JP" do
		x = "\xA4\xA2".force_encoding("EUC-JP")
		check_unpack(x)
	end

	it "EUC-JP invalid" do
		begin
			"\xD0".force_encoding("EUC-JP").to_msgpack
			assert(false)
		rescue Encoding::InvalidByteSequenceError
			assert(true)
		end
	end

	private
	def check_unpack(str)
		if str.encoding.to_s == "ASCII-8BIT"
			should_str = str.dup.force_encoding("UTF-8")
		else
			should_str = str.encode("UTF-8")
		end

		raw = str.to_msgpack
		r = MessagePack.unpack(str.to_msgpack)
		assert_equal(r.encoding.to_s, "UTF-8")
		assert_equal(r, should_str.force_encoding("UTF-8"))

		if str.valid_encoding?
			sym = str.to_sym
			r = MessagePack.unpack(sym.to_msgpack)
			assert_equal(r.encoding.to_s, "UTF-8")
			assert_equal(r, should_str.force_encoding("UTF-8"))
		end
	end
end

