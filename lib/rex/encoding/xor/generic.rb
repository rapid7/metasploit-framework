#!/usr/bin/env ruby
# -*- coding: binary -*-

require 'rex/encoding/xor/exceptions'
require 'rex/text'

module Rex
module Encoding
module Xor

class Generic

	def Generic.keysize
		# special case:
		# 0 means we encode based on the length of the key
		# we don't enforce any perticular key length
		return 0
	end

	#
	# Now for some internal check methods
	#

	# hook stylies!
	# return index of offending byte or nil
	def Generic._check(data, key, badchars)
		return _check_key(key, badchars) || _check_encode(data, key, badchars)
	end
	def Generic._check_key(key, badchars)
		return Rex::Text.badchar_index(key, badchars)
	end
	def Generic._check_encode(data, key, badchars)
		return Rex::Text.badchar_index(encode(data, key), badchars)
	end

	def Generic.find_key(data, badchars)
		return _find_good_key(data, _find_bad_keys(data, badchars), badchars)
	end

	# !!! xxx MAKE THESE BITCHE PRIVATE

	#
	# Find a list of bytes that can't be valid xor keys, from the data and badchars.
	# This returns a Array of hashes, length keysize
	#
	def Generic._find_bad_keys(data, badchars)

		ksize = keysize

		# array of hashes for the bad characters based
		# on their position in the data
		badkeys = [ ]
		ksize.times { badkeys << { } }

		badchars.each_byte { |badchar|
			pos = 0
			data.each_byte { |char|
				badkeys[pos % ksize][char ^ badchar] = true
				pos += 1
			}
		}

		return badkeys
	end

	#
	# (Hopefully) find a good key, from badkeys and badchars
	#
	def Generic._find_good_key(data, badkeys, badchars)

		ksize = keysize
		strip = 0
		key   = ""

		while strip < keysize

			kbyte = rand(256)

			catch(:found_kbyte) do
				256.times {

					if !badkeys[strip][kbyte] && !badchars[kbyte.chr]
						throw :found_kbyte
					end

					kbyte = (kbyte + 1) & 0xff
				}

				raise KeySearchError, "Exhausted byte space for strip #{strip}!", caller
			end

			key << kbyte
			strip += 1
		end

		# ok, we should have a good key now, lets double check...
		if _check(data, key, badchars)
			raise KeySearchError, "Key found, but bad character check failed!", caller
		end

		return key
	end

	def Generic.encode(buf, key)

		if !key.kind_of?(String)
			raise ::ArgumentError, "Key must be a string!", caller
		end

		len = key.length

		if len == 0
			raise ::ArgumentError, "Zero key length!", caller
		end

		if keysize != 0 && keysize != len
			raise ::ArgumentError, "Key length #{len}, expected #{keysize}", caller
		end

		encoded = ""
		pos     = 0

		while pos < buf.length
			encoded += (buf[pos,1].unpack("C*")[0] ^ key[pos % len, 1].unpack("C*")[0]).chr
			key = _encode_mutate_key(buf, key, pos, len)
			pos += 1
		end

		return [ encoded, key ]

	end

	# kind of ghetto, but very convenient for mutating keys
	# by default, do no key mutations
	def Generic._encode_mutate_key(buf, key, pos, len)
		return key
	end

	# maybe a bit a smaller of method name?
	def Generic.find_key_and_encode(data, badchars)
		key        = find_key(data, badchars)
		enc, fkey  = encode(data, key)
		return [ enc, key, fkey ]
	end


end end end end # Generic/Xor/Encoding/Rex
