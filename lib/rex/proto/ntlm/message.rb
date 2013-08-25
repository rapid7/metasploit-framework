# -*- coding: binary -*-
#
# An NTLM Authentication Library for Ruby
#
# This code is a derivative of "dbf2.rb" written by yrock
# and Minero Aoki. You can find original code here:
# http://jp.rubyist.net/magazine/?0013-CodeReview
# -------------------------------------------------------------
# Copyright (c) 2005,2006 yrock
#
# This program is free software.
# You can distribute/modify this program under the terms of the
# Ruby License.
#
# 2011-02-23 refactored by Alexandre Maloteaux for Metasploit Project
# -------------------------------------------------------------
#
# 2006-02-11 refactored by Minero Aoki
# -------------------------------------------------------------
#
# All protocol information used to write this code stems from
# "The NTLM Authentication Protocol" by Eric Glass. The author
# would thank to him for this tremendous work and making it
# available on the net.
# http://davenport.sourceforge.net/ntlm.html
# -------------------------------------------------------------
# Copyright (c) 2003 Eric Glass
#
# Permission to use, copy, modify, and distribute this document
# for any purpose and without any fee is hereby granted,
# provided that the above copyright notice and this list of
# conditions appear in all copies.
# -------------------------------------------------------------
#
# The author also looked Mozilla-Firefox-1.0.7 source code,
# namely, security/manager/ssl/src/nsNTLMAuthModule.cpp and
# Jonathan Bastien-Filiatrault's libntlm-ruby.
# "http://x2a.org/websvn/filedetails.php?
# repname=libntlm-ruby&path=%2Ftrunk%2Fntlm.rb&sc=1"
# The latter has a minor bug in its separate_keys function.
# The third key has to begin from the 14th character of the
# input string instead of 13th:)

#this module defines the message class , useful for easily handling type 1/2/3 ntlm messages

require 'rex/proto/ntlm/base'
require 'rex/proto/ntlm/constants'
require 'rex/proto/ntlm/crypt'


module Rex
module Proto
module NTLM
class Message < Rex::Proto::NTLM::Base::FieldSet

BASE  = Rex::Proto::NTLM::Base
CONST = Rex::Proto::NTLM::Constants
CRYPT = Rex::Proto::NTLM::Crypt


	class << Message
	def parse(str)
		m = Type0.new
		m.parse(str)
		case m.type
		when 1
			t = Type1.parse(str)
		when 2
			t = Type2.parse(str)
		when 3
			t = Type3.parse(str)
		else
			raise ArgumentError, "unknown type: #{m.type}"
		end
		t
	end

	def decode64(str)
		parse(Rex::Text::decode_base64(str))
	end
	end#self

	def has_flag?(flag)
		(self[:flag].value & CONST::FLAGS[flag]) == CONST::FLAGS[flag]
	end

	def set_flag(flag)
		self[:flag].value  |= CONST::FLAGS[flag]
	end

	def dump_flags
		CONST::FLAG_KEYS.each{ |k| print(k, "=", flag?(k), "\n") }
	end

	def serialize
		deflag
		super + security_buffers.map{|n, f| f.value}.join
	end

	def encode64
		Rex::Text::encode_base64(serialize)
	end

	def decode64(str)
		parse(Rex::Text::decode_base64(str))
	end

	alias head_size size

	def data_size
		security_buffers.inject(0){|sum, a| sum += a[1].data_size}
	end

	def size
		head_size + data_size
	end

	private

	def security_buffers
		@alist.find_all{|n, f| f.instance_of?(BASE::SecurityBuffer)}
	end

	def deflag
		security_buffers.inject(head_size){|cur, a|
			a[1].offset = cur
			cur += a[1].data_size
		}
	end

	def data_edge
		security_buffers.map{ |n, f| f.active ? f.offset : size}.min
	end

	# sub class definitions

	Type0 = Message.define {
		string        :sign,      {:size => 8, :value => CONST::SSP_SIGN}
		int32LE       :type,      {:value => 0}
		}

	Type1 = Message.define {
		string          :sign,         {:size => 8, :value => CONST::SSP_SIGN}
		int32LE         :type,         {:value => 1}
		int32LE         :flag,         {:value => CONST::DEFAULT_FLAGS[:TYPE1] }
		security_buffer :domain,       {:value => "", :active => false}
		security_buffer :workstation,  {:value => "", :active => false}
		string          :padding,      {:size => 0, :value => "", :active => false }
		}

	class Type1
		class << Type1
		def parse(str)
			t = new
			t.parse(str)
    			t
		end
		end

		def parse(str)
			super(str)
			enable(:domain) if has_flag?(:DOMAIN_SUPPLIED)
			enable(:workstation) if has_flag?(:WORKSTATION_SUPPLIED)
			super(str)
			if ( (len = data_edge - head_size) > 0)
				self.padding = "\0" * len
				super(str)
			end
		end
	end

	Type2 = Message.define{
		string        :sign,         {:size => 8, :value => CONST::SSP_SIGN}
		int32LE       :type,      {:value => 2}
		security_buffer   :target_name,  {:size => 0, :value => ""}
		int32LE       :flag,         {:value => CONST::DEFAULT_FLAGS[:TYPE2]}
		int64LE           :challenge,    {:value => 0}
		int64LE           :context,      {:value => 0, :active => false}
		security_buffer   :target_info,  {:value => "", :active => false}
		string        :padding,   {:size => 0, :value => "", :active => false }
		}

	class Type2
		class << Type2
		def parse(str)
			t = new
			t.parse(str)
			t
		end
		end

		def parse(str)
			super(str)
			if has_flag?(:TARGET_INFO)
				enable(:context)
				enable(:target_info)
				super(str)
			end
			if ( (len = data_edge - head_size) > 0)
				self.padding = "\0" * len
				super(str)
			end
		end
		#create a type 3 response base on a type2
		# This mehod is not compatible with windows 7 / 2008 r2
		# to make it compatible avpair Time and SPN must be handle as in utils
		def response(arg, opt = {})
			usr = arg[:user]
			pwd = arg[:password]
			if usr.nil? or pwd.nil?
				raise ArgumentError, "user and password have to be supplied"
			end

			if opt[:workstation]
				ws = opt[:workstation]
			else
				ws = ""
			end

			if opt[:client_challenge]
				cc  = opt[:client_challenge]
			else
				cc = rand(CONST::MAX64)
			end
			cc = Rex::Text::pack_int64le(cc) if cc.is_a?(Integer)
			opt[:client_challenge] = cc

			if has_flag?(:OEM) and opt[:unicode]
				usr = Rex::Text::to_ascii(usr,'utf-16le')
				pwd = Rex::Text::to_ascii(pwd,'utf-16le')
				ws  = Rex::Text::to_ascii(ws,'utf-16le')
				opt[:unicode] = false
			end

			if has_flag?(:UNICODE) and !opt[:unicode]
				usr = Rex::Text::to_unicode(usr,'utf-16le')
				pwd = Rex::Text::to_unicode(pwd,'utf-16le')
				ws  = Rex::Text::to_unicode(ws,'utf-16le')
				opt[:unicode] = true
			end

			tgt = self.target_name
			ti = self.target_info

			chal = self[:challenge].serialize

			if opt[:ntlmv2]
				ar = {	:ntlmv2_hash => CRYPT::ntlmv2_hash(usr, pwd, tgt, opt),
					:challenge => chal, :target_info => ti}
				lm_res = CRYPT::lmv2_response(ar, opt)
				ntlm_res = CRYPT::ntlmv2_response(ar, opt)
			elsif has_flag?(:NTLM2_KEY)
				ar = {:ntlm_hash => CRYPT::ntlm_hash(pwd, opt), :challenge => chal}
				lm_res, ntlm_res = CRYPT::ntlm2_session(ar, opt)
			else
				lm_res = CRYPT::lm_response(pwd, chal)
				ntlm_res = CRYPT::ntlm_response(pwd, chal)
			end

			Type3.create({
				:lm_response => lm_res,
				:ntlm_response => ntlm_res,
				:domain => tgt,
				:user => usr,
				:workstation => ws,
				:flag => self.flag
				})
		end
	end


	Type3 = Message.define{
		string          :sign,          {:size => 8, :value => CONST::SSP_SIGN}
		int32LE         :type,          {:value => 3}
		security_buffer :lm_response,   {:value => ""}
		security_buffer :ntlm_response, {:value => ""}
		security_buffer :domain,        {:value => ""}
		security_buffer :user,          {:value => ""}
		security_buffer :workstation,   {:value => ""}
		security_buffer :session_key,   {:value => "", :active => false }
		int64LE         :flag,          {:value => 0, :active => false }
		}

	class Type3
		class << Type3
		def parse(str)
			t = new
			t.parse(str)
			t
		end

		def create(arg, opt ={})
			t = new
			t.lm_response = arg[:lm_response]
			t.ntlm_response = arg[:ntlm_response]
			t.domain = arg[:domain]
			t.user = arg[:user]
			t.workstation = arg[:workstation]

			if arg[:session_key]
				t.enable(:session_key)
				t.session_key = arg[session_key]
			end
			if arg[:flag]
				t.enable(:session_key)
				t.enable(:flag)
				t.flag = arg[:flag]
			end
			t
		end
		end#self
	end

	public
	#those class method have been merged from lib/rex/smb/utils

	#
	# Process Type 3 NTLM Message (in Base64)
	#
	# from http://www.innovation.ch/personal/ronald/ntlm.html
	#
	#	struct {
	#		byte  protocol[8];  // 'N', 'T', 'L', 'M', 'S', 'S', 'P', '\0'
	#		byte  type;         // 0x03
	#		byte  zero[3];
	#
	#		short lm_resp_len;  // LanManager response length (always 0x18)
	#		short lm_resp_len;  // LanManager response length (always 0x18)
	#		short lm_resp_off;  // LanManager response offset
	#		byte  zero[2];
	#
	#		short nt_resp_len;  // NT response length (always 0x18)
	#		short nt_resp_len;  // NT response length (always 0x18)
	#		short nt_resp_off;  // NT response offset
	#		byte  zero[2];
	#
	#		short dom_len;      // domain string length
	#		short dom_len;      // domain string length
	#		short dom_off;      // domain string offset (always 0x40)
	#		byte  zero[2];
	#
	#		short user_len;     // username string length
	#		short user_len;     // username string length
	#		short user_off;     // username string offset
	#		byte  zero[2];
	#
	#		short host_len;     // host string length
	#		short host_len;     // host string length
	#		short host_off;     // host string offset
	#		byte  zero[6];
	#
	#		short msg_len;      // message length
	#		byte  zero[2];
	#
	#		short flags;        // 0x8201
	#		byte  zero[2];
	#
	#		byte  dom[*];       // domain string (unicode UTF-16LE)
	#		byte  user[*];      // username string (unicode UTF-16LE)
	#		byte  host[*];      // host string (unicode UTF-16LE)
	#		byte  lm_resp[*];   // LanManager response
	#		byte  nt_resp[*];   // NT response
	#	} type_3_message
	#
	def self.process_type3_message(message)
		decode = Rex::Text.decode_base64(message.strip)
		type = decode[8,1].unpack("C").first
		if (type == 3)
			lm_len = decode[12,2].unpack("v").first
			lm_offset = decode[16,2].unpack("v").first
			lm = decode[lm_offset, lm_len].unpack("H*").first

			nt_len = decode[20,2].unpack("v").first
			nt_offset = decode[24,2].unpack("v").first
			nt = decode[nt_offset, nt_len].unpack("H*").first

			dom_len = decode[28,2].unpack("v").first
			dom_offset = decode[32,2].unpack("v").first
			domain = decode[dom_offset, dom_len]

			user_len = decode[36,2].unpack("v").first
			user_offset = decode[40,2].unpack("v").first
			user = decode[user_offset, user_len]

			host_len = decode[44,2].unpack("v").first
			host_offset = decode[48,2].unpack("v").first
			host = decode[host_offset, host_len]

			return domain, user, host, lm, nt
		else
			return "", "", "", "", ""
		end
	end



	#
	# Process Type 1 NTLM Messages, return a Base64 Type 2 Message
	#
	def self.process_type1_message(message, nonce = "\x11\x22\x33\x44\x55\x66\x77\x88", win_domain = 'DOMAIN',
					win_name = 'SERVER', dns_name = 'server', dns_domain = 'example.com', downgrade = true)

		dns_name = Rex::Text.to_unicode(dns_name + "." + dns_domain)
		win_domain = Rex::Text.to_unicode(win_domain)
		dns_domain = Rex::Text.to_unicode(dns_domain)
		win_name = Rex::Text.to_unicode(win_name)
		decode = Rex::Text.decode_base64(message.strip)

		type = decode[8,1].unpack("C").first

		if (type == 1)
			# A type 1 message has been received, lets build a type 2 message response

			reqflags = decode[12,4]
			reqflags = reqflags.unpack("V").first

			if (reqflags & CONST::REQUEST_TARGET) == CONST::REQUEST_TARGET

				if (downgrade)
					# At this time NTLMv2 and signing requirements are not supported
					if (reqflags & CONST::NEGOTIATE_NTLM2_KEY) == CONST::NEGOTIATE_NTLM2_KEY
						reqflags = reqflags - CONST::NEGOTIATE_NTLM2_KEY
					end
					if (reqflags & CONST::NEGOTIATE_ALWAYS_SIGN) == CONST::NEGOTIATE_ALWAYS_SIGN
						reqflags = reqflags - CONST::NEGOTIATE_ALWAYS_SIGN
					end
				end

				flags = reqflags + CONST::TARGET_TYPE_DOMAIN + CONST::TARGET_TYPE_SERVER
				tid = true

				tidoffset = 48 + win_domain.length
				tidbuff =
					[2].pack('v') +				# tid type, win domain
					[win_domain.length].pack('v') +
					win_domain +
					[1].pack('v') +				# tid type, server name
					[win_name.length].pack('v') +
					win_name +
					[4].pack('v')	+			 # tid type, domain name
					[dns_domain.length].pack('v') +
					dns_domain +
					[3].pack('v')	+			# tid type, dns_name
					[dns_name.length].pack('v') +
					dns_name
			else
				flags = CONST::NEGOTIATE_UNICODE + CONST::NEGOTIATE_NTLM
				tid = false
			end

			type2msg = "NTLMSSP\0" + # protocol, 8 bytes
				   "\x02\x00\x00\x00"		# type, 4 bytes

			if (tid)
				type2msg +=	# Target security info, 8 bytes. Filled if REQUEST_TARGET
				[win_domain.length].pack('v') +	 # Length, 2 bytes
				[win_domain.length].pack('v')	 # Allocated space, 2 bytes
			end

			type2msg +="\x30\x00\x00\x00" + #		Offset, 4 bytes
					[flags].pack('V') +	# flags, 4 bytes
					nonce +		# the nonce, 8 bytes
					"\x00" * 8		# Context (all 0s), 8 bytes

			if (tid)
				type2msg +=		# Target information security buffer. Filled if REQUEST_TARGET
					[tidbuff.length].pack('v') +	# Length, 2 bytes
					[tidbuff.length].pack('v') +	# Allocated space, 2 bytes
					[tidoffset].pack('V') +		# Offset, 4 bytes (usually \x48 + length of win_domain)
					win_domain +			# Target name data (domain in unicode if REQUEST_UNICODE)
									# Target information data
					tidbuff +			#	Type, 2 bytes
									#	Length, 2 bytes
									#	Data (in unicode if REQUEST_UNICODE)
					"\x00\x00\x00\x00"		# Terminator, 4 bytes, all \x00
			end

			type2msg = Rex::Text.encode_base64(type2msg).delete("\n") # base64 encode and remove the returns
		else
			# This is not a Type2 message
			type2msg = ""
		end

		return type2msg
	end

	#
	# Downgrading Type messages to LMv1/NTLMv1 and removing signing
	#
	def self.downgrade_type_message(message)
		decode = Rex::Text.decode_base64(message.strip)

		type = decode[8,1].unpack("C").first

		if (type > 0 and type < 4)
			reqflags = decode[12..15] if (type == 1 or type == 3)
			reqflags = decode[20..23] if (type == 2)
			reqflags = reqflags.unpack("V")

			# Remove NEGOTIATE_NTLMV2_KEY and NEGOTIATE_ALWAYS_SIGN, this lowers the negotiation
			# down to LMv1/NTLMv1.
			if (reqflags & CONST::NEGOTIATE_NTLM2_KEY) == CONST::NEGOTIATE_NTLM2_KEY
				reqflags = reqflags - CONST::NEGOTIATE_NTLM2_KEY
			end
			if (reqflags & CONST::NEGOTIATE_ALWAYS_SIGN) == CONST::NEGOTIATE_ALWAYS_SIGN
				reqflags = reqflags - CONST::NEGOTIATE_ALWAYS_SIGN
			end

			# Return the flags back to the decode so we can base64 it again
			flags = reqflags.to_s(16)
			0.upto(8) do |idx|
				if (idx > flags.length)
					flags.insert(0, "0")
				end
			end

			idx = 0
			0.upto(3) do |cnt|
				if (type == 2)
					decode[23-cnt] = [flags[idx,1]].pack("C")
				else
					decode[15-cnt] = [flags[idx,1]].pack("C")
				end
				idx += 2
			end

		end
		return Rex::Text.encode_base64(decode).delete("\n") # base64 encode and remove the returns
	end

end
end
end
end
