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
# 2011-02-23 refactored and improved by Alexandre Maloteaux for Metasploit Project
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
#--
# $Id: ntlm.rb 11678 2011-01-30 19:26:35Z hdm $
#++


require 'rex/proto/ntlm/constants'
require 'rex/proto/ntlm/base'

module Rex
module Proto
module NTLM
class Crypt

CONST = Rex::Proto::NTLM::Constants
BASE = Rex::Proto::NTLM::Base

	@@loaded_openssl = false
	
	begin
		require 'openssl'
		require 'openssl/digest'
		@@loaded_openssl = true
	rescue ::Exception
	end
	
begin

	def self.gen_keys(str)
		Rex::Text::split_to_a(str, 7).map{ |str7| 
				bits = Rex::Text::split_to_a(str7.unpack("B*")[0], 7).inject('')\
				{|ret, tkn| ret += tkn + (tkn.gsub('1', '').size % 2).to_s }
				[bits].pack("B*")
				}
	end
      
	def self.apply_des(plain, keys)
		raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl
		dec = OpenSSL::Cipher::DES.new
		keys.map {|k|
			dec.key = k
			dec.encrypt.update(plain)
		}
	end
      
	def self.lm_hash(password, half = false)
		if half then size = 7 else  size = 14 end
		keys = gen_keys password.upcase.ljust(size, "\0")
		apply_des(CONST::LM_MAGIC, keys).join
	end   
      
	def self.ntlm_hash(password, opt = {})
		raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl
		pwd = password.dup
		unless opt[:unicode]
			pwd = Rex::Text.to_unicode(pwd)
		end
		OpenSSL::Digest::MD4.digest pwd
	end

	def self.ntlmv2_hash(user, password, domain, opt={})
		raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl
		ntlmhash = ntlm_hash(password, opt)
		#With Win 7 and maybe other OSs we sometimes get my domain not uppercased,
		#so the domain does not need to be uppercased
		userdomain = user.upcase  + domain
		unless opt[:unicode]
			userdomain = Rex::Text.to_unicode(userdomain)
		end
		OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, ntlmhash, userdomain)
	end

	# responses
	def self.lm_response(arg, half = false)
		begin
			hash = arg[:lm_hash]
			chal = arg[:challenge]
		rescue
			raise ArgumentError
		end
		chal = BASE::pack_int64le(chal) if chal.is_a?(Integer)
		if half then size = 7 else  size = 21 end
		keys = gen_keys hash.ljust(size, "\0")
		apply_des(chal, keys).join
	end

	#synonym of lm_response for old compatibility with lib/rex/proto/smb/crypt
	def self.lanman_des(password, challenge)
		arglm = { 	:lm_hash => self.lm_hash(password),
				:challenge => challenge }
		self.lm_response(arglm)
	end
      
	def self.ntlm_response(arg)
		hash = arg[:ntlm_hash]
		chal = arg[:challenge]
		chal = BASE::pack_int64le(chal) if chal.is_a?(::Integer)
		keys = gen_keys hash.ljust(21, "\0")
		apply_des(chal, keys).join
	end

	#synonym of ntlm_response for old compatibility with lib/rex/proto/smb/crypt
	def self.ntlm_md4(password, challenge)
		argntlm = { 	:ntlm_hash =>  self.ntlm_hash(password), 
				:challenge => challenge }
		self.ntlm_response(argntlm)
	end

	def self.ntlmv2_response(arg, opt = {})
		raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl
		begin
			key = arg[:ntlmv2_hash]
			chal = arg[:challenge]
		rescue
			raise ArgumentError , 'ntlmv2_hash and challenge are mandatory'
		end
		chal = BASE::pack_int64le(chal) if chal.is_a?(::Integer)
		if opt[:nt_client_challenge]
			unless   opt[:nt_client_challenge].is_a?(::String) && opt[:nt_client_challenge].length > 24
				raise ArgumentError,"nt_client_challenge is not in a correct format " 
			end
			bb = opt[:nt_client_challenge]
		else
			begin
				ti = arg[:target_info]
			rescue
				raise ArgumentError, "target_info is mandatory in this case"
			end
			if opt[:client_challenge]
				cc  = opt[:client_challenge]
			else
				cc = rand(CONST::MAX64)
			end
				cc = BASE::pack_int64le(cc) if cc.is_a?(::Integer)

			if opt[:timestamp]
				ts = opt[:timestamp]
			else
				ts = Time.now.to_i
			end
			# epoch -> milsec from Jan 1, 1601
			ts = 10000000 * (ts + CONST::TIME_OFFSET)

			blob = BASE::Blob.new
			blob.timestamp = ts
			blob.challenge = cc
			blob.target_info = ti
		
			bb = blob.serialize
		end

		OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, key, chal + bb) + bb

	end

      
	def self.lmv2_response(arg, opt = {})
		raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl
		key = arg[:ntlmv2_hash]
		chal = arg[:challenge]
        
		chal = BASE::pack_int64le(chal) if chal.is_a?(::Integer)
		if opt[:client_challenge]
			cc  = opt[:client_challenge]
		else
			cc = rand(CONST::MAX64)
		end
		cc = BASE::pack_int64le(cc) if cc.is_a?(::Integer)

		OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, key, chal + cc) + cc
	end
      
	def self.ntlm2_session(arg, opt = {})
		raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl
		begin
			passwd_hash = arg[:ntlm_hash]
			chal = arg[:challenge]
		rescue
			raise ArgumentError
		end

		if opt[:client_challenge]
			cc  = opt[:client_challenge]
		else
			cc = rand(CONST::MAX64)
		end
		cc = BASE::pack_int64le(cc) if cc.is_a?(Integer)

		keys = gen_keys passwd_hash.ljust(21, "\0")
		session_hash = OpenSSL::Digest::MD5.digest(chal + cc).slice(0, 8)
		response = apply_des(session_hash, keys).join
		[cc.ljust(24, "\0"), response]
	end

	#signing method added for metasploit project

	#Used when only the LMv1 response is provided (i.e., with Win9x clients)
	def self.lmv1_user_session_key(pass )
		self.lm_hash(pass.upcase[0,7],true).ljust(16,"\x00")
	end
		
	#This variant is used when the client sends the NTLMv1 response
	def self.ntlmv1_user_session_key(pass )
		raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl
		OpenSSL::Digest::MD4.digest(self.ntlm_hash(pass))
	end

	#Used when NTLMv1 authentication is employed with NTLM2 session security
	def self.ntlm2_session_user_session_key(pass, srv_chall, cli_chall)
		raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl
		ntlm_key = self.ntlmv1_user_session_key(pass )
		session_chal = srv_chall + cli_chall
		OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, ntlm_key, session_chal)
	end

	#Used when the LMv2 response is sent
	def self.lmv2_user_session_key(user, pass, domain, srv_chall, cli_chall)
		raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl
		ntlmv2_key = self.ntlmv2_hash(user, pass, domain)
		hash1 = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, ntlmv2_key, srv_chall + cli_chall)
		OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, ntlmv2_key, hash1)
	end

	#Used when the NTLMv2 response is sent
	 class << self; alias_method :ntlmv2_user_session_key, :lmv2_user_session_key; end

	#Used when LAnMan Key flag is set
	def self.lanman_session_key(pass, srvchall)
		halfhash =self.lm_hash(pass.upcase[0,7],true)
   		arglm = { 	:lm_hash => halfhash[0,7],
				:challenge => srvchall }
		plain = self.lm_response(arglm,true)
		key = halfhash  + ["bdbdbdbdbdbd"].pack("H*")
	        keys = self.gen_keys(key)
        	self.apply_des(plain, keys).join
	end


	def self.encrypt_sessionkey(session_key, user_session_key)
		raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl
		cipher = OpenSSL::Cipher::Cipher.new('rc4')
		cipher.encrypt
		cipher.key = user_session_key
		cipher.update(session_key) 
	end

	def self.decrypt_sessionkey(encrypted_session_key, user_session_key)
		raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl
		cipher = OpenSSL::Cipher::Cipher.new('rc4')
		cipher.decrypt
		cipher.key = user_session_key
		cipher.update(encrypted_session_key) 
	end

	def self.make_weak_sessionkey(session_key,key_size,lanman_key = false)
		case key_size
		when 40
			if lanman_key
				return session_key[0,5] + "\xe5\x38\xb0" 
			else
				return session_key[0,5] 
			end
		when 56
			if lanman_key
				return session_key[0,7]  + "\xa0"
			else
				return session_key[0,7]  
			end
		else #128 
			return session_key[0,16]
		end
	end

rescue LoadError
end

end
end
end
end
