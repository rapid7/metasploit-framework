# encoding: UTF-8
#
# = net/ntlm.rb
#
# An NTLM Authentication Library for Ruby
#
# This code is a derivative of "dbf2.rb" written by yrock
# and Minero Aoki. You can find original code here:
# http://jp.rubyist.net/magazine/?0013-CodeReview
# -------------------------------------------------------------
# Copyright (c) 2005,2006 yrock
#
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
# $Id: ntlm.rb,v 1.1 2006/10/05 01:36:52 koheik Exp $
#++

require 'base64'
require 'openssl'
require 'openssl/digest'
require 'socket'

# Load Order is important here
require 'net/ntlm/exceptions'
require 'net/ntlm/field'
require 'net/ntlm/int16_le'
require 'net/ntlm/int32_le'
require 'net/ntlm/int64_le'
require 'net/ntlm/string'

require 'net/ntlm/field_set'
require 'net/ntlm/blob'
require 'net/ntlm/security_buffer'
require 'net/ntlm/message'
require 'net/ntlm/message/type0'
require 'net/ntlm/message/type1'
require 'net/ntlm/message/type2'
require 'net/ntlm/message/type3'

require 'net/ntlm/encode_util'

require 'net/ntlm/client'
require 'net/ntlm/channel_binding'
require 'net/ntlm/target_info'

module Net
  module NTLM

    LM_MAGIC = "KGS!@\#$%"
    TIME_OFFSET = 11644473600
    MAX64 = 0xffffffffffffffff


    class << self

      # Valid format for LAN Manager hex digest portion: 32 hexadecimal characters.
      LAN_MANAGER_HEX_DIGEST_REGEXP = /[0-9a-f]{32}/i
      # Valid format for NT LAN Manager hex digest portion: 32 hexadecimal characters.
      NT_LAN_MANAGER_HEX_DIGEST_REGEXP = /[0-9a-f]{32}/i
      # Valid format for an NTLM hash composed of `'<LAN Manager hex digest>:<NT LAN Manager hex digest>'`.
      DATA_REGEXP = /\A#{LAN_MANAGER_HEX_DIGEST_REGEXP}:#{NT_LAN_MANAGER_HEX_DIGEST_REGEXP}\z/

      # Takes a string and determines whether it is a valid NTLM Hash
      # @param [String] the string to validate
      # @return [Boolean] whether or not the string is a valid NTLM hash
      def is_ntlm_hash?(data)
        decoded_data = data.dup
        decoded_data = EncodeUtil.decode_utf16le(decoded_data)
        if DATA_REGEXP.match(decoded_data)
          true
        else
          false
        end
      end

      # Conver the value to a 64-Bit Little Endian Int
      # @param [String] val The string to convert
      def pack_int64le(val)
          [val & 0x00000000ffffffff, val >> 32].pack("V2")
      end

      # Builds an array of strings that are 7 characters long
      # @param [String] str The string to split
      # @api private
      def split7(str)
        s = str.dup
        until s.empty?
          (ret ||= []).push s.slice!(0, 7)
        end
        ret
      end

      # Not sure what this is doing
      # @param [String] str String to generate keys for
      # @api private
      def gen_keys(str)
        split7(str).map{ |str7|
          bits = split7(str7.unpack("B*")[0]).inject('')\
            {|ret, tkn| ret += tkn + (tkn.gsub('1', '').size % 2).to_s }
          [bits].pack("B*")
        }
      end

      def apply_des(plain, keys)
        dec = OpenSSL::Cipher.new("des-cbc")
        dec.padding = 0
        keys.map {|k|
          dec.key = k
          dec.encrypt.update(plain) + dec.final
        }
      end

      # Generates a Lan Manager Hash
      # @param [String] password The password to base the hash on
      def lm_hash(password)
        keys = gen_keys password.upcase.ljust(14, "\0")
        apply_des(LM_MAGIC, keys).join
      end

      # Generate a NTLM Hash
      # @param [String] password The password to base the hash on
      # @option opt :unicode (false) Unicode encode the password
      def ntlm_hash(password, opt = {})
        pwd = password.dup
        unless opt[:unicode]
          pwd = EncodeUtil.encode_utf16le(pwd)
        end
        OpenSSL::Digest::MD4.digest pwd
      end

      # Generate a NTLMv2 Hash
      # @param [String] user The username
      # @param [String] password The password
      # @param [String] target The domain or workstation to authenticate to
      # @option opt :unicode (false) Unicode encode the domain
      def ntlmv2_hash(user, password, target, opt={})
        if is_ntlm_hash? password
          decoded_password = EncodeUtil.decode_utf16le(password)
          ntlmhash = [decoded_password.upcase[33,65]].pack('H32')
        else
          ntlmhash = ntlm_hash(password, opt)
        end
        userdomain = user.upcase + target
        unless opt[:unicode]
          userdomain = EncodeUtil.encode_utf16le(userdomain)
        end
        OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, ntlmhash, userdomain)
      end

      def lm_response(arg)
        begin
          hash = arg[:lm_hash]
          chal = arg[:challenge]
        rescue
          raise ArgumentError
        end
        chal = NTLM::pack_int64le(chal) if chal.is_a?(Integer)
        keys = gen_keys hash.ljust(21, "\0")
        apply_des(chal, keys).join
      end

      def ntlm_response(arg)
        hash = arg[:ntlm_hash]
        chal = arg[:challenge]
        chal = NTLM::pack_int64le(chal) if chal.is_a?(Integer)
        keys = gen_keys hash.ljust(21, "\0")
        apply_des(chal, keys).join
      end

      def ntlmv2_response(arg, opt = {})
        begin
          key = arg[:ntlmv2_hash]
          chal = arg[:challenge]
          ti = arg[:target_info]
        rescue
          raise ArgumentError
        end
        chal = NTLM::pack_int64le(chal) if chal.is_a?(Integer)

        if opt[:client_challenge]
          cc  = opt[:client_challenge]
        else
          cc = rand(MAX64)
        end
        cc = NTLM::pack_int64le(cc) if cc.is_a?(Integer)

        if opt[:timestamp]
          ts = opt[:timestamp]
        else
          ts = Time.now.to_i
        end
        # epoch -> milsec from Jan 1, 1601
        ts = 10_000_000 * (ts + TIME_OFFSET)

        blob = Blob.new
        blob.timestamp = ts
        blob.challenge = cc
        blob.target_info = ti

        bb = blob.serialize

        OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, key, chal + bb) + bb
      end

      def lmv2_response(arg, opt = {})
        key = arg[:ntlmv2_hash]
        chal = arg[:challenge]

        chal = NTLM::pack_int64le(chal) if chal.is_a?(Integer)

        if opt[:client_challenge]
          cc  = opt[:client_challenge]
        else
          cc = rand(MAX64)
        end
        cc = NTLM::pack_int64le(cc) if cc.is_a?(Integer)

        OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, key, chal + cc) + cc
      end

      def ntlm2_session(arg, opt = {})
        begin
          passwd_hash = arg[:ntlm_hash]
          chal = arg[:challenge]
        rescue
          raise ArgumentError
        end
        chal = NTLM::pack_int64le(chal) if chal.is_a?(Integer)

        if opt[:client_challenge]
          cc = opt[:client_challenge]
        else
          cc = rand(MAX64)
        end
        cc = NTLM::pack_int64le(cc) if cc.is_a?(Integer)

        keys = gen_keys(passwd_hash.ljust(21, "\0"))
        session_hash = OpenSSL::Digest::MD5.digest(chal + cc).slice(0, 8)
        response = apply_des(session_hash, keys).join
        [cc.ljust(24, "\0"), response]
      end
    end

  end
end
