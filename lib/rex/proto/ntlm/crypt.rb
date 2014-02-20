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
# 2011-03-08 improved through a code merge with Metasploit's SMB::Crypt
# -------------------------------------------------------------
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

  def self.gen_keys(str)
    str.scan(/.{7}/).map{ |key| des_56_to_64(key) }
  end

  def self.des_56_to_64(ckey56s)
    ckey64 = []
    ckey56 = ckey56s.unpack('C*')
    ckey64[0] = ckey56[0]
    ckey64[1] = ((ckey56[0] << 7) & 0xFF) | (ckey56[1] >> 1)
    ckey64[2] = ((ckey56[1] << 6) & 0xFF) | (ckey56[2] >> 2)
    ckey64[3] = ((ckey56[2] << 5) & 0xFF) | (ckey56[3] >> 3)
    ckey64[4] = ((ckey56[3] << 4) & 0xFF) | (ckey56[4] >> 4)
    ckey64[5] = ((ckey56[4] << 3) & 0xFF) | (ckey56[5] >> 5)
    ckey64[6] = ((ckey56[5] << 2) & 0xFF) | (ckey56[6] >> 6)
    ckey64[7] =  (ckey56[6] << 1) & 0xFF
    ckey64.pack('C*')
  end

  def self.apply_des(plain, keys)
    raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl
    dec = OpenSSL::Cipher::DES.new
    keys.map do |k|
      dec.key = k
      dec.encrypt.update(plain)
    end
  end

  def self.lm_hash(password, half = false)
    size = half ? 7 : 14
    keys = gen_keys(password.upcase.ljust(size, "\0"))
    apply_des(CONST::LM_MAGIC, keys).join
  end

  def self.ntlm_hash(password, opt = {})
    raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl
    pwd = password.dup
    unless opt[:unicode]
      pwd = Rex::Text.to_unicode(pwd)
    end
    OpenSSL::Digest::MD4.digest(pwd)
  end

  # This hash is used for lmv2/ntlmv2 response calculation
  def self.ntlmv2_hash(user, password, domain, opt={})
    raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl

    if opt[:pass_is_hash]
      ntlmhash = password
    else
      ntlmhash = ntlm_hash(password, opt)
    end
    # With Win 7 and maybe other OSs we sometimes get the domain not uppercased
    userdomain = user.upcase  + domain
    unless opt[:unicode]
      userdomain = Rex::Text.to_unicode(userdomain)
    end
    OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, ntlmhash, userdomain)
  end

  # Create the LANMAN response
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

  # Synonym of lm_response for old compatibility with lib/rex/proto/smb/crypt
  def self.lanman_des(password, challenge)
    lm_response({
      :lm_hash => self.lm_hash(password),
      :challenge => challenge
    })
  end

  def self.ntlm_response(arg)
    hash = arg[:ntlm_hash]
    chal = arg[:challenge]
    chal = BASE::pack_int64le(chal) if chal.is_a?(::Integer)
    keys = gen_keys(hash.ljust(21, "\0"))
    apply_des(chal, keys).join
  end

  #synonym of ntlm_response for old compatibility with lib/rex/proto/smb/crypt
  def self.ntlm_md4(password, challenge)
    ntlm_response({
      :ntlm_hash =>  self.ntlm_hash(password),
      :challenge => challenge
    })
  end

  def self.ntlmv2_response(arg, opt = {})
    raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl

    key, chal = arg[:ntlmv2_hash], arg[:challenge]
    if not (key and chal)
      raise ArgumentError , 'ntlmv2_hash and challenge are mandatory'
    end

    chal = BASE::pack_int64le(chal) if chal.is_a?(::Integer)
    bb   = nil

    if opt[:nt_client_challenge]
      if opt[:nt_client_challenge].to_s.length <= 8
        raise ArgumentError,"nt_client_challenge is not in a correct format "
      end
      bb = opt[:nt_client_challenge]
    else
      if not arg[:target_info]
        raise ArgumentError, "target_info is mandatory in this case"
      end

      ti = arg[:target_info]
      cc = opt[:client_challenge] || rand(CONST::MAX64)
      cc = BASE::pack_int64le(cc) if cc.is_a?(::Integer)

      ts = opt[:timestamp] || Time.now.to_i

      # Convert the unix timestamp to windows format
      #   epoch -> milsec from Jan 1, 1601
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
    cc   = opt[:client_challenge] || rand(CONST::MAX64)
    cc   = BASE::pack_int64le(cc) if cc.is_a?(::Integer)

    OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, key, chal + cc) + cc
  end

  def self.ntlm2_session(arg, opt = {})
    raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl
    passwd_hash,chal = arg[:ntlm_hash],arg[:challenge]
    if not (passwd_hash and chal)
      raise RuntimeError, "ntlm_hash and challenge are required"
    end

    cc = opt[:client_challenge] || rand(CONST::MAX64)
    cc = BASE::pack_int64le(cc) if cc.is_a?(Integer)

    keys = gen_keys(passwd_hash.ljust(21, "\0"))
    session_hash = OpenSSL::Digest::MD5.digest(chal + cc)[0,8]
    response = apply_des(session_hash, keys).join
    [cc.ljust(24, "\0"), response]
  end

  #this function will check if the net lm response provided correspond to en empty password
  def self.is_hash_from_empty_pwd?(arg)
    hash_type = arg[:type]
    raise ArgumentError,"arg[:type] is mandatory" if not hash_type
    raise ArgumentError,"arg[:type] must be lm or ntlm" if not hash_type  =~ /^((lm)|(ntlm))$/

    ntlm_ver = arg[:ntlm_ver]
    raise ArgumentError,"arg[:ntlm_ver] is mandatory" if not ntlm_ver

    hash = arg[:hash]
    raise ArgumentError,"arg[:hash] is mandatory" if not hash

    srv_chall = arg[:srv_challenge]
    raise ArgumentError,"arg[:srv_challenge] is mandatory" if not srv_chall
    raise ArgumentError,"Server challenge length must be exactly 8 bytes" if srv_chall.length != 8

    #calculate responses for empty pwd
    case ntlm_ver
    when CONST::NTLM_V1_RESPONSE
      if hash.length != 24
        raise ArgumentError,"hash length must be exactly 24 bytes "
      end
      case hash_type
      when 'lm'
        arglm = { 	:lm_hash => self.lm_hash(''),
            :challenge => srv_chall}
        calculatedhash = self.lm_response(arglm)
      when 'ntlm'
        argntlm = { 	:ntlm_hash =>  self.ntlm_hash(''),
            :challenge => srv_chall }
        calculatedhash = self.ntlm_response(argntlm)
      end
    when CONST::NTLM_V2_RESPONSE
      raise ArgumentError,"hash length must be exactly 16 bytes " if hash.length != 16
      cli_chall = arg[:cli_challenge]
      raise ArgumentError,"arg[:cli_challenge] is mandatory in this case" if not cli_chall
      user = arg[:user]
      raise ArgumentError,"arg[:user] is mandatory in this case" if not user
      domain = arg[:domain]
      raise ArgumentError,"arg[:domain] is mandatory in this case" if not domain

      case hash_type
      when 'lm'
        raise ArgumentError,"Client challenge length must be exactly 8 bytes " if cli_chall.length != 8
        arglm = {	:ntlmv2_hash =>  self.ntlmv2_hash(user,'', domain),
            :challenge => srv_chall }
        optlm = {	:client_challenge => cli_chall}
        calculatedhash = self.lmv2_response(arglm, optlm)[0,16]
      when 'ntlm'
        raise ArgumentError,"Client challenge length must be bigger then 8 bytes " if cli_chall.length <= 8
        argntlm = { 	:ntlmv2_hash =>  self.ntlmv2_hash(user, '', domain),
            :challenge => srv_chall }
        optntlm = { 	:nt_client_challenge => cli_chall}
        calculatedhash = self.ntlmv2_response(argntlm,optntlm)[0,16]
      end
    when CONST::NTLM_2_SESSION_RESPONSE
      raise ArgumentError,"hash length must be exactly 16 bytes " if hash.length != 24
      cli_chall = arg[:cli_challenge]
      raise ArgumentError,"arg[:cli_challenge] is mandatory in this case" if not cli_chall
      raise ArgumentError,"Client challenge length must be exactly 8 bytes " if cli_chall.length != 8
      case hash_type
      when 'lm'
        raise ArgumentError, "ntlm2_session is incompatible with lm"
      when 'ntlm'
        argntlm = { 	:ntlm_hash =>  self.ntlm_hash(''),
            :challenge => srv_chall }
        optntlm = {	:client_challenge => cli_chall}
      end
      calculatedhash = self.ntlm2_session(argntlm,optntlm).join[24,24]
    else
      raise ArgumentError,"ntlm_ver is of unknow type"
    end
    hash == calculatedhash
  end



  #
  # Signing method added for metasploit project
  #

  # Used when only the LMv1 response is provided (i.e., with Win9x clients)
  def self.lmv1_user_session_key(pass, opt = {})
    if opt[:pass_is_hash]
      usk = pass[0,8]
    else
      usk = self.lm_hash(pass.upcase[0,7],true)
    end
    usk.ljust(16,"\x00")
  end

  # This variant is used when the client sends the NTLMv1 response
  def self.ntlmv1_user_session_key(pass, opt = {})
    raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl

    if opt[:pass_is_hash]
      usk = pass
    else
      usk = self.ntlm_hash(pass)
    end
    OpenSSL::Digest::MD4.digest(usk)
  end

  # Used when NTLMv1 authentication is employed with NTLM2 session security
  def self.ntlm2_session_user_session_key(pass, srv_chall, cli_chall, opt = {})
    raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl

    ntlm_key = self.ntlmv1_user_session_key(pass, opt )
    session_chal = srv_chall + cli_chall
    OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, ntlm_key, session_chal)
  end

  # Used when the LMv2 response is sent
  def self.lmv2_user_session_key(user, pass, domain, srv_chall, cli_chall, opt = {})
    raise RuntimeError, "No OpenSSL support" if not @@loaded_openssl

    ntlmv2_key = self.ntlmv2_hash(user, pass, domain, opt)
    hash1 = OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, ntlmv2_key, srv_chall + cli_chall)
    OpenSSL::HMAC.digest(OpenSSL::Digest::MD5.new, ntlmv2_key, hash1)
  end

  # Used when the NTLMv2 response is sent
  class << self; alias_method :ntlmv2_user_session_key, :lmv2_user_session_key; end

  # Used when LanMan Key flag is set
  def self.lanman_session_key(pass, srvchall, opt = {})
    if opt[:pass_is_hash]
      halfhash = pass[0,8]
    else
      halfhash = lm_hash(pass.upcase[0,7],true)
    end
    plain = self.lm_response({
      :lm_hash => halfhash[0,7],
      :challenge => srvchall
    }, true )
    key = halfhash  + ["bdbdbdbdbdbd"].pack("H*")
        keys = self.gen_keys(key)
       	apply_des(plain, keys).join
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

end
end
end
end
