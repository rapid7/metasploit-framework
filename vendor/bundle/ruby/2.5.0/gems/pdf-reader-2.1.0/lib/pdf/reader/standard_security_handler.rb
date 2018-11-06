# coding: utf-8

################################################################################
#
# Copyright (C) 2011 Evan J Brunner (ejbrun@appittome.com)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
################################################################################
require 'digest/md5'
require 'openssl'
require 'rc4'

class PDF::Reader

  # class creates interface to encrypt dictionary for use in Decrypt
  class StandardSecurityHandler

    ## 7.6.3.3 Encryption Key Algorithm (pp61)
    #
    # needs a document's user password to build a key for decrypting an
    # encrypted PDF document
    #
    PassPadBytes = [ 0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41,
                     0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
                     0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
                     0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a ]

    attr_reader :key_length, :revision, :encrypt_key
    attr_reader :owner_key, :user_key, :permissions, :file_id, :password

    def initialize(opts = {})
      @key_length    = opts[:key_length].to_i/8
      @revision      = opts[:revision].to_i
      @owner_key     = opts[:owner_key]
      @user_key      = opts[:user_key]
      @permissions   = opts[:permissions].to_i
      @encryptMeta   = opts.fetch(:encrypted_metadata, true)
      @file_id       = opts[:file_id] || ""
      @encrypt_key   = build_standard_key(opts[:password] || "")
      @cfm           = opts[:cfm]

      if @key_length != 5 && @key_length != 16
        msg = "StandardSecurityHandler only supports 40 and 128 bit\
               encryption (#{@key_length * 8}bit)"
        raise ArgumentError, msg
      end
    end

    # This handler supports all encryption that follows upto PDF 1.5 spec (revision 4)
    def self.supports?(encrypt)
      return false if encrypt.nil?

      filter = encrypt.fetch(:Filter, :Standard)
      version = encrypt.fetch(:V, 0)
      algorithm = encrypt.fetch(:CF, {}).fetch(encrypt[:StmF], {}).fetch(:CFM, nil)
      (filter == :Standard) && (encrypt[:StmF] == encrypt[:StrF]) &&
        (version <= 3 || (version == 4 && ((algorithm == :V2) || (algorithm == :AESV2))))
    end

    ##7.6.2 General Encryption Algorithm
    #
    # Algorithm 1: Encryption of data using the RC4 or AES algorithms
    #
    # used to decrypt RC4/AES encrypted PDF streams (buf)
    #
    # buf - a string to decrypt
    # ref - a PDF::Reader::Reference for the object to decrypt
    #
    def decrypt( buf, ref )
      case @cfm
        when :AESV2
          decrypt_aes128(buf, ref)
        else
          decrypt_rc4(buf, ref)
      end
    end

    private

    # decrypt with RC4 algorithm
    # version <=3 or (version == 4 and CFM == V2)
    def decrypt_rc4( buf, ref )
      objKey = @encrypt_key.dup
      (0..2).each { |e| objKey << (ref.id >> e*8 & 0xFF ) }
      (0..1).each { |e| objKey << (ref.gen >> e*8 & 0xFF ) }
      length = objKey.length < 16 ? objKey.length : 16
      rc4 = RC4.new( Digest::MD5.digest(objKey)[0,length] )
      rc4.decrypt(buf)
    end

    # decrypt with AES-128-CBC algorithm
    # when (version == 4 and CFM == AESV2)
    def decrypt_aes128( buf, ref )
      objKey = @encrypt_key.dup
      (0..2).each { |e| objKey << (ref.id >> e*8 & 0xFF ) }
      (0..1).each { |e| objKey << (ref.gen >> e*8 & 0xFF ) }
      objKey << 'sAlT'  # Algorithm 1, b)
      length = objKey.length < 16 ? objKey.length : 16
      cipher = OpenSSL::Cipher.new("AES-#{length << 3}-CBC")
      cipher.decrypt
      cipher.key = Digest::MD5.digest(objKey)[0,length]
      cipher.iv = buf[0..15]
      cipher.update(buf[16..-1]) + cipher.final
    end

    # Pads supplied password to 32bytes using PassPadBytes as specified on
    # pp61 of spec
    def pad_pass(p="")
      if p.nil? || p.empty?
        PassPadBytes.pack('C*')
      else
        p[0, 32] + PassPadBytes[0, 32-p.length].pack('C*')
      end
    end

    def xor_each_byte(buf, int)
      buf.each_byte.map{ |b| b^int}.pack("C*")
    end

    ## 7.6.3.4 Password Algorithms
    #
    # Algorithm 7 - Authenticating the Owner Password
    #
    # Used to test Owner passwords
    #
    # if the string is a valid owner password this will return the user
    # password that should be used to decrypt the document.
    #
    # if the supplied password is not a valid owner password for this document
    # then it returns nil
    #
    def auth_owner_pass(pass)
      md5 = Digest::MD5.digest(pad_pass(pass))
      if @revision > 2 then
        50.times { md5 = Digest::MD5.digest(md5) }
        keyBegins = md5[0, key_length]
        #first iteration decrypt owner_key
        out = @owner_key
        #RC4 keyed with (keyBegins XOR with iteration #) to decrypt previous out
        19.downto(0).each { |i| out=RC4.new(xor_each_byte(keyBegins,i)).decrypt(out) }
      else
        out = RC4.new( md5[0, 5] ).decrypt( @owner_key )
      end
      # c) check output as user password
      auth_user_pass( out )
    end

    # Algorithm 6 - Authenticating the User Password
    #
    # Used to test User passwords
    #
    # if the string is a valid user password this will return the user
    # password that should be used to decrypt the document.
    #
    # if the supplied password is not a valid user password for this document
    # then it returns nil
    #
    def auth_user_pass(pass)
      keyBegins = make_file_key(pass)
      if @revision >= 3
        #initialize out for first iteration
        out = Digest::MD5.digest(PassPadBytes.pack("C*") + @file_id)
        #zero doesn't matter -> so from 0-19
        20.times{ |i| out=RC4.new(xor_each_byte(keyBegins, i)).encrypt(out) }
        pass = @user_key[0, 16] == out
      else
        pass = RC4.new(keyBegins).encrypt(PassPadBytes.pack("C*")) == @user_key
      end
      pass ? keyBegins : nil
    end

    def make_file_key( user_pass )
      # a) if there's a password, pad it to 32 bytes, else, just use the padding.
      @buf  = pad_pass(user_pass)
      # c) add owner key
      @buf << @owner_key
      # d) add permissions 1 byte at a time, in little-endian order
      (0..24).step(8){|e| @buf << (@permissions >> e & 0xFF)}
      # e) add the file ID
      @buf << @file_id
      # f) if revision >= 4 and metadata not encrypted then add 4 bytes of 0xFF
      if @revision >= 4 && !@encryptMeta
        @buf << [0xFF,0xFF,0xFF,0xFF].pack('C*')
      end
      # b) init MD5 digest + g) finish the hash
      md5 = Digest::MD5.digest(@buf)
      # h) spin hash 50 times
      if @revision >= 3
        50.times {
          md5 = Digest::MD5.digest(md5[0, @key_length])
        }
      end
      # i) n = key_length revision >= 3, n = 5 revision == 2
      if @revision < 3
        md5[0, 5]
      else
        md5[0, @key_length]
      end
    end

    def build_standard_key(pass)
      encrypt_key   = auth_owner_pass(pass)
      encrypt_key ||= auth_user_pass(pass)

      raise PDF::Reader::EncryptedPDFError, "Invalid password (#{pass})" if encrypt_key.nil?
      encrypt_key
    end
  end
end
