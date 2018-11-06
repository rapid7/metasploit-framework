# coding: utf-8
require 'digest'
require 'openssl'

class PDF::Reader

  # class creates interface to encrypt dictionary for use in Decrypt
  class StandardSecurityHandlerV5

    attr_reader :key_length, :encrypt_key

    def initialize(opts = {})
      @key_length   = 256
      @O            = opts[:O]   # hash(32B) + validation salt(8B) + key salt(8B)
      @U            = opts[:U]   # hash(32B) + validation salt(8B) + key salt(8B)
      @OE           = opts[:OE]  # decryption key, encrypted w/ owner password
      @UE           = opts[:UE]  # decryption key, encrypted w/ user password
      @encrypt_key  = build_standard_key(opts[:password] || '')
    end

    # This handler supports AES-256 encryption defined in PDF 1.7 Extension Level 3
    def self.supports?(encrypt)
      return false if encrypt.nil?

      filter = encrypt.fetch(:Filter, :Standard)
      version = encrypt.fetch(:V, 0)
      revision = encrypt.fetch(:R, 0)
      algorithm = encrypt.fetch(:CF, {}).fetch(encrypt[:StmF], {}).fetch(:CFM, nil)
      (filter == :Standard) && (encrypt[:StmF] == encrypt[:StrF]) &&
          ((version == 5) && (revision == 5) && (algorithm == :AESV3))
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
      cipher = OpenSSL::Cipher.new("AES-#{@key_length}-CBC")
      cipher.decrypt
      cipher.key = @encrypt_key.dup
      cipher.iv = buf[0..15]
      cipher.update(buf[16..-1]) + cipher.final
    end

    private
    # Algorithm 3.2a - Computing an encryption key
    #
    # Defined in PDF 1.7 Extension Level 3
    #
    # if the string is a valid user/owner password, this will return the decryption key
    #
    def auth_owner_pass(password)
      if Digest::SHA256.digest(password + @O[32..39] + @U) == @O[0..31]
        cipher = OpenSSL::Cipher.new('AES-256-CBC')
        cipher.decrypt
        cipher.key = Digest::SHA256.digest(password + @O[40..-1] + @U)
        cipher.iv = "\x00" * 16
        cipher.padding = 0
        cipher.update(@OE) + cipher.final
      end
    end

    def auth_user_pass(password)
      if Digest::SHA256.digest(password + @U[32..39]) == @U[0..31]
        cipher = OpenSSL::Cipher.new('AES-256-CBC')
        cipher.decrypt
        cipher.key = Digest::SHA256.digest(password + @U[40..-1])
        cipher.iv = "\x00" * 16
        cipher.padding = 0
        cipher.update(@UE) + cipher.final
      end
    end

    def build_standard_key(pass)
      pass = pass.byteslice(0...127)   # UTF-8 encoded password. first 127 bytes

      encrypt_key   = auth_owner_pass(pass)
      encrypt_key ||= auth_user_pass(pass)

      raise PDF::Reader::EncryptedPDFError, "Invalid password (#{pass})" if encrypt_key.nil?
      encrypt_key
    end
  end
end
