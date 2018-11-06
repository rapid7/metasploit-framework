module Zip
  module TraditionalEncryption
    def initialize(password)
      @password = password
      reset_keys!
    end

    def header_bytesize
      12
    end

    def gp_flags
      0x0001 | 0x0008
    end

    protected

    def reset_keys!
      @key0 = 0x12345678
      @key1 = 0x23456789
      @key2 = 0x34567890
      @password.each_byte do |byte|
        update_keys(byte.chr)
      end
    end

    def update_keys(n)
      @key0 = ~Zlib.crc32(n, ~@key0)
      @key1 = ((@key1 + (@key0 & 0xff)) * 134_775_813 + 1) & 0xffffffff
      @key2 = ~Zlib.crc32((@key1 >> 24).chr, ~@key2)
    end

    def decrypt_byte
      temp = (@key2 & 0xffff) | 2
      ((temp * (temp ^ 1)) >> 8) & 0xff
    end
  end

  class TraditionalEncrypter < Encrypter
    include TraditionalEncryption

    def header(mtime)
      [].tap do |header|
        (header_bytesize - 2).times do
          header << Random.rand(0..255)
        end
        header << (mtime.to_binary_dos_time & 0xff)
        header << (mtime.to_binary_dos_time >> 8)
      end.map { |x| encode x }.pack('C*')
    end

    def encrypt(data)
      data.unpack('C*').map { |x| encode x }.pack('C*')
    end

    def data_descriptor(crc32, compressed_size, uncomprssed_size)
      [0x08074b50, crc32, compressed_size, uncomprssed_size].pack('VVVV')
    end

    def reset!
      reset_keys!
    end

    private

    def encode(n)
      t = decrypt_byte
      update_keys(n.chr)
      t ^ n
    end
  end

  class TraditionalDecrypter < Decrypter
    include TraditionalEncryption

    def decrypt(data)
      data.unpack('C*').map { |x| decode x }.pack('C*')
    end

    def reset!(header)
      reset_keys!
      header.each_byte do |x|
        decode x
      end
    end

    private

    def decode(n)
      n ^= decrypt_byte
      update_keys(n.chr)
      n
    end
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
