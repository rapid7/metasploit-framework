# -*- coding: binary -*-
module Rex
  module Text
    # We are re-opening the module to add these module methods.
    # Breaking them up this way allows us to maintain a little higher
    # degree of organisation and make it easier to find what you're looking for
    # without hanging the underlying calls that we historically rely upon.

    # @param str [String] Data to checksum
    # @return [Integer] 8-bit checksum
    def self.checksum8(str)
      (str.unpack("C*").inject(:+) || 0) % 0x100
    end

    # @param str [String] Little-endian data to checksum
    # @return [Integer] 16-bit checksum
    def self.checksum16_le(str)
      (str.unpack("v*").inject(:+) || 0) % 0x10000
    end

    # @param str [String] Big-endian data to checksum
    # @return [Integer] 16-bit checksum
    def self.checksum16_be(str)
      (str.unpack("n*").inject(:+) || 0) % 0x10000
    end

    # @param str [String] Little-endian data to checksum
    # @return [Integer] 32-bit checksum
    def self.checksum32_le(str)
      (str.unpack("V*").inject(:+) || 0) % 0x100000000
    end

    # @param str [String] Big-endian data to checksum
    # @return [Integer] 32-bit checksum
    def self.checksum32_be(str)
      (str.unpack("N*").inject(:+) || 0) % 0x100000000
    end
  end
end