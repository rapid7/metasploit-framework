# -*- coding: binary -*-

module Rex
  module Text

    # Returns a XOR'd string.
    #
    # @param key [String] XOR key.
    # @param value [String] The string to XOR.
    # @return [String] An XOR'd string.
    def self.xor(key, value)
      xor_key = key.kind_of?(Integer) || key.nil? ? key.to_i : key.to_i(16)
      unless xor_key.between?(0, 255)
        raise ArgumentError, 'XOR key should be between 0x00 to 0x0f'
      end

      buf = ''

      value.each_byte do |byte|
        xor_byte = byte ^ xor_key
        buf << [xor_byte].pack('c')
      end

      buf
    end

  end
end