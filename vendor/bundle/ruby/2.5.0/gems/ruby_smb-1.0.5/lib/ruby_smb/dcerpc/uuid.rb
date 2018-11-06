module RubySMB
  module Dcerpc

    # [Universal Unique Identifier](http://pubs.opengroup.org/onlinepubs/9629399/apdxa.htm)
    class Uuid < BinData::Primitive
      endian :little
      uint32 :time_low,                  label: 'Low field of the timestamp'
      uint16 :time_mid,                  label: 'Middle field of the timestamp'
      uint16 :time_hi_and_version,       label: 'High field of the timestamp multiplexed with the version number'

      uint8  :clock_seq_hi_and_reserved, label: 'High field of the clock sequence multiplexed with the variant'
      uint8  :clock_seq_low,             label: 'Low field of the clock sequence'
      array  :node,                      label: 'Spatially unique node identifier', :type => :uint8, initial_length: 6

      def get
        "#{to_string_le(time_low.to_binary_s)}"\
        "-#{to_string_le(time_mid.to_binary_s)}"\
        "-#{to_string_le(time_hi_and_version.to_binary_s)}"\
        "-#{clock_seq_hi_and_reserved.to_hex}#{clock_seq_low.to_hex}"\
        "-#{node.to_hex}"
      end

      def set(uuid_string)
        components = uuid_string.split('-')
        self.time_low.read(to_binary_le(components[0]))
        self.time_mid.read(to_binary_le(components[1]))
        self.time_hi_and_version.read(to_binary_le(components[2]))
        self.clock_seq_hi_and_reserved.read(components[3][0,2].hex.chr)
        self.clock_seq_low.read(components[3][2,2].hex.chr)
        self.node.read(components[4].gsub(/../) {|e| e.hex.chr})
      end


      private

      def to_binary_le(str)
        str.scan(/../).map {|char| char.hex.chr}.reverse.join
      end

      def to_string_le(bin)
        bin.each_byte.map {|byte| byte.to_s(16).rjust(2, '0')}.reverse.join
      end
    end

  end
end
