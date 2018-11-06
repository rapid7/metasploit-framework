module RubySMB
  module Nbss
    # Representation of the NetBIOS Name as defined in
    # [4.1. NAME FORMAT](https://tools.ietf.org/html/rfc1002#section-4.1) and
    # [14. REPRESENTATION OF NETBIOS NAMES](https://tools.ietf.org/html/rfc1001#section-14) and
    # [Domain name representation and compression](https://tools.ietf.org/html/rfc883#page-31)
    class NetbiosName < BinData::Primitive
      endian :big

      bit1   :flag1, initial_value: 0
      bit1   :flag2, initial_value: 0
      bit6   :label_length
      string :label, read_length: -> { label_length }
      string :null_label, read_length: 1, value: "\x00"

      def nb_name_encode(name)
        encoded_name = ''
        name.each_byte do |char|
          first_half = (char >> 4) + 'A'.ord
          second_half = (char & 0xF) + 'A'.ord
          encoded_name << first_half.chr
          encoded_name << second_half.chr
        end
        encoded_name
      end

      def nb_name_decode(encoded_name)
        name = encoded_name.scan(/../).map do |char_pair|
          first_half = char_pair[0];
          second_half = char_pair[1]
          char = ((first_half.ord - 'A'.ord) << 4) + (second_half.ord - 'A'.ord)
          char.chr
        end
        name.join
      end

      def get
        nb_name_decode(label)
      end

      def set(label)
        self.label = nb_name_encode(label)
        self.label_length = self.label.length
      end
    end

  end
end
