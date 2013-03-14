# encoding: utf-8
require 'mail/encodings/binary'

module Mail
  module Encodings
    class EightBit < Binary
      NAME = '8bit'

      PRIORITY = 4

      # 8bit is an identiy encoding, meaning nothing to do
      
      # Decode the string
      def self.decode(str)
        str.to_lf
      end
    
      # Encode the string
      def self.encode(str)
        str.to_crlf
      end
     
      # Idenity encodings have a fixed cost, 1 byte out per 1 byte in
      def self.cost(str)
        1.0
      end

      Encodings.register(NAME, self) 
    end
  end
end
