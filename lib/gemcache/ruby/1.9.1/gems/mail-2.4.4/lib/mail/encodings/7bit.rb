# encoding: utf-8
require 'mail/encodings/8bit'

module Mail
  module Encodings
    class SevenBit < EightBit
      NAME = '7bit'
    
      PRIORITY = 1

      # 7bit and 8bit operate the same
      
      # Decode the string
      def self.decode(str)
        super
      end
    
      # Encode the string
      def self.encode(str)
        super
      end
     
      # Idenity encodings have a fixed cost, 1 byte out per 1 byte in
      def self.cost(str)
        super 
      end

      Encodings.register(NAME, self) 
    end
  end
end
