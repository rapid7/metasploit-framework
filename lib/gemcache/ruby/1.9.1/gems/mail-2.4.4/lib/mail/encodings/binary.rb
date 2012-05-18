# encoding: utf-8
require 'mail/encodings/transfer_encoding'

module Mail
  module Encodings
    class Binary < TransferEncoding
      NAME = 'binary'

      PRIORITY = 5

      # Binary is an identiy encoding, meaning nothing to do
      
      # Decode the string
      def self.decode(str)
        str
      end
    
      # Encode the string
      def self.encode(str)
        str
      end
     
      # Idenity encodings have a fixed cost, 1 byte out per 1 byte in
      def self.cost(str)
        1.0
      end

      Encodings.register(NAME, self) 
    end
  end
end
