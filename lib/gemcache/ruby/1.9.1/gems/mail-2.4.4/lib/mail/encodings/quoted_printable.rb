# encoding: utf-8
require 'mail/encodings/7bit'

module Mail
  module Encodings
    class QuotedPrintable < SevenBit
      NAME='quoted-printable'
   
      PRIORITY = 2

      def self.can_encode?(str)
        EightBit.can_encode? str
      end

      # Decode the string from Quoted-Printable
      def self.decode(str)
        str.unpack("M*").first
      end

      def self.encode(str)
        [str].pack("M").gsub(/\n/, "\r\n")
      end

      def self.cost(str)
        # These bytes probably do not need encoding
        c = str.count("\x9\xA\xD\x20-\x3C\x3E-\x7E")
        # Everything else turns into =XX where XX is a 
        # two digit hex number (taking 3 bytes)
        total = (str.bytesize - c)*3 + c
        total.to_f/str.bytesize
      end
        
      private

      Encodings.register(NAME, self)
    end
  end
end
