# coding: utf-8
#
class PDF::Reader
  module Filter # :nodoc:
    # implementation of the AsciiHex stream filter
    class AsciiHex
      def initialize(options = {})
        @options = options
      end

      ################################################################################
      # Decode the specified data using the AsciiHex algorithm.
      #
      def filter(data)
        data.chop! if data[-1,1] == ">"
        data = data[1,data.size] if data[0,1] == "<"
        data.gsub!(/[^A-Fa-f0-9]/,"")
        data << "0" if data.size % 2 == 1
        data.scan(/.{2}/).map { |s| s.hex.chr }.join("")
      rescue Exception => e
        # Oops, there was a problem decoding the stream
        raise MalformedPDFError,
            "Error occured while decoding an ASCIIHex stream (#{e.class.to_s}: #{e.to_s})"
      end
    end
  end
end

