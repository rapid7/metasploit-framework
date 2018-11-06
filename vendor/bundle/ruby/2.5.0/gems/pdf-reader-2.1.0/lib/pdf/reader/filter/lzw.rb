# coding: utf-8
#
class PDF::Reader
  module Filter # :nodoc:
    # implementation of the LZW stream filter
    class Lzw
      def initialize(options = {})
        @options = options
      end

      ################################################################################
      # Decode the specified data with the LZW compression algorithm
      def filter(data)
        data = PDF::Reader::LZW.decode(data)
        Depredict.new(@options).filter(data)
      end
    end
  end
end
