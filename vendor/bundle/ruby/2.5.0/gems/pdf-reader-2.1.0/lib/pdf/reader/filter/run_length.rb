# coding: utf-8
#
class PDF::Reader # :nodoc:
  module Filter # :nodoc:
    # implementation of the run length stream filter
    class RunLength
      def initialize(options = {})
        @options = options
      end

      ################################################################################
      # Decode the specified data with the RunLengthDecode compression algorithm
      def filter(data)
        pos = 0
        out = ""

        while pos < data.length
          length = data.getbyte(pos)
          pos += 1

          case
          when length == 128
            break
          when length < 128
            # When the length is < 128, we copy the following length+1 bytes
            # literally.
            out << data[pos, length + 1]
            pos += length
          else
            # When the length is > 128, we copy the next byte (257 - length)
            # times; i.e., "\xFA\x00" ([250, 0]) will expand to
            # "\x00\x00\x00\x00\x00\x00\x00".
            out << data[pos, 1] * (257 - length)
          end

          pos += 1
        end

        Depredict.new(@options).filter(out)
      end
    end
  end
end
