# coding: utf-8

class PDF::Reader
  module Filter # :nodoc:
    # some filter implementations support preprocessing of the  data to
    # improve compression
    class Depredict
      def initialize(options = {})
        @options = options || {}
      end

      ################################################################################
      # Streams can be preprocessed to improve compression. This reverses the
      # preprocessing
      #
      def filter(data)
        predictor = @options[:Predictor].to_i

        case predictor
        when 0, 1 then
          data
        when 2    then
          tiff_depredict(data)
        when 10, 11, 12, 13, 14, 15 then
          png_depredict(data)
        else
          raise  MalformedPDFError, "Unrecognised predictor value (#{predictor})"
        end
      end

      private

      ################################################################################
      def tiff_depredict(data)
        data        = data.unpack("C*")
        unfiltered  = []
        bpc         = @options[:BitsPerComponent] || 8
        pixel_bits  = bpc * @options[:Colors]
        pixel_bytes = pixel_bits / 8
        line_len    = (pixel_bytes * @options[:Columns])
        pos         = 0

        if bpc != 8
          raise UnsupportedFeatureError, "TIFF predictor onlys supports 8 Bits Per Component"
        end

        until pos > data.size
          row_data = data[pos, line_len]
          row_data.each_with_index do |byte, index|
            left = index < pixel_bytes ? 0 : row_data[index - pixel_bytes]
            row_data[index] = (byte + left) % 256
          end
          unfiltered += row_data
          pos += line_len
        end

        unfiltered.pack("C*")
      end
      ################################################################################
      def png_depredict(data)
        return data if @options[:Predictor].to_i < 10

        data = data.unpack("C*")

        pixel_bytes     = @options[:Colors] || 1
        scanline_length = (pixel_bytes * @options[:Columns]) + 1
        row = 0
        pixels = []
        paeth, pa, pb, pc = nil
        until data.empty? do
          row_data = data.slice! 0, scanline_length
          filter = row_data.shift
          case filter
          when 0 # None
          when 1 # Sub
            row_data.each_with_index do |byte, index|
              left = index < pixel_bytes ? 0 : row_data[index - pixel_bytes]
              row_data[index] = (byte + left) % 256
              #p [byte, left, row_data[index]]
            end
          when 2 # Up
            row_data.each_with_index do |byte, index|
              col = index / pixel_bytes
              upper = row == 0 ? 0 : pixels[row-1][col][index % pixel_bytes]
              row_data[index] = (upper + byte) % 256
            end
          when 3  # Average
            row_data.each_with_index do |byte, index|
              col = index / pixel_bytes
              upper = row == 0 ? 0 : pixels[row-1][col][index % pixel_bytes]
              left = index < pixel_bytes ? 0 : row_data[index - pixel_bytes]

              row_data[index] = (byte + ((left + upper)/2).floor) % 256
            end
          when 4 # Paeth
            left = upper = upper_left = nil
            row_data.each_with_index do |byte, index|
              col = index / pixel_bytes

              left = index < pixel_bytes ? 0 : row_data[index - pixel_bytes]
              if row.zero?
                upper = upper_left = 0
              else
                upper = pixels[row-1][col][index % pixel_bytes]
                upper_left = col.zero? ? 0 :
                  pixels[row-1][col-1][index % pixel_bytes]
              end

              p = left + upper - upper_left
              pa = (p - left).abs
              pb = (p - upper).abs
              pc = (p - upper_left).abs

              paeth = if pa <= pb && pa <= pc
                        left
                      elsif pb <= pc
                        upper
                      else
                        upper_left
                      end

              row_data[index] = (byte + paeth) % 256
            end
          else
            raise ArgumentError, "Invalid filter algorithm #{filter}"
          end

          s = []
          row_data.each_slice pixel_bytes do |slice|
            s << slice
          end
          pixels << s
          row += 1
        end

        pixels.map { |bytes| bytes.flatten.pack("C*") }.join("")
      end
    end
  end
end
