require_relative '../table'

module TTFunk
  class Table
    class Sbix < Table
      attr_reader :version
      attr_reader :flags
      attr_reader :num_strikes
      attr_reader :strikes

      BitmapData = Struct.new(:x, :y, :type, :data, :ppem, :resolution)

      def bitmap_data_for(glyph_id, strike_index)
        strike = strikes[strike_index]
        return if strike.nil?

        glyph_offset = strike[:glyph_data_offset][glyph_id]
        next_glyph_offset = strike[:glyph_data_offset][glyph_id + 1]

        if glyph_offset && next_glyph_offset
          bytes = next_glyph_offset - glyph_offset
          if bytes > 0
            parse_from(offset + strike[:offset] + glyph_offset) do
              x, y, type = read(8, 's2A4')
              data = StringIO.new(io.read(bytes - 8))
              BitmapData.new(
                x, y, type, data, strike[:ppem], strike[:resolution]
              )
            end
          end
        end
      end

      def all_bitmap_data_for(glyph_id)
        strikes.each_index.map do |strike_index|
          bitmap_data_for(glyph_id, strike_index)
        end.compact
      end

      private

      def parse!
        @version, @flags, @num_strikes = read(8, 'n2N')
        strike_offsets = Array.new(num_strikes) { read(4, 'N').first }

        @strikes = strike_offsets.map do |strike_offset|
          parse_from(offset + strike_offset) do
            ppem, resolution = read(4, 'n2')
            data_offsets = Array.new(file.maximum_profile.num_glyphs + 1) do
              read(4, 'N').first
            end
            {
              ppem: ppem,
              resolution: resolution,
              offset: strike_offset,
              glyph_data_offset: data_offsets
            }
          end
        end
      end
    end
  end
end
