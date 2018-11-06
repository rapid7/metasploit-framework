require_relative '../table'

module TTFunk
  class Table
    class Loca < Table
      attr_reader :offsets

      # Accepts an array of offsets, with each index corresponding to the
      # glyph id with that index.
      #
      # Returns a hash containing:
      #
      # * :table - the string representing the table's contents
      # * :type  - the type of offset (to be encoded in the 'head' table)
      def self.encode(offsets)
        long_offsets = offsets.any? do |offset|
          short_offset = offset / 2
          short_offset * 2 != offset || short_offset > 0xffff
        end

        if long_offsets
          { type: 1, table: offsets.pack('N*') }
        else
          { type: 0, table: offsets.map { |o| o / 2 }.pack('n*') }
        end
      end

      def index_of(glyph_id)
        @offsets[glyph_id]
      end

      def size_of(glyph_id)
        @offsets[glyph_id + 1] - @offsets[glyph_id]
      end

      private

      def parse!
        type = file.header.index_to_loc_format == 0 ? 'n' : 'N'
        @offsets = read(length, "#{type}*")

        if file.header.index_to_loc_format == 0
          @offsets.map! { |v| v * 2 }
        end
      end
    end
  end
end
