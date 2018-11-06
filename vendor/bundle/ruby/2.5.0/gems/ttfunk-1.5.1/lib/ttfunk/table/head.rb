require_relative '../table'

module TTFunk
  class Table
    class Head < TTFunk::Table
      attr_reader :version
      attr_reader :font_revision
      attr_reader :checksum_adjustment
      attr_reader :magic_number
      attr_reader :flags
      attr_reader :units_per_em
      attr_reader :created
      attr_reader :modified
      attr_reader :x_min
      attr_reader :y_min
      attr_reader :x_max
      attr_reader :y_max
      attr_reader :mac_style
      attr_reader :lowest_rec_ppem
      attr_reader :font_direction_hint
      attr_reader :index_to_loc_format
      attr_reader :glyph_data_format

      def self.encode(head, loca)
        table = head.raw
        table[8, 4] = "\0\0\0\0" # set checksum adjustment to 0 initially
        table[-4, 2] = [loca[:type]].pack('n') # set index_to_loc_format
        table
      end

      private

      def parse!
        @version, @font_revision, @check_sum_adjustment, @magic_number,
          @flags, @units_per_em, @created, @modified = read(36, 'N4n2q2')

        @x_min, @y_min, @x_max, @y_max = read_signed(4)

        @mac_style, @lowest_rec_ppem, @font_direction_hint,
          @index_to_loc_format, @glyph_data_format = read(10, 'n*')
      end
    end
  end
end
