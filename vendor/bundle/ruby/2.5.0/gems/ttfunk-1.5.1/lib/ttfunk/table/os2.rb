require_relative '../table'

module TTFunk
  class Table
    class OS2 < Table
      attr_reader :version

      attr_reader :ave_char_width
      attr_reader :weight_class
      attr_reader :width_class
      attr_reader :type
      attr_reader :y_subscript_x_size
      attr_reader :y_subscript_y_size
      attr_reader :y_subscript_x_offset
      attr_reader :y_subscript_y_offset
      attr_reader :y_superscript_x_size
      attr_reader :y_superscript_y_size
      attr_reader :y_superscript_x_offset
      attr_reader :y_superscript_y_offset
      attr_reader :y_strikeout_size
      attr_reader :y_strikeout_position
      attr_reader :family_class
      attr_reader :panose
      attr_reader :char_range
      attr_reader :vendor_id
      attr_reader :selection
      attr_reader :first_char_index
      attr_reader :last_char_index

      attr_reader :ascent
      attr_reader :descent
      attr_reader :line_gap
      attr_reader :win_ascent
      attr_reader :win_descent
      attr_reader :code_page_range

      attr_reader :x_height
      attr_reader :cap_height
      attr_reader :default_char
      attr_reader :break_char
      attr_reader :max_context

      def tag
        'OS/2'
      end

      private

      def parse!
        @version = read(2, 'n').first

        @ave_char_width = read_signed(1)
        @weight_class, @width_class = read(4, 'nn')
        @type, @y_subscript_x_size, @y_subscript_y_size, @y_subscript_x_offset,
          @y_subscript_y_offset, @y_superscript_x_size, @y_superscript_y_size,
          @y_superscript_x_offset, @y_superscript_y_offset, @y_strikeout_size,
          @y_strikeout_position, @family_class = read_signed(12)
        @panose = io.read(10)

        @char_range = io.read(16)
        @vendor_id = io.read(4)

        @selection, @first_char_index, @last_char_index = read(6, 'n*')

        if @version > 0
          @ascent, @descent, @line_gap = read_signed(3)
          @win_ascent, @win_descent = read(4, 'nn')
          @code_page_range = io.read(8)

          if @version > 1
            @x_height, @cap_height = read_signed(2)
            @default_char, @break_char, @max_context = read(6, 'nnn')
          end
        end
      end
    end
  end
end
