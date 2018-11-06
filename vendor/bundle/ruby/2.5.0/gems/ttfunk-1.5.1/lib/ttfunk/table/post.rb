require_relative '../table'

module TTFunk
  class Table
    class Post < Table
      attr_reader :format
      attr_reader :italic_angle
      attr_reader :underline_position
      attr_reader :underline_thickness
      attr_reader :fixed_pitch
      attr_reader :min_mem_type42
      attr_reader :max_mem_type42
      attr_reader :min_mem_type1
      attr_reader :max_mem_type1

      attr_reader :subtable

      def self.encode(post, mapping)
        return nil unless post.exists?
        post.recode(mapping)
      end

      def fixed_pitch?
        @fixed_pitch != 0
      end

      def glyph_for(_code)
        '.notdef'
      end

      def recode(mapping)
        return raw if format == 0x00030000

        table = raw[0, 32]
        table[0, 4] = [0x00020000].pack('N')

        index = []
        strings = []

        mapping.keys.sort.each do |new_id|
          post_glyph = glyph_for(mapping[new_id])
          position = Format10::POSTSCRIPT_GLYPHS.index(post_glyph)
          if position
            index << position
          else
            index << 257 + strings.length
            strings << post_glyph
          end
        end

        table << [mapping.length, *index].pack('n*')
        strings.each do |string|
          table << [string.length, string].pack('CA*')
        end

        table
      end

      private

      def parse!
        @format, @italic_angle, @underline_position, @underline_thickness,
          @fixed_pitch, @min_mem_type42, @max_mem_type42,
          @min_mem_type1, @max_mem_type1 = read(32, 'N2n2N*')

        @subtable =
          case @format
          when 0x00010000
            extend(Post::Format10)
          when 0x00020000
            extend(Post::Format20)
          when 0x00025000
            raise NotImplementedError,
              'Post format 2.5 is not supported by TTFunk'
          when 0x00030000
            extend(Post::Format30)
          when 0x00040000
            extend(Post::Format40)
          end

        parse_format!
      end

      def parse_format!
        warn format('postscript table format 0x%08X is not supported', @format)
      end
    end
  end
end

require_relative 'post/format10'
require_relative 'post/format20'
require_relative 'post/format30'
require_relative 'post/format40'
