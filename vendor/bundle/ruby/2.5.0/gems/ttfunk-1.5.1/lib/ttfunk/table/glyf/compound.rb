require_relative '../../reader'

module TTFunk
  class Table
    class Glyf
      class Compound
        include Reader

        ARG_1_AND_2_ARE_WORDS    = 0x0001
        WE_HAVE_A_SCALE          = 0x0008
        MORE_COMPONENTS          = 0x0020
        WE_HAVE_AN_X_AND_Y_SCALE = 0x0040
        WE_HAVE_A_TWO_BY_TWO     = 0x0080
        WE_HAVE_INSTRUCTIONS     = 0x0100

        attr_reader :raw
        attr_reader :x_min, :y_min, :x_max, :y_max
        attr_reader :glyph_ids

        Component = Struct.new(:flags, :glyph_index, :arg1, :arg2, :transform)

        def initialize(raw, x_min, y_min, x_max, y_max)
          @raw = raw
          @x_min = x_min
          @y_min = y_min
          @x_max = x_max
          @y_max = y_max

          # Because TTFunk only cares about glyphs insofar as they (1) provide
          # a bounding box for each glyph, and (2) can be rewritten into a
          # font subset, we don't really care about the rest of the glyph data
          # except as a whole. Thus, we don't actually decompose the glyph
          # into it's parts--all we really care about are the locations within
          # the raw string where the component glyph ids are stored, so that
          # when we rewrite this glyph into a subset we can rewrite the
          # component glyph-ids so they are correct for the subset.

          @glyph_ids = []
          @glyph_id_offsets = []
          offset = 10 # 2 bytes for each of num-contours, min x/y, max x/y

          loop do
            flags, glyph_id = @raw[offset, 4].unpack('n*')
            @glyph_ids << glyph_id
            @glyph_id_offsets << offset + 2

            break unless flags & MORE_COMPONENTS != 0
            offset += 4

            offset +=
              if flags & ARG_1_AND_2_ARE_WORDS != 0
                4
              else
                2
              end

            if flags & WE_HAVE_A_TWO_BY_TWO != 0
              offset += 8
            elsif flags & WE_HAVE_AN_X_AND_Y_SCALE != 0
              offset += 4
            elsif flags & WE_HAVE_A_SCALE != 0
              offset += 2
            end
          end
        end

        def compound?
          true
        end

        def recode(mapping)
          result = @raw.dup
          new_ids = glyph_ids.map { |id| mapping[id] }

          new_ids.zip(@glyph_id_offsets).each do |new_id, offset|
            result[offset, 2] = [new_id].pack('n')
          end

          result
        end
      end
    end
  end
end
