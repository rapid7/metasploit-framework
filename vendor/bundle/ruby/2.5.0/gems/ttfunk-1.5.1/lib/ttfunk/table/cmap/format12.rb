module TTFunk
  class Table
    class Cmap
      module Format12
        attr_reader :language
        attr_reader :code_map

        def self.encode(charmap)
          next_id = 0
          glyph_map = { 0 => 0 }
          range_firstglyphs = []
          range_firstcodes = []
          range_lengths = []
          last_glyph = last_code = -999

          new_map = charmap.keys.sort.each_with_object({}) do |code, map|
            glyph_map[charmap[code]] ||= next_id += 1
            map[code] = { old: charmap[code], new: glyph_map[charmap[code]] }

            if code > last_code + 1 || glyph_map[charmap[code]] > last_glyph + 1
              range_firstcodes << code
              range_firstglyphs << glyph_map[charmap[code]]
              range_lengths << 1
            else
              range_lengths.push(range_lengths.pop) + 1
            end
            last_code = code
            last_glyph = glyph_map[charmap[code]]
          end

          subtable = [
            12, 0, 16 + 12 * range_lengths.size, 0, range_lengths.size
          ].pack('nnNNN')
          range_lengths.each_with_index do |length, i|
            firstglyph = range_firstglyphs[i]
            firstcode = range_firstcodes[i]
            subtable << [
              firstcode, firstcode + length - 1, firstglyph
            ].pack('NNN')
          end

          { charmap: new_map, subtable: subtable, max_glyph_id: next_id + 1 }
        end

        def [](code)
          @code_map[code] || 0
        end

        def supported?
          true
        end

        private

        def parse_cmap!
          fractional_version, @language, groupcount = read(14, 'nx4NN')
          if fractional_version != 0
            raise NotImplementedError,
              "cmap version 12.#{fractional_version} is not supported"
          end
          @code_map = {}
          (1..groupcount).each do
            startchar, endchar, startglyph = read(12, 'NNN')
            (0..(endchar - startchar)).each do |offset|
              @code_map[startchar + offset] = startglyph + offset
            end
          end
        end
      end
    end
  end
end
