module TTFunk
  class Table
    class Cmap
      module Format04
        attr_reader :language
        attr_reader :code_map

        # Expects a hash mapping character codes to glyph ids (where the
        # glyph ids are from the original font). Returns a hash including
        # a new map (:charmap) that maps the characters in charmap to a
        # another hash containing both the old (:old) and new (:new) glyph
        # ids. The returned hash also includes a :subtable key, which contains
        # the encoded subtable for the given charmap.
        def self.encode(charmap)
          end_codes = []
          start_codes = []
          next_id = 0
          last = difference = nil

          glyph_map = { 0 => 0 }
          new_map = charmap.keys.sort.each_with_object({}) do |code, map|
            old = charmap[code]
            glyph_map[old] ||= next_id += 1
            map[code] = { old: old, new: glyph_map[old] }

            delta = glyph_map[old] - code
            if last.nil? || delta != difference
              end_codes << last if last
              start_codes << code
              difference = delta
            end
            last = code

            map
          end

          end_codes << last if last
          end_codes << 0xFFFF
          start_codes << 0xFFFF
          segcount = start_codes.length

          # build the conversion tables
          deltas = []
          range_offsets = []
          glyph_indices = []

          offset = 0
          start_codes.zip(end_codes).each_with_index do |(a, b), segment|
            if a == 0xFFFF
              deltas << 0
              range_offsets << 0
              break
            end

            start_glyph_id = new_map[a][:new]
            if a - start_glyph_id >= 0x8000
              deltas << 0
              range_offsets << 2 * (glyph_indices.length + segcount - segment)
              a.upto(b) { |code| glyph_indices << new_map[code][:new] }
            else
              deltas << -a + start_glyph_id
              range_offsets << 0
            end
            offset += 2
          end

          # format, length, language
          subtable = [
            4, 16 + 8 * segcount + 2 * glyph_indices.length, 0
          ].pack('nnn')

          search_range = 2 * 2**(Math.log(segcount) / Math.log(2)).to_i
          entry_selector = (Math.log(search_range / 2) / Math.log(2)).to_i
          range_shift = (2 * segcount) - search_range
          subtable << [
            segcount * 2, search_range, entry_selector, range_shift
          ].pack('nnnn')

          subtable << end_codes.pack('n*') << "\0\0" << start_codes.pack('n*')
          subtable << deltas.pack('n*') << range_offsets.pack('n*')
          subtable << glyph_indices.pack('n*')

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
          length, @language, segcount_x2 = read(6, 'nnn')
          segcount = segcount_x2 / 2

          io.read(6) # skip searching hints

          end_code = read(segcount_x2, 'n*')
          io.read(2) # skip reserved value
          start_code = read(segcount_x2, 'n*')
          id_delta = read_signed(segcount)
          id_range_offset = read(segcount_x2, 'n*')

          glyph_ids = read(length - io.pos + @offset, 'n*')

          @code_map = {}

          end_code.each_with_index do |tail, i|
            start_code[i].upto(tail) do |code|
              if id_range_offset[i] == 0
                glyph_id = code + id_delta[i]
              else
                index = id_range_offset[i] / 2 +
                  (code - start_code[i]) - (segcount - i)
                # Decause some TTF fonts are broken
                glyph_id = glyph_ids[index] || 0
                glyph_id += id_delta[i] if glyph_id != 0
              end

              @code_map[code] = glyph_id & 0xFFFF
            end
          end
        end
      end
    end
  end
end
