module TTFunk
  module Encoding
    class MacRoman
      # rubocop: disable Style/ExtraSpacing

      TO_UNICODE =
        Hash[*(0..255).zip(0..255).flatten]
        .update(
          0x81 => 0x00C5, 0x82 => 0x00C7, 0x83 => 0x00C9, 0x84 => 0x00D1,
          0x85 => 0x00D6, 0x86 => 0x00DC, 0x87 => 0x00E1, 0x88 => 0x00E0,
          0x89 => 0x00E2, 0x8A => 0x00E4, 0x8B => 0x00E3, 0x8C => 0x00E5,
          0x8D => 0x00E7, 0x8E => 0x00E9, 0x8F => 0x00E8, 0x90 => 0x00EA,
          0x91 => 0x00EB, 0x92 => 0x00ED, 0x93 => 0x00EC, 0x94 => 0x00EE,
          0x95 => 0x00EF, 0x96 => 0x00F1, 0x97 => 0x00F3, 0x98 => 0x00F2,
          0x99 => 0x00F4, 0x9A => 0x00F6, 0x9B => 0x00F5, 0x9C => 0x00FA,
          0x9D => 0x00F9, 0x9E => 0x00FB, 0x9F => 0x00FC, 0xA0 => 0x2020,
          0xA1 => 0x00B0, 0xA4 => 0x00A7, 0xA5 => 0x2022, 0xA6 => 0x00B6,
          0xA7 => 0x00DF, 0xA8 => 0x00AE, 0xAA => 0x2122, 0xAB => 0x00B4,
          0xAC => 0x00A8, 0xAD => 0x2260, 0xAE => 0x00C6, 0xAF => 0x00D8,
          0xB0 => 0x221E, 0xB2 => 0x2264, 0xB3 => 0x2265, 0xB4 => 0x00A5,
          0xB6 => 0x2202, 0xB7 => 0x2211, 0xB8 => 0x220F, 0xB9 => 0x03C0,
          0xBA => 0x222B, 0xBB => 0x00AA, 0xBC => 0x00BA, 0xBD => 0x03A9,
          0xBE => 0x00E6, 0xBF => 0x00F8, 0xC0 => 0x00BF, 0xC1 => 0x00A1,
          0xC2 => 0x00AC, 0xC3 => 0x221A, 0xC4 => 0x0192, 0xC5 => 0x2248,
          0xC6 => 0x2206, 0xC7 => 0x00AB, 0xC8 => 0x00BB, 0xC9 => 0x2026,
          0xCA => 0x00A0, 0xCB => 0x00C0, 0xCC => 0x00C3, 0xCD => 0x00D5,
          0xCE => 0x0152, 0xCF => 0x0153, 0xD0 => 0x2013, 0xD1 => 0x2014,
          0xD2 => 0x201C, 0xD3 => 0x201D, 0xD4 => 0x2018, 0xD5 => 0x2019,
          0xD6 => 0x00F7, 0xD7 => 0x25CA, 0xD8 => 0x00FF, 0xD9 => 0x0178,
          0xDA => 0x2044, 0xDB => 0x20AC, 0xDC => 0x2039, 0xDD => 0x203A,
          0xDE => 0xFB01, 0xDF => 0xFB02, 0xE0 => 0x2021, 0xE1 => 0x00B7,
          0xE2 => 0x201A, 0xE3 => 0x201E, 0xE4 => 0x2030, 0xE5 => 0x00C2,
          0xE6 => 0x00CA, 0xE7 => 0x00C1, 0xE8 => 0x00CB, 0xE9 => 0x00C8,
          0xEA => 0x00CD, 0xEB => 0x00CE, 0xEC => 0x00CF, 0xED => 0x00CC,
          0xEE => 0x00D3, 0xEF => 0x00D4, 0xF0 => 0xF8FF, 0xF1 => 0x00D2,
          0xF2 => 0x00DA, 0xF3 => 0x00DB, 0xF4 => 0x00D9, 0xF5 => 0x0131,
          0xF6 => 0x02C6, 0xF7 => 0x02DC, 0xF8 => 0x00AF, 0xF9 => 0x02D8,
          0xFA => 0x02D9, 0xFB => 0x02DA, 0xFC => 0x00B8, 0xFD => 0x02DD,
          0xFE => 0x02DB, 0xFF => 0x02C7
        ).freeze

      FROM_UNICODE = TO_UNICODE.invert.freeze

      # Maps MacRoman codes to their corresponding index in the Postscript glyph
      # table (see TTFunk::Table::Post::Format10). If any entry in this array is
      # a string, it is a postscript glyph that is not in the standard list, and
      # which should be emitted specially in the TTF postscript table ('post',
      # see format 2).
      # rubocop: disable Metrics/LineLength,Style/AlignArray,Style/IndentArray
      POSTSCRIPT_GLYPH_MAPPING = [
          0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0, # 0x0F
          0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0, # 0x1F
          3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,  15,  16,  17,  18, # 0x2F
         19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32,  33,  34, # 0x3F
         35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,  49,  50, # 0x4F
         51,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  62,  63,  64,  65,  66, # 0x5F
         67,  68,  69,  70,  71,  72,  73,  74,  75,  76,  77,  78,  79,  80,  81,  82, # 0x6F
         83,  84,  85,  86,  87,  88,  89,  90,  91,  92,  93,  94,  95,  96,  97,   0, # 0x7F
         98,  99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, # 0x8F
        114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, # 0x9F
        130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, # 0xAF
        146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, # 0xBF
        162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, # 0xCF
        178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 'Euro', 190, 191, 192, 193, # 0xDF
        194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, # 0xEF
        210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225  # 0xFF
      ].freeze

      # rubocop: enable Style/AlignArray,Metrics/LineLength,Style/ExtraSpacing,Style/IndentArray

      def self.covers?(character)
        !FROM_UNICODE[character].nil?
      end

      def self.to_utf8(string)
        to_unicode_codepoints(string.unpack('C*')).pack('U*')
      end

      def self.to_unicode(string)
        to_unicode_codepoints(string.unpack('C*')).pack('n*')
      end

      def self.from_utf8(string)
        from_unicode_codepoints(string.unpack('U*')).pack('C*')
      end

      def self.from_unicode(string)
        from_unicode_codepoints(string.unpack('n*')).pack('C*')
      end

      def self.to_unicode_codepoints(array)
        array.map { |code| TO_UNICODE[code] }
      end

      def self.from_unicode_codepoints(array)
        array.map { |code| FROM_UNICODE[code] || 0 }
      end
    end
  end
end
