module TTFunk
  module Encoding
    class Windows1252
      # rubocop: disable Style/ExtraSpacing

      TO_UNICODE =
        Hash[*(0..255).zip((0..255)).flatten]
        .update(
          0x80 => 0x20AC, 0x82 => 0x201A, 0x83 => 0x0192, 0x84 => 0x201E,
          0x85 => 0x2026, 0x86 => 0x2020, 0x87 => 0x2021, 0x88 => 0x02C6,
          0x89 => 0x2030, 0x8A => 0x0160, 0x8B => 0x2039, 0x8C => 0x0152,
          0x8E => 0x017D, 0x91 => 0x2018, 0x92 => 0x2019, 0x93 => 0x201C,
          0x94 => 0x201D, 0x95 => 0x2022, 0x96 => 0x2013, 0x97 => 0x2014,
          0x98 => 0x02DC, 0x99 => 0x2122, 0x9A => 0x0161, 0x9B => 0x203A,
          0x9C => 0x0152, 0x9E => 0x017E, 0x9F => 0x0178
        ).freeze

      FROM_UNICODE = TO_UNICODE.invert.freeze

      # Maps Windows-1252 codes to their corresponding index in the Postscript
      # glyph table (see TTFunk::Table::Post::Format10). If any entry in this
      # array is a string, it is a postscript glyph that is not in the standard
      # list, and which should be emitted specially in the TTF postscript table
      # ('post', see format 2).
      # rubocop: disable Metrics/LineLength,Style/AlignArray,Style/IndentArray
      POSTSCRIPT_GLYPH_MAPPING = [
          0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
          0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
          3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,  15,  16,  17,  18,
         19,  20,  21,  22,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32,  33,  34,
         35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,  49,  50,
         51,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  62,  63,  64,  65,  66,
         67,  68,  69,  70,  71,  72,  73,  74,  75,  76,  77,  78,  79,  80,  81,  82,
         83,  84,  85,  86,  87,  88,  89,  90,  91,  92,  93,  94,  95,  96,  97,   0,
     'Euro',   0, 196, 166, 197, 171, 130, 194, 216, 198, 228, 190, 176,   0, 230,   0,
          0, 182, 183, 180, 181, 135, 178, 179, 217, 140, 229, 191, 177,   0, 231, 186,
          3, 163, 132, 133, 189, 150, 232, 134, 142, 139, 157, 169, 164,  16, 138, 218,
        131, 147, 242, 243, 141, 151, 136, 195, 222, 241, 158, 170, 245, 244, 246, 162,
        173, 201, 199, 174,  98,  99, 144, 100, 203, 101, 200, 202, 207, 204, 205, 206,
        233, 102, 211, 208, 209, 175, 103, 240, 145, 214, 212, 213, 104, 235, 237, 137,
        106, 105, 107, 109, 108, 110, 160, 111, 113, 112, 114, 115, 117, 116, 118, 119,
        234, 120, 122, 121, 123, 125, 124, 184, 161, 127, 126, 128, 129, 236, 238, 186
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
