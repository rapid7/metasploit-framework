# -*- coding: binary -*-
# Copyright (C) 2008 TOMITA Masahiro
# mailto:tommy@tmtm.org

require "#{File.dirname __FILE__}/error"

class RbMysql
  class Charset
    def initialize(number, name, csname)
      @number, @name, @csname = number, name, csname
    end
    attr_reader :number, :name, :csname

    # [[charset_number, charset_name, collation_name, default], ...]
    CHARSETS = [
      [  1, "big5",     "big5_chinese_ci",      true ],
      [  2, "latin2",   "latin2_czech_cs",      false],
      [  3, "dec8",     "dec8_swedish_ci",      true ],
      [  4, "cp850",    "cp850_general_ci",     true ],
      [  5, "latin1",   "latin1_german1_ci",    false],
      [  6, "hp8",      "hp8_english_ci",       true ],
      [  7, "koi8r",    "koi8r_general_ci",     true ],
      [  8, "latin1",   "latin1_swedish_ci",    true ],
      [  9, "latin2",   "latin2_general_ci",    true ],
      [ 10, "swe7",     "swe7_swedish_ci",      true ],
      [ 11, "ascii",    "ascii_general_ci",     true ],
      [ 12, "ujis",     "ujis_japanese_ci",     true ],
      [ 13, "sjis",     "sjis_japanese_ci",     true ],
      [ 14, "cp1251",   "cp1251_bulgarian_ci",  false],
      [ 15, "latin1",   "latin1_danish_ci",     false],
      [ 16, "hebrew",   "hebrew_general_ci",    true ],
      [ 18, "tis620",   "tis620_thai_ci",       true ],
      [ 19, "euckr",    "euckr_korean_ci",      true ],
      [ 20, "latin7",   "latin7_estonian_cs",   false],
      [ 21, "latin2",   "latin2_hungarian_ci",  false],
      [ 22, "koi8u",    "koi8u_general_ci",     true ],
      [ 23, "cp1251",   "cp1251_ukrainian_ci",  false],
      [ 24, "gb2312",   "gb2312_chinese_ci",    true ],
      [ 25, "greek",    "greek_general_ci",     true ],
      [ 26, "cp1250",   "cp1250_general_ci",    true ],
      [ 27, "latin2",   "latin2_croatian_ci",   false],
      [ 28, "gbk",      "gbk_chinese_ci",       true ],
      [ 29, "cp1257",   "cp1257_lithuanian_ci", false],
      [ 30, "latin5",   "latin5_turkish_ci",    true ],
      [ 31, "latin1",   "latin1_german2_ci",    false],
      [ 32, "armscii8", "armscii8_general_ci",  true ],
      [ 33, "utf8",     "utf8_general_ci",      true ],
      [ 34, "cp1250",   "cp1250_czech_cs",      false],
      [ 35, "ucs2",     "ucs2_general_ci",      true ],
      [ 36, "cp866",    "cp866_general_ci",     true ],
      [ 37, "keybcs2",  "keybcs2_general_ci",   true ],
      [ 38, "macce",    "macce_general_ci",     true ],
      [ 39, "macroman", "macroman_general_ci",  true ],
      [ 40, "cp852",    "cp852_general_ci",     true ],
      [ 41, "latin7",   "latin7_general_ci",    true ],
      [ 42, "latin7",   "latin7_general_cs",    false],
      [ 43, "macce",    "macce_bin",            false],
      [ 44, "cp1250",   "cp1250_croatian_ci",   false],
      [ 47, "latin1",   "latin1_bin",           false],
      [ 48, "latin1",   "latin1_general_ci",    false],
      [ 49, "latin1",   "latin1_general_cs",    false],
      [ 50, "cp1251",   "cp1251_bin",           false],
      [ 51, "cp1251",   "cp1251_general_ci",    true ],
      [ 52, "cp1251",   "cp1251_general_cs",    false],
      [ 53, "macroman", "macroman_bin",         false],
      [ 57, "cp1256",   "cp1256_general_ci",    true ],
      [ 58, "cp1257",   "cp1257_bin",           false],
      [ 59, "cp1257",   "cp1257_general_ci",    true ],
      [ 63, "binary",   "binary",               true ],
      [ 64, "armscii8", "armscii8_bin",         false],
      [ 65, "ascii",    "ascii_bin",            false],
      [ 66, "cp1250",   "cp1250_bin",           false],
      [ 67, "cp1256",   "cp1256_bin",           false],
      [ 68, "cp866",    "cp866_bin",            false],
      [ 69, "dec8",     "dec8_bin",             false],
      [ 70, "greek",    "greek_bin",            false],
      [ 71, "hebrew",   "hebrew_bin",           false],
      [ 72, "hp8",      "hp8_bin",              false],
      [ 73, "keybcs2",  "keybcs2_bin",          false],
      [ 74, "koi8r",    "koi8r_bin",            false],
      [ 75, "koi8u",    "koi8u_bin",            false],
      [ 77, "latin2",   "latin2_bin",           false],
      [ 78, "latin5",   "latin5_bin",           false],
      [ 79, "latin7",   "latin7_bin",           false],
      [ 80, "cp850",    "cp850_bin",            false],
      [ 81, "cp852",    "cp852_bin",            false],
      [ 82, "swe7",     "swe7_bin",             false],
      [ 83, "utf8",     "utf8_bin",             false],
      [ 84, "big5",     "big5_bin",             false],
      [ 85, "euckr",    "euckr_bin",            false],
      [ 86, "gb2312",   "gb2312_bin",           false],
      [ 87, "gbk",      "gbk_bin",              false],
      [ 88, "sjis",     "sjis_bin",             false],
      [ 89, "tis620",   "tis620_bin",           false],
      [ 90, "ucs2",     "ucs2_bin",             false],
      [ 91, "ujis",     "ujis_bin",             false],
      [ 92, "geostd8",  "geostd8_general_ci",   true ],
      [ 93, "geostd8",  "geostd8_bin",          false],
      [ 94, "latin1",   "latin1_spanish_ci",    false],
      [ 95, "cp932",    "cp932_japanese_ci"  ,  true ],
      [ 96, "cp932",    "cp932_bin"          ,  false],
      [ 97, "eucjpms",  "eucjpms_japanese_ci",  true ],
      [ 98, "eucjpms",  "eucjpms_bin",          false],
      [128, "ucs2",     "ucs2_unicode_ci",      false],
      [129, "ucs2",     "ucs2_icelandic_ci",    false],
      [130, "ucs2",     "ucs2_latvian_ci",      false],
      [131, "ucs2",     "ucs2_romanian_ci",     false],
      [132, "ucs2",     "ucs2_slovenian_ci",    false],
      [133, "ucs2",     "ucs2_polish_ci",       false],
      [134, "ucs2",     "ucs2_estonian_ci",     false],
      [135, "ucs2",     "ucs2_spanish_ci",      false],
      [136, "ucs2",     "ucs2_swedish_ci",      false],
      [137, "ucs2",     "ucs2_turkish_ci",      false],
      [138, "ucs2",     "ucs2_czech_ci",        false],
      [139, "ucs2",     "ucs2_danish_ci",       false],
      [140, "ucs2",     "ucs2_lithuanian_ci",   false],
      [141, "ucs2",     "ucs2_slovak_ci",       false],
      [142, "ucs2",     "ucs2_spanish2_ci",     false],
      [143, "ucs2",     "ucs2_roman_ci",        false],
      [144, "ucs2",     "ucs2_persian_ci",      false],
      [145, "ucs2",     "ucs2_esperanto_ci",    false],
      [146, "ucs2",     "ucs2_hungarian_ci",    false],
      [192, "utf8",     "utf8_unicode_ci",      false],
      [193, "utf8",     "utf8_icelandic_ci",    false],
      [194, "utf8",     "utf8_latvian_ci",      false],
      [195, "utf8",     "utf8_romanian_ci",     false],
      [196, "utf8",     "utf8_slovenian_ci",    false],
      [197, "utf8",     "utf8_polish_ci",       false],
      [198, "utf8",     "utf8_estonian_ci",     false],
      [199, "utf8",     "utf8_spanish_ci",      false],
      [200, "utf8",     "utf8_swedish_ci",      false],
      [201, "utf8",     "utf8_turkish_ci",      false],
      [202, "utf8",     "utf8_czech_ci",        false],
      [203, "utf8",     "utf8_danish_ci",       false],
      [204, "utf8",     "utf8_lithuanian_ci",   false],
      [205, "utf8",     "utf8_slovak_ci",       false],
      [206, "utf8",     "utf8_spanish2_ci",     false],
      [207, "utf8",     "utf8_roman_ci",        false],
      [208, "utf8",     "utf8_persian_ci",      false],
      [209, "utf8",     "utf8_esperanto_ci",    false],
      [210, "utf8",     "utf8_hungarian_ci",    false],
    ]

    NUMBER_TO_CHARSET = {}
    COLLATION_TO_CHARSET = {}
    CHARSET_DEFAULT = {}
    CHARSETS.each do |number, csname, clname, default|
      cs = Charset.new number, csname, clname
      NUMBER_TO_CHARSET[number] = cs
      COLLATION_TO_CHARSET[clname] = cs
      CHARSET_DEFAULT[csname] = cs if default
    end

    def self.by_number(n)
      raise ClientError, "unknown charset number: #{n}" unless NUMBER_TO_CHARSET.key? n
      NUMBER_TO_CHARSET[n]
    end

    def self.by_name(str)
      ret = COLLATION_TO_CHARSET[str] || CHARSET_DEFAULT[str]
      raise ClientError, "unknown charset: #{str}" unless ret
      ret
    end

    if defined? Encoding

      # MySQL Charset -> Ruby's Encoding
      CHARSET_ENCODING = {
        "armscii8" => nil,
        "ascii"    => Encoding::US_ASCII,
        "big5"     => Encoding::Big5,
        "binary"   => Encoding::ASCII_8BIT,
        "cp1250"   => Encoding::Windows_1250,
        "cp1251"   => Encoding::Windows_1251,
        "cp1256"   => Encoding::Windows_1256,
        "cp1257"   => Encoding::Windows_1257,
        "cp850"    => Encoding::CP850,
        "cp852"    => Encoding::CP852,
        "cp866"    => Encoding::IBM866,
        "cp932"    => Encoding::Windows_31J,
        "dec8"     => nil,
        "eucjpms"  => Encoding::EucJP_ms,
        "euckr"    => Encoding::EUC_KR,
        "gb2312"   => Encoding::EUC_CN,
        "gbk"      => Encoding::GBK,
        "geostd8"  => nil,
        "greek"    => Encoding::ISO_8859_7,
        "hebrew"   => Encoding::ISO_8859_8,
        "hp8"      => nil,
        "keybcs2"  => nil,
        "koi8r"    => Encoding::KOI8_R,
        "koi8u"    => Encoding::KOI8_U,
        "latin1"   => Encoding::ISO_8859_1,
        "latin2"   => Encoding::ISO_8859_2,
        "latin5"   => Encoding::ISO_8859_9,
        "latin7"   => Encoding::ISO_8859_13,
        "macce"    => Encoding::MacCentEuro,
        "macroman" => Encoding::MacRoman,
        "sjis"     => Encoding::SHIFT_JIS,
        "swe7"     => nil,
        "tis620"   => nil,
        "ucs2"     => Encoding::UTF_16BE,
        "ujis"     => Encoding::EucJP_ms,
        "utf8"     => Encoding::UTF_8,
      }

      def self.to_binary(value)
        value.dup.force_encoding Encoding::ASCII_8BIT
      end

      # return corresponding Ruby encoding
      # === Return
      # encoding [Encoding]
      def encoding
        enc = CHARSET_ENCODING[@name.downcase]
        raise RbMysql::ClientError, "unsupported charset: #{@name}" unless enc
        enc
      end

      # convert encoding corresponding to MySQL charset
      def convert(value)
        if value.is_a? String and value.encoding != Encoding::ASCII_8BIT
          value = value.encode encoding
        end
        value
      end

      # convert encoding from MySQL charset to Ruby
      def force_encoding(value)
        if value.is_a? String
          value = value.dup.force_encoding encoding
        end
        value
      end

    else
      # for Ruby 1.8

      def self.to_binary(value)
        value
      end

      def encoding
        nil
      end

      def convert(value)
        value
      end

      def force_encoding(value)
        value
      end
    end
  end
end

