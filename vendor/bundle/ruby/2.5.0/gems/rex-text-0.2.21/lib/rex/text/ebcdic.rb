# -*- coding: binary -*-
module Rex
  module Text
    # We are re-opening the module to add these module methods.
    # Breaking them up this way allows us to maintain a little higher
    # degree of organisation and make it easier to find what you're looking for
    # without hanging the underlying calls that we historically rely upon.


    # The Iconv translation table for IBM's mainframe / System Z
    # (z/os, s390, mvs, etc) - This is a different implementation
    # of EBCDIC than the Iconv_EBCDIC below.
    # It is technically referred to as Code Page IBM1047.
    # This will be net new (until Ruby supports 1047 code page)
    # for all Mainframe / SystemZ based modules
    # that need to convert ASCII to EBCDIC
    #
    # The bytes are indexed by ASCII conversion number
    # e.g.  Iconv_IBM1047[0x41] == \xc1 for letter "A"
    #
    # Note the characters CANNOT be assumed to be in any logical
    # order. Nor are the tables reversible.  Lookups must be for each byte
    # https://gist.github.com/bigendiansmalls/b08483ecedff52cc8fa3
    #
    Iconv_IBM1047 = [
      "\x00","\x01","\x02","\x03","\x37","\x2d","\x2e","\x2f",
      "\x16","\x05","\x15","\x0b","\x0c","\x0d","\x0e","\x0f","\x10",
      "\x11","\x12","\x13","\x3c","\x3d","\x32","\x26","\x18","\x19",
      "\x3f","\x27","\x1c","\x1d","\x1e","\x1f","\x40","\x5a","\x7f",
      "\x7b","\x5b","\x6c","\x50","\x7d","\x4d","\x5d","\x5c","\x4e",
      "\x6b","\x60","\x4b","\x61","\xf0","\xf1","\xf2","\xf3","\xf4",
      "\xf5","\xf6","\xf7","\xf8","\xf9","\x7a","\x5e","\x4c","\x7e",
      "\x6e","\x6f","\x7c","\xc1","\xc2","\xc3","\xc4","\xc5","\xc6",
      "\xc7","\xc8","\xc9","\xd1","\xd2","\xd3","\xd4","\xd5","\xd6",
      "\xd7","\xd8","\xd9","\xe2","\xe3","\xe4","\xe5","\xe6","\xe7",
      "\xe8","\xe9","\xad","\xe0","\xbd","\x5f","\x6d","\x79","\x81",
      "\x82","\x83","\x84","\x85","\x86","\x87","\x88","\x89","\x91",
      "\x92","\x93","\x94","\x95","\x96","\x97","\x98","\x99","\xa2",
      "\xa3","\xa4","\xa5","\xa6","\xa7","\xa8","\xa9","\xc0","\x4f",
      "\xd0","\xa1","\x07","\x20","\x21","\x22","\x23","\x24","\x25",
      "\x06","\x17","\x28","\x29","\x2a","\x2b","\x2c","\x09","\x0a",
      "\x1b","\x30","\x31","\x1a","\x33","\x34","\x35","\x36","\x08",
      "\x38","\x39","\x3a","\x3b","\x04","\x14","\x3e","\xff","\x41",
      "\xaa","\x4a","\xb1","\x9f","\xb2","\x6a","\xb5","\xbb","\xb4",
      "\x9a","\x8a","\xb0","\xca","\xaf","\xbc","\x90","\x8f","\xea",
      "\xfa","\xbe","\xa0","\xb6","\xb3","\x9d","\xda","\x9b","\x8b",
      "\xb7","\xb8","\xb9","\xab","\x64","\x65","\x62","\x66","\x63",
      "\x67","\x9e","\x68","\x74","\x71","\x72","\x73","\x78","\x75",
      "\x76","\x77","\xac","\x69","\xed","\xee","\xeb","\xef","\xec",
      "\xbf","\x80","\xfd","\xfe","\xfb","\xfc","\xba","\xae","\x59",
      "\x44","\x45","\x42","\x46","\x43","\x47","\x9c","\x48","\x54",
      "\x51","\x52","\x53","\x58","\x55","\x56","\x57","\x8c","\x49",
      "\xcd","\xce","\xcb","\xcf","\xcc","\xe1","\x70","\xdd","\xde",
      "\xdb","\xdc","\x8d","\x8e","\xdf"
    ]

    #
    # This is the reverse of the above, converts EBCDIC -> ASCII
    # The bytes are indexed by IBM1047(EBCDIC) conversion number
    # e.g. Iconv_ISO8859_1[0xc1] = \x41 for letter "A"
    #
    # Note the characters CANNOT be assumed to be in any logical (e.g. sequential)
    # order. Nor are the tables reversible.  Lookups must be done byte by byte
    #
    Iconv_ISO8859_1 = [
      "\x00","\x01","\x02","\x03","\x9c","\x09","\x86","\x7f",
      "\x97","\x8d","\x8e","\x0b","\x0c","\x0d","\x0e","\x0f","\x10",
      "\x11","\x12","\x13","\x9d","\x0a","\x08","\x87","\x18","\x19",
      "\x92","\x8f","\x1c","\x1d","\x1e","\x1f","\x80","\x81","\x82",
      "\x83","\x84","\x85","\x17","\x1b","\x88","\x89","\x8a","\x8b",
      "\x8c","\x05","\x06","\x07","\x90","\x91","\x16","\x93","\x94",
      "\x95","\x96","\x04","\x98","\x99","\x9a","\x9b","\x14","\x15",
      "\x9e","\x1a","\x20","\xa0","\xe2","\xe4","\xe0","\xe1","\xe3",
      "\xe5","\xe7","\xf1","\xa2","\x2e","\x3c","\x28","\x2b","\x7c",
      "\x26","\xe9","\xea","\xeb","\xe8","\xed","\xee","\xef","\xec",
      "\xdf","\x21","\x24","\x2a","\x29","\x3b","\x5e","\x2d","\x2f",
      "\xc2","\xc4","\xc0","\xc1","\xc3","\xc5","\xc7","\xd1","\xa6",
      "\x2c","\x25","\x5f","\x3e","\x3f","\xf8","\xc9","\xca","\xcb",
      "\xc8","\xcd","\xce","\xcf","\xcc","\x60","\x3a","\x23","\x40",
      "\x27","\x3d","\x22","\xd8","\x61","\x62","\x63","\x64","\x65",
      "\x66","\x67","\x68","\x69","\xab","\xbb","\xf0","\xfd","\xfe",
      "\xb1","\xb0","\x6a","\x6b","\x6c","\x6d","\x6e","\x6f","\x70",
      "\x71","\x72","\xaa","\xba","\xe6","\xb8","\xc6","\xa4","\xb5",
      "\x7e","\x73","\x74","\x75","\x76","\x77","\x78","\x79","\x7a",
      "\xa1","\xbf","\xd0","\x5b","\xde","\xae","\xac","\xa3","\xa5",
      "\xb7","\xa9","\xa7","\xb6","\xbc","\xbd","\xbe","\xdd","\xa8",
      "\xaf","\x5d","\xb4","\xd7","\x7b","\x41","\x42","\x43","\x44",
      "\x45","\x46","\x47","\x48","\x49","\xad","\xf4","\xf6","\xf2",
      "\xf3","\xf5","\x7d","\x4a","\x4b","\x4c","\x4d","\x4e","\x4f",
      "\x50","\x51","\x52","\xb9","\xfb","\xfc","\xf9","\xfa","\xff",
      "\x5c","\xf7","\x53","\x54","\x55","\x56","\x57","\x58","\x59",
      "\x5a","\xb2","\xd4","\xd6","\xd2","\xd3","\xd5","\x30","\x31",
      "\x32","\x33","\x34","\x35","\x36","\x37","\x38","\x39","\xb3",
      "\xdb","\xdc","\xd9","\xda","\x9f"
    ]

    # The Iconv translation table. The Iconv gem is deprecated in favor of
    # String#encode, yet there is no encoding for EBCDIC. See #4525
    Iconv_EBCDIC = [
      "\x00", "\x01", "\x02", "\x03", "7", "-", ".", "/", "\x16", "\x05",
      "%", "\v", "\f", "\r", "\x0E", "\x0F", "\x10", "\x11", "\x12", "\x13",
      "<", "=", "2", "&", "\x18", "\x19", "?", "'", "\x1C", "\x1D", "\x1E",
      "\x1F", "@", "Z", "\x7F", "{", "[", "l", "P", "}", "M", "]", "\\",
      "N", "k", "`", "K", "a", "\xF0", "\xF1", "\xF2", "\xF3", "\xF4",
      "\xF5", "\xF6", "\xF7", "\xF8", "\xF9", "z", "^", "L", "~", "n", "o",
      "|", "\xC1", "\xC2", "\xC3", "\xC4", "\xC5", "\xC6", "\xC7", "\xC8",
      "\xC9", "\xD1", "\xD2", "\xD3", "\xD4", "\xD5", "\xD6", "\xD7",
      "\xD8", "\xD9", "\xE2", "\xE3", "\xE4", "\xE5", "\xE6", "\xE7",
      "\xE8", "\xE9", nil, "\xE0", nil, nil, "m", "y", "\x81", "\x82",
      "\x83", "\x84", "\x85", "\x86", "\x87", "\x88", "\x89", "\x91",
      "\x92", "\x93", "\x94", "\x95", "\x96", "\x97", "\x98", "\x99",
      "\xA2", "\xA3", "\xA4", "\xA5", "\xA6", "\xA7", "\xA8", "\xA9",
      "\xC0", "O", "\xD0", "\xA1", "\a", nil, nil, nil, nil, nil, nil,
      nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
      nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
      nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
      nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
      nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
      nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
      nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
      nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
      nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
      nil, nil, nil, nil, nil
    ]

    Iconv_ASCII  = [
      "\x00", "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\a", "\b",
      "\t", "\n", "\v", "\f", "\r", "\x0E", "\x0F", "\x10", "\x11", "\x12",
      "\x13", "\x14", "\x15", "\x16", "\x17", "\x18", "\x19", "\x1A", "\e",
      "\x1C", "\x1D", "\x1E", "\x1F", " ", "!", "\"", "#", "$", "%", "&",
      "'", "(", ")", "*", "+", ",", "-", ".", "/", "0", "1", "2", "3", "4",
      "5", "6", "7", "8", "9", ":", ";", "<", "=", ">", "?", "@", "A", "B",
      "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
      "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", nil, "\\", nil,
      nil, "_", "`", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k",
      "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y",
      "z", "{", "|", "}", "~", "\x7F", nil, nil, nil, nil, nil, nil, nil,
      nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
      nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
      nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
      nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
      nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
      nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
      nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
      nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
      nil, nil, nil, nil, nil, nil, nil, nil, nil
    ]

    # A native implementation of the ASCII to EBCDIC conversion table, since
    # EBCDIC isn't available to String#encode as of Ruby 2.1
    #
    # @param str [String] An encodable ASCII string
    # @return [String] an EBCDIC encoded string
    # @note This method will raise in the event of invalid characters
    def self.to_ebcdic(str)
      new_str = []
      str.each_byte do |x|
        if Iconv_ASCII.index(x.chr)
          new_str << Iconv_EBCDIC[Iconv_ASCII.index(x.chr)]
        else
          raise Rex::Text::IllegalSequence, ("\\x%x" % x)
        end
      end
      new_str.join
    end

    # A native implementation of the EBCDIC to ASCII conversion table, since
    # EBCDIC isn't available to String#encode as of Ruby 2.1
    #
    # @param str [String] an EBCDIC encoded string
    # @return [String] An encodable ASCII string
    # @note This method will raise in the event of invalid characters
    def self.from_ebcdic(str)
      new_str = []
      str.each_byte do |x|
        if Iconv_EBCDIC.index(x.chr)
          new_str << Iconv_ASCII[Iconv_EBCDIC.index(x.chr)]
        else
          raise Rex::Text::IllegalSequence, ("\\x%x" % x)
        end
      end
      new_str.join
    end

    #
    # The next two are the same as the above, except strictly for z/os
    # conversions
    #  strictly for IBM1047 -> ISO8859-1
    # A native implementation of the IBM1047(EBCDIC) -> ISO8859-1(ASCII)
    # conversion table, since EBCDIC isn't available to String#encode as of Ruby 2.1
    # all 256 bytes are defined
    #
    def self.to_ibm1047(str)
      return str if str.nil?
      new_str = []
      str.each_byte do |x|
        new_str << Iconv_IBM1047[x.ord]
      end
      new_str.join
    end

    #
    # The next two are the same as the above, except strictly for z/os
    # conversions
    #  strictly for ISO8859-1 -> IBM1047
    # A native implementation of the ISO8859-1(ASCII) -> IBM1047(EBCDIC)
    # conversion table, since EBCDIC isn't available to String#encode as of Ruby 2.1
    #
    def self.from_ibm1047(str)
      return str if str.nil?
      new_str = []
      str.each_byte do |x|
        new_str << Iconv_ISO8859_1[x.ord]
      end
      new_str.join
    end

  end
end
