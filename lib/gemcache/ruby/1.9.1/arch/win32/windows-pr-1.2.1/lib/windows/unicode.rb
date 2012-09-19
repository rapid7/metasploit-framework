# encoding: ascii-8bit
require 'windows/api'
require 'windows/msvcrt/string'
require 'windows/error'

module Windows
  module Unicode
    include Windows::MSVCRT::String
    include Windows::Error

    private
    
    API.auto_namespace = 'Windows::Unicode'
    API.auto_constant  = true
    API.auto_method    = true
    API.auto_unicode   = false

    CP_ACP         = 0
    CP_OEMCP       = 1
    CP_MACCP       = 2
    CP_THREAD_ACP  = 3
    CP_SYMBOL      = 42
    CP_UTF7        = 65000
    CP_UTF8        = 65001

    MB_PRECOMPOSED       = 0x00000001
    MB_COMPOSITE         = 0x00000002
    MB_USEGLYPHCHARS     = 0x00000004
    MB_ERR_INVALID_CHARS = 0x00000008

    WC_COMPOSITECHECK    = 0x00000200 
    WC_DISCARDNS         = 0x00000010
    WC_SEPCHARS          = 0x00000020
    WC_DEFAULTCHAR       = 0x00000040
    WC_NO_BEST_FIT_CHARS = 0x00000400

    ANSI_CHARSET        = 0
    DEFAULT_CHARSET     = 1
    SYMBOL_CHARSET      = 2
    SHIFTJIS_CHARSET    = 128
    HANGEUL_CHARSET     = 129
    HANGUL_CHARSET      = 129
    GB2312_CHARSET      = 134
    CHINESEBIG5_CHARSET = 136
    OEM_CHARSET         = 255
    JOHAB_CHARSET       = 130
    HEBREW_CHARSET      = 177
    ARABIC_CHARSET      = 178
    GREEK_CHARSET       = 161
    TURKISH_CHARSET     = 162
    VIETNAMESE_CHARSET  = 163
    THAI_CHARSET        = 222
    EASTEUROPE_CHARSET  = 238
    RUSSIAN_CHARSET     = 204

    IS_TEXT_UNICODE_ASCII16            = 0x0001
    IS_TEXT_UNICODE_REVERSE_ASCII16    = 0x0010
    IS_TEXT_UNICODE_STATISTICS         = 0x0002
    IS_TEXT_UNICODE_REVERSE_STATISTICS = 0x0020
    IS_TEXT_UNICODE_CONTROLS           = 0x0004
    IS_TEXT_UNICODE_REVERSE_CONTROLS   = 0x0040
    IS_TEXT_UNICODE_SIGNATURE          = 0x0008
    IS_TEXT_UNICODE_REVERSE_SIGNATURE  = 0x0080
    IS_TEXT_UNICODE_ILLEGAL_CHARS      = 0x0100
    IS_TEXT_UNICODE_ODD_LENGTH         = 0x0200
    IS_TEXT_UNICODE_DBCS_LEADBYTE      = 0x0400
    IS_TEXT_UNICODE_NULL_BYTES         = 0x1000
    IS_TEXT_UNICODE_UNICODE_MASK       = 0x000F
    IS_TEXT_UNICODE_REVERSE_MASK       = 0x00F0
    IS_TEXT_UNICODE_NOT_UNICODE_MASK   = 0x0F00
    IS_TEXT_UNICODE_NOT_ASCII_MASK     = 0xF000

    TCI_SRCCHARSET  = 1
    TCI_SRCCODEPAGE = 2
    TCI_SRCFONTSIG  = 3
    TCI_SRCLOCALE   = 0x100

    API.new('GetTextCharset', 'L', 'I', 'gdi32')
    API.new('GetTextCharsetInfo', 'LPL', 'I', 'gdi32')
    API.new('IsDBCSLeadByte', 'P', 'B')
    API.new('IsDBCSLeadByteEx', 'IP', 'B')
    API.new('IsTextUnicode', 'SIP', 'B', 'advapi32')
    API.new('MultiByteToWideChar', 'ILSIPI', 'I')
    API.new('TranslateCharsetInfo', 'PPL', 'B', 'gdi32')
    API.new('WideCharToMultiByte', 'ILSIPIPP', 'I')

    # Convenient wrapper methods
     
    # Maps a wide character string to a new character string using the
    # specified +encoding+.  If no encoding is specified, then CP_UTF8 
    # is used if $KCODE (or the encoding name in Ruby 1.9.x) is set to UTF8.
    # Otherwise, CP_ACP is used.
    # 
    # If the function fails it simply returns the string as-is.
    # 
    def multi_to_wide(string, encoding=nil)
      return nil unless string
      raise TypeError unless string.is_a?(String)
      return string if IsTextUnicode(string, string.size, nil)
       
      unless encoding
        if RUBY_VERSION.to_f >= 1.9
          encoding = (string.encoding.name == 'UTF-8') ? CP_UTF8 : CP_ACP
        else
          encoding = ($KCODE == 'UTF8') ? CP_UTF8 : CP_ACP
        end
      end
       
      int = MultiByteToWideChar(encoding, 0, string, -1, nil, 0)
       
      # Trailing nulls are retained
      if int > 0
        buf = ' ' * int * 2
        MultiByteToWideChar(encoding, 0, string, -1, buf, int)
        buf
      else
        raise ArgumentError, get_last_error
      end         
    end
    
    # Maps a wide character string to a new character string using the
    # specified +encoding+. If no encoding is specified, then CP_UTF8 
    # is used if $KCODE (or the encoding name in Ruby 1.9.x) is set to UTF8.
    # Otherwise, CP_ACP is used.
    # 
    # If the function fails it simply returns the string as-is.
    # 
    def wide_to_multi(wstring, encoding=nil)
      return nil unless wstring
      raise TypeError unless wstring.is_a?(String)
       
      unless encoding
        if RUBY_VERSION.to_f >= 1.9
          encoding = (wstring.encoding.name == 'UTF-8') ? CP_UTF8 : CP_ACP
        else
          encoding = ($KCODE == 'UTF8') ? CP_UTF8 : CP_ACP
        end
      end

      # Add a trailing double null if necessary
      wstring << "\000\000" if wstring[-1].chr != "\000"

      int = WideCharToMultiByte(encoding, 0, wstring, -1, 0, 0, nil, nil)
       
      # Trailing nulls are stripped
      if int > 0
        buf = ' ' * int
        WideCharToMultiByte(encoding, 0, wstring, -1, buf, strlen(buf), nil, nil)
        buf[ /^[^\0]*/ ]
      else
        raise ArgumentError, get_last_error
      end         
    end
  end
end
