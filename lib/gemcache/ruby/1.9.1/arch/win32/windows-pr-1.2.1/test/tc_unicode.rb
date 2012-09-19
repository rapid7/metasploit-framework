# encoding: ascii-8bit
#####################################################################
# tc_unicode.rb
#
# Test case for the Windows::Unicode module.
#####################################################################
require "windows/unicode"
require "test/unit"

class TC_Windows_Unicode < Test::Unit::TestCase
  include Windows::Unicode

  def test_numeric_constants
    assert_equal(0, CP_ACP)
    assert_equal(1, CP_OEMCP)
    assert_equal(2, CP_MACCP)
    assert_equal(3, CP_THREAD_ACP)
    assert_equal(42, CP_SYMBOL)
    assert_equal(65000, CP_UTF7)
    assert_equal(65001, CP_UTF8)

    assert_equal(0x00000001, MB_PRECOMPOSED)
    assert_equal(0x00000002, MB_COMPOSITE)
    assert_equal(0x00000004, MB_USEGLYPHCHARS)
    assert_equal(0x00000008, MB_ERR_INVALID_CHARS)

    assert_equal(0x00000200, WC_COMPOSITECHECK)
    assert_equal(0x00000010, WC_DISCARDNS)
    assert_equal(0x00000020, WC_SEPCHARS)
    assert_equal(0x00000040, WC_DEFAULTCHAR)
    assert_equal(0x00000400, WC_NO_BEST_FIT_CHARS)
  end

  def test_method_constants
    assert_respond_to(self, :GetTextCharset)
    assert_respond_to(self, :GetTextCharsetInfo)
    assert_respond_to(self, :IsDBCSLeadByte)
    assert_respond_to(self, :IsDBCSLeadByteEx)
    assert_respond_to(self, :IsTextUnicode)
    assert_respond_to(self, :MultiByteToWideChar)
    assert_respond_to(self, :TranslateCharsetInfo)
    assert_respond_to(self, :WideCharToMultiByte)
  end

  def test_multi_to_wide
    assert(self.respond_to?(:multi_to_wide, true))
    assert_equal("\000\000", multi_to_wide(''))
    assert_equal("h\000e\000l\000l\000o\000\000\000", multi_to_wide('hello'))
    assert_equal(
      "\316\000\" \316\000\273\000\316\000\273\000\316\000\254\000\317\000\222\001\000\000",
      multi_to_wide("Ελλάσ")
    )
  end
   
  def test_multi_to_wide_with_encoding
    assert_equal("h\000e\000l\000l\000o\000\000\000", multi_to_wide('hello', CP_UTF8))
    assert_equal("\225\003\273\003\273\003\254\003\303\003\000\000", multi_to_wide("Ελλάσ", CP_UTF8))
  end
   
  def test_multi_to_wide_expected_errors
    assert_raise(TypeError){ multi_to_wide(1) }
    assert_raise(TypeError){ multi_to_wide([]) }
  end
   
  def test_wide_to_multi
    assert(self.respond_to?(:wide_to_multi, true))
    assert_equal('', wide_to_multi("\000\000"))
    assert_equal('hello', wide_to_multi("h\000e\000l\000l\000o\000\000\000"))
    assert_equal("Ελλάσ",
      wide_to_multi("\316\000\" \316\000\273\000\316\000\273\000\316\000\254\000\317\000\222\001\000\000")
    )
  end
   
  def test_wide_to_multi_with_encoding
    assert_equal('hello', wide_to_multi("h\000e\000l\000l\000o\000\000\000"), CP_UTF8)
    assert_equal("Ελλάσ", wide_to_multi("\225\003\273\003\273\003\254\003\303\003\000\000", CP_UTF8))
  end
   
  def test_wide_to_multi_expected_errors
    assert_raise(TypeError){ wide_to_multi(1) }
    assert_raise(TypeError){ wide_to_multi([]) }      
  end
end
