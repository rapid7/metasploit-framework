#####################################################################
# tc_clipboard.rb
#
# Test case for the Windows::Clipboard module.
#####################################################################
require 'windows/clipboard'
require 'test/unit'

class TC_Windows_Clipboard < Test::Unit::TestCase
   include Windows::Clipboard

   def test_methods
      assert_respond_to(self, :OpenClipboard)
      assert_respond_to(self, :CloseClipboard)
      assert_respond_to(self, :GetClipboardData)
      assert_respond_to(self, :EmptyClipboard)
      assert_respond_to(self, :SetClipboardData)
      assert_respond_to(self, :CountClipboardFormats)
      assert_respond_to(self, :IsClipboardFormatAvailable)
      assert_respond_to(self, :GetClipboardFormatName)
      assert_respond_to(self, :EnumClipboardFormats)
      assert_respond_to(self, :RegisterClipboardFormat)
   end

   def test_constants
      assert_equal(1, CF_TEXT)
      assert_equal(2, CF_BITMAP)
      assert_equal(3, CF_METAFILEPICT)
      assert_equal(4, CF_SYLK)
      assert_equal(5, CF_DIF)
      assert_equal(6, CF_TIFF)
      assert_equal(7, CF_OEMTEXT)
      assert_equal(8, CF_DIB)
      assert_equal(9, CF_PALETTE)
      assert_equal(10, CF_PENDATA)
      assert_equal(11, CF_RIFF)
      assert_equal(12, CF_WAVE)
      assert_equal(13, CF_UNICODETEXT)
      assert_equal(14, CF_ENHMETAFILE)
   end
end
