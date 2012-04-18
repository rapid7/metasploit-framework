#####################################################################
# tc_gdi_bitmap.rb
#
# Test case for the Windows::GDI::Bitmap module.
#####################################################################
require 'windows/gdi/bitmap'
require 'test/unit'

class TC_Windows_GDI_Bitmap < Test::Unit::TestCase
   include Windows::GDI::Bitmap

   def test_methods
      assert_respond_to(self, :AlphaBlend)
      assert_respond_to(self, :BitBlt)
      assert_respond_to(self, :CreateBitmap)
      assert_respond_to(self, :CreateBitmapIndirect)
      assert_respond_to(self, :CreateCompatibleBitmap)
      assert_respond_to(self, :CreateDIBitmap)
   end

   def test_constants
      assert_equal(0, DIB_RGB_COLORS)
      assert_equal(1, DIB_PAL_COLORS)
   end
end
