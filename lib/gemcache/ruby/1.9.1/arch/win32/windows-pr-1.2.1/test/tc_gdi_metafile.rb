#####################################################################
# tc_gdi_metafile.rb
#
# Test case for the Windows::GDI::MetaFile module.
#####################################################################
require 'windows/gdi/metafile'
require 'test/unit'

class TC_Windows_GDI_MetaFile < Test::Unit::TestCase
   include Windows::GDI::MetaFile

   def test_methods
      assert_respond_to(self, :CloseEnhMetaFile)
      assert_respond_to(self, :CloseMetaFile)
      assert_respond_to(self, :CopyEnhMetaFile)
      assert_respond_to(self, :CopyMetaFile)
      assert_respond_to(self, :CreateEnhMetaFile)
      assert_respond_to(self, :CreateMetaFile)
      assert_respond_to(self, :DeleteEnhMetaFile)
      assert_respond_to(self, :DeleteMetaFile)
      assert_respond_to(self, :EnumEnhMetaFile)
   end
end
