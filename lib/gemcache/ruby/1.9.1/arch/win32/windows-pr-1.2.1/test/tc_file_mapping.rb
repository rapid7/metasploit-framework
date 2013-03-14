#####################################################################
# tc_file_mapping.rb
#
# Test case for the Windows::FileMapping module.
#####################################################################
require 'windows/file_mapping'
require 'test/unit'

class FileMappingFoo
   include Windows::FileMapping
end

class TC_Windows_FileMapping < Test::Unit::TestCase
  
   def setup
      @foo = FileMappingFoo.new
   end
   
   def test_numeric_constants
      assert_equal(0x00000001, FileMappingFoo::FILE_MAP_COPY)
      assert_equal(0x00000002, FileMappingFoo::FILE_MAP_WRITE)
      assert_equal(0x00000004, FileMappingFoo::FILE_MAP_READ)
      assert_equal(983071, FileMappingFoo::FILE_MAP_ALL_ACCESS)
   end
   
   def test_method_constants
      assert_not_nil(FileMappingFoo::CreateFileMapping)
      assert_not_nil(FileMappingFoo::FlushViewOfFile)
      assert_not_nil(FileMappingFoo::MapViewOfFile)
      assert_not_nil(FileMappingFoo::MapViewOfFileEx)
      assert_not_nil(FileMappingFoo::OpenFileMapping)
      assert_not_nil(FileMappingFoo::UnmapViewOfFile)
   end
   
   def teardown
      @foo = nil
   end
end
