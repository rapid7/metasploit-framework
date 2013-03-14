#####################################################################
# tc_library.rb
#
# Test case for the Windows::Library module.
#####################################################################
require 'windows/library'
require 'test/unit'

class LibraryFoo
   include Windows::Library
end

class TC_Windows_Library < Test::Unit::TestCase
   def setup
      @LibraryFoo  = LibraryFoo.new
   end

   def test_numeric_constants
      assert_equal(0, LibraryFoo::DLL_PROCESS_DETACH)
      assert_equal(1, LibraryFoo::DLL_PROCESS_ATTACH)
      assert_equal(2, LibraryFoo::DLL_THREAD_ATTACH)
      assert_equal(3, LibraryFoo::DLL_THREAD_DETACH)
   end

   def test_method_constants
      assert_not_nil(LibraryFoo::FreeLibrary)
      assert_not_nil(LibraryFoo::GetModuleFileName)
      assert_not_nil(LibraryFoo::GetModuleHandle)
      assert_not_nil(LibraryFoo::LoadLibrary)
      assert_not_nil(LibraryFoo::LoadLibraryEx)
      assert_not_nil(LibraryFoo::LoadModule)
   end

   def teardown
      @LibraryFoo  = nil
   end
end
