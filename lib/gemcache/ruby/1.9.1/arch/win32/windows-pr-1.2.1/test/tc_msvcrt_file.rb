#####################################################################
# tc_msvcrt_file.rb
#
# Test case for the Windows::MSVCRT::File module.
#####################################################################
require 'windows/msvcrt/file'
require 'test/unit'

class MFileFoo
   include Windows::MSVCRT::File
end

class TC_Windows_MSVCRT_File < Test::Unit::TestCase
   def setup
      @foo = MFileFoo.new
   end

   def test_numeric_constants
      assert_not_nil(MFileFoo::S_IFMT)
      assert_not_nil(MFileFoo::S_IFDIR)
      assert_not_nil(MFileFoo::S_IFCHR)
      assert_not_nil(MFileFoo::S_IFIFO)
      assert_not_nil(MFileFoo::S_IFREG)
      assert_not_nil(MFileFoo::S_IREAD)
      assert_not_nil(MFileFoo::S_IWRITE)
      assert_not_nil(MFileFoo::S_IEXEC)
   end
   
   def test_method_constants
      assert_not_nil(MFileFoo::Chmod)
      assert_not_nil(MFileFoo::Chsize)
      assert_not_nil(MFileFoo::Mktemp)
      assert_not_nil(MFileFoo::Stat)
      assert_not_nil(MFileFoo::Stat64)
      assert_not_nil(MFileFoo::Wchmod)
      assert_not_nil(MFileFoo::Wmktemp)
      assert_not_nil(MFileFoo::Wstat)
      assert_not_nil(MFileFoo::Wstat64)
   end
   
   def test_chmod
      assert_respond_to(@foo, :chmod)
   end

   def test_chsize
      assert_respond_to(@foo, :chsize)
   end

   def test_mktemp
      assert_respond_to(@foo, :mktemp)
   end

   def test_stat
      assert_respond_to(@foo, :stat)
   end

   def test_stat64
      assert_respond_to(@foo, :stat64)
   end

   def test_wchmod
      assert_respond_to(@foo, :wchmod)
   end

   def test_wmktemp
      assert_respond_to(@foo, :wmktemp)
   end

   def test_wstat
      assert_respond_to(@foo, :wstat)
   end

   def test_wstat64
      assert_respond_to(@foo, :wstat64)
   end
   
   def teardown
      @foo  = nil
   end
end
