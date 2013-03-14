#####################################################################
# test_ntfs_winternl.rb
#
# Test case for the Windows::NTFS::Winternl module.
#####################################################################
require "windows/ntfs/winternl"
require "test/unit"

class TC_Windows_NTFS_Winternl < Test::Unit::TestCase
  include Windows::NTFS::Winternl

  def setup
    @name = "winternl_test.txt"
    @handle = File.open(@name, 'w')
  end
   
  def test_numeric_constants
    assert_equal(8, FileAccessInformation)
  end
  
  def test_methods_defined
    assert(self.respond_to?(:NtQueryInformationFile, true))
  end

  def test_get_final_path_name_by_handle
    assert(self.respond_to?(:GetFinalPathNameByHandle, true))
  end

  def test_get_final_path_name_by_handle_returns_expected_result
    buf = 0.chr * 260
    res = nil
    assert_nothing_raised{
      res = GetFinalPathNameByHandle(@handle, buf, buf.size, 2)
    }
    assert_kind_of(Fixnum, res)
    assert_equal(@name, File.basename(buf))
  end

  def teardown
    @handle.close if @handle
    File.delete(@name) if File.exists?(@name)
    @name = nil
  end
end
