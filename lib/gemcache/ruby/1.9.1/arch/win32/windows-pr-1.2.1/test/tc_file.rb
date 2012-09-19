#####################################################################
# tc_file.rb
#
# Test case for the Windows::File module.
#####################################################################
require 'windows/file'
require 'test/unit'

class FileFoo
   include Windows::File
end

class TC_Windows_File < Test::Unit::TestCase
  
   def setup
      @foo = FileFoo.new
   end
   
   def test_numeric_constants
      assert_equal(0x00000001, FileFoo::FILE_ATTRIBUTE_READONLY)  
      assert_equal(0x00000002, FileFoo::FILE_ATTRIBUTE_HIDDEN)  
      assert_equal(0x00000004, FileFoo::FILE_ATTRIBUTE_SYSTEM)
      assert_equal(0x00000010, FileFoo::FILE_ATTRIBUTE_DIRECTORY) 
      assert_equal(0x00000020, FileFoo::FILE_ATTRIBUTE_ARCHIVE)  
      assert_equal(0x00000040, FileFoo::FILE_ATTRIBUTE_ENCRYPTED)
      assert_equal(0x00000080, FileFoo::FILE_ATTRIBUTE_NORMAL)  
      assert_equal(0x00000100, FileFoo::FILE_ATTRIBUTE_TEMPORARY)  
      assert_equal(0x00000200, FileFoo::FILE_ATTRIBUTE_SPARSE_FILE) 
      assert_equal(0x00000400, FileFoo::FILE_ATTRIBUTE_REPARSE_POINT)  
      assert_equal(0x00000800, FileFoo::FILE_ATTRIBUTE_COMPRESSED)  
      assert_equal(0x00001000, FileFoo::FILE_ATTRIBUTE_OFFLINE) 
      assert_equal(0x00002000, FileFoo::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
   end
   
   def test_method_constants
      assert_not_nil(FileFoo::CopyFile)
      assert_not_nil(FileFoo::CopyFileEx)
      assert_not_nil(FileFoo::CreateFile)
      assert_not_nil(FileFoo::CreateFileW)
      assert_not_nil(FileFoo::CreateHardLink)
      assert_not_nil(FileFoo::DecryptFile)
      assert_not_nil(FileFoo::DeleteFile)
      assert_not_nil(FileFoo::EncryptFile)
      assert_not_nil(FileFoo::GetBinaryType)
      assert_not_nil(FileFoo::GetFileAttributes)
      assert_not_nil(FileFoo::GetFileAttributesEx)
      assert_not_nil(FileFoo::GetFileSize)
      assert_not_nil(FileFoo::GetFileSizeEx)
      assert_not_nil(FileFoo::GetFileType)
      assert_not_nil(FileFoo::GetFullPathName)
      assert_not_nil(FileFoo::GetFullPathNameW)
      assert_not_nil(FileFoo::GetLongPathName)
      assert_not_nil(FileFoo::GetShortPathName)
      assert_not_nil(FileFoo::LockFile)
      assert_not_nil(FileFoo::LockFileEx)
      assert_not_nil(FileFoo::ReadFile)
      assert_not_nil(FileFoo::ReadFileEx)
      assert_not_nil(FileFoo::SetFileAttributes)
      assert_not_nil(FileFoo::UnlockFile)
      assert_not_nil(FileFoo::UnlockFileEx)
      assert_not_nil(FileFoo::WriteFile)
      assert_not_nil(FileFoo::WriteFileEx)
   end
   
   def teardown
      @foo = nil
   end
end