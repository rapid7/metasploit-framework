#####################################################################
# tc_error.rb
#
# Test case for the Windows::Error module.
#####################################################################
require "windows/error"
require "test/unit"

class TC_Windows_Error < Test::Unit::TestCase
  include Windows::Error
 
  def test_numeric_constants
    assert_equal(0x00000100, FORMAT_MESSAGE_ALLOCATE_BUFFER)
    assert_equal(0x00000200, FORMAT_MESSAGE_IGNORE_INSERTS)
    assert_equal(0x00000400, FORMAT_MESSAGE_FROM_STRING)
    assert_equal(0x00000800, FORMAT_MESSAGE_FROM_HMODULE)
    assert_equal(0x00001000, FORMAT_MESSAGE_FROM_SYSTEM)
    assert_equal(0x00002000, FORMAT_MESSAGE_ARGUMENT_ARRAY) 
    assert_equal(0x000000FF, FORMAT_MESSAGE_MAX_WIDTH_MASK) 
    assert_equal(0x0001, SEM_FAILCRITICALERRORS)
    assert_equal(0x0004, SEM_NOALIGNMENTFAULTEXCEPT)
    assert_equal(0x0002, SEM_NOGPFAULTERRORBOX)
    assert_equal(0x8000, SEM_NOOPENFILEERRORBOX)
  end
   
  def test_method_constants
    assert_not_nil(GetLastError)
    assert_not_nil(SetLastError)
    assert_not_nil(SetLastErrorEx)
    assert_not_nil(SetErrorMode)
    assert_not_nil(FormatMessage)
  end
   
  def test_get_last_error
    assert_nothing_raised{ get_last_error }
    assert_kind_of(String, get_last_error)
  end
end
