#####################################################################
# tc_msvcrt_string.rb
#
# Test case for the Windows::MSVCRT::String module.
#####################################################################
require 'windows/msvcrt/string'
require 'test/unit'

class TC_Windows_MSVCRT_String < Test::Unit::TestCase
  include Windows::MSVCRT::String

  def setup
    @buf = 0.chr * 260
    @str = 'hello'
  end

  def test_method_constants
    assert_not_nil(Strcmp)
    assert_not_nil(Strcpy)
    assert_not_nil(Strcspn)
    assert_not_nil(Strlen)
    assert_not_nil(Strncpy)
    assert_not_nil(Strrchr)
    assert_not_nil(Strrev)
    assert_not_nil(Strtok)
  end

  def test_strchr
    assert(self.respond_to?(:strchr, true))
    assert_equal('llo', strchr('hello', 108))
    assert_equal(nil, strchr('hello', 120))
  end

  def test_strchr_with_zero
    assert_nil(strchr(0, 'l'[0]))
    assert_nil(strchr('hello', 0))
  end

  def test_strchr_expected_errors
    assert_raise(ArgumentError){ strchr }
    assert_raise(ArgumentError){ strchr('hello') }
  end

  def test_strcmp
    assert(self.respond_to?(:strcmp, true))
    assert_equal(-1, strcmp('alpha', 'beta'))
    assert_equal(1, strcmp('beta', 'alpha'))
    assert_equal(0, strcmp('alpha', 'alpha'))
  end

  def test_strcmp_expected_errors
    assert_raise(ArgumentError){ strcmp }
    assert_raise(ArgumentError){ strcmp('alpha') }
  end

  def test_strcpy
    assert(self.respond_to?(:strcpy, true))
    assert_kind_of(Fixnum, strcpy(@buf, ['hello'].pack('p*').unpack('L')[0]))
    assert_equal('hello', @buf.strip)
  end

  def test_strcspn
    assert(self.respond_to?(:strcspn, true))
    assert_equal(3, strcspn('abcxyz123', '&^(x'))
    assert_equal(9, strcspn('abcxyz123', '&^(('))
  end

  def test_strcspn_expected_errors
    assert_raise(ArgumentError){ strcspn }
    assert_raise(ArgumentError){ strcspn('alpha') }
  end

  def test_strlen
    assert(self.respond_to?(:strlen, true))
    assert_equal(5, strlen('hello'))
    assert_equal(0, strlen(''))
  end

  def test_strlen_expected_errors
    assert_raise(ArgumentError){ strlen }
    assert_raise(ArgumentError){ strlen('a', 'b') }
  end

  def test_strncpy
    assert(self.respond_to?(:strncpy, true))
    assert_equal('alp', strncpy(@buf, 'alpha', 3))
    assert_equal('alp', @buf.strip)
  end

  def teardown
    @buf = nil
    @str = nil
  end
end
