#####################################################################
# tc_msvcrt_buffer.rb
#
# Test case for the Windows::MSVCRT::Buffer module.
#####################################################################
require 'rubygems'
require 'windows/msvcrt/buffer'
require 'test/unit'

class TC_Windows_MSVCRT_Buffer < Test::Unit::TestCase
  include Windows::MSVCRT::Buffer

  def test_method_constants
    assert_not_nil(Memcpy)
    assert_not_nil(MemcpyPLL)
    assert_not_nil(MemcpyLPL)
    assert_not_nil(MemcpyLLL)
    assert_not_nil(MemcpyPPL)
    assert_not_nil(Memccpy)
    assert_not_nil(Memchr)
    assert_not_nil(Memcmp)
    assert_not_nil(Memicmp)
    assert_not_nil(Memmove)
    assert_not_nil(Memset)
    assert_not_nil(Swab)
  end

  def test_memcpy
    assert(private_methods.include?("memcpy"))
  end
 
  def test_memccpy
    assert(private_methods.include?("memccpy"))
  end
 
  def test_memchr
    assert(private_methods.include?("memchr"))
  end
 
  def test_memcmp
    assert(private_methods.include?("memcmp"))
  end
 
  def test_memicmp
    assert(private_methods.include?("memicmp"))
  end
 
  def test_memmove
    assert(private_methods.include?("memmove"))
  end
 
  def test_memset
    assert(private_methods.include?("memset"))
  end
 
  def test_swab
    assert(private_methods.include?("swab"))
  end
end
