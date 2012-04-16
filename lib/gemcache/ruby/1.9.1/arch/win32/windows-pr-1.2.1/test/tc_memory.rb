#####################################################################
# tc_memory.rb
#
# Test case for the Windows::Memory module.
#####################################################################
require 'windows/memory'
require 'test/unit'

class MemoryFoo
   include Windows::Memory
end

class TC_Windows_Memory < Test::Unit::TestCase
   def setup
      @foo  = MemoryFoo.new
      @path = "C:\\"
   end

   def test_numeric_constants
      assert_not_nil(MemoryFoo::GHND)
      assert_not_nil(MemoryFoo::GMEM_FIXED)
      assert_not_nil(MemoryFoo::GMEM_MOVABLE)
      assert_not_nil(MemoryFoo::GMEM_ZEROINIT)
      assert_not_nil(MemoryFoo::GPTR)
   end

   def test_method_constants
      assert_not_nil(MemoryFoo::GlobalAlloc)
      assert_not_nil(MemoryFoo::GlobalFlags)
      assert_not_nil(MemoryFoo::GlobalFree)
      assert_not_nil(MemoryFoo::GlobalHandle)
      assert_not_nil(MemoryFoo::GlobalLock)
      assert_not_nil(MemoryFoo::GlobalMemoryStatus)
      assert_not_nil(MemoryFoo::GlobalMemoryStatusEx)
      assert_not_nil(MemoryFoo::GlobalReAlloc)
      assert_not_nil(MemoryFoo::GlobalSize)
      assert_not_nil(MemoryFoo::GlobalUnlock)
   end

   def teardown
      @foo  = nil
      @path = nil
   end
end
