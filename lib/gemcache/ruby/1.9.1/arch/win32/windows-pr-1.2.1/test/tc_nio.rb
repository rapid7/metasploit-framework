#####################################################################
# tc_nio.rb
#
# Test case for the Windows::NIO module.
#####################################################################
require 'windows/nio'
require 'test/unit'

class NIOFoo
   include Windows::NIO
end

class TC_Windows_NIO < Test::Unit::TestCase
   def setup
      @foo = NIOFoo.new
   end

   def test_numeric_constants
      assert_equal(0, NIOFoo::OF_READ)
      assert_equal(1, NIOFoo::OF_WRITE)
      assert_equal(2, NIOFoo::OF_READWRITE)
   end
   
   def test_method_constants
      assert_not_nil(NIOFoo::CancelIo)
      assert_not_nil(NIOFoo::ReadFileScatter)
   end
   
   def teardown
      @foo = nil
   end
end
