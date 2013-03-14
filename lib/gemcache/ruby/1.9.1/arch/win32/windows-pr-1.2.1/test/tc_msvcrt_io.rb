#####################################################################
# tc_msvcrt_io.rb
#
# Test case for the Windows::MSVCRT::IO module.
#####################################################################
require 'windows/msvcrt/io'
require 'test/unit'

class MIOFoo
   include Windows::MSVCRT::IO
end

class TC_Windows_MSVCRT_IO < Test::Unit::TestCase
   def setup
      @foo = MIOFoo.new
   end

   def test_numeric_constants
      assert_not_nil(MIOFoo::S_IFMT)
   end
   
   def test_method_constants
      assert_not_nil(MIOFoo::Clearerr)
      assert_not_nil(MIOFoo::Close)
      assert_not_nil(MIOFoo::Fclose)
      assert_not_nil(MIOFoo::Fileno)
   end
   
   def test_clearerr
      assert_respond_to(@foo, :clearerr)
   end

   def test_close
      assert_respond_to(@foo, :close)
   end

   def test_fclose
      assert_respond_to(@foo, :fclose)
   end

   def test_fileno
      assert_respond_to(@foo, :fileno)
   end
   
   def teardown
      @foo  = nil
   end
end
