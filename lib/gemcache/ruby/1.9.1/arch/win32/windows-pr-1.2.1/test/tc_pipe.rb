#####################################################################
# tc_pipe.rb
#
# Test case for the Windows::Pipe module.
#####################################################################
require 'windows/pipe'
require 'test/unit'

class PipeFoo
   include Windows::Pipe
end

class TC_Windows_Pipe < Test::Unit::TestCase
  
   def setup
      @foo = PipeFoo.new
   end
   
   def test_numeric_constants
      assert_equal(0x00000001, PipeFoo::NMPWAIT_NOWAIT)
      assert_equal(0xffffffff, PipeFoo::NMPWAIT_WAIT_FOREVER)
      assert_equal(0x00000000, PipeFoo::NMPWAIT_USE_DEFAULT_WAIT)
      assert_equal(0x00000000, PipeFoo::PIPE_WAIT)
      assert_equal(0x00000001, PipeFoo::PIPE_NOWAIT)
      assert_equal(0x00000001, PipeFoo::PIPE_ACCESS_INBOUND)
      assert_equal(0x00000002, PipeFoo::PIPE_ACCESS_OUTBOUND)
      assert_equal(0x00000003, PipeFoo::PIPE_ACCESS_DUPLEX)
      assert_equal(0x00000000, PipeFoo::PIPE_TYPE_BYTE)
      assert_equal(0x00000004, PipeFoo::PIPE_TYPE_MESSAGE)
      assert_equal(0x00000000, PipeFoo::PIPE_READMODE_BYTE)
      assert_equal(0x00000002, PipeFoo::PIPE_READMODE_MESSAGE)
      assert_equal(0x00000000, PipeFoo::PIPE_CLIENT_END)
      assert_equal(0x00000001, PipeFoo::PIPE_SERVER_END)
   end
   
   def test_method_constants
      assert_not_nil(PipeFoo::CallNamedPipe)
      assert_not_nil(PipeFoo::ConnectNamedPipe)
      assert_not_nil(PipeFoo::CreateNamedPipe)
      assert_not_nil(PipeFoo::CreatePipe)
      assert_not_nil(PipeFoo::DisconnectNamedPipe)
      assert_not_nil(PipeFoo::GetNamedPipeHandleState)
      assert_not_nil(PipeFoo::GetNamedPipeInfo)
      assert_not_nil(PipeFoo::PeekNamedPipe)
      assert_not_nil(PipeFoo::SetNamedPipeHandleState)
      assert_not_nil(PipeFoo::TransactNamedPipe)
      assert_not_nil(PipeFoo::WaitNamedPipe)
   end
   
   def teardown
      @foo = nil
   end
end
