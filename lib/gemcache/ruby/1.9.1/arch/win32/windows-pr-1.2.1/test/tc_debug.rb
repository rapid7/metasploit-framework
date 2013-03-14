#####################################################################
# tc_debug.rb
#
# Test case for the Windows::Debug module.
#####################################################################
require "windows/debug"
require "test/unit"

class DebugFoo
   include Windows::Debug
end

class TC_Windows_Debug < Test::Unit::TestCase
   def setup
      @foo = DebugFoo.new
      @ver = `ver`.chomp
   end
   
   def test_method_constants
      assert_not_nil(DebugFoo::ContinueDebugEvent)
      assert_not_nil(DebugFoo::DebugActiveProcess)
      assert_not_nil(DebugFoo::DebugBreak)
      assert_not_nil(DebugFoo::FatalExit)
      assert_not_nil(DebugFoo::FlushInstructionCache)
      assert_not_nil(DebugFoo::GetThreadContext)
      assert_not_nil(DebugFoo::GetThreadSelectorEntry)
      assert_not_nil(DebugFoo::IsDebuggerPresent)
      assert_not_nil(DebugFoo::OutputDebugString)
      assert_not_nil(DebugFoo::ReadProcessMemory)
      assert_not_nil(DebugFoo::SetThreadContext)
      assert_not_nil(DebugFoo::WaitForDebugEvent)
      assert_not_nil(DebugFoo::WriteProcessMemory)
   end

   def test_method_constants_xp_or_later
      if @ver =~ /XP/
         assert_not_nil(DebugFoo::CheckRemoteDebuggerPresent)
         assert_not_nil(DebugFoo::DebugActiveProcessStop)
         assert_not_nil(DebugFoo::DebugBreakProcess)
         assert_not_nil(DebugFoo::DebugSetProcessKillOnExit)
      end
   end

   def teardown
      @foo = nil
      @ver = nil
   end
end
