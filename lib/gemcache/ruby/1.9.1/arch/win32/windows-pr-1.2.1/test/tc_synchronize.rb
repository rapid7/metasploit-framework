##################################################################
# tc_synchronize.rb
#
# Test case for the windows/synchronize package.
##################################################################
require "windows/synchronize"
require "test/unit"

class TC_Windows_Synchronize < Test::Unit::TestCase
  include Windows::Synchronize

  def setup
    @handle = (0.chr * 16).unpack('LLLL')
  end
   
  def test_numeric_constants
    assert_not_nil(INFINITE)
    assert_not_nil(WAIT_OBJECT_0)
    assert_not_nil(WAIT_TIMEOUT)
    assert_not_nil(WAIT_ABANDONED)
    assert_not_nil(WAIT_FAILED)
    assert_not_nil(QS_ALLEVENTS)
    assert_not_nil(QS_ALLINPUT)
    assert_not_nil(QS_ALLPOSTMESSAGE)
    assert_not_nil(QS_HOTKEY)
    assert_not_nil(QS_INPUT)
    assert_not_nil(QS_KEY)
    assert_not_nil(QS_MOUSE)
    assert_not_nil(QS_MOUSEBUTTON)
    assert_not_nil(QS_MOUSEMOVE)
    assert_not_nil(QS_PAINT)
    assert_not_nil(QS_POSTMESSAGE)
    assert_not_nil(QS_RAWINPUT)
    assert_not_nil(QS_SENDMESSAGE)
    assert_not_nil(QS_TIMER)
    assert_not_nil(MWMO_ALERTABLE)
    assert_not_nil(MWMO_INPUTAVAILABLE)
    assert_not_nil(MWMO_WAITALL)
    assert_not_nil(EVENT_ALL_ACCESS)
    assert_not_nil(EVENT_MODIFY_STATE)
    assert_not_nil(MUTEX_ALL_ACCESS)
    assert_not_nil(MUTEX_MODIFY_STATE)
    assert_not_nil(SEMAPHORE_ALL_ACCESS)
    assert_not_nil(SEMAPHORE_MODIFY_STATE)
  end
   
  def test_method_constants
    assert_not_nil(CreateEvent)
    assert_not_nil(CreateMutex)
    assert_not_nil(CreateSemaphore)
    assert_not_nil(DeleteCriticalSection)
    assert_not_nil(EnterCriticalSection)
    assert_not_nil(GetOverlappedResult)
    assert_not_nil(InitializeCriticalSection)
    assert_not_nil(InitializeCriticalSectionAndSpinCount)
    assert_not_nil(LeaveCriticalSection)
    assert_not_nil(MsgWaitForMultipleObjects)
    assert_not_nil(MsgWaitForMultipleObjectsEx)
    assert_not_nil(OpenEvent)
    assert_not_nil(OpenMutex)
    assert_not_nil(OpenSemaphore)
    assert_not_nil(ReleaseMutex)
    assert_not_nil(ReleaseSemaphore)
    assert_not_nil(ResetEvent)
    assert_not_nil(SetEvent)
    assert_not_nil(WaitForMultipleObjects)
    assert_not_nil(WaitForMultipleObjectsEx)
    assert_not_nil(WaitForSingleObject)
    assert_not_nil(WaitForSingleObjectEx)
  end
   
  def teardown
    @handle = nil
  end
end
