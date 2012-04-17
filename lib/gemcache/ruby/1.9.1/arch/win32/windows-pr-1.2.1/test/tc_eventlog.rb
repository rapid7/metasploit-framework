#####################################################################
# tc_eventlog.rb
#
# Test case for the Windows::EventLog module.
#####################################################################
require 'windows/eventlog'
require 'test/unit'

class EventLogFoo
   include Windows::EventLog
end

class TC_Windows_EventLog < Test::Unit::TestCase
   def setup
      @foo = EventLogFoo.new
   end
   
   def test_numeric_constants
      assert_equal(1, EventLogFoo::EVENTLOG_SEQUENTIAL_READ)
      assert_equal(2, EventLogFoo::EVENTLOG_SEEK_READ)
      assert_equal(4, EventLogFoo::EVENTLOG_FORWARDS_READ)
      assert_equal(8, EventLogFoo::EVENTLOG_BACKWARDS_READ)
      assert_equal(0, EventLogFoo::EVENTLOG_SUCCESS)
      assert_equal(1, EventLogFoo::EVENTLOG_ERROR_TYPE)
      assert_equal(2, EventLogFoo::EVENTLOG_WARNING_TYPE)
      assert_equal(4, EventLogFoo::EVENTLOG_INFORMATION_TYPE)
      assert_equal(8, EventLogFoo::EVENTLOG_AUDIT_SUCCESS)
      assert_equal(16, EventLogFoo::EVENTLOG_AUDIT_FAILURE)
      assert_equal(0, EventLogFoo::EVENTLOG_FULL_INFO)
   end
   
   def test_method_constants
      assert_not_nil(EventLogFoo::BackupEventLog)
      assert_not_nil(EventLogFoo::BackupEventLogW)
      assert_not_nil(EventLogFoo::ClearEventLog)
      assert_not_nil(EventLogFoo::ClearEventLogW)
      assert_not_nil(EventLogFoo::CloseEventLog)
      assert_not_nil(EventLogFoo::DeregisterEventSource)
      assert_not_nil(EventLogFoo::GetEventLogInformation)
      assert_not_nil(EventLogFoo::GetNumberOfEventLogRecords)
      assert_not_nil(EventLogFoo::GetOldestEventLogRecord)
      assert_not_nil(EventLogFoo::NotifyChangeEventLog)
      assert_not_nil(EventLogFoo::OpenBackupEventLog)
      assert_not_nil(EventLogFoo::OpenBackupEventLogW)
      assert_not_nil(EventLogFoo::OpenEventLog)
      assert_not_nil(EventLogFoo::OpenEventLogW)
      assert_not_nil(EventLogFoo::ReadEventLog)
      assert_not_nil(EventLogFoo::ReadEventLogW)
      assert_not_nil(EventLogFoo::RegisterEventSource)
      assert_not_nil(EventLogFoo::RegisterEventSourceW)
      assert_not_nil(EventLogFoo::ReportEvent)
      assert_not_nil(EventLogFoo::ReportEventW)
   end
   
   def teardown
      @foo = nil
   end
end
