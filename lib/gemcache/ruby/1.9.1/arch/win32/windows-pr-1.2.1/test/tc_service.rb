#####################################################################
# tc_service.rb
#
# Test case for the Windows::Service module.
#####################################################################
require 'windows/service'
require 'test/unit'

class ServiceFoo
   include Windows::Service
end

class TC_Windows_Service < Test::Unit::TestCase
   def setup
      @foo = ServiceFoo.new
   end

   def test_numeric_constants
      assert_equal(0, ServiceFoo::SC_ACTION_NONE)
      assert_equal(1, ServiceFoo::SC_ACTION_RESTART)
      assert_equal(2, ServiceFoo::SC_ACTION_REBOOT)
      assert_equal(3, ServiceFoo::SC_ACTION_RUN_COMMAND)
   end
   
   def test_method_constants
      assert_not_nil(ServiceFoo::ChangeServiceConfig)
      assert_not_nil(ServiceFoo::ChangeServiceConfig2)
      assert_not_nil(ServiceFoo::CloseServiceHandle)
      assert_not_nil(ServiceFoo::ControlService)
      assert_not_nil(ServiceFoo::CreateService)
      assert_not_nil(ServiceFoo::DeleteService)
      assert_not_nil(ServiceFoo::EnumDependentServices)
      assert_not_nil(ServiceFoo::EnumServicesStatus)
      assert_not_nil(ServiceFoo::EnumServicesStatusEx)
      assert_not_nil(ServiceFoo::GetServiceDisplayName)
      assert_not_nil(ServiceFoo::GetServiceKeyName)
      assert_not_nil(ServiceFoo::LockServiceDatabase)
      assert_not_nil(ServiceFoo::NotifyBootConfigStatus)
      assert_not_nil(ServiceFoo::OpenSCManager)
      assert_not_nil(ServiceFoo::OpenService)
      assert_not_nil(ServiceFoo::QueryServiceConfig)
      assert_not_nil(ServiceFoo::QueryServiceConfig2)
      assert_not_nil(ServiceFoo::QueryServiceStatus)
      assert_not_nil(ServiceFoo::QueryServiceStatusEx)
      assert_not_nil(ServiceFoo::RegisterServiceCtrlHandler)
      assert_not_nil(ServiceFoo::RegisterServiceCtrlHandlerEx)
      assert_not_nil(ServiceFoo::SetServiceBits)
      assert_not_nil(ServiceFoo::SetServiceStatus)
      assert_not_nil(ServiceFoo::StartService)
      assert_not_nil(ServiceFoo::StartServiceCtrlDispatcher)
      assert_not_nil(ServiceFoo::UnlockServiceDatabase)
   end
   
   def teardown
      @foo = nil
   end
end
