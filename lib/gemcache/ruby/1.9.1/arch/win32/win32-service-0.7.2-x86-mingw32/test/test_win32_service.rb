##########################################################################
# test_win32_service.rb
# 
# Tests for the Win32::Service class.
##########################################################################
require 'rubygems'
gem 'test-unit'

require 'win32/service'
require 'socket'
require 'test/unit'

class TC_Win32_Service < Test::Unit::TestCase
  def self.startup
    @@host = Socket.gethostname
    @@service_name = 'stisvc'
  end

  def setup
    @display_name = 'Windows Image Acquisition (WIA)'
    @service_name = 'stisvc'
    @service_stat = nil
    @services     = []
  end

  def start_service(service)
    status = Win32::Service.status(@service_name).current_state
    if status == 'paused'
      Win32::Service.resume(service)
    else
      unless ['running', 'start pending'].include?(status)
        Win32::Service.start(service)
      end
    end
    wait_for_status('running')
  end

  def stop_service(service)
    status = Win32::Service.status(@service_name).current_state
    unless ['stopped', 'stop pending'].include?(status)
      Win32::Service.stop(service)
    end
    wait_for_status('stopped')
  end
   
  # Helper method that waits for a status to change its state since state
  # changes aren't usually instantaneous.
  def wait_for_status(status)
    sleep 0.1 while Win32::Service.status(@service_name).current_state != status
  end

  test "version number is expected value" do
    assert_equal('0.7.2', Win32::Service::VERSION)
  end
   
  test "services basic functionality" do
    assert_respond_to(Win32::Service, :services)
    assert_nothing_raised{ Win32::Service.services }
    assert_nothing_raised{ Win32::Service.services(nil) }
    assert_nothing_raised{ Win32::Service.services(nil, 'network') }
  end
      
  test "services method returns an array without a block" do
    assert_nothing_raised{ @services = Win32::Service.services }
    assert_kind_of(Array, @services)
    assert_kind_of(Struct::ServiceInfo, @services[0])
  end
   
  test "services method yields service objects when a block is provided" do
    assert_nothing_raised{ Win32::Service.services{ |s| @services << s } }
    assert_kind_of(Array, @services)
    assert_kind_of(Struct::ServiceInfo, @services[0])      
  end
      
  test "the host argument must be a string or an error is raised" do
    assert_raise(TypeError){ Win32::Service.services(1) }
  end

  test "the group argument must be a string or an error is raised" do
    assert_raise(TypeError){ Win32::Service.services(nil, 1) }
  end

  test "the services method only accepts 2 arguments" do
    assert_raise(ArgumentError){ Win32::Service.services(nil, 'network', 1) }
  end

  test "a valid hostname must be provided or an error is raised" do
    assert_raise(Win32::Service::Error){ Win32::Service.services('bogus') }
  end   
   
  test "delete method basic functionality" do
    assert_respond_to(Win32::Service, :delete)
  end
   
  test "a service name must be provided to the delete method" do
    assert_raise(ArgumentError){ Win32::Service.delete }
  end

  test "delete method raises an error if a bogus service name is provided" do
    assert_raise(Win32::Service::Error){ Win32::Service.delete('bogus') }
  end

  test "delete method raises an error if a bogus host name is provided" do
    assert_raise(Win32::Service::Error){ Win32::Service.delete('bogus', 'bogus') }
  end

  test "delete method only accepts up to two arguments" do
    assert_raise(ArgumentError){ Win32::Service.delete('x', 'y', 'z') }
  end
   
  test "pause basic functionality" do
    assert_respond_to(Win32::Service, :pause)
  end

  test "resume basic functionality" do
    assert_respond_to(Win32::Service, :resume)
  end

  test "pause and resume work as expected" do
    start_service(@service_name)

    assert_nothing_raised{ Win32::Service.pause(@service_name) }
    wait_for_status('paused')

    assert_nothing_raised{ Win32::Service.resume(@service_name) }
    wait_for_status('running')
  end

  test "pausing an already paused service is harmless" do
    start_service(@service_name)

    assert_nothing_raised{ Win32::Service.pause(@service_name) }  
    wait_for_status('paused')
    assert_nothing_raised{ Win32::Service.pause(@service_name) }  
  end
   
  test "pause requires a service name as an argument" do
    assert_raise(ArgumentError){ Win32::Service.pause }
  end

  test "pausing an unrecognized service name raises an error" do
    assert_raise(Win32::Service::Error){ Win32::Service.pause('bogus') }
  end

  test "pausing a service on an unrecognized host raises an error" do
    assert_raise(Win32::Service::Error){ Win32::Service.pause('W32Time', 'bogus') }
  end

  test "pause method accepts a maximum of two arguments" do
    assert_raise(ArgumentError){ Win32::Service.pause('x', 'y', 'z') }
  end
   
  test "resume method requires a service name" do
    assert_raise(ArgumentError){ Win32::Service.resume }
  end

  test "resume method with an unrecognized service name raises an error" do
    assert_raise(Win32::Service::Error){ Win32::Service.resume('bogus') }
  end

  test "resume method with an unrecognized host name raises an error" do
    assert_raise(Win32::Service::Error){ Win32::Service.resume('W32Time', 'bogus') }
  end

  test "resume method accepts a maximum of two arguments" do
    assert_raise(ArgumentError){ Win32::Service.resume('W32Time', @@host, true) }
  end          

  test "stop method basic functionality" do
    assert_respond_to(Win32::Service, :stop)
  end
   
  test "start method basic functionality" do
    assert_respond_to(Win32::Service, :start)
  end

  test "stop and start methods work as expected" do
    start_service(@service_name)

    assert_nothing_raised{ Win32::Service.stop(@service_name) }
    wait_for_status('stopped')

    assert_nothing_raised{ Win32::Service.start(@service_name) }
    wait_for_status('running')
  end

  test "attempting to stop a stopped service raises an error" do
    start_service(@service_name)

    assert_nothing_raised{ Win32::Service.stop(@service_name) }
    wait_for_status('stopped')
    assert_raise(Win32::Service::Error){ Win32::Service.stop(@service_name) }  

    assert_nothing_raised{ Win32::Service.start(@service_name) }
  end
   
  test "stop method requires a service name" do
    assert_raise(ArgumentError){ Win32::Service.stop }
  end

  test "stop method raises an error if the service name is unrecognized" do
    assert_raise(Win32::Service::Error){ Win32::Service.stop('bogus') }
  end

  test "stop method raises an error if the host is unrecognized" do
    assert_raise(Win32::Service::Error){ Win32::Service.stop('W32Time', 'bogus') }
  end

  test "stop metho accepts a maximum of two arguments" do
    assert_raise(ArgumentError){ Win32::Service.stop('W32Time', @@host, true) }
  end
   
  test "start method requires a service name" do
    assert_raise(ArgumentError){ Win32::Service.start }
  end

  test "attempting to start a running service raises an error" do
    assert_raise(Win32::Service::Error){ Win32::Service.start(@service_name) }
  end

  test "attempting to start an unrecognized service raises an error" do
    assert_raise(Win32::Service::Error){ Win32::Service.start('bogus') }
  end

  test "attempting to start a service on an unknown host raises an error" do
    assert_raise(Win32::Service::Error){ Win32::Service.start('bogus', 'bogus') }
  end

  test "stop requires at least one argument" do
    assert_raise(ArgumentError){ Win32::Service.stop }
  end

  test "stop raises an error with an unrecognized service name" do
    assert_raise(Win32::Service::Error){ Win32::Service.stop('bogus') }
  end

  test "stop raises an error with an unrecognized host" do
    assert_raise(Win32::Service::Error){ Win32::Service.stop('W32Time', 'bogus') }
  end

  test "stop accepts a maximum of 2 arguments" do
    assert_raise(ArgumentError){ Win32::Service.stop('a', 'b', 'c') }
  end

  test "status basic functionality" do
    assert_respond_to(Win32::Service, :status)
    assert_nothing_raised{ Win32::Service.status(@service_name) }
    assert_kind_of(Struct::ServiceStatus, Win32::Service.status(@service_name))
  end

  test "get_service_name basic functionality" do
    assert_respond_to(Win32::Service, :get_service_name)
    assert_nothing_raised{ Win32::Service.get_service_name(@display_name) }
    assert_kind_of(String, Win32::Service.get_service_name(@display_name))
  end

  test "get_service_name returns expected results" do
    assert_equal(@service_name, Win32::Service.get_service_name(@display_name))
  end

  test "getservicename is an alias for get_service_name" do
    assert_respond_to(Win32::Service, :getservicename)
    assert_alias_method(Win32::Service, :getservicename, :get_service_name)
  end

  test "get_service_name requires at least one argument" do
    assert_raise(ArgumentError){ Win32::Service.get_service_name }
  end

  test "get_service_name raises an error if a bogus service name is provided" do
    assert_raise(Win32::Service::Error){ Win32::Service.get_service_name('bogus') }
  end

  test "get_service_name raises an error if a bogus host is provided" do
    assert_raise(Win32::Service::Error){ Win32::Service.get_service_name('foo', 'bogus') }
  end

  test "get_service_name accepts a maximum of two arguments" do
    assert_raise(ArgumentError){ Win32::Service.get_service_name('x', 'y', 'z') }
  end

  test "get_display_name basic functionality" do
    assert_respond_to(Win32::Service, :get_display_name)
    assert_nothing_raised{ Win32::Service.get_display_name(@service_name) }
    assert_kind_of(String, Win32::Service.get_display_name(@service_name))
  end

  test "get_display_name returns expected results" do
    assert_equal(@display_name, Win32::Service.get_display_name(@service_name))
  end

  test "getdisplayname is an alias for get_display_name" do
    assert_respond_to(Win32::Service, :getdisplayname)
    assert_alias_method(Win32::Service, :getdisplayname, :get_display_name)
  end

  test "get_display_name requires at least one argument" do
    assert_raise(ArgumentError){ Win32::Service.get_display_name }
  end

  test "get_display_name raises an error if the service does not exist" do
    assert_raise(Win32::Service::Error){ Win32::Service.get_display_name('bogus') }
  end

  test "get_display_name raises an error if a bad host name is provided" do
    assert_raise(Win32::Service::Error){ Win32::Service.get_display_name('W32Time', 'bogus') }
  end

  test "get_display_name takes a maximum of two arguments" do
    assert_raise(ArgumentError){ Win32::Service.get_display_name('x', 'y', 'z') }
  end

  test "exists method basic functionality" do
    assert_respond_to(Win32::Service, :exists?)
    assert_nothing_raised{ Win32::Service.exists?('W32Time') }
  end

  test "exists method returns expected results" do
    assert_true(Win32::Service.exists?('W32Time'))
    assert_false(Win32::Service.exists?('foobar'))
  end

  test "exists method requires at least one argument or an error is raised" do
    assert_raises(ArgumentError){ Win32::Service.exists? }
  end

  test "exists method raises an error if a bogus host is passed" do
    assert_raises(Win32::Service::Error){Win32::Service.exists?('foo', 'bogushost') }
  end

  test "exists method only accepts up to two arguments" do
    assert_raises(ArgumentError){ Win32::Service.exists?('foo', 'bar', 'baz') }
  end
      
  test "scm security constants are defined" do
    assert_not_nil(Win32::Service::MANAGER_ALL_ACCESS)
    assert_not_nil(Win32::Service::MANAGER_CREATE_SERVICE)
    assert_not_nil(Win32::Service::MANAGER_CONNECT)
    assert_not_nil(Win32::Service::MANAGER_ENUMERATE_SERVICE)
    assert_not_nil(Win32::Service::MANAGER_LOCK)
    assert_not_nil(Win32::Service::MANAGER_QUERY_LOCK_STATUS)
  end

  test "service specific constants are defined" do
    assert_not_nil(Win32::Service::ALL_ACCESS)
    assert_not_nil(Win32::Service::CHANGE_CONFIG)
    assert_not_nil(Win32::Service::ENUMERATE_DEPENDENTS)
    assert_not_nil(Win32::Service::INTERROGATE)
    assert_not_nil(Win32::Service::PAUSE_CONTINUE)
    assert_not_nil(Win32::Service::QUERY_CONFIG)
    assert_not_nil(Win32::Service::QUERY_STATUS)
    assert_not_nil(Win32::Service::STOP)
    assert_not_nil(Win32::Service::START)
    assert_not_nil(Win32::Service::USER_DEFINED_CONTROL)
  end

  test "service type constants are defined" do
    assert_not_nil(Win32::Service::FILE_SYSTEM_DRIVER)
    assert_not_nil(Win32::Service::KERNEL_DRIVER)
    assert_not_nil(Win32::Service::WIN32_OWN_PROCESS)
    assert_not_nil(Win32::Service::WIN32_SHARE_PROCESS)
    assert_not_nil(Win32::Service::INTERACTIVE_PROCESS)
  end

  test "service start option constants are defined" do
    assert_not_nil(Win32::Service::AUTO_START)
    assert_not_nil(Win32::Service::BOOT_START)
    assert_not_nil(Win32::Service::DEMAND_START)
    assert_not_nil(Win32::Service::DISABLED)
    assert_not_nil(Win32::Service::SYSTEM_START)
  end

  test "service error control constants are defined" do
    assert_not_nil(Win32::Service::ERROR_IGNORE)
    assert_not_nil(Win32::Service::ERROR_NORMAL)
    assert_not_nil(Win32::Service::ERROR_SEVERE)
    assert_not_nil(Win32::Service::ERROR_CRITICAL)
  end

  test "service state constants are defined" do
    assert_not_nil(Win32::Service::CONTINUE_PENDING)
    assert_not_nil(Win32::Service::PAUSE_PENDING)
    assert_not_nil(Win32::Service::PAUSED)
    assert_not_nil(Win32::Service::RUNNING)
    assert_not_nil(Win32::Service::START_PENDING)
    assert_not_nil(Win32::Service::STOP_PENDING)
    assert_not_nil(Win32::Service::STOPPED)      
  end
   
  def teardown
    @display_name = nil
    @service_name = nil
    @service_stat = nil
    @services     = nil
  end

  def self.shutdown
    @@host = nil
    status = Win32::Service.status(@@service_name).current_state

    if status == 'paused'
      Win32::Service.resume(@@service_name)
    end

    unless ['running', 'start pending'].include?(status)
      Win32::Service.start(@@service_name)
    end
  end
end
