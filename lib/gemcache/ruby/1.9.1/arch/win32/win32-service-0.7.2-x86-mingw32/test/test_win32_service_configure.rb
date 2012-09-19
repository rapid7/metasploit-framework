#######################################################################
# test_win32_service_configure.rb
#
# Test suite that validates the Service.configure method.
#######################################################################
require 'rubygems'
gem 'test-unit'

require 'win32/service'
require 'test/unit'

class TC_Win32_Service_Configure < Test::Unit::TestCase
  def self.startup
    @@service = "notepad_service"
    @@command = "C:\\windows\\system32\\notepad.exe"
            
    Win32::Service.new(
      :service_name     => @@service,
      :binary_path_name => @@command
    )
  end
   
  def config_info
    Win32::Service.config_info(@@service)
  end
   
  def full_info
    service = nil
    Win32::Service.services{ |s|
      if s.service_name == @@service
        service = s
        break
      end
    }
    service
  end
   
  def service_configure(opt)
    options = {:service_name => @@service}
    options = options.merge(opt)
    assert_nothing_raised{ Win32::Service.configure(options) }    
  end
   
  def setup
    @info = Win32::Service.config_info(@@service)
  end
   
  test "configure method is defined" do
    assert_respond_to(Win32::Service, :configure)
  end
   
  test "configuring the service type works as expected" do
    assert_equal('own process, interactive', config_info.service_type)
    service_configure(:service_type => Win32::Service::WIN32_SHARE_PROCESS)      
    assert_equal('share process', config_info.service_type)
  end
   
  test "configuring the description works as expected" do
    assert_equal('', full_info.description)
    service_configure(:description => 'test service')     
    assert_equal('test service', full_info.description)
  end
   
  test "configuring the start type works as expected" do
    assert_equal('demand start', config_info.start_type)
    service_configure(:start_type => Win32::Service::DISABLED)
    assert_equal('disabled', config_info.start_type)      
  end
   
  test "the configure method requires one argument" do
    assert_raise(ArgumentError){ Win32::Service.configure }
  end

  test "the configure method requires a hash argument" do
    assert_raise(ArgumentError){ Win32::Service.configure('bogus') }
  end

  test "the hash argument must not be empty" do
    assert_raise(ArgumentError){ Win32::Service.configure({}) }
  end

  test "the service name must be provided or an error is raised" do
    assert_raise(ArgumentError){
      Win32::Service.configure(:binary_path_name => 'notepad.exe')
    }
  end
   
  def teardown
    @info = nil
  end
   
  def self.shutdown
    Win32::Service.delete(@@service) if Win32::Service.exists?(@@service)
    @@service = nil
    @@command = nil      
  end   
end
