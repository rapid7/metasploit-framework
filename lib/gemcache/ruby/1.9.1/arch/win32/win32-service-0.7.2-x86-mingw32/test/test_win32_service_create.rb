########################################################################
# test_win32_service_create.rb
#
# Test case for the Service.create method. This test case will create
# a dummy (notepad) service. It won't actually run of course.
########################################################################
require 'rubygems'
gem 'test-unit'

require 'win32/service'
require 'test/unit'

class TC_Win32_Service_Create < Test::Unit::TestCase
  def self.startup
    @@service1 = "notepad_service1"
    @@service2 = "notepad_service2"
    @@command  = "C:\\windows\\system32\\notepad.exe"
      
    Win32::Service.new(
      :service_name     => @@service1,
      :binary_path_name => @@command
    )
      
    Win32::Service.new(
      :service_name     => @@service2,
      :display_name     => 'Notepad Test',
      :desired_access   => Win32::Service::ALL_ACCESS,
      :service_type     => Win32::Service::WIN32_OWN_PROCESS,
      :start_type       => Win32::Service::DISABLED,
      :error_control    => Win32::Service::ERROR_IGNORE,
      :binary_path_name => @@command,
      :load_order_group => 'Network',
      :dependencies     => 'W32Time',
      :description      => 'Test service. Please delete me'
    )
  end
   
  def setup
    @info1 = Win32::Service.config_info(@@service1)
    @info2 = Win32::Service.config_info(@@service2)
  end

  test "constructor basic functionality" do
    assert_respond_to(Win32::Service, :new)
  end
   
  test "create is an alias for new" do
    assert_respond_to(Win32::Service, :create)
    assert_alias_method(Win32::Service, :create, :new)
  end
   
  test "ensure services were created in startup method" do
    notify "If this test fails then remaining results are meaningless."
    assert_true(Win32::Service.exists?(@@service1))
    assert_true(Win32::Service.exists?(@@service2))
  end
   
  test "expected service type configuration information" do 
    assert_equal('own process, interactive', @info1.service_type)
  end

  test "expected start type configuration information" do 
    assert_equal('demand start', @info1.start_type)
  end

  test "expected error control configuration information" do 
    assert_equal('normal', @info1.error_control)
  end

  test "expected binary path name configuration information" do 
    assert_equal(@@command, @info1.binary_path_name)
  end

  test "expected load order group configuration information" do 
    assert_equal('', @info1.load_order_group)
  end

  test "expected tag id configuration information" do 
    assert_equal(0, @info1.tag_id)
  end

  test "expected dependency configuration information" do 
    assert_equal([], @info1.dependencies)
  end

  test "expected service start time configuration information" do 
    assert_equal('LocalSystem', @info1.service_start_name)
  end

  test "expected display name configuration information" do 
    assert_equal('notepad_service1', @info1.display_name)
  end
  
  test "configuration information options are set properly for service 2" do
    assert_equal('own process', @info2.service_type)
    assert_equal('disabled', @info2.start_type)
    assert_equal('ignore', @info2.error_control)
    assert_equal(@@command, @info2.binary_path_name)
    assert_equal('Network', @info2.load_order_group)
    assert_equal(0, @info2.tag_id)
    assert_equal(['W32Time'], @info2.dependencies)
    assert_equal('LocalSystem', @info2.service_start_name)
    assert_equal('Notepad Test', @info2.display_name)      
  end

  test "at least one argument is required or an error is raised" do
    assert_raise(ArgumentError){ Win32::Service.new }
  end

  test "passing a bogus option to the constructor will cause an error" do
    assert_raise(ArgumentError){ Win32::Service.new(:bogus => 'test.exe') }
  end

  test "the service name must be provided or an error is raised" do
    assert_raise(ArgumentError){ Win32::Service.new(:binary_path_name => 'test.exe') }
  end

  def teardown
    @info1 = nil
    @info2 = nil
  end
   
  def self.shutdown
    Win32::Service.delete(@@service1) if Win32::Service.exists?(@@service1)
    Win32::Service.delete(@@service2) if Win32::Service.exists?(@@service2)

    @@service1 = nil
    @@service2 = nil
    @@command  = nil
  end
end
