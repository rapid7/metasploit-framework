########################################################################
# test_win32_service_info.rb
#
# Test case for the Struct::ServiceInfo structure.
########################################################################
require 'rubygems'
gem 'test-unit'

require 'win32/service'
require 'test/unit'

class TC_Win32_ServiceInfo_Struct < Test::Unit::TestCase
  def self.startup
    @@services = Win32::Service.services      
  end
   
  def setup
    @service_info = @@services.find{ |s| s.service_name == 'W32Time' }

    @error_controls = [
      'critical',
      'ignore',
      'normal',
      'severe',
      nil
    ]

    @start_types = [
      'auto start',
      'boot start',
      'demand start',
      'disabled',
      'system start',
       nil
    ]

    @types = [
      'file system driver',
      'kernel driver',
      'own process',
      'share process',
      'recognizer token',
      'driver',
      'win32',
      'all',
      'own process, interactive',
      'share process, interactive',
      nil
    ]

    @states = [
      'continue pending',
      'pause pending',
      'paused',
      'running',
      'start pending',
      'stop pending',
      'stopped',
       nil
    ]

    @controls = [ 
      'netbind change',
      'param change',
      'pause continue',
      'pre-shutdown',
      'shutdown',
      'stop',
      'hardware profile change',
      'power event',
      'session change',
      'interrogate'
    ]
  end

  def test_service_info_info_service_name
    assert_respond_to(@service_info, :service_name)
    assert_kind_of(String, @service_info.service_name)
  end

  def test_service_info_info_display_name
    assert_respond_to(@service_info, :display_name)
    assert_kind_of(String, @service_info.display_name)
  end

  def test_service_info_info_service_type
    assert_respond_to(@service_info, :service_type)
    assert(@types.include?(@service_info.service_type))
  end

  def test_service_info_current_state
    assert_respond_to(@service_info, :current_state)
    assert(@states.include?(@service_info.current_state))
  end

  def test_service_info_controls_accepted
    assert_respond_to(@service_info, :controls_accepted)
    assert_kind_of(Array, @service_info.controls_accepted)
    assert_false(@service_info.controls_accepted.empty?)
    @service_info.controls_accepted.each{ |control|
      assert_true(@controls.include?(control))
    }
  end

  def test_service_info_win32_exit_code
    assert_respond_to(@service_info, :win32_exit_code)
    assert_kind_of(Fixnum, @service_info.win32_exit_code)
  end

  def test_service_info_service_specific_exit_code
    assert_respond_to(@service_info, :service_specific_exit_code)
    assert_kind_of(Fixnum, @service_info.service_specific_exit_code)
  end

  def test_service_info_check_point
    assert_respond_to(@service_info, :check_point)
    assert_kind_of(Fixnum, @service_info.check_point)
  end

  def test_service_info_wait_hint
    assert_respond_to(@service_info, :wait_hint)
    assert_kind_of(Fixnum, @service_info.wait_hint)
  end

  def test_service_info_binary_path_name
    assert_respond_to(@service_info, :binary_path_name)
    assert_kind_of(String, @service_info.binary_path_name)
  end

  def test_service_info_start_type
    assert_respond_to(@service_info, :start_type)
    assert(@start_types.include?(@service_info.start_type))
  end

  def test_service_info_error_control
    assert_respond_to(@service_info, :error_control)
    assert(@error_controls.include?(@service_info.error_control))
  end

  def test_service_info_load_order_group
    assert_respond_to(@service_info, :load_order_group)
    assert_kind_of(String, @service_info.load_order_group)
  end

  def test_service_info_tag_id
    assert_respond_to(@service_info, :tag_id)
    assert_kind_of(Fixnum, @service_info.tag_id)
  end

  def test_service_info_start_name
    assert_respond_to(@service_info, :start_name)
    assert_kind_of(String, @service_info.start_name)
  end

  def test_service_info_dependencies
    assert_respond_to(@service_info, :dependencies)
    assert_kind_of(Array, @service_info.dependencies)
  end

  def test_service_info_description
    assert_respond_to(@service_info, :description)
    assert_kind_of(String, @service_info.description)
  end

  def test_service_info_interactive
    assert_respond_to(@service_info, :interactive)
    assert([true, false].include?(@service_info.interactive))
  end

  def test_service_info_service_flags
    assert_respond_to(@service_info, :service_flags)
    assert([0,1].include?(@service_info.service_flags))
  end

  def teardown
    @types    = nil
    @states   = nil
    @controls = nil
  end
   
  def self.shutdown
    @@services = nil
  end
end
