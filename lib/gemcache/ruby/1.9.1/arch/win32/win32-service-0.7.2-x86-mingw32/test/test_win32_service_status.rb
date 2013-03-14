########################################################################
# test_win32_service_status.rb
#
# Test case for the Struct::ServiceStatus struct.
########################################################################
require 'rubygems'
gem 'test-unit'

require 'win32/service'
require 'test/unit'

class TC_Win32_ServiceStatus_Struct < Test::Unit::TestCase
  def setup
    @service_name = 'Schedule'
    @service_stat = Win32::Service.status(@service_name)

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
      'shutdown',
      'stop',
      'hardware profile change',
      'power event',
      'session change'
    ]
  end

  def test_service_status_service_type
    assert_respond_to(@service_stat, :service_type)
    assert(@types.include?(@service_stat.service_type))
  end

  def test_service_status_current_state
    assert_respond_to(@service_stat, :current_state)
    assert(@states.include?(@service_stat.current_state))
  end

  def test_service_status_controls_accepted
    assert_respond_to(@service_stat, :controls_accepted)
    assert_kind_of(Array, @service_stat.controls_accepted)
    @service_stat.controls_accepted.each{ |control|
      assert_true(@controls.include?(control))
    }
  end

  def test_service_status_win32_exit_code
    assert_respond_to(@service_stat, :win32_exit_code)
    assert_kind_of(Fixnum, @service_stat.win32_exit_code)
  end

  def test_service_status_service_specific_exit_code
    assert_respond_to(@service_stat, :service_specific_exit_code)
    assert_kind_of(Fixnum, @service_stat.service_specific_exit_code)
  end

  def test_service_status_check_point
    assert_respond_to(@service_stat, :check_point)
    assert_kind_of(Fixnum, @service_stat.check_point)
  end

  def test_service_status_wait_hint
    assert_respond_to(@service_stat, :wait_hint)
    assert_kind_of(Fixnum, @service_stat.wait_hint)
  end

  def test_service_status_interactive
    assert_respond_to(@service_stat, :interactive)
    assert([true, false].include?(@service_stat.interactive))
  end

  def test_service_status_pid
    assert_respond_to(@service_stat, :pid)
    assert_kind_of(Fixnum, @service_stat.pid)
  end

  def test_service_status_service_flags
    assert_respond_to(@service_stat, :service_flags)
    assert_kind_of(Fixnum, @service_stat.service_flags)
  end

  def teardown
    @service_stat = nil
    @types        = nil
    @states       = nil
    @controls     = nil
  end
end
