#########################################################################
# test_win32_daemon.rb
#
# Test suite for the Win32::Daemon class. You should run this test via
# the 'rake test' or 'rake test_daemon' tasks.
#
# These tests are rather limited, since the acid test is to install
# your daemon as a service and see how it behaves.
#########################################################################
require 'rubygems'
gem 'test-unit'

require 'win32/daemon'
require 'test/unit'
include Win32

class TC_Daemon < Test::Unit::TestCase
  def setup
    @daemon = Daemon.new
  end
   
  test "version number is set properly" do
    assert_equal('0.7.2', Daemon::VERSION)
  end
   
  test "constructor basic functionality" do
    assert_respond_to(Daemon, :new)
    assert_nothing_raised{ Daemon.new }
  end

  test "constructor does not accept any arguments" do
    assert_raises(ArgumentError){ Daemon.new(1) }
  end
   
  test "mainloop basic functionality" do
    assert_respond_to(@daemon, :mainloop)
  end
   
  test "state basic functionality" do
    assert_respond_to(@daemon, :state)
  end
   
  test "is_running basic functionality" do
    assert_respond_to(@daemon, :running?)
  end
   
  test "expected constants are defined" do
    assert_not_nil(Daemon::CONTINUE_PENDING)
    assert_not_nil(Daemon::PAUSE_PENDING)
    assert_not_nil(Daemon::PAUSED)
    assert_not_nil(Daemon::RUNNING)
    assert_not_nil(Daemon::START_PENDING)
    assert_not_nil(Daemon::STOP_PENDING)
    assert_not_nil(Daemon::STOPPED)
    assert_not_nil(Daemon::IDLE) 
  end
   
  def teardown
    @daemon = nil
  end
end
