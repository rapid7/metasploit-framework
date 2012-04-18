#####################################################################
# tc_process.rb
#
# Test case for the Windows::Process module.
#####################################################################
require 'windows/process'
require 'test/unit'

class TC_Windows_Process < Test::Unit::TestCase
  include Windows::Process

  def test_constants
    assert_equal(0x1F0FFF, PROCESS_ALL_ACCESS)
  end

  def test_methods
    assert(self.respond_to?(:CreateProcess, true))
  end

  def test_helper_methods
    assert(self.respond_to?(:windows_64?, true))
    assert_equal(true, [true, false].include?(windows_64?))
  end
end
