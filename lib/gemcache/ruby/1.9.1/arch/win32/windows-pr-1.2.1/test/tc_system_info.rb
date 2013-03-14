#####################################################################
# tc_system_info.rb
#
# Test case for the Windows::SystemInfo module.
#####################################################################
require 'windows/system_info'
require 'test/unit'

class TC_Windows_SystemInfo < Test::Unit::TestCase
  include Windows::SystemInfo

  def test_numeric_constants
    assert_equal(386, PROCESSOR_INTEL_386)
    assert_equal(486, PROCESSOR_INTEL_486)
    assert_equal(586, PROCESSOR_INTEL_PENTIUM)
    assert_equal(2200, PROCESSOR_INTEL_IA64)
    assert_equal(8664, PROCESSOR_AMD_X8664)
  end
   
  def test_method_constants
    assert_not_nil(ExpandEnvironmentStrings)
    assert_not_nil(GetComputerName)
    assert_not_nil(GetComputerNameEx)
    assert_not_nil(GetSystemInfo)
  end

  def test_custom_boolean_methods
    assert(self.respond_to?(:windows_2000?, true))
    assert(self.respond_to?(:windows_xp?, true))
    assert(self.respond_to?(:windows_2003?, true))
    assert(self.respond_to?(:windows_vista?, true))
  end
end
