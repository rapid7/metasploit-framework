##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex'

lib = File.join(Msf::Config.install_root, "test", "lib")
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
require 'module_test'

class MetasploitModule < Msf::Post

  include Msf::ModuleTest::PostTest

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'railgun_testing',
        'Description' => %q{ This module will test railgun code used in post modules},
        'License' => MSF_LICENSE,
        'Author' => [ 'kernelsmith'],
        'Platform' => [ 'linux', 'osx', 'windows' ],
        'SessionTypes' => [ 'meterpreter' ]
      )
    )

    register_options(
      [
        OptInt.new("ERR_CODE", [ false, "Error code to reverse lookup" ]),
        OptInt.new("WIN_CONST", [ false, "Windows constant to reverse lookup" ]),
        OptRegexp.new("WCREGEX", [ false, "Regexp to apply to constant rev lookup" ]),
        OptRegexp.new("ECREGEX", [ false, "Regexp to apply to error code lookup" ]),
      ], self.class
    )
  end

  #
  # Return an array of constants names matching const
  #
  def select_const_names(const, filter_regex = nil)
    session.railgun.constant_manager.select_const_names(const, filter_regex)
  end

  #
  # Returns an array of windows error code names for a given windows error code matching +err_code+
  #
  def lookup_windows_error(err_code, filter_regex = nil)
    select_const_names(err_code, /^ERROR_/).select do |name|
      name =~ filter_regex
    end
  end

  def test_osx_static
    return skip('session platform is not osx') unless session.platform == 'osx'
    return skip('session does not support COMMAND_ID_STDAPI_RAILGUN_API') unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)

    it "should return a constant name given a const and a filter" do
      results = select_const_names(4, /^PROT/)
      results == ['PROT_EXEC']
    end
  end

  def test_linux_static
    return skip('session platform is not osx') unless session.platform == 'linux'
    return skip('session does not support COMMAND_ID_STDAPI_RAILGUN_API') unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)

    it "should return a constant name given a const and a filter" do
      results = select_const_names(277, /^SOL_I/)
      results == ['SOL_IUCV']
    end
  end

  def test_windows_static
    return skip('session platform is not windows') unless session.platform == 'windows'
    return skip('session does not support COMMAND_ID_STDAPI_RAILGUN_API') unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)

    it "should return a constant name given a const and a filter" do
      ret = true
      results = select_const_names(4, /^SERVICE/)

      ret &&= !!(results.kind_of? Array)
      # All of the returned values should match the filter and have the same value
      results.each { |const|
        ret &&= !!(const =~ /^SERVICE/)
        ret &&= !!(session.railgun.constant_manager.parse(const) == 4)
      }

      # Should include things that match the filter and the value
      ret &&= !!(results.include? "SERVICE_RUNNING")
      # Should NOT include things that match the value but not the filter
      ret &&= !!(not results.include? "CLONE_FLAG_ENTITY")

      ret
    end

    it "should return an error string given an error code" do
      ret = true
      results = lookup_windows_error(0x420, /^ERROR_SERVICE/)
      ret &&= !!(results.kind_of? Array)
      ret &&= !!(results.length == 1)

      ret
    end
  end

  def test_windows_datastore
    return skip('session platform is not windows') unless session.platform == 'windows'
    return skip('session does not support COMMAND_ID_STDAPI_RAILGUN_API') unless session.commands.include?(Rex::Post::Meterpreter::Extensions::Stdapi::COMMAND_ID_STDAPI_RAILGUN_API)

    if (datastore["WIN_CONST"])
      it "should look up arbitrary constants" do
        ret = true
        results = select_const_names(datastore['WIN_CONST'], datastore['WCREGEX'])
        # vprint_status("RESULTS:  #{results.class} #{results.pretty_inspect}")

        ret
      end
    end

    if (datastore["ERR_CODE"])
      it "should look up arbitrary error codes" do
        ret = true
        results = lookup_error(datastore['ERR_CODE'], datastore['ECREGEX'])
        # vprint_status("RESULTS:  #{results.class} #{results.inspect}")

        ret
      end
    end
  end
end
