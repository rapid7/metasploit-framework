require 'rex'

lib = File.join(Msf::Config.install_root, "test", "lib")
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
require 'module_test'

class MetasploitModule < Msf::Post
  include Msf::ModuleTest::PostTest
  include Msf::Post::File

  def initialize(info = {})
    super(update_info(info,
        'Name'          => 'Meterpreter cmd_exec test',
        'Description'   => %q( This module will test the meterpreter cmd_exec API ),
        'License'       => MSF_LICENSE,
        'Platform'      => ['windows', 'linux', 'unix'],
        'SessionTypes'  => ['meterpreter']
      ))
  end

  def test_cmd_exec
    # we are inconsistent reporting windows session types
    windows_strings = ['windows', 'win']
    vprint_status("Starting cmd_exec tests")

    it "should return the result of echo" do
      test_string = Rex::Text.rand_text_alpha(4)
      if windows_strings.include? session.platform and session.type.eql? 'meterpreter'
        vprint_status("meterpreter?")
        output = cmd_exec('cmd.exe', "/c echo #{test_string}")
      else
        output = cmd_exec("echo #{test_string}")
      end
      output == test_string
    end

    # Powershell supports this, but not windows meterpreter (unsure about windows shell)
    if not windows_strings.include? session.platform or session.type.eql? 'powershell'
      it "should return the full response after sleeping" do
        test_string = Rex::Text.rand_text_alpha(4)
        output = cmd_exec("sleep 1; echo #{test_string}")
        output == test_string
      end
      it "should return the full response after sleeping" do
        test_string = Rex::Text.rand_text_alpha(4)
        test_string2 = Rex::Text.rand_text_alpha(4)
        output = cmd_exec("echo #{test_string}; sleep 1; echo #{test_string2}")
        output.delete("\r") == "#{test_string}\n#{test_string2}"
      end

      it "should return the result of echo 10 times" do
        10.times do
          test_string = Rex::Text.rand_text_alpha(4)
          output = cmd_exec("echo #{test_string}")
          return false unless output == test_string
        end
        true
      end
    else
      vprint_status("Session does not support sleep, skipping sleep tests")
    end
    vprint_status("Finished cmd_exec tests")
  end

  def test_cmd_exec_quotes
    vprint_status("Starting cmd_exec quote tests")

    it "should return the result of echo with single quotes" do
      test_string = Rex::Text.rand_text_alpha(4)
      if session.platform.eql? 'windows' and session.arch == ARCH_PYTHON
        output = cmd_exec("cmd.exe", "/c echo \"#{test_string}\"")
        output == test_string
      elsif session.platform.eql? 'windows'
        output = cmd_exec("cmd.exe", "/c echo '#{test_string}'")
        output == "'" + test_string + "'"
      else
        output = cmd_exec("echo '#{test_string}'")
        output == test_string
      end
    end

    it "should return the result of echo with double quotes" do
      test_string = Rex::Text.rand_text_alpha(4)
      if session.platform.eql? 'windows' and session.arch == ARCH_PYTHON
        output = cmd_exec("cmd.exe", "/c echo \"#{test_string}\"")
        output == test_string
      elsif session.platform.eql? 'windows'
        output = cmd_exec("cmd.exe", "/c echo \"#{test_string}\"")
        output == "\"" + test_string + "\""
      else
        output = cmd_exec("echo \"#{test_string}\"")
        output == test_string
      end
    end
  end
end
