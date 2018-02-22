require 'msf/core'
require 'rex'

lib = File.join(Msf::Config.install_root, "test", "lib")
$:.push(lib) unless $:.include?(lib)
require 'module_test'

class MetasploitModule < Msf::Post

  include Msf::ModuleTest::PostTest
  include Msf::Post::File

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Meterpreter cmd_exec test',
        'Description'   => %q{ This module will test the meterpreter cmd_exec API },
        'License'       => MSF_LICENSE,
        'Platform'      => [ 'windows', 'linux', 'unix' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
  end

  def test_cmd_exec
    print_status("Starting cmd_exec tests")

    it "should return the result of echo" do
      test_string = Rex::Text.rand_text_alpha(4)
      output = cmd_exec("echo #{test_string}")
      output == test_string
    end

    it "should return the result after sleeping" do
      test_string = Rex::Text.rand_text_alpha(4)
      output = cmd_exec("sleep 1; echo #{test_string}")
      output == test_string
    end

    it "should return the full response after sleeping" do
      test_string = Rex::Text.rand_text_alpha(4)
      test_string2 = Rex::Text.rand_text_alpha(4)
      output = cmd_exec("echo #{test_string}; sleep 1; echo #{test_string2}")
      output == "#{test_string}\n#{test_string2}"
    end

    print_status("Finished cmd_exec tests")
  end
end