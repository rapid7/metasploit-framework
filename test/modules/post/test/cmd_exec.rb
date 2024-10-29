require 'rex'

lib = File.join(Msf::Config.install_root, "test", "lib")
$LOAD_PATH.push(lib) unless $LOAD_PATH.include?(lib)
require 'module_test'

class MetasploitModule < Msf::Post
  include Msf::ModuleTest::PostTest
  include Msf::Post::File

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Meterpreter cmd_exec test',
        'Description' => %q( This module will test the meterpreter cmd_exec API ),
        'License' => MSF_LICENSE,
        'Platform' => [ 'windows', 'linux', 'unix', 'java', 'osx' ],
        'SessionTypes' => ['meterpreter', 'shell', 'powershell']
      )
    )
  end

  def upload_precompiled_binaries
    print_status 'Uploading precompiled binaries'
    upload_file(show_args_binary[:path], "data/cmd_exec/#{show_args_binary[:path]}")
    if session.platform.eql?('linux') || session.platform.eql?('osx')
      chmod(show_args_binary[:path])
    end
  end

  def show_args_binary
    if session.platform == 'linux'
      { path: 'show_args_linux', cmd: './show_args_linux' }
    elsif session.platform == 'osx'
      { path: 'show_args_osx', cmd: './show_args_osx' }
    elsif session.platform == 'windows'
      { path: 'show_args.exe', cmd: 'show_args.exe' }
    else
      raise "unknown platform #{session.platform}"
    end
  end

  def valid_show_args_response?(output, expected:)
    # Handle both unix new lines `\n` and windows `\r\n`
    output_lines = output.lines(chomp: true)
    # extract the program name and remainder args
    output_binary, *output_args = output_lines

    # Match the binary name, to support the binary name containig relative or absolute paths, i.e.
    # "show_args.exe\r\none\r\ntwo",
    match = output_binary.match?(expected[0]) && output_args == expected[1..]
    if !match
      vprint_status("#{__method__}: expected: #{expected.inspect} - actual: #{output_lines.inspect}")
    end

    match
  end

  def test_cmd_exec
    # we are inconsistent reporting windows session types
    windows_strings = ['windows', 'win']
    vprint_status("Starting cmd_exec tests")
    upload_precompiled_binaries

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

    it 'should execute the show_args binary a single string' do
      # TODO: Fix this functionality
      if session.type.eql?('meterpreter') && session.arch.eql?('python')
        vprint_status("test skipped for Python Meterpreter - functionality not correct")
        next true
      end
      output = cmd_exec("#{show_args_binary[:cmd]} one two")
      valid_show_args_response?(output, expected: [show_args_binary[:path], 'one', 'two'])
    end

    it 'should execute the show_args binary with the binary name and args provided separately' do
      output = cmd_exec(show_args_binary[:cmd], "one two")
      valid_show_args_response?(output, expected: [show_args_binary[:path], 'one', 'two'])
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

  def test_cmd_exec_stderr
    vprint_status("Starting cmd_exec stderr tests")

    it "should return the stderr output" do
      test_string = Rex::Text.rand_text_alpha(4)
      if session.platform.eql? 'windows'
        output = cmd_exec("cmd.exe", "/c echo #{test_string} 1>&2")
        output.rstrip == test_string
      else
        output = cmd_exec("echo #{test_string} 1>&2")
        output == test_string
      end
    end
  end
end
