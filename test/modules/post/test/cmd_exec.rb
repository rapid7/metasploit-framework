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

  def upload_show_args_binary
    print_status 'Uploading precompiled binaries'
    upload_file(show_args_binary[:path], "data/cmd_exec/#{show_args_binary[:path]}")
    unless session.platform.eql?('windows')
      chmod(show_args_binary[:path])
    end
  end

  def show_args_binary
    if session.platform == 'linux' || session.platform == 'unix'
      { path: 'show_args_linux', cmd: './show_args_linux' }
    elsif session.platform == 'osx'
      { path: 'show_args_osx', cmd: './show_args_osx' }
    elsif session.platform == 'windows' && session.type == 'powershell'
      { path: 'show_args.exe', cmd: "#{pwd}\\show_args.exe" }
    elsif session.platform == 'windows' && session.type == 'shell'
      { path: 'show_args.exe', cmd: 'show_args.exe' }
    elsif session.platform == 'windows' && session.arch == 'php'
      { path: 'show_args.exe', cmd: '.\\show_args.exe' }
    elsif session.platform == 'windows'
      { path: 'show_args.exe', cmd: './show_args.exe' }
      elsif session.type == 'meterpreter' && session.arch == 'java'
    else
      raise "unknown platform #{session.platform}"
    end
  end

  def valid_show_args_response?(output, expected:)
    # Handle both unix new lines `\n` and windows `\r\n`
    output_lines = output.lines(chomp: true)
    # extract the program name and remainder args
    output_binary, *output_args = output_lines

    # Match the binary name, to support the binary name containing relative or absolute paths, i.e.
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
    upload_show_args_binary

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

    it 'should execute the show_args binary with a string' do
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
      if session.platform.eql? 'windows'
        if session.arch == ARCH_PYTHON
          output = cmd_exec("cmd.exe", "/c echo \"#{test_string}\"")
          output == test_string
        # TODO: Fix this functionality
        elsif session.type.eql?('shell') || session.type.eql?('powershell')
          vprint_status("test skipped for Windows CMD and Powershell - functionality not correct")
          true
        else
          output = cmd_exec("cmd.exe", "/c echo '#{test_string}'")
          output == "'" + test_string + "'"
        end
      else
        output = cmd_exec("echo '#{test_string}'")
        output == test_string
      end
    end

    it "should return the result of echo with double quotes" do
      test_string = Rex::Text.rand_text_alpha(4)
      if session.platform.eql? 'windows'
        if session.platform.eql? 'windows' and session.arch == ARCH_PYTHON
          output = cmd_exec("cmd.exe", "/c echo \"#{test_string}\"")
          output == test_string
        # TODO: Fix this functionality
        elsif session.type.eql?('shell') || session.type.eql?('powershell')
          vprint_status("test skipped for Windows CMD and Powershell - functionality not correct")
          true
        else
          output = cmd_exec("cmd.exe", "/c echo \"#{test_string}\"")
          output == "\"" + test_string + "\""
        end
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
        # TODO: Fix this functionality
        if session.type.eql?('shell') || session.arch.eql?("php") || session.type.eql?("powershell")
          vprint_status("test skipped for Windows CMD, Powershell and PHP - functionality not correct")
          true
        else
          output = cmd_exec("cmd.exe", "/c echo #{test_string} 1>&2")
          output.rstrip == test_string
        end
      else
        output = cmd_exec("echo #{test_string} 1>&2")
        output == test_string
      end
    end
  end

  # TODO: These tests are in preparation for Smashery's create process API
  # def test_create_process
  #   upload_show_args_binary
  #
  #   test_string = Rex::Text.rand_text_alpha(4)
  #
  #   it 'should accept blank strings and return the create_process output' do
  #     if session.arch.eql?("php")
  #       # TODO: Fix this functionality
  #
  #       vprint_status("test skipped for PHP - functionality not correct")
  #       true
  #     end
  #     output = create_process(show_args_binary[:cmd], args: [test_string, '', test_string, '', test_string])
  #     valid_show_args_response?(output, expected: [show_args_binary[:path], test_string, '', test_string, '', test_string])
  #   end
  #
  #   it 'should accept multiple args and return the create_process output' do
  #     output = create_process(show_args_binary[:cmd], args: [test_string, test_string])
  #     valid_show_args_response?(output, expected: [show_args_binary[:path], test_string, test_string])
  #   end
  #
  #   it 'should accept spaces and return the create_process output' do
  #     output = create_process(show_args_binary[:cmd], args: ['with spaces'])
  #     valid_show_args_response?(output, expected: [show_args_binary[:path], 'with spaces'])
  #   end
  #
  #   it 'should accept environment variables and return the create_process output' do
  #     output = create_process(show_args_binary[:cmd], args: ['$PATH'])
  #     valid_show_args_response?(output, expected: [show_args_binary[:path], '$PATH'])
  #   end
  #
  #   it 'should accept environment variables within a string and return the create_process output' do
  #     output = create_process(show_args_binary[:cmd], args: ["it's $PATH"])
  #     valid_show_args_response?(output, expected: [show_args_binary[:path], "it's $PATH"])
  #   end
  #
  #   it 'should accept special characters and return the create_process output' do
  #     if session.platform.eql? 'windows'
  #       # TODO: Fix this functionality
  #       vprint_status('test skipped for Windows - functionality not correct')
  #       true
  #     end
  #     output = create_process(show_args_binary[:cmd], args: ['~!@#$%^&*(){`1234567890[]",.\'<>'])
  #     valid_show_args_response?(output, expected: [show_args_binary[:path], '~!@#$%^&*(){`1234567890[]",.\'<>'])
  #   end
  #
  #   it 'should accept command line commands and return the create_process output' do
  #     if session.arch.eql?("php")
  #       # TODO: Fix this functionality
  #       vprint_status("test skipped for PHP - functionality not correct")
  #       true
  #     end
  #
  #     output = create_process(show_args_binary[:cmd], args: ['run&echo'])
  #     valid_show_args_response?(output, expected: [show_args_binary[:path], 'run&echo'])
  #   end
  #
  #   it 'should accept semicolons to separate multiple command on a single line and return the create_process output' do
  #     if session.arch.eql?("php")
  #       # TODO: Fix this functionality
  #       vprint_status("test skipped for PHP - functionality not correct")
  #       true
  #     end
  #
  #     output = create_process(show_args_binary[:cmd], args: ['run&echo;test'])
  #     valid_show_args_response?(output, expected: [show_args_binary[:path], 'run&echo;test'])
  #   end
  #
  #   it 'should accept spaces in the filename and return the create_process output' do
  #     if session.platform.eql? 'windows'
  #       # TODO: Fix this functionality
  #       vprint_status('test skipped for Windows CMD - functionality not correct')
  #       true
  #     end
  #
  #     output = create_process('./show_args file', args: [test_string, test_string])
  #     valid_show_args_response?(output, expected: ['./show_args file', test_string, test_string])
  #   end
  #
  #   it 'should accept special characters in the filename and return the create_process output' do
  #     if session.platform.eql? 'windows'
  #       # TODO: Fix this functionality
  #       vprint_status('test skipped for Windows CMD - functionality not correct')
  #       true
  #     end
  #
  #     output = create_process('./~!@#$%^&*(){}', args: [test_string, test_string])
  #     valid_show_args_response?(output, expected: ['./~!@#$%^&*(){}', test_string, test_string])
  #     end
  #   end
  # end
end
