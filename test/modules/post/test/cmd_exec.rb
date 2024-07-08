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

  def upload_create_process_precompiled_binaries
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
    elsif session.platform == 'windows' && session.type.eql?('powershell')
      { path: 'show_args.exe', cmd: "#{pwd}\\show_args.exe" }
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
    upload_create_process_precompiled_binaries

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

    it 'should execute the show_args binary with strings' do
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

  # TODO: This can be added back in once Smashery's create process API has been landed
  # def test_create_process
  #   upload_create_process_precompiled_binaries
  #
  #   test_string = Rex::Text.rand_text_alpha(4)
  #
  #   it 'should accept blank strings and return the create_process output' do
  #     if session.platform.eql? 'windows'
  #       output = create_process('./show_args.exe', args: [test_string, '', test_string, '', test_string])
  #       if session.type.eql? 'powershell'
  #         output.rstrip == "#{pwd}\\show_args.exe\r\n#{test_string}\r\n\r\n#{test_string}\r\n\r\n#{test_string}"
  #       elsif session.type.eql? 'shell'
  #         output = create_process('show_args.exe', args: [test_string, '', test_string, '', test_string])
  #         output.rstrip == "show_args.exe\r\n#{test_string}\r\n\r\n#{test_string}\r\n\r\n#{test_string}"
  #       elsif (session.type.eql?('meterpreter') && session.arch.eql?('java'))
  #         output.rstrip == ".\\show_args.exe\r\n#{test_string}\r\n\r\n#{test_string}\r\n\r\n#{test_string}"
  #       elsif session.arch.eql?("php")
  #         # output = create_process('.\\show_args.exe', args: [test_string, '', test_string, '', test_string])
  #         # $stderr.puts output.rstrip.inspect
  #         # output.rstrip == ".\\show_args.exe\r\n#{test_string}\r\n\r\n#{test_string}\r\n\r\n#{test_string}"
  #         # TODO: Fix this functionality
  #
  #         vprint_status("test skipped for PHP - functionality not correct")
  #         true
  #       else
  #         output.rstrip == "./show_args.exe\r\n#{test_string}\r\n\r\n#{test_string}\r\n\r\n#{test_string}"
  #       end
  #     else
  #       output = create_process('./show_args', args: [test_string, '', test_string, '', test_string])
  #       output.rstrip == "./show_args\n#{test_string}\n\n#{test_string}\n\n#{test_string}"
  #     end
  #   end
  #
  #   it 'should accept multiple args and return the create_process output' do
  #     if session.platform.eql? 'windows'
  #       output = create_process('./show_args.exe', args: [test_string, test_string])
  #       if session.type.eql? 'powershell'
  #         output.rstrip == "#{pwd}\\show_args.exe\r\n#{test_string}\r\n#{test_string}"
  #       elsif session.type.eql? 'shell'
  #         output = create_process('show_args.exe', args: [test_string, test_string])
  #         output.rstrip == "show_args.exe\r\n#{test_string}\r\n#{test_string}"
  #       elsif session.type.eql?('meterpreter') && session.arch.eql?('java')
  #         output.rstrip == ".\\show_args.exe\r\n#{test_string}\r\n#{test_string}"
  #       elsif session.arch.eql?("php")
  #         output = create_process('.\\show_args.exe', args: [test_string, test_string])
  #         output.rstrip == ".\\show_args.exe\r\n#{test_string}\r\n#{test_string}"
  #       else
  #         output.rstrip == "./show_args.exe\r\n#{test_string}\r\n#{test_string}"
  #       end
  #     else
  #       output = create_process('./show_args', args: [test_string, test_string])
  #       output.rstrip == "./show_args\n#{test_string}\n#{test_string}"
  #     end
  #   end
  #
  #   it 'should accept spaces and return the create_process output' do
  #     if session.platform.eql? 'windows'
  #       output = create_process('./show_args.exe', args: ['with spaces'])
  #       if session.type.eql? 'powershell'
  #         output.rstrip == "#{pwd}\\show_args.exe\r\nwith spaces"
  #       elsif session.type.eql? 'shell'
  #         output = create_process('show_args.exe', args: ['with spaces'])
  #         output.rstrip == "show_args.exe\r\nwith spaces"
  #       elsif session.type.eql?('meterpreter') && session.arch.eql?('java')
  #         output.rstrip == ".\\show_args.exe\r\nwith spaces"
  #       elsif session.arch.eql?("php")
  #         output = create_process('.\\show_args.exe', args: ['with spaces'])
  #         output.rstrip == ".\\show_args.exe\r\nwith spaces"
  #       else
  #         output.rstrip == "./show_args.exe\r\nwith spaces"
  #       end
  #     else
  #       output = create_process('./show_args', args: ['with spaces'])
  #       output.rstrip == "./show_args\nwith spaces"
  #     end
  #   end
  #
  #   it 'should accept environment variables and return the create_process output' do
  #     if session.platform.eql? 'windows'
  #       output = create_process('./show_args.exe', args: ['$PATH'])
  #       if session.type.eql? 'powershell'
  #         output.rstrip == "#{pwd}\\show_args.exe\r\n$PATH"
  #       elsif session.type.eql? 'shell'
  #         output = create_process('show_args.exe', args: ['$PATH'])
  #         output.rstrip == "show_args.exe\r\n$PATH"
  #       elsif session.type.eql?('meterpreter') && session.arch.eql?('java')
  #         output.rstrip == ".\\show_args.exe\r\n$PATH"
  #       elsif session.arch.eql?("php")
  #         output = create_process('.\\show_args.exe', args: ['$PATH'])
  #         output.rstrip == ".\\show_args.exe\r\n$PATH"
  #       else
  #         output.rstrip == "./show_args.exe\r\n$PATH"
  #       end
  #     else
  #       output = create_process('./show_args', args: ['$PATH'])
  #       output.rstrip == "./show_args\n$PATH"
  #     end
  #   end
  #
  #   it 'should accept environment variables within a string and return the create_process output' do
  #     if session.platform.eql? 'windows'
  #       output = create_process('./show_args.exe', args: ["it's $PATH"])
  #       if session.type.eql? 'powershell'
  #         output.rstrip == "#{pwd}\\show_args.exe\r\nit's $PATH"
  #       elsif session.type.eql? 'shell'
  #         output = create_process('show_args.exe', args: ["it's $PATH"])
  #         output.rstrip == "show_args.exe\r\nit's $PATH"
  #       elsif session.type.eql?('meterpreter') && session.arch.eql?('java')
  #         output.rstrip == ".\\show_args.exe\r\nit's $PATH"
  #       elsif session.arch.eql?("php")
  #         output = create_process('.\\show_args.exe', args: ["it's $PATH"])
  #         output.rstrip == ".\\show_args.exe\r\nit's $PATH"
  #       else
  #         output.rstrip == "./show_args.exe\r\nit's $PATH"
  #       end
  #     else
  #       output = create_process('./show_args', args: ["it's $PATH"])
  #       output.rstrip == "./show_args\nit's $PATH"
  #     end
  #   end
  #
  #   it 'should accept special characters and return the create_process output' do
  #     if session.platform.eql? 'windows'
  #       # TODO: Fix this functionality
  #       vprint_status('test skipped for Windows CMD - functionality not correct')
  #       true
  #       # output = create_process('./show_args.exe', args: ['~!@#$%^&*(){`1234567890[]",.\'<>'])
  #       # if session.type.eql? 'powershell'
  #       #   output.rstrip == "#{pwd}\\show_args.exe\r\n~!@#$%^&*(){`1234567890[]\",.\'<>"
  #       # elsif session.type.eql? 'shell'
  #       #   output = create_process('show_args.exe', args: ['~!@#$%^&*(){`1234567890[]",.\'<>'])
  #       #   output.rstrip == "show_args.exe\r\n~!@#$%^&*(){`1234567890[]\",.\'<>"
  #       # elsif session.type.eql?('meterpreter') && session.arch.eql?('java')
  #       #   output.rstrip == ".\\show_args.exe\r\n~!@#$%^&*(){`1234567890[]\",.\'<>"
  #       # elsif session.arch.eql?("php")
  #       #   output = create_process('.\\show_args.exe', args: ['~!@#$%^&*(){`1234567890[]",.\'<>'])
  #       #   output.rstrip == ".\\show_args.exe\r\n~!@#$%^&*(){`1234567890[]\",.\'<>"
  #       # else
  #       #   output.rstrip == "./show_args.exe\r\n~!@#$%^&*(){`1234567890[]\",.\'<>"
  #       # end
  #     else
  #       output = create_process('./show_args', args: ['~!@#$%^&*(){`1234567890[]",.\'<>'])
  #       output.rstrip == "./show_args\n~!@#$%^&*(){`1234567890[]\",.\'<>"
  #     end
  #   end
  #
  #   it 'should accept command line commands and return the create_process output' do
  #     if session.platform.eql? 'windows'
  #       output = create_process('./show_args.exe', args: ['run&echo'])
  #       if session.type.eql? 'powershell'
  #         output.rstrip == "#{pwd}\\show_args.exe\r\nrun&echo"
  #       elsif session.type.eql? 'shell'
  #         output = create_process('show_args.exe', args: ['run&echo'])
  #         output.rstrip == "show_args.exe\r\nrun&echo"
  #       elsif session.type.eql?('meterpreter') && session.arch.eql?('java')
  #         output.rstrip == ".\\show_args.exe\r\nrun&echo"
  #       elsif session.arch.eql?("php")
  #         # output = create_process('.\\show_args.exe', args: ['run&echo'])
  #         # TODO: We get ".\\show_args.exe\r\nrun\r\nECHO is on." here for some reason
  #         # output.rstrip == ".\\show_args\nrun&echo"
  #
  #         # TODO: Fix this functionality
  #         vprint_status("test skipped for PHP - functionality not correct")
  #         true
  #       else
  #         output.rstrip == "./show_args.exe\r\nrun&echo"
  #       end
  #     else
  #       output = create_process('./show_args', args: ['run&echo'])
  #       output.rstrip == "./show_args\nrun&echo"
  #     end
  #   end
  #
  #   it 'should accept semicolons to separate multiple command on a single line and return the create_process output' do
  #     if session.platform.eql? 'windows'
  #       output = create_process('./show_args.exe', args: ['run&echo;test'])
  #       if session.type.eql? 'powershell'
  #         output.rstrip == "#{pwd}\\show_args.exe\r\nrun&echo;test"
  #       elsif session.type.eql? 'shell'
  #         output = create_process('show_args.exe', args: ['run&echo;test'])
  #         output.rstrip == "show_args.exe\r\nrun&echo;test"
  #       elsif session.type.eql?('meterpreter') && session.arch.eql?('java')
  #         output.rstrip == ".\\show_args.exe\r\nrun&echo;test"
  #       elsif session.arch.eql?("php")
  #         # output = create_process('.\\show_args.exe', args: ['run&echo;test'])
  #         # TODO: we get ".\\show_args.exe\r\nrun\r\ntest" here, which I think might be fine but will skip for now
  #         #         until I get some eyes during a review
  #         # output.rstrip == ".\\show_args.exe\r\nrun&echo;test"
  #
  #         # TODO: Fix this functionality
  #         vprint_status("test skipped for PHP - functionality not correct")
  #         true
  #       else
  #         output.rstrip == "./show_args.exe\r\nrun&echo;test"
  #       end
  #     else
  #       output = create_process('./show_args', args: ['run&echo;test'])
  #       output.rstrip == "./show_args\nrun&echo;test"
  #     end
  #   end
  #
  #   it 'should accept spaces in the filename and return the create_process output' do
  #     if session.platform.eql? 'windows'
  #       # TODO: Fix this functionality
  #       vprint_status('test skipped for Windows CMD - functionality not correct')
  #       true
  #       # output = create_process('./show_args file.exe', args: [test_string, test_string])
  #       # if session.type.eql? 'powershell'
  #       #   output.rstrip == "#{pwd}\\show_args file.exe\r\n#{test_string}\r\n#{test_string}"
  #       # elsif session.type.eql? 'shell'
  #       #   # TODO: Fix this functionality
  #       #   #         Can't get the file to upload due to now being able to escape the space, our API considers this string as two args
  #       #   #         @ result = session.shell_command_token("#{cmd} && echo #{token}") - msf/core/post/file.rb
  #       #   #         "Expected no more than 2 args, received 4\r\nCertUtil: Too many arguments\r\n\r\nUsage:\r\n  CertUtil [Options] -decode InFile OutFile\r\n  Decode Base64-encoded file\r\n\r\nOptions:\r\n  -f                -- Force overwrite\r\n  -Unicode          -- Write redirected output in Unicode\r\n  -gmt              -- Display times as GMT\r\n  -seconds          -- Display times with seconds and milliseconds\r\n  -v                -- Verbose operation\r\n  -privatekey       -- Display password and private key data\r\n  -pin PIN                  -- Smart Card PIN\r\n  -sid WELL_KNOWN_SID_TYPE  -- Numeric SID\r\n            22 -- Local System\r\n            23 -- Local Service\r\n            24 -- Network Service\r\n\r\nCertUtil -?              -- Display a verb list (command list)\r\nCertUtil -decode -?      -- Display help text for the \"decode\" verb\r\nCertUtil -v -?           -- Display all help text for all verbs\r\n\r\n"
  #       #   vprint_status('test skipped for Windows CMD - functionality not correct')
  #       #   true
  #       # elsif session.type.eql?('meterpreter') && session.arch.eql?('java')
  #       #   output.rstrip == ".\\show_args file.exe\r\n#{test_string}\r\n#{test_string}"
  #       # elsif session.arch.eql?("php")
  #       #   output = create_process('.\\show_args file.exe', args: [test_string, test_string])
  #       #   output.rstrip == ".\\show_args file.exe\r\n#{test_string}\r\n#{test_string}"
  #       # else
  #       #   output.rstrip == "./show_args file.exe\r\n#{test_string}\r\n#{test_string}"
  #       # end
  #     else
  #       output = create_process('./show_args file', args: [test_string, test_string])
  #       output.rstrip == "./show_args file\n#{test_string}\n#{test_string}"
  #     end
  #   end
  #
  #   it 'should accept special characters in the filename and return the create_process output' do
  #     if session.platform.eql? 'windows'
  #       # TODO: Fix this functionality
  #       vprint_status('test skipped for Windows CMD - functionality not correct')
  #       true
  #       # output = create_process('./~!@#$%^&(){}.exe', args: [test_string, test_string])
  #       # if session.type.eql? 'powershell'
  #       #   output.rstrip == "#{pwd}\\~!@#$%^&(){}.exe\r\n#{test_string}\r\n#{test_string}"
  #       # elsif session.type.eql? 'shell'
  #       #   output = create_process('.\\"~!@#$%(){}.exe"', args: [test_string, test_string])
  #       #   output.rstrip == ".\\\\~!@\#$%(){}.exe\r\n#{test_string}\r\n#{test_string}"
  #       # elsif session.type.eql?('meterpreter') && session.arch.eql?('java')
  #       #   output.rstrip == ".\\~!@#$%^&(){}.exe\r\n#{test_string}\r\n#{test_string}"
  #       # elsif session.arch.eql?("php")
  #       #   output = create_process('.\\~!@#$%^&(){}.exe', args: [test_string, test_string])
  #       #   output.rstrip == ".\\~!@#$%^&(){}.exe\r\n#{test_string}\r\n#{test_string}"
  #       # else
  #       #   output.rstrip == "./~!@#$%^&(){}.exe\r\n#{test_string}\r\n#{test_string}"
  #       # end
  #     else
  #       output = create_process('./~!@#$%^&*(){}', args: [test_string, test_string])
  #       output.rstrip == "./~!@#$%^&*(){}\n#{test_string}\n#{test_string}"
  #     end
  #   end
  # end
end
