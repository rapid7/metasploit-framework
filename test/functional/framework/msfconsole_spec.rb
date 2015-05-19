$:.unshift(File.join(File.dirname(__FILE__)))
$:.unshift(File.join(File.dirname(__FILE__), '..', '..', 'lib'))
$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'lib'))
$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'test', 'lib'))

require 'fileutils'
require 'msf/base'
require 'msf_matchers'
require 'msf_test_case'


module MsfTest

include MsfTest::MsfMatchers


## This spec exists to help us describe the behavior of msfconsole - TODO

describe "Msfconsole" do
  
  ###
  # Setup!
  ###
  
  before :all do
    
    @working_directory = File.dirname(__FILE__)

    ## Static specs will make use of RC files here
    @static_resource_directory = "#{@working_directory}/msftest/resource"

    ## Directories for the generated specs
    @temp_directory = "#{@working_directory}/msfconsole_specs"
    @temp_input_directory = "#{@temp_directory}/generated_rc"

    ## Where all output from the runs will go
    @temp_output_directory = "#{@temp_directory}/output"

    ## Create a framework object
    @framework = ::Msf::Simple::Framework.create
  end

  before :each do
  end

  after :each do
  
  end

  after :all do
    ## Clean up
    #FileUtils.rm_rf(@temp_directory)
  end

  ###
  # Static Test cases!
  ###

  it "should start and let us run help" do
      data = start_console_and_run_rc("help","#{@static_resource_directory}/help.rc")
      
      success_strings = [	'help',
            'Database Backend Commands',
            'Core Commands' ]
      failure_strings = [] | generic_failure_strings
      failure_exception_strings = [] | generic_failure_exception_strings

      data.should contain_all_successes(success_strings)
      data.should contain_no_failures_except(failure_strings, failure_exception_strings)
  end

  it "should generate a meterpreter session against a vulnerable win32 host" do
    ## Set input & output to something sane
    input        = Rex::Ui::Text::Input::Stdio.new
    output       = Rex::Ui::Text::Output::File.new("temp.output")
    session = generate_x86_meterpreter_session(input, output)

    session.should_not be_nil	
  
    if session
      session.load_stdapi
      session.run_cmd("help")
    else
      flunk "Error interacting with session"
    end
  end
  
  ###
  # Dynamic Test Cases!!
  ###

  @working_directory = File.dirname(__FILE__)

  ## Directories for the generated specs
  @temp_directory = "#{@working_directory}/msfconsole_specs"
  @temp_input_directory = "#{@temp_directory}/generated_rc"

  ## Where all output from the runs will go
  @temp_output_directory = "#{@temp_directory}/output"

  if File.directory? @temp_directory
    FileUtils.rm_rf(@temp_directory)
  end

  Dir.mkdir(@temp_directory)
  Dir.mkdir(@temp_input_directory)
  Dir.mkdir(@temp_output_directory)
  
  Dir.glob("#{@working_directory}/msftest/*.msftest").each do |filename|
    
    ## Parse this test case
    test_case = MsfTestCase.new(filename)
    puts "Found #{test_case.name} in: #{filename}" 	

    ## Write the commands back to a temporary RC file
    puts "Writing #{@temp_input_directory}/#{test_case.name}.rc"
    File.open("#{@temp_input_directory}/#{test_case.name}.rc", 'w') { |f|  f.puts test_case.commands } 
    
    ## Create the rspec Test Case
    it "should #{test_case.name}" do
      
      ## Gather the success / failure strings, and combine with the generics
      success_strings = test_case.expected_successes
      failure_strings = test_case.expected_failures | generic_failure_strings
      failure_exception_strings = test_case.expected_failure_exceptions | generic_failure_exception_strings
      
      ## run the commands
      data = start_console_and_run_rc( test_case.name, "#{@temp_input_directory}/#{test_case.name}.rc")	
          
      ## check the output		
      data.should contain_all_successes(success_strings)
      data.should contain_no_failures_except(failure_strings, failure_exception_strings)
      
      ## Clean up 
      #File.delete("#{@temp_input_directory}/#{test_case.name}.rc")
      #File.delete("#{@temp_output_directory}/#{test_case.name}")
    end
  end

  ###
  # Test case helpers:
  ###
  def generic_success_strings
    []	
  end
  
  def generic_failure_strings
    ['fatal', 'fail', 'error', 'exception']
  end
  
  def generic_failure_exception_strings
    []
  end

  def start_console_and_run_rc(name,rc_file, database_file=false)
    output_file = "#{@temp_output_directory}/#{name}"

    if database_file
      msfconsole_string = "ruby #{@working_directory}/../../../msfconsole -o #{output_file} -r #{rc_file} -y #{database_file}"
    else
      msfconsole_string = "ruby #{@working_directory}/../../../msfconsole -o #{output_file} -r #{rc_file}"
    end
    
    system("#{msfconsole_string}")

    data = hlp_file_to_string("#{output_file}")			
  end
  
  	def generate_x86_meterpreter_session(input, output)
    ## Setup for win32
    exploit_name = 'windows/smb/psexec'
    payload_name = 'windows/meterpreter/bind_tcp'
      
    ## Fire it off against a known-vulnerable host
    session = @framework.exploits.create(exploit_name).exploit_simple(
      'Options'     => {'RHOST' => "vulnerable", "SMBUser" => "administrator", "SMBPass" => ""},
      'Payload'     => payload_name,
      'LocalInput'  => input,
      'LocalOutput' => output)

    ## If a session came back, try to interact with it.
    if session
      return session
    else
      return nil
    end
  end

  	def generate_win64_meterpreter_session(input, output)
    raise "Not Implemented"
  end


  	def generate_java_meterpreter_session(input, output)
    raise "Not Implemented"
  end
 
   	def generate_php_meterpreter_session(input, output)
    raise "Not Implemented"
  end

  def hlp_file_to_string(filename)
    data = ""
    f = File.open(filename, "r") 
    f.each_line do |line|
      data += line
    end
    return data
  end
end
end
