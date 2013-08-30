$:.unshift(File.join(File.dirname(__FILE__)))
$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'lib'))
$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'test', 'lib'))

require 'fileutils'
require 'msf/base'
require 'meterpreter_spec_helper'
require 'meterpreter_specs'

module MsfTest

describe "JavaMeterpreter" do
	
	# This include brings in all the spec helper methods
	include MsfTest::MeterpreterSpecHelper
	
	# This include brings in all the specs that are generic across the 
	# meterpreter platforms
	include MsfTest::MeterpreterSpecs
	
	# This include brings in all the specs that are specific to the java
	# meterpreter
	include MsfTest::JavaMeterpreterSpecs

	before :all do
		@verbose = true
	
		@meterpreter_type = "java"
		
		## Set up an outupt directory
		@output_directory = File.join(File.dirname(__FILE__), "test_output_#{@meterpreter_type}")

		if File.directory? @output_directory
			FileUtils.rm_rf(@output_directory)
		end

		Dir.mkdir(@output_directory)
		@default_file = "#{@output_directory}/default"

		create_session_java
	end

	before :each do

	end

	after :each do
		@session.init_ui(@input, @output)
	end
	
	after :all do
		#FileUtils.rm_rf("*.jpeg")		
		#FileUtils.rm_rf("payload.jar")		
		FileUtils.rm_rf(@output_directory)
	end

	
	def create_session_java

		## Setup for win32
		@framework    = Msf::Simple::Framework.create
		
		test_modules_path = File.join(File.dirname(__FILE__), '..', '..', 'modules')
		@framework.modules.add_path(test_modules_path)
		
		@exploit_name = 'test/java_tester'
		@payload_name = 'java/meterpreter/bind_tcp'
		@input        = Rex::Ui::Text::Input::Stdio.new 
		@output       = Rex::Ui::Text::Output::File.new(@default_file)

		# Initialize the exploit instance
		exploit = @framework.exploits.create(@exploit_name)

		## Fire it off against a known-vulnerable host
		@session = exploit.exploit_simple(
			'Options'     => {},
			'Payload'     => @payload_name,
			'LocalInput'  => @input,
			'LocalOutput' => @output)

		puts @session.inspect

		## If a session came back, try to interact with it.
		if @session
			@session.load_stdapi
		else
			raise Exception "Couldn't get a session!"
		end
	end
  
end
end
