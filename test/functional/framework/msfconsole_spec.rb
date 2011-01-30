$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'lib'))
$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..', 'test', 'lib'))


require 'fileutils'
require 'msf_matchers'
require 'singleton'
require 'nokogiri'

Spec::Runner.configure do |config|  
  config.include(MsfMatchers)  
end

module MsfTest

class MsfTestCase
	
	attr_accessor :verbose, :name, :description
	attr_accessor :commands, :expected_successes,  :expected_failures
	attr_accessor :expected_failure_exceptions
	
	def initialize(filename,verbose=nil)
		@filename = filename
		@verbose = verbose || false
		@name = ""
		@description = ""
		@commands = ""
		@expected_successes = []
		@expected_failures  = []
		@expected_failure_exceptions = []
		parse
	end

	def parse
		
		if @verbose
			puts "Parsing: #{@filename}"
		end
		
		input = Nokogiri::XML(File.new(@filename))

		@name = input.root.xpath("//name").text.strip
		
		##
		## Get commands
		##
		@commands = input.root.xpath("//commands").children.to_s.gsub("\t","")

		##
		## Get successes
		##
		@expected_successes = input.root.xpath("//success").collect(&:text)
		@expected_successes.each { |item| item.strip!}
		
		## 
		## Get failures
		## 
		@expected_failures = input.root.xpath("//failure").collect(&:text)
		@expected_failures.each { |item| item.strip!}
			
		## 
		## Get failure exceptions
		## 
		@expected_failure_exceptions = input.root.xpath("//failure_exceptions").collect(&:text)
		@expected_failure_exceptions.each { |item| item.strip!}
	end
end




describe "Msfconsole" do
	
	###
	### Setup!
	###
	
	before :all do
		
		## This needs to be here for the actual test cases (and helpers)
		## Note that the actual setup happens pre-rspec (see below)
		@working_directory = "msfconsole_spec_working"
		@output_directory = "#{@working_directory}/output"
		@input_directory = "#{@working_directory}/input"
		@default_file = "#{@output_directory}/default"
	end

	before :each do

	end

	after :each do
	end

	after :all do
		## CLEANUP THE WORKING DIRECTORY	
		FileUtils.rm_rf(@working_directory)
	end

	###
	### Static Test cases!
	###
	it "should start and let us run help" do
			success_strings = [	'help',
						'Database Backend Commands',
						'Core Commands' ]
				
			failure_strings = [] | generic_failure_strings
			failure_exception_strings = [] | generic_failure_exception_strings

			data = hlp_run_command_check_output("help","msftest/resource/help.rc")
			
			data.should contain_all_successes(success_strings)
			data.should contain_no_failures_except(failure_strings, failure_exception_strings)
	end

	###
	### Dynamic Test Cases!!
	###

	## PRE_TEST WORKING DIR SETUP`
	@working_directory = "msfconsole_spec_working"
	if File.directory? @working_directory
		FileUtils.rm_rf(@working_directory)
	end
	Dir.mkdir(@working_directory)

	## INPUT
	@input_directory = "#{@working_directory}/input"
	if File.directory? @input_directory
		FileUtils.rm_rf(@input_directory)
	end
	Dir.mkdir(@input_directory)

	@output_directory = "#{@working_directory}/output"
	if File.directory? @output_directory
		FileUtils.rm_rf(@output_directory)
	end
	Dir.mkdir(@output_directory)
	## END PRE_TEST WORKING DIR SETUP

	Dir.glob("msftest/*.msftest").each do |filename|
		
		## Parse this test case
		test_case = MsfTestCase.new(filename)
		puts "Found #{test_case.name} in: #{filename}" 	

		## Write the commands back to a temporary RC file
		File.open("#{@input_directory}/#{test_case.name}.rc", 'w') { |f|  f.puts test_case.commands } 
		
		## Create the rspec Test Case
		it "should #{test_case.name}" do
			
			## Gather the success / failure strings, and combine with the generics
			success_strings = test_case.expected_successes
			failure_strings = test_case.expected_failures | generic_failure_strings
			failure_exception_strings = test_case.expected_failure_exceptions | generic_failure_exception_strings
			
			## run the commands
			data = hlp_run_command_check_output( test_case.name, "#{@input_directory}/#{test_case.name}.rc")	
					
			## check the output		
			data.should contain_all_successes(success_strings)
			data.should contain_no_failures_except(failure_strings, failure_exception_strings)
			
			## Clean up 
			#File.delete("#{@input_directory}/#{test_case.name}.rc")
			#File.delete("#{@output_directory}/#{test_case.name}")
		end
	end



	###
	### Test case helpers:
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

	def hlp_do_test_setup

	end

	def hlp_run_command_check_output(name,rc_file, database_file=false)

		temp_output_file  = "#{@output_directory}/#{name}"
		if database_file
			msfconsole_string = "../../../msfconsole -o #{temp_output_file} -r #{rc_file} -y #{database_file}"
		else
			msfconsole_string = "../../../msfconsole -o #{temp_output_file} -r #{rc_file}"
		end

		puts "\n\nName: #{name}"
		puts "RC File: #{rc_file}"
		puts "Output File: #{temp_output_file}"	
		puts "System Command: #{msfconsole_string}"	
		
		system(msfconsole_string)
		data = hlp_file_to_string(temp_output_file)			
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
