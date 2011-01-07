module MsfTest
module MeterpreterSpecHelper

	def self.included(base)
        	base.class_eval do

			def generic_failure_strings
				['fail', 'error', 'exception']
			end
			
			def generic_failure_exception_strings
				['nserror.dll', 'tiki-error.php','tiki-error_simple.php','tiki-rss_error.php'] ##ugh, this is dependent on the target
			end

			def hlp_run_command_check_output(name,command,success_strings=[],fail_strings=[], fail_exception_strings=[])

				fail_strings = fail_strings | generic_failure_strings
				fail_exception_strings = fail_exception_strings | generic_failure_exception_strings

				temp_command_file  = "#{@output_directory}/#{name}"
		
				command_output = Rex::Ui::Text::Output::File.new(temp_command_file)
				@session.init_ui(@input, command_output)
	
				command_output.print_line("meterpreter_functional_test_start")
				
				if @verbose
					puts "Running Command: " + command
				end
				
				@session.run_cmd(command)
				command_output.print_line("meterpreter_functional_test_end")		
				data = hlp_file_to_string(temp_command_file)
		
				## Ugh, this is ghetto.
				x = MsfTestCaseHelper.new(@debug)
				x.complete?(data,"meterpreter_functional_test_start","meterpreter_functional_test_end").should be_true
				x.all_successes_exist?(data, success_strings).should be_true
				x.no_failures_exist?(data, fail_strings, fail_exception_strings ).should be_true
			end
	
			def hlp_file_to_string(filename)
				data = ""
				f = File.open(filename, "r") 
				f.each_line do |line|
					data += line
				end
				return data
			end
	
			def hlp_string_to_file(string, filepath)
				# Create a new file and write to it  
				File.open(filepath, 'w') do |f2|  
		  			f2.puts string
				end 
			end
		end
	end
end
end
