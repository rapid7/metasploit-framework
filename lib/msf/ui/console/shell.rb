require 'Msf/Ui'
require 'Msf/Ui/Console/InputMethods'
require 'Msf/Ui/Console/OutputMethods'

module Msf
module Ui
module Console

###
#
# Shell
# -----
#
# The shell class provides a command-prompt style interface in a 
# generic fashion.
#
###
module Shell

	def initialize(prompt)
		# Initialize the input and output methods
		self.input  = StdioInputMethod.new
		self.output = StdioOutputMethod.new

		begin
			self.input = ReadlineInputMethod.new
		rescue
		end

		# Set the stop flag to false
		self.stop_flag = false

		# Initialize the prompt
		self.init_prompt = prompt

		update_prompt

		super()
	end

	# Run the command processing loop
	def run
		stop_flag = false

		while ((line = input.gets))
			run_single(line)

			break if (input.eof? or self.stop_flag)
		end
	end

	# Stop processing user input
	def stop
		self.stop_flag = true
	end

	# Change the input prompt
	def update_prompt(prompt = '')
		self.input.prompt = self.init_prompt + ' ' + prompt + '> '
	end

	#
	# Output shortcuts
	#
	
	def print_error(msg)
		output.print_error(msg)
	end

	def print_status(msg)
		output.print_status(msg)
	end

	def print_line(msg)
		output.print_line(msg)
	end

	def print(msg)
		output.print(msg)
	end

protected

	# Parse a line into an array of arguments
	def parse_line(line)
		line.gsub!("(\r|\n)", '')

		args = line.split(' ')
	end


	attr_accessor :input, :output, :stop_flag, :init_prompt

end

end end end
