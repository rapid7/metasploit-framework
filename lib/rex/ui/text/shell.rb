require 'rex/ui'

module Rex
module Ui
module Text

###
#
# The shell class provides a command-prompt style interface in a
# generic fashion.
#
###
module Shell

	###
	#
	# This module is meant to be mixed into an input medium class instance as a
	# means of extending it to display a prompt before each call to gets.
	#
	###
	module InputShell
		attr_accessor :prompt, :output

		def pgets
			output.print(prompt)
			output.flush

			output.prompting
			buf = gets
			output.prompting(false)

			buf
		end
	end

	#
	# Initializes a shell that has a prompt and can be interacted with.
	#
	def initialize(prompt, prompt_char = '>')
		# Set the stop flag to false
		self.stop_flag      = false
		self.disable_output = false
		self.stop_count	    = 0

		# Initialize the prompt
		self.init_prompt = prompt
		self.prompt_char = prompt_char

		# Initialize the user interface handles
		init_ui(Input::Stdio.new, Output::Stdio.new)
	end

	#
	# Initializes the user interface input/output classes.
	#
	def init_ui(in_input = nil, in_output = nil)

		# Initialize the input and output methods
		self.input  = in_input
		self.output = in_output

		if (self.input)
			begin
				if (self.input.supports_readline)
					self.input = Input::Readline.new(lambda { |str| tab_complete(str) })
				end
			rescue
			end

			# Extend the input medium as an input shell if the input medium
			# isn't intrinsicly a shell.
			if (self.input.intrinsic_shell? == false)
				self.input.extend(InputShell)
			end

			self.input.output = self.output
		end

		update_prompt('')
	end

	#
	# Resets the user interface handles.
	#
	def reset_ui
		init_ui
	end

	#
	# Sets the log source that should be used for logging input and output.
	#
	def set_log_source(log_source)
		self.log_source = log_source
	end

	#
	# Unsets the log source so that logging becomes disabled.
	#
	def unset_log_source
		set_log_source(nil)
	end

	#
	# Performs tab completion on the supplied string.
	#
	def tab_complete(str)
		return tab_complete_proc(str) if (tab_complete_proc)
	end

	#
	# Run the command processing loop.
	#
	def run(&block)

		begin

			while true
				# If the stop flag was set or we've hit EOF, break out
				break if (self.stop_flag or self.stop_count > 1)

				line = input.pgets
				log_output(input.prompt)

				# If a block was passed in, pass the line to it.  If it returns true,
				# break out of the shell loop.
				if (block)
					break if (line == nil or block.call(line))
				elsif(input.eof? or line == nil)
				# If you have sessions active, this will give you a shot to exit gravefully
				# If you really are ambitious, 2 eofs will kick this out
					self.stop_count += 1
					next if(self.stop_count > 1)
					run_single("quit")
				else
				# Otherwise, call what should be an overriden instance method to
				# process the line.
					run_single(line)
					self.stop_count = 0
				end

			end
		# Prevent accidental console quits
		rescue ::Interrupt
			output.print("Interrupt: use the 'exit' command to quit\n")
			retry
		end
	end

	#
	# Stop processing user input.
	#
	def stop
		self.stop_flag = true
	end

	#
	# Checks to see if the shell has stopped.
	#
	def stopped?
		self.stop_flag
	end

	#
	# Change the input prompt.
	#
	def update_prompt(prompt = nil, new_prompt_char = nil)
		if (self.input)
			if (prompt)
				new_prompt = self.init_prompt + ' ' + prompt + prompt_char + ' '
			else
				new_prompt = self.prompt || ''
			end

			# Save the prompt before any substitutions
			self.prompt = new_prompt

			# Set the actual prompt to the saved prompt with any substitutions
			# or updates from our output driver, be they color or whatever
			self.input.prompt = self.output.update_prompt(new_prompt)
			self.prompt_char  = new_prompt_char if (new_prompt_char)
		end
	end

	#
	# Output shortcuts
	#

	#
	# Prints an error message to the output handle.
	#
	def print_error(msg='')
		return if (output.nil?)

		# Errors are not subject to disabled output
		log_output(output.print_error(msg))
	end

	#
	# Prints a status message to the output handle.
	#
	def print_status(msg='')
		return if (disable_output == true)

		log_output(output.print_status(msg))
	end

	#
	# Prints a line of text to the output handle.
	#
	def print_line(msg='')
		return if (disable_output == true)

		log_output(output.print_line(msg))
	end

	#
	# Prints a raw message to the output handle.
	#
	def print(msg='')
		return if (disable_output == true)
		log_output(output.print(msg))
	end

	#
	# Whether or not output has been disabled.
	#
	attr_accessor :disable_output
	#
	# The input handle to read user input from.
	#
	attr_reader   :input
	#
	# The output handle to write output to.
	#
	attr_reader   :output

protected

	#
	# Parse a line into an array of arguments.
	#
	def parse_line(line)
		log_input(line)

		line.gsub!(/(\r|\n)/, '')

		begin
			return args = Rex::Parser::Arguments.from_s(line)
		rescue ::ArgumentError
			print_error("Parse error: #{$!}")
		end

		return []
	end

	#
	# Print the prompt, but do not log it.
	#
	def _print_prompt(prompt)
		output.print(prompt)
	end

	#
	# Writes the supplied input to the log source if one has been registered.
	#
	def log_input(buf)
		rlog(buf, log_source) if (log_source)
	end

	#
	# Writes the supplied output to the log source if one has been registered.
	#
	def log_output(buf)
		rlog(buf, log_source) if (log_source)
	end

	attr_writer   :input, :output # :nodoc:
	attr_accessor :stop_flag, :init_prompt # :nodoc:
	attr_accessor :prompt # :nodoc:
	attr_accessor :prompt_char, :tab_complete_proc # :nodoc:
	attr_accessor :log_source, :stop_count # :nodoc:

end

###
#
# Pseudo-shell interface that simply includes the Shell mixin.
#
###
class PseudoShell
	include Shell
end


end end end

