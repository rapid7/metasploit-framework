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
		
		update_prompt
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
		stop_flag = false

		begin
		
			while ((line = input.pgets))
				log_output(input.prompt)

				# If a block was passed in, pass the line to it.  If it returns true,
				# break out of the shell loop.
				if (block)
					break if (block.call(line))
				# Otherwise, call what should be an overriden instance method to
				# process the line.
				else
					run_single(line)
				end

				# If the stop flag was set or we've hit EOF, break out
				break if (input.eof? or self.stop_flag)
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
	def update_prompt(prompt = '', new_prompt_char = nil)
		new_prompt = self.init_prompt + ' ' + prompt + prompt_char + ' '

		# Substitute colors
		new_prompt.gsub!(/%u/, colorize('underline'))
		new_prompt.gsub!(/%b/, colorize('bold'))
		new_prompt.gsub!(/%c/, colorize('clear'))
		new_prompt.gsub!(/%red/, colorize('red'))
		new_prompt.gsub!(/%grn/, colorize('green'))
		new_prompt.gsub!(/%blu/, colorize('blue'))
		new_prompt.gsub!(/%yel/, colorize('yellow'))
		new_prompt.gsub!(/%cya/, colorize('cyan'))
		new_prompt.gsub!(/%whi/, colorize('white'))
		new_prompt.gsub!(/%mag/, colorize('magenta'))
		new_prompt.gsub!(/%blk/, colorize('black'))
		new_prompt.gsub!(/%dred/, colorize('dark', 'red'))
		new_prompt.gsub!(/%dgrn/, colorize('dark', 'green'))
		new_prompt.gsub!(/%dblu/, colorize('dark', 'blue'))
		new_prompt.gsub!(/%dyel/, colorize('dark', 'yellow'))
		new_prompt.gsub!(/%dcya/, colorize('dark', 'cyan'))
		new_prompt.gsub!(/%dwhi/, colorize('dark', 'white'))
		new_prompt.gsub!(/%dmag/, colorize('dark', 'magenta'))

		self.input.prompt = new_prompt if (self.input)
		self.prompt_char  = new_prompt_char if (new_prompt_char)
	end

	#
	# Color checks
	#
	
	#
	# Checks to see whether or not colors are supported on this shell
	# console.
	#
	def supports_color?
		# Color is disabled until we resolve some bugs
		return false

		term = Rex::Compat.getenv('TERM')
		(term and term.match(/(?:vt10[03]|xterm(?:-color)?|linux|screen)/i) != nil)
	end

	#
	# Resets coloring so that it's back to normal.
	#
	def reset_color
		print(colorize('clear'))
	end

	#
	# Returns colorized text if it's supported, otherwise an empty string.
	#
	def colorize(*color)
		return do_colorize(*color)
	end

	#
	# Colorize if this shell supports it
	#
	def do_colorize(*color) 
		supports_color?() ? Rex::Ui::Text::Color.ansi(*color) : ''
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
		rlog(do_colorize("red") + buf + do_colorize("clear"), log_source) if (log_source)
	end

	#
	# Writes the supplied output to the log source if one has been registered.
	#
	def log_output(buf)
		rlog(do_colorize("blue") + buf + do_colorize("clear"), log_source) if (log_source)
	end

	attr_writer   :input, :output # :nodoc:
	attr_accessor :stop_flag, :init_prompt # :nodoc:
	attr_accessor :prompt_char, :tab_complete_proc # :nodoc:
	attr_accessor :log_source # :nodoc:

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
