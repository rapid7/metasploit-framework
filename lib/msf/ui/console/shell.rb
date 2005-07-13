require 'msf/ui'
require 'msf/ui/console/input_methods'
require 'msf/ui/console/output_methods'

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

	def initialize(prompt, prompt_char = '>')
		# Initialize the input and output methods
		self.input  = StdioInputMethod.new		
		self.output = StdioOutputMethod.new

		begin
			self.input = ReadlineInputMethod.new(lambda { |str| tab_complete(str) })
		rescue
		end

		# Set the stop flag to false
		self.stop_flag = false

		# Initialize the prompt
		self.init_prompt = prompt
		self.prompt_char = prompt_char

		update_prompt

		super()
	end

	#
	# Performs tab completion on the supplied string
	#
	def tab_complete(str)
		return tab_complete_proc(str) if (tab_complete_proc)
	end

	#
	# Run the command processing loop
	#
	def run
		stop_flag = false

		while ((line = input.gets))
			run_single(line)

			break if (input.eof? or self.stop_flag)
		end
	end

	#
	# Stop processing user input
	#
	def stop
		self.stop_flag = true
	end

	#
	# Change the input prompt
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

		self.input.prompt = new_prompt
		self.prompt_char  = new_prompt_char if (new_prompt_char)
	end

	#
	# Color checks
	#
	
	#
	# Checks to see whether or not colors are supported on this shell
	# console
	#
	def supports_color?
		return (ENV['TERM'].match(/(?:vt10[03]|xterm(?:-color)?|linux|screen)/i) != nil)
	end

	#
	# Resets coloring so that it's back to normal
	#
	def reset_color
		print(colorize('clear'))
	end

	#
	# Returns colorized text if it's supported, otherwise an empty string
	#
	def colorize(*color)
		#return (supports_color? == false) ? '' : Rex::Ui::Text::Color.ansi(color)
		return Rex::Ui::Text::Color.ansi(*color)
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

	#
	# Parse a line into an array of arguments
	#
	def parse_line(line)
		line.gsub!(/(\r|\n)/, '')
		
		begin
			return args = Rex::Parser::Arguments.from_s(line)
		rescue ArgumentError
			print_error("Parse error: #{$!}")
		end

		return []
	end


	attr_accessor :input, :output, :stop_flag, :init_prompt
	attr_accessor :prompt_char, :tab_complete_proc

end

end end end
