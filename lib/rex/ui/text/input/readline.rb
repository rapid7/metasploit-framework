require 'rex/ui'

module Rex
module Ui
module Text

begin 
	require 'readline'

	###
	#
	# This class implements standard input using readline against
	# standard input.  It supports tab completion.
	#
	###
	class Input::Readline < Rex::Ui::Text::Input
		include ::Readline
		
		#
		# Initializes the readline-aware Input instance for text.
		#
		def initialize(tab_complete_proc = nil)
			if (tab_complete_proc)
				::Readline.basic_word_break_characters = "\x00"
				::Readline.completion_proc = tab_complete_proc
				@rl_saved_proc = tab_complete_proc
			end
		end

		#
		# Reattach the original completion proc
		#
		def reset_tab_completion(tab_complete_proc = nil)
			::Readline.basic_word_break_characters = "\x00"
			::Readline.completion_proc = tab_complete_proc || @rl_saved_proc
		end

		def child_readline(wtr, prompt, history)
			$0 = "<readline>"
			line = ::Readline.readline(prompt, history)
			line = "\n" if (line and line.strip.length == 0)
			wtr.write(line || "exit\n")
			wtr.flush
			wtr.close
			exit(0)
		end
		
		#
		# Whether or not the input medium supports readline.
		#
		def supports_readline
			true
		end
		
		#
		# Calls sysread on the standard input handle.
		#
		def sysread(len = 1)
			$stdin.sysread(len)

		end
		
		#
		# Read a line from stdin
		#
		def gets()
			$stdin.gets()
		end

		#
		# Prompt-based getline using readline. We run the actual Readline routine inside of
		# a forked child process. This solves a ton of problems introduced by the Readline
		# extension. Specifically, readline will use 100ms for each time slice that its thread
		# receives, massively slowing down the entire framework.
		#
		def pgets
		
			# if(Rex::Compat.is_windows())
			if(true)
				output.prompting
				line = ::Readline.readline(prompt, true)
				HISTORY.pop if (line and line.empty?)
				return line
			end

			# Wrap readline in a child process and secure with a mutex
			# This prevents threading hangs in the calling process.
			require "thread"
			@@child_mutex ||= Mutex.new
			@@child_mutex.synchronize do
			
			output.prompting

			rdr,wtr = ::IO.pipe
			pid = fork()

			if(not pid)
				child_readline(wtr, prompt, true)
			end

			line = nil
			while(not line)
				r = select([rdr], nil, nil, 0.01)
				if(r)
					line = rdr.sysread(16384)
					break if not line
				end
			end

			output.prompting(false)

			::Process.waitpid(pid, 0)

			if line
				HISTORY.push(line) if (not line.empty?)
				return line + "\n"
			else
				eof = true
				return line
			end
			
			# Release the readline mutex
			end
		end

		#
		# Returns the output pipe handle
		#
		def fd
			$stdin
		end
		
		#
		# Indicates that this input medium as a shell builtin, no need 
		# to extend.
		#
		def intrinsic_shell?
			true
		end

		#
		# The prompt that is to be displayed.
		#
		attr_accessor :prompt
		#
		# The output handle to use when displaying the prompt.
		#
		attr_accessor :output

	end
rescue LoadError
end

end
end
end
