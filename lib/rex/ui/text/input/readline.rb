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

		@@rl_thread  = nil
		@@rl_pipes   = nil
		@@rl_prompt  = ''
		@@rl_history = false

		#
		# Initializes the readline-aware Input instance for text.
		#
		def initialize(tab_complete_proc = nil)
			if (tab_complete_proc)
				::Readline.basic_word_break_characters = "\x00"
				::Readline.completion_proc = tab_complete_proc
			end
		end
	
		#
		# Start the readline thread
		#
		def readline_start
			return if @@rl_thread
			@@rl_pipes  = Rex::Compat.pipe		
			@@rl_thread = ::Thread.new do
				begin
				while (line = ::Readline.readline(@@rl_prompt, @@rl_history))
					@@rl_pipes[1].write(line+"\n")
					@@rl_pipes[1].flush
				end
				rescue ::Exception => e
					$stderr.puts "ERROR: readline thread: #{e.to_s} #{e.backtrace.to_s}"
				end
			end
		end

		#
		# Stop the readline thread
		#
		def readline_stop			
			# Stop the reader thread
			if (@@rl_thread)
				begin
					@@rl_thread.kill
				rescue ::Exception
				end
				@@rl_thread = nil
			end
			
			# Close the pipes
			if (@@rl_pipes)
				begin
					@rl_pipes[0].close
					@rl_pipes[1].close
				rescue ::Exception
				end
				@@rl_pipes = nil
			end
		end 
		
		#
		# Status of the readline thread
		#
		def readline_status
			@@rl_thread ? true : false
		end
		
		#
		# Calls sysread on the standard input handle.
		#
		def sysread(len = 1)
			if (! readline_status)
				$stderr.puts "ERROR: sysread() called outside of thread mode: " + caller(1).to_s
				return ''
			end
			@@rl_pipes[0].sysread(len)
		end
		
		#
		# Fake gets using readline
		#
		def gets()
			if (! readline_status)
				$stderr.puts "ERROR: gets() called outside of thread mode: " + caller(1).to_s
				return ''
			end

			@@rl_pipes[0].gets
		end

		#
		# Print a prompt and flush standard output.
		#
		def prompt(prompt)
			_print_prompt(prompt)
			return gets()
		end
	
		#
		# Prompt-based getline using readline.
		# XXX: Incompatible with thread mode
		#
		def pgets
			if (readline_status)
				$stderr.puts "ERROR: pgets called inside of thread mode: " + caller(1).to_s
				return ''
			end
		
			if ((line = ::Readline.readline(prompt, true)))
				HISTORY.pop if (line.empty?)
				return line + "\n"
			else
				eof = true
				return line
			end
		end

		#
		# Returns the output pipe handle
		#
		def fd
			if (! readline_status)
				$stderr.puts "fd called outside of thread mode: " + caller(1).to_s
				return ''
			end
					
			@@rl_pipes[0]
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
