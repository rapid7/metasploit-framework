module Msf

###
# 
# This plugin is a simple editor command, designed to make it easy to edit modules in the console.
#
###
class Plugin::Editor < Msf::Plugin

	###
	#
	# This class implements a single edit command.
	#
	###
	class ConsoleCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher

		#
		# The dispatcher's name.
		#
		def name
			"Editor"
		end

		#
		# Returns the hash of commands supported by this dispatcher.
		#
		def commands
			{
				"edit" => "A handy editor commmand"
			}
		end

		#
		# This method handles the sample command.
		#
		def cmd_edit(*args)
			print_line ("Launching editor...")
			
			e = Rex::Compat.getenv("EDITOR") || "vi"

			if (not active_module) or (not (path = active_module.file_path))
				$stderr.puts "no active module selected"
				return nil
			end
		
			system(e + " " + path)
		end
	end

	#
	def initialize(framework, opts)
		super

		# console dispatcher commands.
		add_console_dispatcher(ConsoleCommandDispatcher)

		print_status("Editor plugin loaded.")
	end

	#
	def cleanup
		# If we had previously registered a console dispatcher with the console,
		# deregister it now.
		remove_console_dispatcher('Editor') 
	end

	#
	#
	def name
		"editor"
	end

	#
	def desc
		"Simple Editor Plugin"
	end

protected
end

end
