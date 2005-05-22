require 'Msf/Ui/Console/CommandDispatcher/Encoder'

module Msf
module Ui
module Console
module CommandDispatcher

class Core

	include Msf::Ui::Console::CommandDispatcher

	# Uses a module
	def cmd_use(args)
		if (args.length == 0)
			print(
				"Usage: use module_name\n\n" +
				"The use command is used to interact with a module of a given name.\n")
			return false
		end

		# Try to create an instance of the supplied module name
		mod_name = args[0]

		begin
			if ((mod = framework.modules.create(mod_name)) == nil)
				print_error("Failed to load module: #{mod_name}")
				return false
			end
		rescue NameError => info
			print_error("The supplied module name is ambiguous.")
			return false
		end

		# Enstack the command dispatcher for this module type
		dispatcher = nil

		case mod.type
			when MODULE_ENCODER
				dispatcher = Encoder
		end

		if (dispatcher != nil)
			driver.enstack_dispatcher(dispatcher)
		end

		# Update the active module
		set_active_module(mod)

		# Update the command prompt
		driver.update_prompt("#{mod.type}(#{mod_name}) ")
	end

	# Adds one or more search paths
	def cmd_search(args)
		args.each { |path|
			framework.modules.add_module_path(path)
		}

		print_line("Added #{args.length} search paths.")
	end

	# Sets a name to a value in a context aware environment
	def cmd_set(args)

		# Determine which data store we're operating on
		if (mod = get_active_module())
			datastore = mod.datastore
		else
			datastore = driver.datastore
		end

		# Dump the contents of the active datastore if no args were supplied
		if (args.length == 0)
			datastore.each_pair { |name, value|
				print_line("#{name}: #{value}")
			}

			return true
		elsif (args.length < 2)
			print(
				"Usage: set name value\n\n" +
				"Sets an arbitrary name to an arbitrary value.\n")
			return false
		end

		# Set the supplied name to the supplied value
		name  = args[0]
		value = args[1]

		datastore[name] = value

		print_line("#{name} => #{value}")
	end

	# Instructs the driver to stop executing
	def cmd_exit(args)
		print_line("Exiting...")

		driver.stop
	end

	alias cmd_quit cmd_exit

end

end end end end
