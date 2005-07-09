require 'msf/ui/console/command_dispatcher/encoder'

module Msf
module Ui
module Console
module CommandDispatcher

class Core

	include Msf::Ui::Console::CommandDispatcher

	# Returns the list of commands supported by this command dispatcher
	def commands
		return {
				"?"      => "Help menu",
				"exit"   => "Exit the console",
				"help"   => "Help menu",
				"info"   => "Displays information about one or more module",
				"search" => "Adds one or more module search paths",
				"set"    => "Sets a variable to a value",
				"unset"  => "Unsets one or more variables",
				"show"   => "Displays modules of a given type, or all modules",
				"use"    => "Selects a module by name",
				"quit"   => "Exit the console",
			}
	end

	# Instructs the driver to stop executing
	def cmd_exit(args)
		driver.stop
	end

	alias cmd_quit cmd_exit

	# Displays the command help banner
	def cmd_help(args)
		all_commands = {}

		driver.dispatcher_stack.reverse.each { |dispatcher|
			begin
				commands = dispatcher.commands
			rescue
				commands = nil
				next
			end

			all_commands.update(commands)
		}
	
		# Display the commands
		tbl = Table.new(
			Table::Style::Default,
			'Columns' => 
				[
					'Command',
					'Description'
				])

		all_commands.sort.each { |c|
			tbl << c
		}

		print(tbl.to_s)
	end

	# Displays information about one or more module
	def cmd_info(args)
		if (args.length == 0)
			print(
				"Usage: info mod1 mod2 mod3 ...\n\n" +
				"Queries the supplied module or modules for information.\n")
			return false
		end

		args.each { |name|
			mod = framework.modules.create(name)

			if (mod == nil)
				print_error("Invalid module: #{name}")
			else
				print(Serializer::ReadableText.dump_module(mod))
			end
		}
	end

	alias cmd_? cmd_help

	# Adds one or more search paths
	def cmd_search(args)
		if (args.length == 0)
			print_error("No search paths were provided.")
			return false
		end

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
			tbl = Table.new(
				Table::Style::Default,
				'Columns' =>
					[
						'Name',
						'Value'
					])

			datastore.each_pair { |name, value|
				tbl << [ name, value ]
			}

			print(tbl.to_s)

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

	# Unsets a value if it's been set
	def cmd_unset(args)
		# Determine which data store we're operating on
		if (mod = get_active_module())
			datastore = mod.datastore
		else
			datastore = driver.datastore
		end

		# No arguments?  No cookie.
		if (args.length == 0)
			print(
				"Usage: unset var1 var2 var3 ...\n\n" +
				"The unset command is used to unset one or more variables.\n")

			return false
		end

		while ((val = args.shift))
			print_line("Unsetting #{val}...")

			datastore.delete(val)
		end
	end

	# Displays the list of modules based on their type, or all modules if
	# no type is provided
	def cmd_show(args)
		args << "all" if (args.length == 0)

		args.each { |type|
			case type
				when 'all'
					show_encoders
					show_nops
					show_exploits
					show_payloads
					show_recon
				when 'encoders'
					show_encoders
				when 'nops'
					show_nops
				when 'exploits'
					show_exploits
				when 'payloads'
					show_payloads
				when 'recon'
					show_recon
			end
		}
	end

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
			when MODULE_NOPS
		end

		if (dispatcher != nil)
			driver.enstack_dispatcher(dispatcher)
		end

		# Update the active module
		set_active_module(mod)

		# Update the command prompt
		driver.update_prompt("#{mod.type}(#{mod_name}) ")
	end

protected

	#
	# Module list enumeration
	#

	def show_encoders
		show_module_set("Encoders", framework.encoders)
	end

	def show_nops
		show_module_set("NOP Generators", framework.nops)
	end

	def show_exploits
		show_module_set("Exploits", framework.exploits)
	end

	def show_payloads
		show_module_set("Payloads", framework.payloads)
	end

	def show_recon
		show_module_set("Recon", framework.recon)
	end

	def show_module_set(type, module_set)

		tbl = Table.new(
			Table::Style::Default,
			'Header'  => type,
			'Prefix'  => "\n",
			'Postfix' => "\n",
			'Columns' => 
				[
					'Name',
					'Description'
				],
			'ColProps' =>
				{
					'Name' =>
						{
							# Default max width to 25
							'MaxWidth' => 25
						}
				})

		module_set.each_module { |mod|
			instance = mod.new

			tbl << [ instance.alias, instance.description ]
		}

		print(tbl.to_s)
	end

end

end end end end
