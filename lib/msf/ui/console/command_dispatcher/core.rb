require 'msf/ui/console/command_dispatcher/encoder'
require 'msf/ui/console/command_dispatcher/exploit'
require 'msf/ui/console/command_dispatcher/nop'
require 'msf/ui/console/command_dispatcher/payload'
require 'msf/ui/console/command_dispatcher/recon'

module Msf
module Ui
module Console
module CommandDispatcher

class Core

	include Msf::Ui::Console::CommandDispatcher

	# Session command options
	@@session_opts = Rex::Parser::Arguments.new(
		"-i" => [ true,  "Interact with the supplied session identifier." ],
		"-h" => [ false, "Help banner."                                   ],
		"-l" => [ false, "List all active sessions."                      ],
		"-q" => [ false, "Quiet mode."                                    ])

	@@jobs_opts = Rex::Parser::Arguments.new(
		"-h" => [ false, "Help banner."                                   ],
		"-k" => [ true,  "Terminate the specified job name."              ],
		"-l" => [ false, "List all running jobs."                         ])

	# Returns the list of commands supported by this command dispatcher
	def commands
		{
			"?"       => "Help menu",
			"back"    => "Move back from the current context",
			"banner"  => "Display an awesome metasploit banner",
			"exit"    => "Exit the console",
			"help"    => "Help menu",
			"info"    => "Displays information about one or more module",
			"jobs"    => "Displays and manages jobs",
			"quit"    => "Exit the console",
			"save"    => "Saves the active datastores",
			"search"  => "Adds one or more module search paths",
			"session" => "Dump session listings and display information about sessions",
			"set"     => "Sets a variable to a value",
			"setg"    => "Sets a global variable to a value",
			"show"    => "Displays modules of a given type, or all modules",
			"unset"   => "Unsets one or more variables",
			"unsetg"  => "Unsets one or more global variables",
			"use"     => "Selects a module by name",
			"version" => "Show the console library version number",
		}
	end

	def name
		"Core"
	end

	#
	# Pop the current dispatcher stack context, assuming it isn't pointed at
	# the core stack context.
	#
	def cmd_back(*args)
		if (driver.dispatcher_stack.size > 1)
			# Reset the active module if we have one
			if (active_module)
				self.active_module = nil
			end

			# Destack the current dispatcher
			driver.destack_dispatcher
	
			# Restore the prompt
			driver.update_prompt
		end
	end

	#
	# Display one of the fabulous banners
	#
	def cmd_banner(*args)
		banner  = Banner.to_s + "\n\n"
		banner += "       =[ msf v#{Msf::Framework::Version}\n"
		banner += "+ -- --=[ "
		banner += "#{framework.stats.num_exploits} exploits - "
		banner += "#{framework.stats.num_payloads} payloads\n"
		banner += "+ -- --=[ "
		banner += "#{framework.stats.num_encoders} encoders - "
		banner += "#{framework.stats.num_nops} nops\n"
		banner += "       =[ "
		banner += "#{framework.stats.num_recon} recon\n"
		banner += "\n"

		# Display the banner
		print(banner)
	end

	#
	# Instructs the driver to stop executing
	#
	def cmd_exit(*args)
		driver.stop
	end

	alias cmd_quit cmd_exit

	#
	# Displays the command help banner
	#
	def cmd_help(*args)
		print(driver.help_to_s)
	end

	#
	# Displays information about one or more module
	#
	def cmd_info(*args)
		if (args.length == 0)
			if (active_module)
				print(Serializer::ReadableText.dump_module(active_module))
				return true
			else
				print(
					"Usage: info mod1 mod2 mod3 ...\n\n" +
					"Queries the supplied module or modules for information.\n")
				return false
			end
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

	#
	# Displays and manages running jobs for the active instance of the
	# framework.
	#
	def cmd_jobs(*args)
		if (args.length == 0)
			args.unshift("-l")
		end

		# Parse the command options
		@@jobs_opts.parse(args) { |opt, idx, val|
			case opt
				when "-l"
					print("\n" +
						Serializer::ReadableText.dump_jobs(framework) + "\n")

				# Terminate the supplied job name
				when "-k"
					print_line("Stopping job: #{val}...")

					framework.jobs.stop_job(val)

				when "-h"
					print(
						"Usage: jobs [options]\n\n" +
						"Active job manipulation and interaction.\n" +
						@@jobs_opts.usage())
					return false
			end
		}
	end

	#
	# Saves the active datastore contents to disk for automatic use across
	# restarts of the console.
	#
	def cmd_save(*args)
		# Save the console config
		driver.save_config

		# Save the framework's datastore
		begin
			framework.save_config
	
			if (active_module)
				active_module.save_config
			end
		rescue
			log_error("Save failed: #{$!}")
			return false
		end
	
		print_line("Saved configuration to: #{Msf::Config.config_file}")
	end

	#
	# Adds one or more search paths
	#
	def cmd_search(*args)
		if (args.length == 0)
			print_error("No search paths were provided.")
			return true
		end

		totals    = {}
		overall   = 0
		curr_path = nil

		begin 
			# Walk the list of supplied search paths attempting to add each one
			# along the way
			args.each { |path|
				curr_path = path

				if (counts = framework.modules.add_module_path(path))
					counts.each_pair { |type, count|
						totals[type] = (totals[type]) ? (totals[type] + count) : count
	
						overall += count
					}
				end
			}
		rescue NameError
			log_error("Failed to add search path #{curr_path}: #{$!}")
			return true
		end

		added = "Loaded #{overall} modules:\n"

		totals.each_pair { |type, count|
			added += "    #{count} #{type}#{count != 1 ? 's' : ''}\n"
		}

		print(added)

		recalculate_tab_complete
	end

	#
	# Provides an interface to the sessions currently active in the framework.
	#
	def cmd_session(*args)
		if (args.length == 0)
			args.unshift("-h")
		end

		begin
		method = nil
		quiet  = false
		sid    = nil

		# Parse the command options
		@@session_opts.parse(args) { |opt, idx, val|
			case opt
				when "-q"
					quiet = true

				# Interact with the supplied session identifier
				when "-i"
					method = 'interact'
					sid    = val

				# Display the list of active sessions
				when "-l"
					print("\n" + 
						Serializer::ReadableText.dump_sessions(framework) + "\n")

				# Display help banner
				when "-h"
					print(
						"Usage: session [options]\n\n" +
						"Active session manipulation and interaction.\n" +
						@@session_opts.usage())
					return false
			end
		}
	
		# Now, perform the actual method
		case method
			when 'interact'
				if ((session = framework.sessions.get(sid)))
					if (session.interactive?)
						print_status("Starting interaction with #{session.name}...\n") if (quiet == false)

						# Set the session's input and output handles
						session.init_ui(driver.input, driver.output)

						# Interact
						session.interact()

						# Once interact returns, swap the output handle with a
						# none output
						#
						# TODO: change this to use buffered output so we can call
						# flush later on
						session.reset_ui
					else
						print_error("Session #{sid} is non-interactive.")
					end
				else
					print_error("Invalid session identifier: #{sid}")
				end
		end

		rescue
			log_error("Session manipulation failed: #{$!}")
		end

		return true
	end

	#
	# Sets a name to a value in a context aware environment
	#
	def cmd_set(*args)
	
		# Figure out if these are global variables
		global = false

		if (args[0] == '-g')
			args.shift
			global = true
		end

		# Determine which data store we're operating on
		if (active_module and global == false)
			datastore = active_module.datastore
		else
			global = true
			datastore = self.framework.datastore
		end

		# Dump the contents of the active datastore if no args were supplied
		if (args.length == 0)
			# If we aren't dumping the global data store, then go ahead and
			# dump it first
			if (!global)
				print("\n" +
					Msf::Serializer::ReadableText.dump_datastore(
						"Global", framework.datastore))
			end

			# Dump the active datastore
			print("\n" +
				Msf::Serializer::ReadableText.dump_datastore(
					(global) ? "Global" : "Module: #{active_module.refname}",
					datastore) + "\n")
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

		# If the driver indicates that the value is not valid, bust out.
		if (driver.on_variable_set(global, name, value) == false)
			print_error("The value specified for #{name} is not valid.")
			return true
		end

		datastore[name] = value

		print_line("#{name} => #{value}")
	end

	#
	# Sets the supplied variables in the global datastore
	#
	def cmd_setg(*args)
		args.unshift('-g')

		cmd_set(*args)
	end

	#
	# Displays the list of modules based on their type, or all modules if
	# no type is provided
	#
	def cmd_show(*args)
		mod = self.active_module

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
				when 'options'
					if (mod)
						show_options(mod)
					else
						print_error("No module selected.")
					end
				when 'advanced'
					if (mod)
						show_advanced_options(mod)
					else
						print_error("No module selected.")
					end
			end
		}
	end

	#
	# Unsets a value if it's been set
	#
	def cmd_unset(*args)

		# Figure out if these are global variables
		global = false

		if (args[0] == '-g')
			args.shift
			global = true
		end

		# Determine which data store we're operating on
		if (active_module and global == false)
			datastore = active_module.datastore
		else
			datastore = framework.datastore
		end

		# No arguments?  No cookie.
		if (args.length == 0)
			print(
				"Usage: unset var1 var2 var3 ...\n\n" +
				"The unset command is used to unset one or more variables.\n")

			return false
		end

		while ((val = args.shift))
			if (driver.on_variable_unset(global, val) == false)
				print_error("The variable #{val} cannot be unset at this time.")
				next
			end

			print_line("Unsetting #{val}...")

			datastore.delete(val)
		end
	end

	#
	# Unsets variables in the global data store
	#
	def cmd_unsetg(*args)
		args.unshift('-g')

		cmd_unset(*args)
	end

	#
	# Uses a module
	#
	def cmd_use(*args)
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
		rescue Rex::AmbiguousArgumentError => info
			print_error(info.to_s)
		rescue NameError => info
			log_error("The supplied module name is ambiguous: #{$!}.")
		end

		return false if (mod == nil)

		# Enstack the command dispatcher for this module type
		dispatcher = nil

		case mod.type
			when MODULE_ENCODER
				dispatcher = Encoder
			when MODULE_EXPLOIT
				dispatcher = Exploit
			when MODULE_NOP
				dispatcher = Nop
			when MODULE_PAYLOAD
				dispatcher = Payload
			when MODULE_RECON
				dispatcher = Recon
			else
				print_error("Unsupported module type: #{mod.type}")
				return false
		end

		# If there's currently an active module, go back
		if (active_module)
			cmd_back()
		end

		if (dispatcher != nil)
			driver.enstack_dispatcher(dispatcher)
		end

		# Update the active module
		self.active_module = mod

		# Update the command prompt
		driver.update_prompt("#{mod.type}(#{mod.refname}) ")
	end

	#
	# Returns the revision of the console library
	#
	def cmd_version(*args)
		ver = "$Revision$"

		print_line("Framework: #{Msf::Framework::Version}.#{Msf::Framework::Revision.match(/ (.+?) \$/)[1]}")
		print_line("Console  : #{Msf::Framework::Version}.#{ver.match(/ (.+?) \$/)[1]}")

		return true
	end

	#
	# Internal routine to recalculate tab complete.
	#
	def cmd__recalculate_tc(*args)
		recalculate_tab_complete
	end

protected

	#
	# Recalculates the tab completion list
	#
	def recalculate_tab_complete
		self.tab_complete_items = []

		framework.modules.each_module { |refname, mod|
			self.tab_complete_items << refname
			self.tab_complete_items << mod.fullname
		}
	end

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
		# If an active module has been selected and it's an exploit, get the
		# list of compatible payloads and display them
		if (active_module and active_module.exploit? == true)
			tbl = generate_module_table("Compatible payloads")

			active_module.compatible_payloads.each { |refname, payload|
				tbl << [ refname, payload.new.name ]
			}

			print(tbl.to_s)
		else
			show_module_set("Payloads", framework.payloads)
		end
	end

	def show_recon
		show_module_set("Recon", framework.recon)
	end

	def show_options(mod)
		print("\n" + Serializer::ReadableText.dump_options(mod) + "\n")
	
		# If it's an exploit and a payload is defined, create it and
		# display the payload's options
		if (mod.exploit? and mod.datastore['PAYLOAD'])
			p = framework.modules.create(mod.datastore['PAYLOAD'])

			if (!p)
				print_error("Invalid payload defined: #{mod.datastore['PAYLOAD']}\n")
				return
			end
			
			p.share_datastore(mod.datastore)

			if (p)
				print("  Payload options:\n\n" + Serializer::ReadableText.dump_options(p) + "\n");
			end
		end
	end

	def show_advanced_options(mod)
		print("\n" + Serializer::ReadableText.dump_advanced_options(mod) + "\n")
	end

	def show_module_set(type, module_set)
		tbl = generate_module_table(type)

		module_set.each_module { |refname, mod|
			instance = mod.new

			tbl << [ refname, instance.name ]
		}

		print(tbl.to_s)
	end

	def generate_module_table(type)
		Table.new(
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
	end

end

end end end end
