require 'msf/ui/console/command_dispatcher/encoder'
require 'msf/ui/console/command_dispatcher/exploit'
require 'msf/ui/console/command_dispatcher/nop'
require 'msf/ui/console/command_dispatcher/payload'
require 'msf/ui/console/command_dispatcher/recon'

module Msf
module Ui
module Console
module CommandDispatcher

###
#
# Command dispatcher for core framework commands, such as module loading,
# session interaction, and other general things.
#
###
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
	
	@@persist_opts = Rex::Parser::Arguments.new(
		"-s" => [ true,  "Storage medium to be used (ex: flatfile)."      ],
		"-r" => [ false, "Restore framework state."                       ],
		"-h" => [ false, "Help banner."                                   ])

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
			"load"    => "Load a framework plugin",
			"persist" => "Persist or restore framework state information",
			"quit"    => "Exit the console",
			"route"   => "Route traffic through a session",
			"save"    => "Saves the active datastores",
			"search"  => "Adds one or more module search paths",
			"session" => "Dump session listings and display information about sessions",
			"set"     => "Sets a variable to a value",
			"setg"    => "Sets a global variable to a value",
			"show"    => "Displays modules of a given type, or all modules",
			"unload"  => "Unload a framework plugin",
			"unset"   => "Unsets one or more variables",
			"unsetg"  => "Unsets one or more global variables",
			"use"     => "Selects a module by name",
			"version" => "Show the console library version number",
		}
	end

	#
	# Returns the name of the command dispatcher.
	#
	def name
		"Core"
	end

	#
	# Pop the current dispatcher stack context, assuming it isn't pointed at
	# the core stack context.
	#
	def cmd_back(*args)
		if (driver.dispatcher_stack.size > 1 and
		    driver.current_dispatcher.name != 'Core')
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
	# Display one of the fabulous banners.
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
	# Instructs the driver to stop executing.
	#
	def cmd_exit(*args)
		driver.stop
	end

	alias cmd_quit cmd_exit

	#
	# Displays the command help banner.
	#
	def cmd_help(*args)
		print(driver.help_to_s)
	end

	#
	# Displays information about one or more module.
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
	
	#
	# Tab completion for the info command (same as use)
	#
	def cmd_info_tabs(str, words)
		cmd_use_tabs(str, words)
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
	# Tab completion for the jobs command
	#
	def cmd_jobs_tabs(str, words)
		if(not words[1])
			return %w{-l -k -h}
		end
		if (words[1] == '-k')
			# XXX return the list of job values
		end
	end	
	
	#
	# Loads a plugin from the supplied path.  If no absolute path is supplied,
	# the framework root plugin directory is used.
	#
	def cmd_load(*args)
		if (args.length == 0)
			print_line(
				"Usage: load <path> [var=val var=val ...]\n\n" +
				"Load a plugin from the supplied path.  The optional\n" +
				"var=val options are custom parameters that can be\n" +
				"passed to plugins.")
			return false
		end

		# Default to the supplied argument path.
		path = args.shift
		opts  = {
			'LocalInput'    => driver.input,
			'LocalOutput'   => driver.output,
			'ConsoleDriver' => driver
			}

		# Parse any extra options that should be passed to the plugin
		args.join(' ').split(/\s+/).each { |opt|
			k, v = opt.split(/=/)

			opts[k] = v if (k and v)
		}

		# If no absolute path was supplied, use the plugin directory as a base.
		path = Msf::Config.plugin_directory + File::SEPARATOR + path if (path !~ /#{File::SEPARATOR}/)

		# Load that plugin!
		if ((inst = framework.plugins.load(path, opts)))
			print_status("Successfully loaded plugin: #{inst.name}")
		else
			print_error("Failed to load plugin from #{arg[0]}")
		end
	end
	
	#
	# Tab completion for the load command
	#
	def cmd_load_tabs(str, words)
		if(not words[1] or not words[1].match(/^\//))
			begin
				return Dir.new(Msf::Config.plugin_directory).find_all { |e|
					path = Msf::Config.plugin_directory + File::SEPARATOR + e
					File.file?(path) and File.readable?(path)
				}.map { |e|
					e.sub!(/\.rb$/, '')
				}
			rescue Exception
			end
		end
	end	

	#
	# This method persists or restores framework state from a persistent
	# storage medium, such as a flatfile.
	#
	def cmd_persist(*args)
		if (args.length == 0)
			args.unshift("-h")
		end

		arg_idx = 0
		restore = false
		storage = 'flatfile'

		@@persist_opts.parse(args) { |opt, idx, val|
			case opt
				when "-s"
					storage = val
					arg_idx = idx + 2
				when "-r"
					restore = true
					arg_idx = idx + 1
				when "-h"
					print(
						"Usage: persist [-r] -s storage arg1 arg2 arg3 ...\n\n" +
						"Persist or restore framework state information.\n" +
						@@persist_opts.usage())
					return false
			end
		}

		# Chop off all the non-arguments
		args = args[arg_idx..-1]

		begin
			if (inst = Msf::PersistentStorage.create(storage, *args))
				inst.store(framework)
			else
				print_error("Failed to find storage medium named '#{storage}'")
			end
		rescue
			log_error("Failed to persist to #{storage}: #{$!}")
		end
	end

	#
	# Tab completion for the persist command
	#
	def cmd_persist_tabs(str, words)
		if (not words[1])
			return %w{-s -r -h}
		end	
	end
	
	#
	# This method handles the route command which allows a user to specify
	# which session a given subnet should route through.
	#
	def cmd_route(*args)
		if (args.length == 0)
			print(
				"Usage: route [add/remove/get/flush/print] subnet netmask [comm/sid]\n\n" +
				"Route traffic destined to a given subnet through a supplied session. \n" +
				"The default comm is Local.\n")
			return false
		end

		case args.shift
			when "add"
				if (args.length < 3)
					print_error("Missing arguments to route add.")
					return false
				end

				gw = nil

				# Satisfy case problems
				args[2] = "Local" if (args[2] =~ /local/i)

				begin
					# If the supplied gateway is a global Comm, use it.
					if (Rex::Socket::Comm.const_defined?(args[2]))
						gw = Rex::Socket::Comm.const_get(args[2])
					end
				rescue NameError
				end

				# If we still don't have a gateway, check if it's a session.
				if ((gw == nil) and
				    (session = framework.sessions.get(args[2])) and
				    (session.kind_of?(Msf::Session::Comm)))
					gw = session
				elsif (gw == nil)
					print_error("Invalid gateway specified.")
					return false
				end

				Rex::Socket::SwitchBoard.add_route(
					args[0],
					args[1],
					gw)
			when "remove"
				if (args.length < 3)
					print_error("Missing arguments to route remove.")
					return false
				end
				
				gw = nil

				# Satisfy case problems
				args[2] = "Local" if (args[2] =~ /local/i)

				# If the supplied gateway is a global Comm, use it.
				if (Rex::Socket::Comm.const_defined?(args[2]))
					gw = Rex::Socket::Comm.const_get(args[2])
				end

				# If we still don't have a gateway, check if it's a session.
				if ((gw == nil) and
				    (session = framework.sessions.get(args[2])) and
				    (session.kind_of?(Msf::Session::Comm)))
					gw = session
				elsif (gw == nil)
					print_error("Invalid gateway specified.")
					return false
				end

				Rex::Socket::SwitchBoard.remove_route(
					args[0],
					args[1],
					gw)
			when "get"
				if (args.length == 0)
					print_error("You must supply an IP address.")
					return false
				end

				comm = Rex::Socket::SwitchBoard.best_comm(args[0])

				if ((comm) and
				    (comm.kind_of?(Msf::Session)))
					print_line("#{args[0]} routes through: Session #{comm.sid}")
				else
					print_line("#{args[0]} routes through: Local")
				end
			when "flush"
				Rex::Socket::SwitchBoard.flush_routes
			when "print"
				tbl =	Table.new(
					Table::Style::Default,
					'Header'  => "Active Routing Table",
					'Prefix'  => "\n",
					'Postfix' => "\n",
					'Columns' => 
						[
							'Subnet',
							'Netmask',
							'Gateway',
						],
					'ColProps' =>
						{
							'Subnet'  => { 'MaxWidth' => 17 },
							'Netmask' => { 'MaxWidth' => 17 },
						})

				Rex::Socket::SwitchBoard.each { |route|

					if (route.comm.kind_of?(Msf::Session))
						gw = "Session #{route.comm.sid}"
					else
						gw = route.comm.name.split(/::/)[-1]
					end

					tbl << [ route.subnet, route.netmask, gw ]
				}

				print(tbl.to_s)
		end
	end
	
	#
	# Tab completion for the route command
	#
	def cmd_route_tabs(str, words)
		if (not words[1])
			return %w{add remove get flush print}
		end
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
	# Adds one or more search paths.
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
						session.init_ui(driver.input.dup, driver.output)

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
	# Tab completion for the route command
	#
	def cmd_session_tabs(str, words)
		if (not words[1])
			return %w{-q -i -l -h}
		end
	end
	
	#
	# Sets a name to a value in a context aware environment.
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
	# Tab completion for the set command
	#
	def cmd_set_tabs(str, words)
	
		# A value has already been specified
		if (words[2])
			return nil
		end
		
		# A value needs to be specified
		if(words[1])
			return tab_complete_option(words[1])
		end
		
		res = cmd_unset_tabs(str, words) || [ ]
		mod = active_module
		
		if (not mod)
			return res
		end
		
		mod.options.sorted.each { |e|
			name, opt = e
			res << name
		}

		if (mod.exploit? and mod.datastore['PAYLOAD'])
			p = framework.modules.create(mod.datastore['PAYLOAD'])
			if (p)
				p.options.sorted.each { |e|
					name, opt = e
					res << name
				}				
			end
		end
		
		return res
	end

		
	#
	# Sets the supplied variables in the global datastore.
	#
	def cmd_setg(*args)
		args.unshift('-g')

		cmd_set(*args)
	end
	
	#
	# Tab completion for the setg command
	#
	def cmd_setg_tabs(str, words)
		res = cmd_set_tabs(str, words) || [ ]
	end
	
	#
	# Displays the list of modules based on their type, or all modules if
	# no type is provided.
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
					show_plugins
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
				when "plugins"
					show_plugins
			end
		}
	end
	
	#
	# Tab completion for the show command
	#
	def cmd_show_tabs(str, words)
		res = %w{all encoders nops exploits payloads recon plugins}
		if (active_module)
			res.concat(%w{ options advanced })
		end
		return res
	end
	
	#
	# Unloads a plugin by its name.
	#
	def cmd_unload(*args)
		if (args.length == 0)
			print_line(
				"Usage: unload [plugin name]\n\n" +
				"Unloads a plugin by its symbolic name.")
			return false
		end

		# Walk the plugins array
		framework.plugins.each { |plugin|
			# Unload the plugin if it matches the name we're searching for
			if (plugin.name == args[0])
				print("Unloading plugin #{args[0]}...")
				framework.plugins.unload(plugin)
				print_line("unloaded.")
				break
			end
		}
	end
	
	#
	# Tab completion for the unload command
	#
	def cmd_unload_tabs(str, words)
		framework.plugins.each { k.name }
	end

	#
	# Unsets a value if it's been set.
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
	# Tab completion for the unset command
	#
	def cmd_unset_tabs(str, words)
		datastore = active_module ? active_module.datastore : self.framework.datastore
		datastore.keys
	end
	
	#
	# Unsets variables in the global data store.
	#
	def cmd_unsetg(*args)
		args.unshift('-g')

		cmd_unset(*args)
	end
	
	#
	# Tab completion for the unsetg command
	#
	def cmd_unsetg_tabs(str, words)
		self.framework.datastore.keys
	end
	
	#
	# Uses a module.
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
	# Tab completion for the use command
	#
	def cmd_use_tabs(str, words)
		res = []
		framework.modules.each_module { |refname, mod|
			res << mod.fullname
		}
		return res
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
	# Provide command-specific tab completion
	#
	def tab_complete_helper(str, words)
		items = []
		
		# Is the user trying to tab complete one of our commands?
		if (commands.include?(words[0]))
			if (self.respond_to?('cmd_'+words[0]+'_tabs')) 
				res = self.send('cmd_'+words[0]+'_tabs', str, words)
				return nil if res.nil?
				items.concat(res)
			else
				# Avoid the default completion list for known commands
				return nil
			end
		end
		
		return items
	end

	#
	# Provide tab completion for option values
	#
	def tab_complete_option(opt)	
		res = []
		mod = active_module
		
		# With no active module, we have nothing to compare
		if (not mod)
			return res
		end
		
		# Well-known option names specific to exploits
		if (mod.exploit?)
			return option_values_payloads() if opt == 'PAYLOAD'
			return option_values_targets()  if opt == 'TARGET'
			return option_values_nops()     if opt == 'NOPS'
		end
		
		# The ENCODER option works for payloads and exploits
		if ((mod.exploit? or mod.payload?) and opt == 'ENCODER')
			return option_values_encoders()
		end
		
		# Is this option used by the active module?
		if (mod.options.include?(opt))
			res.concat(option_values_dispatch(mod.options[opt]))
		end
		
		# How about the selected payload?
		if (mod.exploit? and mod.datastore['PAYLOAD'])
			p = framework.modules.create(mod.datastore['PAYLOAD'])
			if (p and p.options.include?(opt))
				res.concat(option_values_dispatch(p.options[opt]))
			end
		end

		return res
	end
	
	#
	# Provide possible option values based on type
	#
	def option_values_dispatch(o)	
		res = []
		res << o.default.to_s if o.default

		case o.class.to_s
		
			when 'Msf::OptAddress'
				case o.name
					when 'RHOST'
						res << option_values_last_target()
					when 'LHOST'
						res << Rex::Socket.source_address()
					else
				end
				
			when 'Msf::OptPort'
				if (res.empty?)
					res << (rand(65534)+1).to_s
				end
		end
		
		return res
	end
	
	#
	# Provide valid payload options for the current exploit
	#
	def option_values_payloads
		active_module.compatible_payloads.map { |refname, payload| refname }
	end
	
	#
	# Provide valid target options for the current exploit
	#
	def option_values_targets
		res = []
		if (active_module.targets)
			1.upto(active_module.targets.length) { |i| res << (i-1).to_s }
		end
		return res
	end	
	
	#
	# Provide valid nops options for the current exploit
	#
	def option_values_nops
		framework.nops.map { |refname, mod| refname }
	end	
	
	#
	# Provide valid encoders options for the current exploit or payload
	#
	def option_values_encoders
		framework.encoders.map { |refname, mod| refname }
	end

	#
	# Provide the last target address
	#
	def option_values_last_target
		# Replace this once we start tracking these things...
		return Rex::Socket.source_address()
	end
			
protected

	#
	# Module list enumeration
	#

	def show_encoders # :nodoc:
		show_module_set("Encoders", framework.encoders)
	end

	def show_nops # :nodoc:
		show_module_set("NOP Generators", framework.nops)
	end

	def show_exploits # :nodoc:
		show_module_set("Exploits", framework.exploits)
	end

	def show_payloads # :nodoc:
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

	def show_recon # :nodoc:
		show_module_set("Recon", framework.recon)
	end

	def show_options(mod) # :nodoc:
		mod_opt = Serializer::ReadableText.dump_options(mod, '   ')
		print("\nModule options:\n\n#{mod_opt}\n") if (mod_opt and mod_opt.length > 0)
	
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
				p_opt = Serializer::ReadableText.dump_options(p, '   ') 
				print("\nPayload options:\n\n#{p_opt}\n") if (p_opt and p_opt.length > 0)
			end
		end
	end

	def show_advanced_options(mod) # :nodoc:
		mod_opt = Serializer::ReadableText.dump_advanced_options(mod, '   ') 
		print("\nModule advanced options:\n\n#{mod_opt}\n") if (mod_opt and mod_opt.length > 0)

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
				p_opt = Serializer::ReadableText.dump_advanced_options(p, '   ') 
				print("\nPayload advanced options:\n\n#{p_opt}\n") if (p_opt and p_opt.length > 0)
			end
		end
	end

	def show_plugins # :nodoc:
		tbl = generate_module_table("Plugins")

		framework.plugins.each { |plugin|
			tbl << [ plugin.name, plugin.desc ]
		}

		print(tbl.to_s)
	end

	def show_module_set(type, module_set) # :nodoc:
		tbl = generate_module_table(type)

		module_set.each_module { |refname, mod|
			instance = mod.new

			tbl << [ refname, instance.name ]
		}

		print(tbl.to_s)
	end

	def generate_module_table(type) # :nodoc:
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
