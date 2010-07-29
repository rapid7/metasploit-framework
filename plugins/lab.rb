#
#
$:.unshift(File.join(File.expand_path(File.dirname(__FILE__)), '..', 'lib', 'lab'))

require 'yaml'
require 'lab_controller'

module Msf

class Plugin::Lab < Msf::Plugin
	class LabCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher

		attr_accessor :controller
		attr_accessor :target_map
		
		def initialize(driver)
			super(driver)
			@controller = nil
			@target_map = nil
		end

		#
		# Returns the hash of commands supported by this dispatcher.
		#
		def commands
			{
			
				### Lab Management!
				"lab_load_file" => "lab_load_file - load a lab definition from disk.", 			
				"lab_load_running" => "lab_load_running - use the running vms to create a lab definition.", 
				"lab_load_dir" => "lab_load_dir - load a lab definition from a directory.", 			
				"lab_clear" => "lab_clear - clear the running lab_definition.",	
				"lab_save" => "lab_save [filename] - save a lab_definition to filename.",
				"lab_show" => "lab_show - show all vms in the lab.",
				"lab_show_running" => "lab_show_running - show running vms.",
				"lab_start" => "lab_start [vmid+|all] start all targets for this exploit.",
				"lab_reset" => "lab_reset [vmid+|all] reset all targets for this exploit.",
				"lab_suspend" => "lab_suspend [vmid+|all] suspend all targets for this exploit.",
				"lab_stop" => "lab_stop [vmid+|all] stop all targets for this exploit.",
				"lab_revert" => "lab_revert [vmid+|all] [snapshot] revert all targets for this exploit.",
				"lab_run_command" => "lab_run_command [vmid+|all] [command] run a command on all targets.",
				"lab_snapshot" => "lab_snapshot [vmid+|all] [snapshot] snapshot all targets for this exploit.",
				"lab_browse_to" => "lab_browse_to [vmid+|all] [uri] use the default browser to browse to a uri.",

				### Target map management
				"target_map_load" => "target_map_load",
				"target_map_unload" => "target_map_unload",
				"target_map_save" => "targets_map_save",
				"target_map_show" => "target_map_show",

				### Target (module-specific mappings) commands
				"targets_show" => "targets_show - show all targets for this exploit",
				"targets_add" => "target_add [vmid] - add a target for this exploit",
#				"targets_add_running" => "target_add_running [vmid] - add a target for this exploit",
				"targets_remove" => "target_remove [vmid] - remove a target for this exploit",
				"targets_clear" => "targets_clear - clear targets list for this exploit",
				"targets_start" => "targets_start - start all targets for this exploit",
				"targets_stop" => "targets_stop - stop all targets for this exploit",
				"targets_reset" => "targets_reset - reset all targets for this exploit",
				"targets_suspend" => "targets_suspend - suspend all targets for this exploit",
				"targets_snapshot" => "targets_snapshot [snapshot] - snapshot all targets for this exploit",
				"targets_revert" => "targets_revert [revert] - snapshot all targets for this exploit",
#				"targets_run_command" => "targets_run_command run a command on all targets",
#				"targets_browse_to" => "targets_browse_to [uri] use the default browser to browse to a uri"
#				"targets_exploit" => "targets_exploit exploit all targets",
#				"targets_verify" => "targets_verify - exploit and verify against all targets",
#				"targets_auto_verify" => "targets_verify - exploit and verify by querying targets that should work, and matching to the lab"
		}
		end

		def name
			"Lab"
		end

		##
		## Commands for Lab Management
		##



		def cmd_lab_save(*args)
			print_error "Not currently supported."		
	        end
		
		def cmd_lab_load_file(*args)

			if args[0]
				labdef = YAML::load_file(args[0])
				@target_map = {}
			else
				print_error "Please provide a valid lab file."
			end

			hlp_print_lab
	        end

		def cmd_lab_load_dir(*args)			
		
		
			if args[0]
				x = @controller.build_lab_from_files(args[0])
				@target_map = {}	
			else
				print_error "Please provide a valid lab file."
			end

			hlp_print_lab

	        end
	        
	        def cmd_lab_load_running(*args)
			@controller.build_lab_from_running        
			@target_map = {}
			
			hlp_print_lab
	        end


		def cmd_lab_clear(*args)

			@controller = LabController.new({},"vmware")
			hlp_print_lab		
	        end

		def cmd_lab_save(*args)		
			File.open(args[0], 'w')  {|f| f.write(@controller.labdef.to_yaml) }
			hlp_print_targets
		
		end
		

		## 
		## Commands for dealing with a currently-loaded lab
		## 

		def cmd_lab_show(*args)
			hlp_print_lab
	        end

		def cmd_lab_show_running(*args)
			hlp_print_lab_running
	        end
	        
	        def cmd_lab_start(*args)
		
			if args[0] == "all"
				print_line "Starting all lab vms.\n"
				@controller.start_lab
			else
				args.each do |arg| 
					if @controller.exists?(arg)
						if !@controller.running?(arg)
							print_line "Starting lab vm '" + arg + "'."	
							@controller.start_lab_vm(arg)
						else
							print_error "Lab vm '" + arg + "' " + "already running."
						end
					end
				end
			end

			hlp_print_lab_running
	        end
	     
		def cmd_lab_stop(*args)
		
			if args[0] == "all"
				print_line "Stopping all running lab vms.\n"
				@controller.stop_lab
			else
				args.each do |arg| 
					if @controller.exists?(arg)
						if @controller.running?(arg)
							print_line "Stopping lab vm '" + arg + "'."	
							@controller.stop_lab_vm(arg)
						else
							print_error "Lab vm '" + arg + "' " + "not running."
						end
					end
				end
			end

			hlp_print_lab_running
	        end

		def cmd_lab_suspend(*args)
		
			if args[0] == "all"
				print_line "Suspending all running lab vms.\n"
				@controller.suspend_lab
			else
				args.each do |arg| 
					if @controller.exists?(arg)
						if @controller.running?(arg)
							print_line "Suspending lab vm '" + arg + "'."	
							@controller.suspend_lab_vm(arg)
						else
							print_error "Lab vm '" + arg + "' " + "not running."
						end
					end
				end
			end

			hlp_print_lab_running
	        end

		def cmd_lab_reset(*args)
		
			if args[0] == "all"
				print_line "Resetting all running lab vms.\n"
				@controller.reset_lab
			else
				args.each do |arg| 
					if @controller.exists?(arg)
						if @controller.running?(arg)
							print_line "Resetting lab vm '" + arg + "'."	
							@controller.reset_lab_vm(arg)
						else
							print_error "Lab vm '" + arg + "' " + "not running."
						end
					end
				end
			end

			hlp_print_lab_running
	        end


		def cmd_lab_snapshot(*args)

			snapshot = args[args.count-1] 	
		
			if args[0] == "all"
				print_line "Snapshotting all running lab vms.\n"
				@controller.snapshot_lab(snapshot)
			else
				args.each do |arg| 
					if @controller.exists?(arg)
						print_line "snapshotting lab vm '" + arg + "'."	
						@controller.snapshot_lab_vm(arg,snapshot)
					end
				end
			end
	        end


		def cmd_lab_revert(*args)
		
			snapshot = args[args.count-1] 		

			if args[0] == "all"
				print_line "Reverting all running lab vms.\n"
				@controller.revert_lab(snapshot)
			else
				args.each do |arg| 
					if @controller.exists?(arg)
						print_line "Reverting lab vm '" + arg + "'."	
						@controller.revert_lab_vm(arg, snapshot)
					end
				end
			end
	        end


		def cmd_lab_run_command(*args)

			command = args[args.count-1] 
		
			if args[0] == "all"
				print_line "Running command '" + command + "' on all running lab vms.\n"
				@controller.run_command_on_lab(args[1])
			else
				args.each do |arg|
					if arg != command ## Make sure we don't use the command as a vmid
						if @controller.exists?(arg)
							if @controller.running?(arg)
								print_line "Running command '" + command + "' on lab vm '" + arg + "'."	
								@controller.run_command_on_lab_vm(arg, command)
							else
								print_error "Lab vm '" + arg + "' " + "not running."
							end
						else
							print_error "Unknown lab vm '" + arg + "'."
						end
					end
				end
			end

#			hlp_print_lab_running
	        end

		def cmd_lab_browse_to(*args)

			uri = args[args.count-1] ## where's that final argument, that's our command, boiiii
		
			if args[0] == "all"
				print_line "Browsing to uri '" + url + "' on all running lab vms.\n"
				@controller.run_command_on_lab(args[1])
			else
				args.each do |arg|
					if arg != uri ## Make sure we don't use the uri as a vmid
						if @controller.exists?(arg)
							if @controller.running?(arg)
								@controller.run_browser_on_lab_vm(arg,uri)
							else
								print_error "Lab vm '" + arg + "' " + "not running."
							end
						else
							print_error "Unknown lab vm '" + arg + "'."
						end
					end
				end
			end

#			hlp_print_lab_running
	        end

		##
		## Commands for dealing with a target map
		## 



		def cmd_target_map_show(*args)
			hlp_print_targets
		end

		def cmd_target_map_load(*args)
			## Set up a mapping of exploits -> vms
			default_target_map_file = args[0]
			@target_map = YAML::load_file(default_target_map_file)
			hlp_print_targets
		end

		def cmd_target_map_unload(*args)
			@target_map = {}
			hlp_print_targets
		end

		def cmd_target_map_save(*args)
			File.open(args[0], 'w')  {|f| f.write(@target_map.to_yaml) }
			hlp_print_targets
		end


		## Commands for dealing with targets for a loaded 

		def cmd_targets_show(*args)
			if (not active_module) then
				print_error "No active module. Try 'use [modulename]' first."
				return nil
			end

			hlp_print_targets(active_module.fullname)
		end

		def cmd_targets_add(*args)
			if (not active_module) then
				print_error "No active module. Try 'use [modulename]' first."
				return nil
			end

			if args[0]
				if @controller.exists?(args[0])
					if @target_map == {}
						@target_map[active_module.fullname] = []
						@target_map[active_module.fullname] << args[0]											
					else
						@target_map[active_module.fullname] << args[0]
					end
				else
					print_error "VM: '" + "' doesn't exist in this lab."
				end
			end

			hlp_print_targets(active_module.fullname)
		end
	
		def cmd_targets_remove(*args)
			if (not active_module) then
				print_error "No active module. Try 'use [modulename]' first."
				return nil
			end

			if args[0]
				if @controller.exists?(args[0])
					@target_map[active_module.fullname].delete(args[0])
				else
					print_error "VM: '" + "' doesn't exist in this lab."
				end
			end

			hlp_print_targets(active_module.fullname)
		end

		def cmd_targets_start(*args)
			if (not active_module) then
				print_error "No active module selected. Please select a module first."
				return nil
			end

			@target_map[active_module.fullname].each { |target| @controller.start_lab_vm(target) }

			hlp_print_targets_running(active_module.fullname)
		end

		def cmd_targets_stop(*args)
			if (not active_module) then
				print_error "No active module selected. Please select a module first."
				return nil
			end

			@target_map[active_module.fullname].each { |target| @controller.stop_lab_vm(target) }

			hlp_print_targets_running(active_module.fullname)
		end

		def cmd_targets_reset(*args)
			if (not active_module) then
				print_error "No active module selected. Please select a module first."
				return nil
			end

			@target_map[active_module.fullname].each { |target| @controller.reset_lab_vm(target) }

			hlp_print_targets_running(active_module.fullname)
		end

		def cmd_targets_suspend(*args)
			if (not active_module) then
				print_error "No active module selected. Please select a module first."
				return nil
			end

			@target_map[active_module.fullname].each { |target| @controller.suspend_lab_vm(target) }

			hlp_print_targets_running(active_module.fullname)
		end

		
		def cmd_targets_snapshot(*args)
			if (not active_module) then
				print_error "No active module selected. Please select a module first."
				return nil
			end

			if args[0]
				@target_map[active_module.fullname].each { |target| @controller.snapshot_lab_vm(target, args[0]) }
			else
				print_error "Please enter a snapshot name."
			end
			
			hlp_print_targets_running(active_module.fullname)
		end		

		def cmd_targets_revert(*args)
			if (not active_module) then
				print_error "No active module selected. Please select a module first."
				return nil
			end

			if args[0]
				@target_map[active_module.fullname].each { |target| @controller.revert_lab_vm(target, args[0]) }
			else
				print_error "Please enter a snapshot name."
			end
			
			hlp_print_targets_running(active_module.fullname)
		end	


		## 
		## This stuff needs a lot more thought before it should be exposed
		##
		def cmd_targets_exploit(*args)
			if (not active_module) then
				print_error "No active module selected. Please select a module first."
				return nil
			end

			if @target_map
				@target_map[active_module.fullname].each do |target|
					
					## auto start targets that aren't running
					if !@controller.running?(target)
						print_status target + " isn't running, starting it for you :)"
						@controller.start_lab_vm(target)
						print_status "I'll hang out for a second while it gets going. Note, this value may need tweaking if you've got a slow box."						
						sleep 20 ##resonable default? Guess?
					end
					
					hostname = @controller.labdef[target]['hostname']
					username = @controller.labdef[target]['username']
					password = @controller.labdef[target]['password']
					os = @controller.labdef[target]['os']
					#x64 = @controller.labdef[target]['x64']
				
					active_module.datastore["RHOST"] = hostname
				
					### G.H.E.TT.O.
					if os == "windows"
						active_module.datastore["PAYLOAD"] = "windows/meterpreter/bind_tcp"
					elsif os == "linux"
						active_module.datastore["PAYLOAD"] = "cmd/unix/bind_perl"
					else
						active_module.datastore["PAYLOAD"] = "windows/meterpreter/bind_tcp"
						print_error "Unknown OS, please set it in the lab. Guessing windows."
					end
				
				
					### Hmm, this is good for demo purposes, but how do we abstract this
					if active_module.fullname == "windows/smb/psexec"
						active_module.datastore["SMBUser"] = username
						active_module.datastore["SMBPass"] = password
					end
				
					active_module.exploit
					
					### Now, our on-session handler should handle this
				end
			else
				print_error "No target map found. Something went wrong. Try loading a ne"
			end
			
#			hlp_print_targets_running(active_module.fullname)
		end	

		
		def cmd_targets_clear(*args)
			if (not active_module) then
				print_error "No active module. Try 'use [modulename]' first."
				return nil
			end
			
			@target_map[active_module.fullname] = {}
			
			hlp_print_targets(active_module.fullname)
		end

			
		private
		def hlp_print_lab
			indent = '    '

			tbl = Rex::Ui::Text::Table.new(
				'Header'  => 'Available Lab VMs',
				'Indent'  => indent.length,
				'Columns' => [ 'vmid', 'file', "powered on" ]
			)

			@controller.labdef.each do |key, value| 
				tbl << [ 	key, 
						@controller.get_full_path(key),
						@controller.running?(key)]
			end
			
			print_line tbl.to_s
		end
				
		def hlp_print_lab_running
			indent = '    ' 

			tbl = Rex::Ui::Text::Table.new(
				'Header'  => 'Running Lab VMs',
				'Indent'  => indent.length,
				'Columns' => [ 'vmid', 'file', 'powered on' ]
			)

			@controller.labdef.each do |key, value| 
				if @controller.running?(key)
					tbl << [ 	key, 
							@controller.get_full_path(key),
							true] 
				end
			end
			print_line tbl.to_s
		end

		def hlp_print_targets(mod_id=nil)
			indent = '    ' 

			if @target_map[mod_id]
				begin
					if mod_id
						tbl = Rex::Ui::Text::Table.new(
							'Header'  => 'Mapped Targets for ' + mod_id,
							'Indent'  => indent.length,
							'Columns' => [ 'vmid', 'file', "powered on" ]
						)
		
						@target_map[mod_id].each do |target| 			
							tbl << [ 	target.to_s, 
									@controller.get_full_path(target),
									@controller.running?(target)]
						end
					else

						tbl = Rex::Ui::Text::Table.new(
							'Header'  => 'All Mapped Targets',
							'Indent'  => indent.length,
							'Columns' => [ 'module', 'vmid', 'file', "powered on" ]
						)
		
						@target_map.each do |key, value|
							value.each do |target|
										
							tbl << [ 	key.to_s,
									target.to_s,
									@controller.get_full_path(target.to_s),
									@controller.running?(target.to_s)]
							end
						end
					end
				rescue Exception => e
				end
				
			else
				print_error "No target map"
			end
			
			print_line tbl.to_s
		end

		def hlp_print_targets_running(mod_id = nil)
			indent = '    ' 

			begin			
				if @target_map	
					if mod_id
			
						tbl = Rex::Ui::Text::Table.new(
							'Header'  => 'Running Targets for ' + mod_id,
							'Indent'  => indent.length,
							'Columns' => [ 'vmid', 'file', "powered on" ]
						)

						@target_map[mod_id].each do |target| 			
							tbl << [ 	target.to_s, 
									@controller.get_full_path(target),
									@controller.running?(target)]
						end
					else
			
						tbl = Rex::Ui::Text::Table.new(
							'Header'  => 'All Running Targets',
							'Indent'  => indent.length,
							'Columns' => [ 'module', 'vmid', 'file', "powered on" ]
						)

						@target_map.each do |key, value|
							value.each do |target| 
								if @controller.running?(target)			
									tbl << [ 	key.to_s,
											target.to_s, 
											@controller.get_full_path(target),
											true]
								end
							end
						end
					end
				end
			rescue Exception => e
			end					
			print_line tbl.to_s
		end		


	end
	
	#
	# The constructor is called when an instance of the plugin is created.  The
	# framework instance that the plugin is being associated with is passed in
	# the framework parameter.  Plugins should call the parent constructor when
	# inheriting from Msf::Plugin to ensure that the framework attribute on
	# their instance gets set.
	#
	def initialize(framework, opts)
		super

                #self.framework.events.add_session_subscriber(self)

		## Register the commands above
		console_dispatcher = add_console_dispatcher(LabCommandDispatcher)

		## Set up a lab here. Note that we're going directly to the controller, so all data's gonna 
		##   have to get stored here, and not in a separate lab class (probably the right way to do)
		#default_lab_file = File.join(File.dirname(__FILE__), "..", "data", "lab", "test_lab.yml" )
		#labdef = YAML::load_file(default_lab_file)
		
		labdef = {}
		
		@lab_controller = LabController.new(labdef,"vmware")

		## Set up a mapping of exploits -> vms
		## default_target_map_file = File.join(File.dirname(__FILE__), "..", "data", "lab", "test_targets.yml" )
		
	
		#@lab_target_map = YAML::load_file(default_target_map_file)
		@lab_target_map = {}
	
		## Share the controller & target map with the console_dispatcher
		console_dispatcher.controller = @lab_controller
		console_dispatcher.target_map = @lab_target_map

		## Great Success!

	end


	#
	# The cleanup routine for plugins gives them a chance to undo any actions
	# they may have done to the framework.  For instance, if a console
	# dispatcher was added, then it should be removed in the cleanup routine.
	#
	def cleanup
		# If we had previously registered a console dispatcher with the console,
		# deregister it now.
		remove_console_dispatcher('Lab')
	end

	#
	# This method returns a short, friendly name for the plugin.
	#
	def name
		"lab"
	end

	#
	# This method returns a brief description of the plugin.  It should be no
	# more than 60 characters, but there are no hard limits.
	#
	def desc
		"Adds the ability to manage vms and targets"
	end

	#def on_session_open(session)
		
		#return if not session.type == 'meterpreter'
		#session.load_stdapi
		#sb = Rex::Socket::SwitchBoard.instance
		#session.net.config.each_route { |route|
		#	# Remove multicast and loopback interfaces
		#	next if route.subnet =~ /^(224\.|127\.)/
		#	next if route.subnet == '0.0.0.0'
		#	next if route.netmask == '255.255.255.255'
		#	if not sb.route_exists?(route.subnet, route.netmask)
		#		print_status("AutoAddRoute: Routing new subnet #{route.subnet}/#{route.netmask} through session #{session.sid}")
		#		sb.add_route(route.subnet, route.netmask, session)
		#	end
		#}
	
	#end
end ## End Class
end ## End Module
