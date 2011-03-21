#!/usr/bin/env ruby
#
# This plugin provides integration with OpenVAS. Written by kost.
# Distributed under MIT license: 
# http://www.opensource.org/licenses/mit-license.php
#
# Typical usage:
# load openvas
# db_connect
# openvas_connect test test localhost 9390 ok
# openvas_scan localhost
# Type openvas_help for more

require 'openvas/openvas-omp'

module Msf
class Plugin::OpenVAS < Msf::Plugin
	class OpenVASCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher

		def name
			"OpenVAS"
		end

		def commands
			{
				'openvas_help'           => "Displays help",
				'openvas_connect'        => "Connect to a OpenVAS manager using OMP ( user:pass@host[:port] )",
				'openvas_task_list'      => "Display list of tasks",
				'openvas_task_create'      => "Creates task (name, comment, target, config)",
				'openvas_task_start'    => "Start task by ID",
				'openvas_task_stop'    => "Stop task by ID",
				'openvas_task_pause'    => "Pause task by ID",
				'openvas_task_resume'    => "Resume task by ID",
				'openvas_task_resume_or_start'    => "Resume task or start task by ID",
				'openvas_task_info'    => "Get info about task ID",
				'openvas_task_delete'    => "Delete task by ID",
				'openvas_task_cleanup' => "Cleanup tasks automatically made",

				'openvas_target_create'    => "Create target (name, hosts, comment)",
				'openvas_target_list'    => "Display list of targets",
				'openvas_target_info'      => "Get info about target ID",
				'openvas_target_delete'  => "Delete target by ID",
				'openvas_target_cleanup' => "Cleanup targets automatically made",

				'openvas_config_list'    => "Quickly display list of configs",
				'openvas_config_info'    => "Get info about config ID",
				'openvas_report_import'	 => "Import report specified by ID to framework",
				'openvas_report_save'	=> "Save report specified by ID and format to file",

				'openvas_scan'           => "Launch an automatic OpenVAS scan against a specific IP range and import the results",
				'openvas_cleanup'        => "Cleanup target/tasks automatically made",

				'openvas_debug'          => "Sets debug level",
				'openvas_disconnect'     => "Disconnect from OpenVAS manager",

			}
		end

		def cmd_openvas_help (*args)
			usage="
openvas_help			Display this help

CONNECTION
==========
openvas_connect			Connects to OpenVAS
openvas_disconnect		Disconnects from OpenVAS

TARGETS
=======
openvas_target_list		Lists targets
openvas_target_info		Display info about target specified by ID
openvas_target_create		Create target
openvas_target_delete		Deletes target specified by ID
openvas_target_cleanup		Cleanup targets automatically made

TASKS
=====
openvas_task_list		Lists tasks
openvas_task_info		Display info about task specified by ID
openvas_task_create		Create task 
openvas_task_start		Starts task specified by ID
openvas_task_stop		Stops task specified by ID
openvas_task_pause		Pauses task specified by ID
openvas_task_resume		Resumes task specified by ID
openvas_task_resume_or_start	Resumes or starts task specified by ID
openvas_task_cleanup		Cleanup tasks automatically made

CONFIGS
=======
openvas_config_list		Lists configs
openvas_config_info		Display info about config specified by ID

REPORTS
=======
openvas_report_import		Imports OpenVAS report in framework spec. by ID
openvas_report_save		Saves OpenVAS report specified by ID and format

AUTO
====
openvas_scan			Launch an automatic OpenVAS scan against a specific IP range and import the results automatically with optional autopwn
openvas_cleanup			Cleanup target/tasks automatically made
"
			print_status(usage)
		end

		def openvas_verify
			if ! @ov
				print_error("No active OpenVAS instance has been configured, please use 'openvas_connect'")
				return false
			end

			if ! (framework.db and framework.db.usable)
				print_error("No database has been configured, please use db_create/db_connect first")
				return false
			end

			true
		end

		def openvas_task_cleanup
			return if not openvas_verify
			begin
				@ov.task_get_all().each do |task|
					if task['comment'] == @ovcomment
						print_status(">> Deleting: #{task['name']} with ID #{task['id']}")
						@ov.task_delete(task['id']);
#					else
#						print_status(">> Skipping: #{task['name']} with ID #{task['id']}")
					end
				end
				print_good("Completed deleting tasks.")
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def openvas_target_cleanup
			return if not openvas_verify
			begin
				@ov.target_get_all().each do |target|
					if target['comment'] == @ovcomment
						if target['in_use'] == '0'
							print_status(">> Deleting: #{target['name']} with ID #{target['id']}")
							@ov.target_delete(target['id'])
						else
							print_error(">> Target in use(#{target['in_use']}), not deleting #{target['name']} with ID #{target['id']}")
						end
#					else
#						print_status(">> Skipping: #{target['name']} with ID #{target['id']}")
					end
				end
				print_good("Completed deleting targets.")
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_task_cleanup(*args)
			usagecmd="openvas_task_cleanup yes
Example: openvas_task_cleanup yes"
			return if not openvas_verify
			if(args.length == 0 or args[0].empty? or args[0] == "-h")
				print_status(usagecmd)
				return
			end
			begin
				if args[0] != "yes"
					print_error("Please, type yes as argument")
					return
				end
				openvas_task_cleanup
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_target_cleanup(*args)
			usagecmd="openvas_target_cleanup yes
Example: openvas_target_cleanup yes"
			return if not openvas_verify
			if(args.length == 0 or args[0].empty? or args[0] == "-h")
				print_status(usagecmd)
				return
			end
			begin
				if args[0] != "yes"
					print_error("Please, type yes as argument")
					return
				end
				openvas_target_cleanup
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_cleanup(*args)
			usagecmd="openvas_cleanup yes
Example: openvas_cleanup yes"
			return if not openvas_verify
			if(args.length == 0 or args[0].empty? or args[0] == "-h")
				print_status(usagecmd)
				return
			end
			begin
				if args[0] != "yes"
					print_error("Please, type yes as argument")
					return
				end
				print_status("Doing task cleanup")
				openvas_task_cleanup
				print_status("Doing target cleanup")
				openvas_target_cleanup
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_debug(*args)
			usagecmd="openvas_debug <level>
Example: openvas_debug 99"
			return if not openvas_verify
			if(args.length == 0 or args[0].empty? or args[0] == "-h")
				print_status(usagecmd)
				return
			end
			begin
				level=args[0]
				@ov.debug(level)
				print_good("Command completed successfuly: "+level)
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_task_start(*args)
			usagecmd="openvas_task_start <id>
Example: openvas_task_start 9fd90790-a79b-49e0-b08e-6912afde72f4"
			return if not openvas_verify
			if(args.length == 0 or args[0].empty? or args[0] == "-h")
				print_status(usagecmd)
				return
			end
			begin
				id=args[0]
				@ov.task_start(id)
				print_good("Command completed successfuly: "+id)
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_task_create(*args)
			usagecmd="openvas_task_create <name> <comment> <config_id> <target_id>
Example: openvas_task_create newtask MyNewTask abc12345-a234-46a1-c01c-123456789012 9abc0790-a79b-49e0-b08e-6912afde72f4"
			return if not openvas_verify
			if(args.length != 4 or args[0].empty? or args[0] == "-h")
				print_status(usagecmd)
				return
			end
			begin
				id=@ov.task_create({"name"=>args[0],"comment"=>arg[1],"config"=>args[2],"target"=>args[3]})
				print_good("Command completed successfuly: "+id)
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_task_stop(*args)
			usagecmd="openvas_task_stop <id>
Example: openvas_task_stop 9fd90790-a79b-49e0-b08e-6912afde72f4"
			return if not openvas_verify
			if(args.length == 0 or args[0].empty? or args[0] == "-h")
				print_status(usagecmd)
				return
			end
			begin
				id=args[0]
				@ov.task_stop(id)
				print_good("Command completed successfuly: "+id)
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_task_pause(*args)
			usagecmd="openvas_task_pause <id>
Example: openvas_task_pause 9fd90790-a79b-49e0-b08e-6912afde72f4"
			return if not openvas_verify
			if(args.length == 0 or args[0].empty? or args[0] == "-h")
				print_status(usagecmd)
				return
			end
			begin
				id=args[0]
				@ov.task_pause(id)
				print_good("Command completed successfuly: "+id)
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_task_resume(*args)
			usagecmd="openvas_task_resume <id>
Example: openvas_task_resume 9fd90790-a79b-49e0-b08e-6912afde72f4"
			return if not openvas_verify
			if(args.length == 0 or args[0].empty? or args[0] == "-h")
				print_status(usagecmd)
				return
			end
			begin
				id=args[0]
				@ov.task_resume(id)
				print_good("Command completed successfuly: "+id)
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_task_resume_or_start(*args)
			usagecmd="openvas_task_resume_or_start <id>
Example: openvas_task_resume_or_start 9fd90790-a79b-49e0-b08e-6912afde72f4"
			return if not openvas_verify
			if(args.length == 0 or args[0].empty? or args[0] == "-h")
				print_status(usagecmd)
				return
			end
			begin
				id=args[0]
				@ov.task_resume_or_start(id)
				print_good("Command completed successfuly: "+id)
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_task_delete(*args)
			usagecmd="openvas_task_delete <id>
Example: openvas_task_delete 9fd90790-a79b-49e0-b08e-6912afde72f4"
			return if not openvas_verify
			if(args.length == 0 or args[0].empty? or args[0] == "-h")
				print_status(usagecmd)
				return
			end
			begin
				id=args[0]
				@ov.task_delete(id)
				print_good("Command completed successfuly: "+id)
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_task_info(*args)
			usagecmd="openvas_task_info <id>
Example: openvas_task_info 9fd90790-a79b-49e0-b08e-6912afde72f4"
			return if not openvas_verify
			if (args.length == 0 or args[0].empty? or args[0] == "-h")
				print_status(usagecmd)
				return
			end
			begin
				print_good("OpenVAS task info")
				id=args[0]
				@ov.task_get_all("task_id"=>id).each do |task|
					tbl = Rex::Ui::Text::Table.new(
						'Columns' => 
						[ "Field", "Value" ]
					)
					task.each_key do |key|
						tbl.add_row([key,task[key]]);
					end
					puts "\n"
					puts tbl.to_s + "\n"
				end
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_task_list(*args)
			usagecmd="openvas_task_list [id]
Example: openvas_task_list 
Example: openvas_task_list 9fd90790-a79b-49e0-b08e-6912afde72f4"
			return if not openvas_verify
			if (args[0] == "-h") then
				print_status(usagecmd)
				return
			end
			if not (args.length == 0 or args[0].empty?) then
				id=args[0]
			end
			begin
				tbl = Rex::Ui::Text::Table.new(
					'Columns' => 
					[ "ID", "Name", "Status", "Progress" ]
				)
				p={}
				if id 
					p={"task_id"=>id}
				end
				@ov.task_get_all(p).each do |task|
					tbl << [ task["id"] , task["name"] , 
						task["status"] , task["progress"] ]
				end
				print_good("OpenVAS list of tasks")
				puts "\n"
				puts tbl.to_s + "\n"
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_target_list(*args)
			usagecmd="openvas_target_list [id]
Example: openvas_target_list 
Example: openvas_target_list 9fd90790-a79b-49e0-b08e-6912afde72f4"
			return if not openvas_verify
			if (args[0] == "-h") then
				print_status(usagecmd)
				return
			end
			if not (args.length == 0 or args[0].empty?) then
				id=args[0]
			end
			begin
				tbl = Rex::Ui::Text::Table.new(
					'Columns' => [ "ID","Name","Hosts" ])
				p={}
				if id 
					p={"target_id"=>id}
				end
				@ov.target_get_all(p).each do |target|
					tbl << [target["id"], 
					target["name"], 
					target["hosts"] ]
				end
				print_good("OpenVAS list of targets")
				puts "\n"
				puts tbl.to_s + "\n"
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_target_info(*args)
			usagecmd="openvas_target_info <id>
Example: openvas_target_info 9fd90790-a79b-49e0-b08e-6912afde72f4"
			return if not openvas_verify
			if (args.length == 0 or args[0].empty? or args[0] == "-h")
				print_status(usagecmd)
				return
			end
			begin
				print_good("OpenVAS target info")
				id=args[0]
				p={}
				if id 
					p={"target_id"=>id}
				end
				@ov.target_get_all(p).each do |target|
					tbl = Rex::Ui::Text::Table.new(
						'Columns' => 
						[ "Field", "Value" ]
					)
					target.each_key do |key|
						tbl.add_row([key,target[key]]);
					end
					puts "\n"
					puts tbl.to_s + "\n"
				end
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_target_create(*args)
			usagecmd="openvas_target_create <name> <hosts> <comment>

Example: openvas_target_create mylocalhost 127.0.0.1 MyLocalHostComment"
			return if not openvas_verify
			if(args.length != 3 or args[0].empty? or args[0] == "-h")
				print_status(usagecmd)
				return
			end
			begin
				id=@ov.target_create({"name"=>args[0],"comment"=>arg[2],"hosts"=>args[1]})
				print_good("Command completed successfuly: "+id)
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_target_delete(*args)
			usagecmd="openvas_target_delete <id>
Example: openvas_target_delete 9fd90790-a79b-49e0-b08e-6912afde72f4"
			return if not openvas_verify
			if(args.length == 0 or args[0].empty? or args[0] == "-h")
				print_status(usagecmd)
				return
			end
			begin
				id=args[0]
				@ov.target_delete(id)
				print_good("Command completed successfuly: "+id)
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_connect(*args)
			usagecmd = "Usage:
       openvas_connect username:password@host[:port] <ssl-confirm>
 -OR- 
       openvas_connect username password host port <ssl-confirm>"			

			if(args.length == 0 or args[0].empty? or args[0] == "-h")
				print_status(usagecmd)
				return
			end

			user = pass = host = port = sslv = nil

			@ovname="Metasploit"
			@ovcomment="Autocreated by the Metasploit Framework"

			case args.length
			when 1,2
				cred,targ = args[0].split('@', 2)
				user,pass = cred.split(':', 2)
				targ ||= '127.0.0.1:9390'
				host,port = targ.split(':', 2)
				port ||= '9390'
				sslv = args[1]
			when 4,5
				user,pass,host,port,sslv = args
			else
				print_status(usagecmd)
				return
			end


			if ! ((user and user.length > 0) and (host and host.length > 0) and (port and port.length > 0 and port.to_i > 0) and (pass and pass.length > 0))
				print_status(usagecmd)
				return
			end

			# taken from NeXpose WARNING
			if(host != "localhost" and host != "127.0.0.1" and sslv != "ok")
				print_error("Warning: SSL connections are not verified in this release, it is possible for an attacker")
				print_error("         with the ability to man-in-the-middle the OpenVAS traffic to capture the OpenVAS")
				print_error("         credentials. If you are running this on a trusted network, please pass in 'ok'")
				print_error("         as an additional parameter to this command.")
				return
			end

			# Wrap this so a duplicate session doesnt prevent a new login
			begin
			cmd_openvas_disconnect
			rescue ::Interrupt
				raise $!
			rescue ::Exception
			end

			begin
				print_status("Connecting to OpenVAS instance at #{host}:#{port} with username #{user}...")
				ov = OpenVASOMP::OpenVASOMP.new("user"=>user,"password"=>pass,"host"=>host,"port"=>port)
			rescue OpenVASOMP::OMPAuthError => e
				print_error("Connection failed: #{e.reason}")
				return
			end

			@ov = ov
		end

		def cmd_openvas_config_list(*args)
			usagecmd="openvas_config_list [id]
Example: openvas_config_list 
Example: openvas_config_list 9fd90790-a79b-49e0-b08e-6912afde72f4"
			return if not openvas_verify
			if (args[0] == "-h") then
				print_status(usagecmd)
				return
			end
			if not (args.length == 0 or args[0].empty?) then
				id=args[0]
			end
			begin
				tbl = Rex::Ui::Text::Table.new(
					'Columns' => 
					[ "ID", "Name", "Comments" ]
				)
				p={}
				if id 
					p={"config_id"=>id}
				end
				@ov.config_get_all(p).each do |config|
					tbl << [ config["id"], config["name"], 
						config["comment"] ]
				end
				print_good("OpenVAS list of configs")
				puts "\n"
				puts tbl.to_s + "\n"
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_config_info(*args)
			usagecmd="openvas_config_info <id>
Example: openvas_config_info 9fd90790-a79b-49e0-b08e-6912afde72f4"
			return if not openvas_verify
			if (args.length == 0 or args[0].empty? or args[0] == "-h")
				print_status(usagecmd)
				return
			end
			begin
				print_good("OpenVAS config info")
				id=args[0]
				p={}
				if id 
					p={"config_id"=>id}
				end
				@ov.config_get_all(p).each do |item|
					tbl = Rex::Ui::Text::Table.new(
						'Columns' => 
						[ "Field", "Value" ]
					)
					item.each_key do |key|
						tbl.add_row([key,item[key]]);
					end
					puts "\n"
					puts tbl.to_s + "\n"
				end
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_report_import(*args)
			usagecmd="openvas_report_import <id> 
Example: openvas_report_import 9fd90790-a79b-49e0-b08e-6912afde72f4
Note: gets NBE report from the OpenVAS and tries to import it into framework
"
			return if not openvas_verify
			if(args.length == 0 or args[0].empty? or args[0] == "-h")
				print_status(usagecmd)
				return
			end
			begin
				id=args[0]
				content=@ov.report_get_byid(id,'NBE')
				framework.db.import({:data => content})
				print_good("Command completed successfuly: "+id)
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_report_save(*args)
			usagecmd="openvas_report_save <id> <format> <file>
Example: openvas_report_save 9fd90790-a79b-49e0-b08e-6912afde72f4 PDF /tmp/a.pdf"
			return if not openvas_verify
			if(args.length != 3 or args[0].empty? or args[0] == "-h")
				print_status(usagecmd)
				return
			end
			begin
				id=args[0]
				content=@ov.report_get_byid(id,args[1])
				File.open(args[2], 'w') {|f| f.write(content) }
				print_good("Command completed successfuly: "+id)
			rescue ::Exception
				print_error("Error executing")
			end
		end

		def cmd_openvas_scan(*args)
			opts = Rex::Parser::Arguments.new(
				"-h"   => [ false,  "This help menu"],
				"-t"   => [ true,   "The scan template to use (default:Full and fast )"],
				"-P"   => [ false,  "Leave the scan data on the server when it completes (this counts against the maximum licensed IPs)"],
				"-x"   => [ false,  "Automatically launch all exploits by matching reference after the scan completes (unsafe)"],
				"-X"   => [ false,  "Automatically launch all exploits by matching reference and port after the scan completes (unsafe)"],
				"-d"   => [ false,  "Scan hosts based on the contents of the existing database"],
				"-v"   => [ false,  "Display diagnostic information about the scanning process"],
				"-I"   => [ true,   "Only scan systems with an address within the specified range"],
				"-E"   => [ true,   "Exclude hosts in the specified range from the scan"],
				"-R"   => [ true,   "Specify a minimum exploit rank to use for automated exploitation"]
			)

			opt_template  = "Full and fast"
			opt_verbose   = false
			opt_preserve  = false
			opt_autopwn   = false
			opt_rescandb  = false
			opt_addrinc   = nil
			opt_addrexc   = nil
			opt_scanned   = []
			opt_minrank   = "manual"

			opt_ranges    = []

			opts.parse(args) do |opt, idx, val|
				case opt
				when "-h"
					print_line("Usage: openvas_scan [options] <Target IP Ranges>")
					print_line(opts.usage)
					return
				when "-v"
					opt_verbose = true
				when "-t"
					opt_template = val
				when "-P"
					opt_preserve = true
				when "-X"
					opt_autopwn = "-p -x"
				when "-x"
					opt_autopwn = "-x" unless opt_autopwn
				when "-d"
					opt_rescandb = true
				when '-I'
					opt_addrinc = OptAddressRange.new('TEMPRANGE', [ true, '' ]).normalize(val)
				when '-E'
					opt_addrexc = OptAddressRange.new('TEMPRANGE', [ true, '' ]).normalize(val)
				else
					opt_ranges << val
				end
			end

			return if not openvas_verify

			# Include all database hosts as scan targets if specified
			if(opt_rescandb)
				print_status("Loading scan targets from the active database...") if opt_verbose
				framework.db.hosts.each do |host|
					next if host.state != ::Msf::HostState::Alive
					opt_ranges << host.address
				end
			end

			opt_ranges = opt_ranges.join(',')

			if(opt_ranges.strip.empty?)
				print_line("Usage: openvas_scan [options] <Target IP Ranges>")
				print_line(opts.usage)
				return
			end

			if(opt_verbose)
				print_status("Creating a new scan using config #{opt_template} against #{opt_ranges}")
			end

			range_inp = ::Msf::OptAddressRange.new('TEMPRANGE', [ true, '' ]).normalize(opt_ranges)
			range     = ::Rex::Socket::RangeWalker.new(range_inp)
			include_range = opt_addrinc ? ::Rex::Socket::RangeWalker.new(opt_addrinc) : nil
			exclude_range = opt_addrexc ? ::Rex::Socket::RangeWalker.new(opt_addrexc) : nil

			completed = 0
			total     = range.num_ips
			count     = 0

			print_status("Scanning #{total} addresses with config #{opt_template}")

			while(completed < total)
				count    += 1
				queue     = []

				while(ip = range.next_ip )

					if(exclude_range and exclude_range.include?(ip))
						print_status(" >> Skipping host #{ip} due to exclusion") if opt_verbose
						next
					end

					if(include_range and ! include_range.include?(ip))
						print_status(" >> Skipping host #{ip} due to inclusion filter") if opt_verbose
						next
					end

					opt_scanned << ip
					queue << ip
				end

				break if queue.empty?
				print_status("Scanning #{queue[0]}-#{queue[-1]}...") if opt_verbose

				msfid = Time.now.to_i
				
				ipstr=''
				queue.each do |ip|
					if ipstr==''
						ipstr=ip 
					else
						ipstr=ipstr+","+ip
					end
				end	
				# Create a temporary site
				mname="#{@ovname}-#{msfid}"
				mcomment=@ovcomment

				mtarget=@ov.target_create({"name"=>mname, "hosts"=>ipstr, "comment"=>mcomment})		
				
				print_status(" >> Created temporary target #{mname} with id #{mtarget}") if opt_verbose

				mconfig=@ov.config_get().index(opt_template)	
				
				if mconfig 
					print_status(" >> Found config #{opt_template} with id #{mconfig}") if opt_verbose
				else
					print_error("Config not found")
					break
				end
	
				# Create temporary task
				mtask = @ov.task_create({"name"=>mname,"comment"=>mcomment, "target"=>mtarget, "config"=>mconfig})
				if mtask 
					print_status(" >> Created task #{mname} with id #{mtask}") if opt_verbose
				else
					print_error("Task could not be created")
					break
				end


				@ov.task_start(mtask)

				print_status(" >> Scan has been launched with ID #{mtask}") if opt_verbose

				rep = true
				begin
				prev = nil
				while(true)
					stat = @ov.task_get_byid(mtask)
					break if stat["status"] == "Done" or stat["status"] == "Stopped"
					percent=stat["progress"]

					stat = "Progress: #{percent} %"
					if(stat != prev)
						print_status(" >> #{stat}") if opt_verbose
					end
					prev = stat
					select(nil, nil, nil, 5.0)
				end
				print_status(" >> Scan has been completed with task ID #{mtask}") if opt_verbose
				rescue ::Interrupt
					rep = false
					print_status(" >> Terminating task ID #{mtask} due to console interupt") if opt_verbose
					@ov.task_stop(mtask)
					break
				end

				# Wait for the automatic report generation to complete
				if(rep)
					print_status(" >> Getting report...") if opt_verbose
					stat = @ov.task_get_byid(mtask)

					if stat["status"] != "Done" 
					content=@ov.report_get_byid(stat["lastreport"],'NBE')
					print_status(" >> Importing the report data from OpenVAS...") if opt_verbose
					framework.db.import({:data => content})

				end

				if ! opt_preserve
					print_status(" >> Deleting the temporary task and target...") if opt_verbose
					@ov.task_delete(mtask)
					@ov.target_delete(mtarget)
				end
			end

			print_status("Completed the scan of #{total} addresses")

			if(opt_autopwn)
				print_status("Launching an automated exploitation session")
				driver.run_single("db_autopwn -q -r -e -t #{opt_autopwn} -R #{opt_minrank} -I #{opt_scanned.join(",")}")
			end
		end
		end

		def cmd_openvas_disconnect(*args)
			@ov.logout if @ov
			@ov = nil
		end
	end

	#
	# Plugin initialization
	#

	def initialize(framework, opts)
		super
		add_console_dispatcher(OpenVASCommandDispatcher)
		print "Welcome to OpenVAS integration by kost\n\n"	
		print "Use openvas_help for list of commands you can use.\n"
		print "Note that you should have database ready. After that you should connect with:\n"
		print "openvas_connect (try with -h for help on connecting)\n"
		print_status("OpenVAS integration has been activated")
	end

	def cleanup
		remove_console_dispatcher('OpenVAS')
	end

	def name
		"OpenVAS"
	end

	def desc
		"Integrates with the OpenVAS - open source vulnerability management"
	end
end
end

