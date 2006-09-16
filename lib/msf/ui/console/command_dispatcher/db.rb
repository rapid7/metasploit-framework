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
			matches = {}
			framework.exploits.each_module do |n,m|
				e = m.new
				e.references.each do |r|
					next if r.ctx_id == 'URL'
					ref_name = r.ctx_id + '-' + r.ctx_val
					ref = framework.db.has_ref(ref_name)
					next if not ref
					ref.vulns.each do |vuln|
						xport = vuln.service.port
						xprot = vuln.service.proto
						xhost = vuln.service.host.address
						matches[[xport,xprot,xhost,n]]=true
					end
				end
			end
			
			matches.each_key do |xref|
				print_status("exploit/#{xref[3]} RPORT=#{xref[0].to_s} RHOST=#{xref[2].to_s}")
			end
		end

end
end
end
end
end
