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
				puts "Vuln: host=#{vuln.host.address} port=#{vuln.service.port} proto=#{vuln.service.proto} name=#{vuln.name}"
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
				print_status("Usage: db_import_nessus [nessus.nbe]")
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
				
				m = r[3].match(/^([^\(]+)\((\d+)\/([^\)]+)\)/)
				next if not m
				
				host = framework.db.get_host(nil, addr)
				next if not host
				
				service = framework.db.get_service(nil, host, m[3].downcase, m[2].to_i)
				service.name = m[1]
				service.save
				
				vuln = framework.db.get_vuln(nil, service, "NSS-#{nasl.to_s}", data)
			end
		end	

end
end
end
end
end
