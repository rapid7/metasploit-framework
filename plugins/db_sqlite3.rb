require 'fileutils'

module Msf

###
# 
# This class intializes the database db with a shiny new
# SQLite3 database instance.
#
###

class Plugin::DBSQLite3 < Msf::Plugin

	###
	#
	# This class implements an event handler for db events
	#
	###
	class DBEventHandler
		def on_db_host(context, host)
			puts "New host event: #{host.address}"
		end
		
		def on_db_service(context, service)
			puts "New service event: host=#{service.host.address} port=#{service.port} proto=#{service.proto} state=#{service.state}"
		end
		
		def on_db_vuln(context, vuln)
			puts "New vuln event: host=#{vuln.host.address} port=#{vuln.service.port} proto=#{vuln.service.proto} name=#{vuln.name}"
		end
	end
	
	###
	#
	# This class implements a sample console command dispatcher.
	#
	###
	class ConsoleCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher

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
				print_status("Service: host=#{service.host.address} port=#{service.port} proto=#{service.proto} state=#{service.state}")
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



	def initialize(framework, opts)
		super

		odb = File.join(Msf::Config.install_root, "data", "sql", "sqlite3.db")
		ndb = File.join(Msf::Config.install_root, "current.db")
		
		if (File.exists?(ndb))
			File.unlink(ndb)
		end
		
		FileUtils.copy(odb, ndb)
		
		if (not framework.db.connect("adapter" => "sqlite3", "dbfile" => ndb))
			File.unlink(ndb)
			raise PluginLoadError.new("Failed to connect to the database")
		end
		
		@dbh = DBEventHandler.new
		
		add_console_dispatcher(ConsoleCommandDispatcher)
		framework.events.add_db_subscriber(@dbh)
		
	end

	def cleanup
		framework.events.remove_db_subscriber(@dbh)
		remove_console_dispatcher('Database Backend')	
	end

	#
	# This method returns a short, friendly name for the plugin.
	#
	def name
		"db_sqlite3"
	end

	#
	# This method returns a brief description of the plugin.  It should be no
	# more than 60 characters, but there are no hard limits.
	#
	def desc
		"Loads a new sqlite3 database backend"
	end

protected

end
end
