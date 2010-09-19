
require 'nessus/nessus-xmlrpc'

module Msf

class Plugin::Nessus < Msf::Plugin

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
			"Nessus"
		end

		#
		# Returns the hash of commands supported by this dispatcher.
		#
		def commands
			{
				"nconnect" => "Connect to a nessus server: nconnect username:password@hostname:port <ssl ok>",
				"nreports" => "List all Nessus reports",
				"ngetreport" => "Import a report from the nessus server in Nessus v2 format",
				"nscans" => "List all currently running Nessus scans",
				"nstatus" => "Check the status of your Nessus Server",
				"nfeed" => "Nessus Feed Type",
				"npluginlist" => "Displays each plugin family and the number of plugins",
				"nusers" => "Show Nessus Users"
			}
		end
		
		def cmd_nfeed
			
			if nessus_verify_token
				@feed, @version, @web_version = @n.feed
				tbl = Rex::Ui::Text::Table.new(
					'Columns' =>
						[
							'Feed',
							'Nessus Version',
							'Nessus Web Version'
						])
				tbl << [@feed, @version, @web_version]
				print_good("Nessus Status")
				$stdout.puts "\n"
				$stdout.puts tbl.to_s + "\n"
			end
			
		end
		
		def nessus_verify_token
			if ! @token
				if ((@user and @user.length > 0) and (@host and @host.length > 0) and (@port and @port.length > 0 and @port.to_i > 0) and (@pass and @pass.length > 0))
					nessus_login
					return false
				else
					print_status("You are not logged in")
					ncusage
					return false
				end
			end
			
			true
		end
		
		def nessus_verify_db
			
			if ! (framework.db and framework.db.active)
				print_error("No database has been configured, please use db_create/db_connect first")
				return false
			end
			
			true
			
		end
		
		def ncusage
			print_status("Usage: ")
			print_status("       nconnect username:password@hostname:port <ssl ok>")
			print_status(" Example:> nconnect msf:msf@192.168.1.10:8834 ok")
			return
		end

		
		def cmd_nconnect(*args)
			
			if(args.length == 0 or args[0].empty? or args[0] == "-h")
				ncusage
				return
			end
			
			@user = @pass = @host = @port = @sslv = nil
			
			case args.length
			when 1,2
				cred,targ = args[0].split('@', 2)
				@user,@pass = cred.split(':', 2)
				targ ||= '127.0.0.1:8834'
				@host,@port = targ.split(':', 2)
				@port ||= '8834'
				@sslv = args[1]
			when 3,4,5
				ncusage
				return
			else
				ncusage
				return
			end
			
			if /\/\//.match(@host)
				ncusage
				return
			end
			
			if ! ((@user and @user.length > 0) and (@host and @host.length > 0) and (@port and @port.length > 0 and @port.to_i > 0) and (@pass and @pass.length > 0))
				ncusage
				return
			end
			
			if(@host != "localhost" and @host != "127.0.0.1" and @sslv != "ok")
				print_error("Warning: SSL connections are not verified in this release, it is possible for an attacker")
				print_error("         with the ability to man-in-the-middle the Nessus traffic to capture the Nessus")
				print_error("         credentials. If you are running this on a trusted network, please pass in 'ok'")
				print_error("         as an additional parameter to this command.")
				return
			end
			nessus_login
		end
		
		def nessus_login
			
			if ! ((@user and @user.length > 0) and (@host and @host.length > 0) and (@port and @port.length > 0 and @port.to_i > 0) and (@pass and @pass.length > 0))
				print_status("You need to connect to a server first.")
				ncusage
				exit!
			end
			
			@url = "https://#{@host}:#{@port}/"
			
			print_status("Connecting to #{@url}") 
			@n=NessusXMLRPC::NessusXMLRPC.new(@url,@user,@pass)
			@token=@n.login(@user,@pass)
			if @n.logged_in 
				print_status("Authenticated")
			else
				print_error("Error connecting/logging to the server!") 
				exit 2
			end
			
		end
		
		def cmd_nreports
			
			if ! nessus_verify_token
				return
			end
			
			#lets try this with a table.
			list=@n.report_list_hash
			
			tbl = Rex::Ui::Text::Table.new(
				'Columns' =>
					[
						'ID',
						'Name',
						'Status',
						'Date'
					])
			
			list.each {|report|
				t = Time.at(report['timestamp'].to_i)
				tbl << [ report['id'], report['name'], report['status'], t.strftime("%H:%M %b %d %Y") ]
			}
			print_good("Nessus Reports")
			$stdout.puts "\n"
			$stdout.puts tbl.to_s + "\n"
		end
		
		def cmd_ngetreport(*args)
			
			if ! nessus_verify_token
				return
			end
			
			if ! nessus_verify_db
				return
			end
			
			
			
			if(args.length == 0 or args[0].empty? or args[0] == "-h")
				print_status("Usage: ")	
				print_status("       ngetreport <report id> ")
				print_status("       use nreports to list all available reports for importing")
				return
			end
			
			rid = nil
			
			case args.length
			when 1
				rid = args[0]
			else
				print_status("Usage: ")
				print_status("       ngetreport <report id> ")
				print_status("       use nreports to list all available reports for importing")
				return
			end
			
			content=@n.report_file_download(rid)
			print_status("importing " + rid)
			framework.db.import({:data => content})
			
		end
		
		def cmd_nscans
			
			nessus_login
			list=@n.scan_list_hash
			if list.empty?
				print_status("No Scans Running.")
				print_status("You can:")
				print_status("        List Reports of completed scans:     nreports")
				#print_status("        Create a scan:                       nstartscan <policy id> <scan name> <target(s)>")
				#print_status("        Get policy ID:                       ngetpolicies")
				return
			end
			
			tbl = Rex::Ui::Text::Table.new(
				'Columns' =>
					[
						'ID',
						'Name',
						'Current Hosts',
						'Total Hosts'
					])
			
			list.each {|scan|
				tbl << [ scan['id'], scan['name'], scan['current'], scan['total'] ]
			}
			print_good("Running Scans")
			$stdout.puts "\n"
			$stdout.puts tbl.to_s + "\n"
			$stdout.puts "\n"
			print_good("Import Nessus report to database : ngetreport <reportid>")
			
		end
		
		def cmd_nusers
			if ! nessus_verify_token
				return
			end
			
			list=@n.users_list
			print_good("There are #{list.length} users")
			tbl = Rex::Ui::Text::Table.new(
				'Columns' =>
					[
						'Name',
						'Is Admin?',
						'Last Login'
					])
			
			list.each {|user|
				t = Time.at(user['lastlogin'].to_i)
				tbl << [ user['name'], user['admin'], t.strftime("%H:%M %b %d %Y") ]
			}
			print_good("Nessus users")
			$stdout.puts "\n"
			$stdout.puts tbl.to_s + "\n"
		end
		
		def cmd_nstatus
			#Auth
			if ! nessus_verify_token
				return
			end
			
			#Check if we are an admin
			if @n.is_admin
				print_status("Your Nessus user is an admin")
			end
			
			#Versions
			cmd_nfeed
			
			tbl = Rex::Ui::Text::Table.new(
				'Columns' =>
					[
						'Users',
						'Policies',
						'Running Scans',
						'Reports',
						'Plugins'
					])
			#Count how many users the server has.
			list=@n.users_list
			users = list.length
			
			#Count how many policies
			list=@n.policy_list_uids
			policies = list.length
			
			#Count how many running scans
			list=@n.scan_list_uids
			scans = list.length
			
			#Count how many reports are available
			list=@n.report_list_hash
			reports = list.length
			
			#Count how many plugins
			list=@n.plugins_list
			total = Array.new
			list.each {|plugin| 
				total.push(plugin['num'].to_i)
			}
			plugins = total.sum
			tbl << [users, policies, scans, reports, plugins]
			$stdout.puts "\n"
			$stdout.puts tbl.to_s + "\n"
		end
		
		def cmd_npluginlist
			if ! nessus_verify_token
				nessus_login
				return
			end
			
			tbl = Rex::Ui::Text::Table.new(
				'Columns' =>
					[
						'Family Name',
						'Total Plugins'
					])
			list=@n.plugins_list
			total = Array.new
			list.each {|plugin|
				total.push(plugin['num'].to_i)
				tbl << [ plugin['name'], plugin['num'] ]
			}
			plugins = total.sum
			tbl << [ '', '']
			tbl << [ 'Total Plugins', plugins ]
			print_good("Plugins By Family")
			$stdout.puts "\n"
			$stdout.puts tbl.to_s + "\n"
			print_status("List plugins for a family : ngetreport <family name>")
		end
		
	end

	#
	# The constructor is called when an instance of the plugin is created.  The
	# framework instance that the plugin is being associated with is passed in
	# the framework parameter.  Plugins should call the parent constructor when
	# inheriting from Msf::Plugin to ensure that the framework attribute on
	# their instance gets set.
	#
	def initialize(framework, opts)
		super

		# If this plugin is being loaded in the context of a console application
		# that uses the framework's console user interface driver, register
		# console dispatcher commands.
		add_console_dispatcher(ConsoleCommandDispatcher)

		print_status("Nessus Bridge for Nessus 4.2.x")
	end

	#
	# The cleanup routine for plugins gives them a chance to undo any actions
	# they may have done to the framework.  For instance, if a console
	# dispatcher was added, then it should be removed in the cleanup routine.
	#
	def cleanup
		# If we had previously registered a console dispatcher with the console,
		# deregister it now.
		remove_console_dispatcher('Nessus')
	end

	#
	# This method returns a short, friendly name for the plugin.
	#
	def name
		"nessus"
	end

	#
	# This method returns a brief description of the plugin.  It should be no
	# more than 60 characters, but there are no hard limits.
	#
	def desc
		"HTTP Bridge to control a Nessus 4.2 scanner."
	end

protected
end

end