
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
		def name
			"Nessus"
		end

		#
		# Returns the hash of commands supported by this dispatcher.
		#
		def commands
			{
				"nessus_connect" => "Connect to a nessus server: nconnect username:password@hostname:port <ssl ok>",
				"nessus_report_list" => "List all Nessus reports",
				"nessus_report_get" => "Import a report from the nessus server in Nessus v2 format",
				"nessus_scan_status" => "List all currently running Nessus scans",
				"nessus_server_status" => "Check the status of your Nessus Server",
				"nessus_server_feed" => "Nessus Feed Type",
				"nessus_plugin_list" => "Displays each plugin family and the number of plugins",
				"nessus_user_list" => "Show Nessus Users",
				"nessus_scan_new" => "Create new Nessus Scan",
				"nessus_scan_pause" => "Pause a Nessus Scan",
				"nessus_scan_pause_all" => "Pause all Nessus Scans",
				"nessus_scan_stop" => "Stop a Nessus Scan",
				"nessus_scan_stop_all" => "Stop all Nessus Scans",
				"nessus_scan_resume" => "Resume a Nessus Scan",
				"nessus_scan_resume_all" => "Resume all Nessus Scans",
				"nessus_user_add" => "Add a new Nessus User",
				"nessus_user_del" => "Delete a Nessus User",
				"nessus_user_passwd" => "Change Nessus Users Password",
				"nessus_plugin_family" => "List plugins in a family",
				#"nessus_plugin_details" => "List details of a particular plugin"
				#"nessus_server_prefs" => "Display Server Prefs"
				#"nessus_policy_list" => "List all polciies"
				#"nessus_policy_new" => "Save new policy"
				#"nessus_policy_del" => "Delete a policy"
				#"nessus_policy_dupe" => "Duplicate a policy"
				#"nessus_policy_rename" => "Rename a policy"
				#"nessus_report_del" => "Delete a report"
				"nessus_report_hosts" => "Get list of hosts from a report",
				"nessus_admin" => "Checks if user is an admin",
				#"nessus_report_hosts_filter" => "Get list of hosts from a report with filter"
				"nessus_report_host_ports" => "Get list of open ports from a host from a report",
				"nessus_report_host_detail" => "Detail from a report item on a host"
				#"nessus_report_tags" => "Not sure what this does yet"
				#"nessus_report_upload" => "Upload nessusv2 report"
				
			}
		end
		
		def cmd_nessus_server_feed
			
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
			print_status("       nessus_connect username:password@hostname:port <ssl ok>")
			print_status(" Example:> nessus_connect msf:msf@192.168.1.10:8834 ok")
			return
		end

		
		def cmd_nessus_connect(*args)
			
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
		
		def cmd_nessus_report_list
			
			if ! nessus_verify_token
				return
			end
			
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
			print_good("Nessus Report List")
			$stdout.puts "\n"
			$stdout.puts tbl.to_s + "\n"
		end
		
		def cmd_nessus_report_get(*args)
			
			if ! nessus_verify_token
				return
			end
			
			if ! nessus_verify_db
				return
			end
			
			if(args.length == 0 or args[0].empty? or args[0] == "-h")
				print_status("Usage: ")	
				print_status("       nessus_report_get <report id> ")
				print_status("       use nessus_report_list to list all available reports for importing")
				return
			end
			
			rid = nil
			
			case args.length
			when 1
				rid = args[0]
			else
				print_status("Usage: ")
				print_status("       nessus_report_get <report id> ")
				print_status("       use nessus_report_list to list all available reports for importing")
				return
			end
			
			content=@n.report_file_download(rid)
			print_status("importing " + rid)
			framework.db.import({:data => content})
			
		end
		
		def cmd_nessus_scan_status
			#need to expand this to list policies and templates too.
			nessus_login
			list=@n.scan_list_hash
			if list.empty?
				print_status("No Scans Running.")
				print_status("You can:")
				print_status("        List of completed scans:     	nessus_report_list")
				print_status("        Create a scan:           		nessus_scan_new <policy id> <scan name> <target(s)>")
				return
			end
			
			tbl = Rex::Ui::Text::Table.new(
				'Columns' =>
					[
						'Scan ID',
						'Name',
						'Owner',
						'Started',
						'Status',
						'Current Hosts',
						'Total Hosts'
					])
			
			list.each {|scan|
				t = Time.at(scan['start'].to_i)
				tbl << [ scan['id'], scan['name'], scan['owner'], t.strftime("%H:%M %b %d %Y"), scan['status'], scan['current'], scan['total'] ]
			}
			print_good("Running Scans")
			$stdout.puts "\n"
			$stdout.puts tbl.to_s + "\n"
			$stdout.puts "\n"
			print_status("You can:")
			print_good("		Import Nessus report to database : 	nessus_report_get <reportid>")
			print_good("		Pause a nessus scan : 			nessus_scan_pause <scanid>")
		end
		
		def cmd_nessus_user_list
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
		
		def cmd_nessus_server_status
			#Auth
			if ! nessus_verify_token
				return
			end
			
			#Check if we are an admin
			if @n.is_admin
				print_status("Your Nessus user is an admin")
			end
			
			#Versions
			cmd_nessus_server_feed
			
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
		
		def cmd_nessus_plugin_list
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
			print_status("List plugins for a family : nessus_report_get <family name>")
		end
		
		def cmd_nessus_scan_new(*args)
			if ! nessus_verify_token
				nessus_login
				return
			end
			
			case args.length
			when 3
				pid = args[0].to_i
				name = args[1]
				tgts = args[2]
			else
				print_status("Usage: ")
				print_status("       nessus_scan_new <policy id> <scan name> <targets>")
				print_status("       use nessus_policy_list to list all available policies")
				return
			end
			
			print_status("Creating scan from policy number #{pid}, called \"#{name}\" and scanning #{tgts}")
			
			scan = @n.scan_new(pid, name, tgts)
			
			if scan
				print_status("Scan started.  uid is #{scan}")
			end
			#need policy id, scan name and targets
		end
		
		def cmd_nessus_scan_pause(*args)
			if ! nessus_verify_token
				nessus_login
				return
			end
			
			case args.length
			when 1
				sid = args[0]
			else
				print_status("Usage: ")
				print_status("       nessus_scan_pause <scan id>")
				print_status("       use nessus_scan_status to list all available scans")
				return
			end
			
			pause = @n.scan_pause(sid)
			
			print_status("#{sid} has been paused")
		end
		
		def cmd_nessus_scan_resume(*args)
			if ! nessus_verify_token
				nessus_login
				return
			end
			
			case args.length
			when 1
				sid = args[0]
			else
				print_status("Usage: ")
				print_status("       nessus_scan_resume <scan id>")
				print_status("       use nessus_scan_status to list all available scans")
				return
			end
			
			resume = @n.scan_resume(sid)
			
			print_status("#{sid} has been resumed")
		end
		
		def cmd_nessus_report_hosts(*args)
			if ! nessus_verify_token
				nessus_login
				return
			end
			
			case args.length
			when 1
				rid = args[0]
			else
				print_status("Usage: ")
				print_status("       nessus_report_hosts <report id>")
				print_status("       use nessus_report_list to list all available reports")
				return
			end
			
			tbl = Rex::Ui::Text::Table.new(
				'Columns' =>
					[
						'Hostname',
						'Severity',
						'Sev 0',
						'Sev 1',
						'Sev 2',
						'Sev 3',
						'Current Progress',
						'Total Progress'
					])
			hosts=@n.report_hosts(rid)
			hosts.each {|host|
				tbl << [ host['hostname'], host['severity'], host['sev0'], host['sev1'], host['sev2'], host['sev3'], host['current'], host['total'] ]
			}
			print_good("Report Info")
			$stdout.puts "\n"
			$stdout.puts tbl.to_s + "\n"
		end
		
		def cmd_nessus_report_host_ports(*args)
			if ! nessus_verify_token
				nessus_login
				return
			end
			
			case args.length
			when 2
				host = args[0]
				rid = args[1]
			else
				print_status("Usage: ")
				print_status("       nessus_report_host_ports <hostname> <report id>")
				print_status("       use nessus_report_list to list all available reports")
				return
			end
			
			tbl = Rex::Ui::Text::Table.new(
				'Columns' =>
					[
						'Port',
						'Protocol',
						'Severity',
						'Service Name',
						'Sev 0',
						'Sev 1',
						'Sev 2',
						'Sev 3'
					])
			ports=@n.report_host_ports(rid, host)
			ports.each {|port|
				tbl << [ port['portnum'], port['protocol'], port['severity'], port['svcname'], port['sev0'], port['sev1'], port['sev2'], port['sev3'] ]
			}
			print_good("Host Info")
			$stdout.puts "\n"
			$stdout.puts tbl.to_s + "\n"
		end
		
		def cmd_nessus_report_host_detail(*args)
			if ! nessus_verify_token
				nessus_login
				return
			end
			
			case args.length
			when 4
				host = args[0]
				port = args[1]
				prot = args[2]
				rid = args[3]
			else
				print_status("Usage: ")
				print_status("       nessus_report_host_detail <hostname> <port> <protocol> <report id>")
				print_status("       use nessus_report_host_ports to list all available ports")
				return
			end
			
			tbl = Rex::Ui::Text::Table.new(
				'Columns' =>
					[
						'Port',
						'Severity',
						'PluginID',
						'Plugin Name',
						'CVSS2',
						'Exploit?',
						'CVE',
						'Risk Factor',
						'CVSS Vector'
					])
			details=@n.report_host_port_details(rid, host, port, prot)
			details.each {|detail|
				tbl << [ detail['port'], detail['severity'], detail['pluginID'], detail['pluginName'], detail['cvss_base_score'] || 'none', detail['exploit_available'] || '.', detail['cve'] || '.', detail['risk_factor'] || '.', detail['cvss_vector'] || '.' ]
			}
			print_good("Port Info")
			$stdout.puts "\n"
			$stdout.puts tbl.to_s + "\n"
		end
		
		def cmd_nessus_scan_pause_all
			if ! nessus_verify_token
				nessus_login
				return
			end
			
			pause = @n.scan_pause_all
			
			print_status("All scans have been paused")
		end
		
		def cmd_nessus_scan_stop(*args)
			if ! nessus_verify_token
				nessus_login
				return
			end
			
			case args.length
			when 1
				sid = args[0]
			else
				print_status("Usage: ")
				print_status("       nessus_scan_stop <scan id>")
				print_status("       use nessus_scan_status to list all available scans")
				return
			end
			
			pause = @n.scan_stop(sid)
			
			print_status("#{sid} has been stopped")
		end
		
		def cmd_nessus_scan_stop_all
			if ! nessus_verify_token
				nessus_login
				return
			end
			
			pause = @n.scan_stop_all
			
			print_status("All scans have been stopped")
		end
		
		def cmd_nessus_scan_resume_all
			if ! nessus_verify_token
				nessus_login
				return
			end
			
			pause = @n.scan_resume_all
			
			print_status("All scans have been resumed")
		end
		
		def cmd_nessus_user_add(*args)
			if ! nessus_verify_token
				nessus_login
				return
			end
			
			if ! @n.is_admin
				print_error("Your Nessus user is not an admin")
				return
			end
			
			case args.length
			when 2
				user = args[0]
				pass = args[1]
			else
				print_status("Usage: ")
				print_status("       nessus_user_add <username> <password>")
				print_status("       Only adds non admin users")
				return
			end
			
			add = @n.user_add(user,pass)
			status = add.root.elements['status'].text
			if status == "OK"
				print_good("#{user} has been added") 
			else 
				print_error("#{user} was not added")
			end
		end
		
		def cmd_nessus_user_del(*args)
			if ! nessus_verify_token
				nessus_login
				return
			end
			
			if ! @n.is_admin
				print_error("Your Nessus user is not an admin")
				return
			end
			
			case args.length
			when 1
				user = args[0]
			else
				print_status("Usage: ")
				print_status("       nessus_user_del <username>")
				print_status("       Only dels non admin users")
				return
			end
			
			del = @n.user_del(user)
			status = del.root.elements['status'].text
			if status == "OK"
				print_good("#{user} has been deleted") 
			else 
				print_error("#{user} was not deleted")
			end
		end
		
		def cmd_nessus_user_passwd(*args)
			if ! nessus_verify_token
				nessus_login
				return
			end
			
			if ! @n.is_admin
				print_error("Your Nessus user is not an admin")
				return
			end
			
			case args.length
			when 2
				user = args[0]
				pass = args[1]
			else
				print_status("Usage: ")
				print_status("       nessus_user_passwd <username> <password>")
				print_status("       User list from nessus_user_list")
				return
			end
			
			pass = @n.user_pass(user,pass)
			status = pass.root.elements['status'].text
			if status == "OK"
				print_good("#{user}'s password has been changed") 
			else 
				print_error("#{user}'s password has not been changed")
			end
		end
		
		def cmd_nessus_admin
			if ! nessus_verify_token
				nessus_login
				return
			end
			
			if ! @n.is_admin
				print_error("Your Nessus user is not an admin")
			else
				print_good("Your Nessus user is an admin")	
			end
		end
		
		def cmd_nessus_plugin_family(*args)
			if ! nessus_verify_token
				nessus_login
				return
			end
			
			case args.length
			when 1
				fam = args[0]
			else
				print_status("Usage: ")
				print_status("       nessus_plugin_family <plugin family name>")
				print_status("       Family list from nessus_plugin_list")
				return
			end
			
			tbl = Rex::Ui::Text::Table.new(
				'Columns' =>
					[
						'Plugin ID',
						'Plugin Name',
						'Plugin File Name'
					])
			
			family = @n.plugin_family(fam)
			
			family.each {|plugin|
				tbl << [ plugin['id'], plugin['name'], plugin['filename'] ]
			}
			print_good("#{fam} Info")
			$stdout.puts "\n"
			$stdout.puts tbl.to_s + "\n"
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
