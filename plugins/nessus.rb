# $Id$
# $Revision$

require 'nessus/nessus-xmlrpc'
require 'rex/parser/nessus_xml'

module Msf
	class Plugin::Nessus < Msf::Plugin

		#creates the index of exploit details to make searching for exploits much faster.
		def create_xindex
			start = Time.now
				print_status("Creating Exploit Search Index - (#{@xindex}) - this wont take long.")
				count = 0
				# use Msf::Config.get_config_root as the location.
				File.open("#{@xindex}", "w+") do |f|
					#need to add version line.
					f.puts(Msf::Framework::RepoRevision)
					framework.exploits.sort.each { |refname, mod|
						stuff = ""
						o = nil
						begin
							o = mod.new
						rescue ::Exception
						end
						stuff << "#{refname}|#{o.name}|#{o.platform_to_s}|#{o.arch_to_s}"
						next if not o
						o.references.map do |x|
							if !(x.ctx_id == "URL")
								if (x.ctx_id == "MSB")
									stuff << "|#{x.ctx_val}"
								else
									stuff << "|#{x.ctx_id}-#{x.ctx_val}"
								end
							end
						end
						stuff << "\n"
						f.puts(stuff)
					}
				end
				total = Time.now - start
				print_status("It has taken : #{total} seconds to build the exploits search index")
		end

		def nessus_index
			if File.exist?("#{@xindex}")
				#check if it's version line matches current version.
				File.open("#{@xindex}") {|f|
					line = f.readline
					line.chomp!
					if line.to_i == Msf::Framework::RepoRevision
						print_good("Exploit Index - (#{@xindex}) -  is valid.")
					else
						create_xindex
					end
				}
			else
				create_xindex
			end
		end

		class ConsoleCommandDispatcher
			include Msf::Ui::Console::CommandDispatcher

			def name
				"Nessus"
			end

			def commands
				{
					"nessus_connect" => "Connect to a nessus server: nconnect username:password@hostname:port <ssl ok>.",
					"nessus_admin" => "Checks if user is an admin.",
					"nessus_help" => "Get help on all commands.",
					"nessus_logout" => "Terminate the session.",
					"nessus_server_status" => "Check the status of your Nessus Server.",
					"nessus_server_feed" => "Nessus Feed Type.",
					"nessus_server_prefs" => "Display Server Prefs.",
					"nessus_report_list" => "List all Nessus reports.",
					"nessus_report_get" => "Import a report from the nessus server in Nessus v2 format.",
					"nessus_report_del" => "Delete a report.",
					"nessus_report_vulns" => "Get list of vulns from a report.",
					"nessus_report_hosts" => "Get list of hosts from a report.",
					"nessus_report_host_ports" => "Get list of open ports from a host from a report.",
					"nessus_report_host_detail" => "Detail from a report item on a host.",
					"nessus_scan_status" => "List all currently running Nessus scans.",
					"nessus_scan_new" => "Create new Nessus Scan.",
					"nessus_scan_pause" => "Pause a Nessus Scan.",
					"nessus_scan_pause_all" => "Pause all Nessus Scans.",
					"nessus_scan_stop" => "Stop a Nessus Scan.",
					"nessus_scan_stop_all" => "Stop all Nessus Scans.",
					"nessus_scan_resume" => "Resume a Nessus Scan.",
					"nessus_scan_resume_all" => "Resume all Nessus Scans.",
					"nessus_user_list" => "Show Nessus Users.",
					"nessus_user_add" => "Add a new Nessus User.",
					"nessus_user_del" => "Delete a Nessus User.",
					"nessus_user_passwd" => "Change Nessus Users Password.",
					"nessus_plugin_family" => "List plugins in a family.",
					"nessus_plugin_details" => "List details of a particular plugin.",
					"nessus_plugin_list" => "Displays each plugin family and the number of plugins.",
					"nessus_plugin_prefs" => "Display Plugin Prefs.",
					"nessus_policy_list" => "List all polciies.",
					"nessus_policy_del" => "Delete a policy.",
					"nessus_index" => "Manually generates a search index for exploits.",
					"nessus_template_list" => "List all the templates on the server.",
					"nessus_db_scan" => "Create a scan of all ips in db_hosts.",
					"nessus_save" => "Save username/passowrd/server/port details."
					}
			end

			def cmd_nessus_index
				Msf::Plugin::Nessus.nessus_index
			end

			def cmd_nessus_save(*args)
				#if we are logged in, save session details to nessus.yaml
				@nessus_yaml = "#{Msf::Config.get_config_root}/nessus.yaml"
				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_save")
					return
				end

				if args[0]
					print_status("Usage: ")
					print_status("       nessus_save")
					return
				end

				group = "default"

				if ((@user and @user.length > 0) and (@host and @host.length > 0) and (@port and @port.length > 0 and @port.to_i > 0) and (@pass and @pass.length > 0))
					config = Hash.new
					config = {"#{group}" => {'username' => @user, 'password' => @pass, 'server' => @host, 'port' => @port}}
					File.open("#{@nessus_yaml}", "w+") do |f|
						f.puts YAML.dump(config)
					end
					print_good("#{@nessus_yaml} created.")

				else
					print_error("Missing username/password/server/port - relogin and then try again.")
					return
				end
			end

			def cmd_nessus_db_scan(*args)
				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_db_scan <policy id> <scan name>")
					print_status(" Example:> nessus_db_scan 1 \"My Scan\"")
					print_status()
					print_status("Creates a scan based on all the hosts listed in db_hosts.")
					print_status("use nessus_policy_list to list all available policies")
					return
				end

				if ! nessus_verify_token
					return
				end

				case args.length
				when 2
					pid = args[0].to_i
					name = args[1]
				else
					print_status("Usage: ")
					print_status("       nessus_db_scan <policy id> <scan name>")
					print_status("       use nessus_policy_list to list all available policies")
					return
				end

				if check_policy(pid)
					print_error("That policy does not exist.")
					return
				end

				tgts = ""
				framework.db.hosts(framework.db.workspace).each do |host|
					tgts << host.address
					tgts << ","
				end

				tgts.chop!

				print_status("Creating scan from policy number #{pid}, called \"#{name}\" and scanning all hosts in workspace")

				scan = @n.scan_new(pid, name, tgts)

				if scan
					print_status("Scan started.  uid is #{scan}")
				end

			end

			def cmd_nessus_logout
				@token = nil
				print_status("Logged out")
				system("rm #{@nessus_yaml}")
				print_good("#{@nessus_yaml} removed.")
				return
			end

			def cmd_nessus_help(*args)
				tbl = Rex::Ui::Text::Table.new(
					'Columns' => [
						"Command",
						"Help Text"
					],
					'SortIndex' => -1
				)
				tbl << [ "Generic Commands", "" ]
				tbl << [ "-----------------", "-----------------"]
				tbl << [ "nessus_connect", "Connect to a nessus server" ]
				tbl << [ "nessus_save", "Save nessus login info between sessions" ]
				tbl << [ "nessus_logout", "Logout from the nessus server" ]
				tbl << [ "nessus_help", "Listing of available nessus commands" ]
				tbl << [ "nessus_server_status", "Check the status of your Nessus Server" ]
				tbl << [ "nessus_admin", "Checks if user is an admin" ]
				tbl << [ "nessus_server_feed", "Nessus Feed Type" ]
				tbl << [ "nessus_find_targets", "Try to find vulnerable targets from a report" ]
				tbl << [ "nessus_server_prefs", "Display Server Prefs" ]
				tbl << [ "", ""]
				tbl << [ "Reports Commands", "" ]
				tbl << [ "-----------------", "-----------------"]
				tbl << [ "nessus_report_list", "List all Nessus reports" ]
				tbl << [ "nessus_report_get", "Import a report from the nessus server in Nessus v2 format" ]
				tbl << [ "nessus_report_vulns", "Get list of vulns from a report" ]
				tbl << [ "nessus_report_hosts", "Get list of hosts from a report" ]
				tbl << [ "nessus_report_host_ports", "Get list of open ports from a host from a report" ]
				tbl << [ "nessus_report_host_detail", "Detail from a report item on a host" ]
				tbl << [ "", ""]
				tbl << [ "Scan Commands", "" ]
				tbl << [ "-----------------", "-----------------"]
				tbl << [ "nessus_scan_new", "Create new Nessus Scan" ]
				tbl << [ "nessus_scan_status", "List all currently running Nessus scans" ]
				tbl << [ "nessus_scan_pause", "Pause a Nessus Scan" ]
				tbl << [ "nessus_scan_pause_all", "Pause all Nessus Scans" ]
				tbl << [ "nessus_scan_stop", "Stop a Nessus Scan" ]
				tbl << [ "nessus_scan_stop_all", "Stop all Nessus Scans" ]
				tbl << [ "nessus_scan_resume", "Resume a Nessus Scan" ]
				tbl << [ "nessus_scan_resume_all", "Resume all Nessus Scans" ]
				tbl << [ "", ""]
				tbl << [ "Plugin Commands", "" ]
				tbl << [ "-----------------", "-----------------"]
				tbl << [ "nessus_plugin_list", "Displays each plugin family and the number of plugins" ]
				tbl << [ "nessus_plugin_family", "List plugins in a family" ]
				tbl << [ "nessus_plugin_details", "List details of a particular plugin" ]
				tbl << [ "", ""]
				tbl << [ "User Commands", "" ]
				tbl << [ "-----------------", "-----------------"]
				tbl << [ "nessus_user_list", "Show Nessus Users" ]
				tbl << [ "nessus_user_add", "Add a new Nessus User" ]
				tbl << [ "nessus_user_del", "Delete a Nessus User" ]
				tbl << [ "nessus_user_passwd", "Change Nessus Users Password" ]
				tbl << [ "", ""]
				tbl << [ "Policy Commands", "" ]
				tbl << [ "-----------------", "-----------------"]
				tbl << [ "nessus_policy_list", "List all polciies" ]
				tbl << [ "nessus_policy_del", "Delete a policy" ]
				print_status ""
				print_line tbl.to_s
				print_status ""
			end

			def cmd_nessus_server_feed(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_server_feed")
					print_status(" Example:> nessus_server_feed")
					print_status()
					print_status("Returns information about the feed type and server version.")
					return
				end

				if nessus_verify_token
					@feed, @version, @web_version = @n.feed
					tbl = Rex::Ui::Text::Table.new(
						'Columns' => [
							'Feed',
							'Nessus Version',
							'Nessus Web Version'
						])
					tbl << [@feed, @version, @web_version]
					print_good("Nessus Status")
					print_good "\n"
					print_line tbl.to_s
				end
			end

			def nessus_verify_token
				if @token.nil? or @token == ''
					ncusage
					return false
				end
				true
			end

      def nessus_verify_db
        if framework.db.connected?
          true
        else
          print_error("No database has been configured, please use db_create/db_connect first")
          return false
        end
      end

			def ncusage
				print_status("%redYou must do this before any other commands.%clr")
				print_status("Usage: ")
				print_status("       nessus_connect username:password@hostname:port <ssl ok>")
				print_status(" Example:> nessus_connect msf:msf@192.168.1.10:8834 ok")
				print_status("          OR")
				print_status("       nessus_connect username@hostname:port <ssl ok>")
				print_status(" Example:> nessus_connect msf@192.168.1.10:8834 ok")
				print_status("          OR")
				print_status("       nessus_connect hostname:port <ssl ok>")
				print_status(" Example:> nessus_connect 192.168.1.10:8834 ok")
				print_status("          OR")
				print_status("       nessus_connect")
				print_status(" Example:> nessus_connect")
				print_status("This only works after you have saved creds with nessus_save")
				return
			end

			def cmd_nessus_connect(*args)
				# Check if config file exists and load it
				@nessus_yaml = "#{Msf::Config.get_config_root}/nessus.yaml"
				if ! args[0]
					if File.exist?("#{@nessus_yaml}")
						lconfig = YAML.load_file("#{@nessus_yaml}")
						@user = lconfig['default']['username']
						@pass = lconfig['default']['password']
						@host = lconfig['default']['server']
						@port = lconfig['default']['port']
						nessus_login
						return
					else
						ncusage
						return
					end
				end

				if args[0] == "-h"
					print_status("%redYou must do this before any other commands.%clr")
					print_status("Usage: ")
					print_status("       nessus_connect username:password@hostname:port <ssl ok>")
					print_status(" Example:> nessus_connect msf:msf@192.168.1.10:8834 ok")
					print_status("		OR")
					print_status("       nessus_connect username@hostname:port <ssl ok>")
					print_status(" Example:> nessus_connect msf@192.168.1.10:8834 ok")
					print_status("		OR")
					print_status("       nessus_connect hostname:port <ssl ok>")
					print_status(" Example:> nessus_connect 192.168.1.10:8834 ok")
					print_status("          OR")
					print_status("       nessus_connect")
					print_status(" Example:> nessus_connect")
					print_status("This only works after you have saved creds with nessus_save")
					print_status()
					print_status("%bldusername%clr and %bldpassword%clr are the ones you use to login to the nessus web front end")
					print_status("%bldhostname%clr can be an ip address or a dns name of the web front end.")
					print_status("%bldport%clr is the standard that the nessus web front end runs on : 8834.  This is NOT 1241.")
					print_status("The \"ok\" on the end is important.  It is a way of letting you")
					print_status("know that nessus used a self signed cert and the risk that presents.")
					return
				end

				if ! @token == ''
					print_error("You are already authenticated.  Call nessus_logout before authing again")
					return
				end

				if(args.length == 0 or args[0].empty?)
					ncusage
					return
				end

				@user = @pass = @host = @port = @sslv = nil

				case args.length
				when 1,2
					if args[0].include? "@"
						cred,targ = args[0].split('@', 2)
						@user,@pass = cred.split(':', 2)
						targ ||= '127.0.0.1:8834'
						@host,@port = targ.split(':', 2)
						@port ||= '8834'
						@sslv = args[1]
					else
						@host,@port = args[0].split(':', 2)
						@port ||= '8834'
						@sslv = args[1]
					end

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

				if(@host != "localhost" and @host != "127.0.0.1" and @sslv != "ok")
					print_error("Warning: SSL connections are not verified in this release, it is possible for an attacker")
					print_error("         with the ability to man-in-the-middle the Nessus traffic to capture the Nessus")
					print_error("         credentials. If you are running this on a trusted network, please pass in 'ok'")
					print_error("         as an additional parameter to this command.")
					return
				end

				if ! @user
					print_error("Missing Username")
					ncusage
					return
				end

				if ! @pass
					print_error("Missing Password")
					ncusage
					return
				end

				if ! ((@user and @user.length > 0) and (@host and @host.length > 0) and (@port and @port.length > 0 and @port.to_i > 0) and (@pass and @pass.length > 0))
					ncusage
					return
				end
				nessus_login
			end

			def nessus_login

				if ! ((@user and @user.length > 0) and (@host and @host.length > 0) and (@port and @port.length > 0 and @port.to_i > 0) and (@pass and @pass.length > 0))
					print_status("You need to connect to a server first.")
					ncusage
					return
				end

				@url = "https://#{@host}:#{@port}/"
				print_status("Connecting to #{@url} as #{@user}")
				@n=NessusXMLRPC::NessusXMLRPC.new(@url,@user,@pass)
				@token=@n.login(@user,@pass)
				if @n.logged_in
					print_status("Authenticated")
				else
					print_error("Error connecting/logging to the server!")
					return
				end
			end

			def cmd_nessus_report_list(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_report_list")
					print_status(" Example:> nessus_report_list")
					print_status()
					print_status("Generates a list of all reports visable to your user.")
					return
				end

				if ! nessus_verify_token
					return
				end

				list=@n.report_list_hash

				tbl = Rex::Ui::Text::Table.new(
					'Columns' => [
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
				print_good "\n"
				print_line tbl.to_s + "\n"
				print_status("You can:")
				print_status("        Get a list of hosts from the report:          nessus_report_hosts <report id>")
			end

			def check_scan(*args)

				case args.length
				when 1
					rid = args[0]
				else
					print_error("No Report ID Supplied")
					return
				end

				scans = @n.scan_list_hash
				scans.each {|scan|
					if scan['id'] == rid
						return true
					end
				}
				return false
			end

			def cmd_nessus_report_get(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_report_get <report id>")
					print_status(" Example:> nessus_report_get f0eabba3-4065-7d54-5763-f191e98eb0f7f9f33db7e75a06ca")
					print_status()
					print_status("This command pulls the provided report from the nessus server in the nessusv2 format")
					print_status("and parses it the same way db_import_nessus does.  After it is parsed it will be")
					print_status("available to commands such as db_hosts, db_vulns, db_services and db_autopwn.")
					print_status("Use: nessus_report_list to obtain a list of report id's")
					return
				end

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

				if check_scan(rid)
					print_error("That scan is still running.")
					return
				end
				content = nil
				content=@n.report_file_download(rid)
				if content.nil?
					print_error("Failed, please reauthenticate")
					return
				end
				print_status("importing " + rid)
				framework.db.import({:data => content}) do |type,data|
					case type
					when :address
						print_line("%bld%blu[*]%clr %bld#{data}%clr")
					end
				end
				print_good("Done")
			end

			def cmd_nessus_scan_status(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_scan_status")
					print_status(" Example:> nessus_scan_status")
					print_status()
					print_status("Returns a list of information about currently running scans.")
					return
				end

				if ! nessus_verify_token
					return
				end

				list=@n.scan_list_hash
				if list.empty?
					print_status("No Scans Running.")
					print_status("You can:")
					print_status("        List of completed scans:     	nessus_report_list")
					print_status("        Create a scan:           		nessus_scan_new <policy id> <scan name> <target(s)>")
					return
				end

				tbl = Rex::Ui::Text::Table.new(
					'Columns' => [
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
				print_good "\n"
				print_line tbl.to_s
				print_good "\n"
				print_status("You can:")
				print_good("		Import Nessus report to database : 	nessus_report_get <reportid>")
				print_good("		Pause a nessus scan : 			nessus_scan_pause <scanid>")
			end

			def cmd_nessus_template_list(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_template_list")
					print_status(" Example:> nessus_template_list")
					print_status()
					print_status("Returns a list of information about the server templates..")
					return
				end

				if ! nessus_verify_token
					return
				end

				list=@n.template_list_hash

				if list.empty?
					print_status("No Templates Created.")
					print_status("You can:")
					print_status("        List of completed scans:     	nessus_report_list")
					print_status("        Create a template:           		nessus_template_new <policy id> <scan name> <target(s)>")
					return
				end

				tbl = Rex::Ui::Text::Table.new(
					'Columns' => [
						'Template ID',
						'Policy ID',
						'Name',
						'Owner',
						'Target'
					])

				list.each {|template|
					tbl << [ template['name'], template['pid'], template['rname'], template['owner'], template['target'] ]
				}
				print_good("Templates")
				print_good "\n"
				print_line tbl.to_s + "\n"
				print_good "\n"
				print_status("You can:")
				print_good("		Import Nessus report to database : 	nessus_report_get <reportid>")
			end

			def cmd_nessus_user_list(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_user_list")
					print_status(" Example:> nessus_user_list")
					print_status()
					print_status("Returns a list of the users on the Nessus server and their access level.")
					return
				end

				if ! nessus_verify_token
					return
				end

				if ! @n.is_admin
					print_status("Your Nessus user is not an admin")
				end

				list=@n.users_list
				print_good("There are #{list.length} users")
				tbl = Rex::Ui::Text::Table.new(
					'Columns' => [
						'Name',
						'Is Admin?',
						'Last Login'
					])

				list.each {|user|
					t = Time.at(user['lastlogin'].to_i)
					tbl << [ user['name'], user['admin'], t.strftime("%H:%M %b %d %Y") ]
				}
				print_good("Nessus users")
				print_good "\n"
				print_line tbl.to_s
			end

			def cmd_nessus_server_status(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_server_status")
					print_status(" Example:> nessus_server_status")
					print_status()
					print_status("Returns some status items for the server..")
					return
				end
				#Auth
				if ! nessus_verify_token
					return
				end

				#Check if we are an admin
				if ! @n.is_admin
					print_status("You need to be an admin for this.")
					return
				end

				#Versions
				cmd_nessus_server_feed

				tbl = Rex::Ui::Text::Table.new(
					'Columns' => [
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
				list=@n.policy_list_hash
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
				print_good "\n"
				print_line tbl.to_s
			end

			def cmd_nessus_plugin_list(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_plugin_list")
					print_status(" Example:> nessus_plugin_list")
					print_status()
					print_status("Returns a list of the plugins on the server per family.")
					return
				end

				if ! nessus_verify_token
					return
				end

				tbl = Rex::Ui::Text::Table.new(
					'Columns' => [
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
				print_good "\n"
				print_line tbl.to_s
				print_status("List plugins for a family : nessus_plugin_family <family name>")
			end

			def check_policy(*args)

				case args.length
				when 1
					pid = args[0]
				else
					print_error("No Policy ID supplied.")
					return
				end

				pol = @n.policy_list_hash
				pol.each {|p|
					if p['id'].to_i == pid
						return false
					end
				}
				return true
			end

			def cmd_nessus_scan_new(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_scan_new <policy id> <scan name> <targets>")
					print_status(" Example:> nessus_scan_new 1 \"My Scan\" 192.168.1.250")
					print_status()
					print_status("Creates a scan based on a policy id and targets.")
					print_status("use nessus_policy_list to list all available policies")
					return
				end

				if ! nessus_verify_token
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

				if check_policy(pid)
					print_error("That policy does not exist.")
					return
				end

				print_status("Creating scan from policy number #{pid}, called \"#{name}\" and scanning #{tgts}")

				scan = @n.scan_new(pid, name, tgts)

				if scan
					print_status("Scan started.  uid is #{scan}")
				end
			end

			def cmd_nessus_scan_pause(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_scan_pause <scan id>")
					print_status(" Example:> nessus_scan_pause f0eabba3-4065-7d54-5763-f191e98eb0f7f9f33db7e75a06ca")
					print_status()
					print_status("Pauses a running scan")
					print_status("use nessus_scan_status to list all available scans")
					return
				end

				if ! nessus_verify_token
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

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_scan_resume <scan id>")
					print_status(" Example:> nessus_scan_resume f0eabba3-4065-7d54-5763-f191e98eb0f7f9f33db7e75a06ca")
					print_status()
					print_status("resumes a running scan")
					print_status("use nessus_scan_status to list all available scans")
					return
				end

				if ! nessus_verify_token
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

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_report_hosts <report id>")
					print_status(" Example:> nessus_report_hosts f0eabba3-4065-7d54-5763-f191e98eb0f7f9f33db7e75a06ca")
					print_status()
					print_status("Returns all the hosts associated with a scan and details about their vulnerabilities")
					print_status("use nessus_report_list to list all available scans")
					return
				end

				if ! nessus_verify_token
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
					'Columns' => [
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
				print_good "\n"
				print_line tbl.to_s
				print_status("You can:")
				print_status("        Get information from a particular host:          nessus_report_host_ports <hostname> <report id>")
			end

			def cmd_nessus_report_vulns(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_report_vulns <report id>")
					print_status(" Example:> nessus_report_vulns f0eabba3-4065-7d54-5763-f191e98eb0f7f9f33db7e75a06ca")
					print_status()
					print_status("Returns all the vulns associated with a scan and details about hosts and their vulnerabilities")
					print_status("use nessus_report_list to list all available scans")
					return
				end

				if ! nessus_verify_token
					return
				end

				case args.length
				when 1
					rid = args[0]
				else
					print_status("Usage: ")
					print_status("       nessus_report_vulns <report id>")
					print_status("       use nessus_report_vulns to list all available reports")
					return
				end

				tbl = Rex::Ui::Text::Table.new(
					'Columns' => [
						'Hostname',
						'Port',
						'Proto',
						'Sev',
						'PluginID',
						'Plugin Name'
					])
				print_status("Grabbing all vulns for report #{rid}")
				hosts=@n.report_hosts(rid)
				hosts.each do |host|
					ports=@n.report_host_ports(rid, host['hostname'])
					ports.each do |port|
						details=@n.report_host_port_details(rid, host['hostname'], port['portnum'], port['protocol'])
						details.each do |detail|
							tbl << [host['hostname'],
							port['portnum'],
							port['protocol'],
							detail['severity'],
							detail['pluginID'],
							detail['pluginName']
							]
						end
					end
				end
				print_good("Report Info")
				print_line
				print_line tbl.to_s
				print_status("You can:")
				print_status("        Get information from a particular host:          nessus_report_host_ports <hostname> <report id>")
			end

			def cmd_nessus_report_host_ports(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_report_host_ports <hostname> <report id>")
					print_status(" Example:> nessus_report_host_ports 192.168.1.250 f0eabba3-4065-7d54-5763-f191e98eb0f7f9f33db7e75a06ca")
					print_status()
					print_status("Returns all the ports associated with a host and details about their vulnerabilities")
					print_status("use nessus_report_hosts to list all available hosts for a report")
				end

				if ! nessus_verify_token
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
					'Columns' => [
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
				print_good "\n"
				print_line tbl.to_s
				print_status("You can:")
				print_status("        Get detailed scan infromation about a specfic port: nessus_report_host_detail <hostname> <port> <protocol> <report id>")
			end

			def cmd_nessus_report_host_detail(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_report_host_detail <hostname> <port> <protocol> <report id>")
					print_status(" Example:> nessus_report_host_ports 192.168.1.250 445 tcp f0eabba3-4065-7d54-5763-f191e98eb0f7f9f33db7e75a06ca")
					print_status()
					print_status("Returns all the vulns associated with a port for a specific host")
					print_status("use nessus_report_host_ports to list all available ports for a host")
					return
				end

				if ! nessus_verify_token
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
					'Columns' => [
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
					tbl << [
						detail['port'],
						detail['severity'],
						detail['pluginID'],
						detail['pluginName'],
						detail['cvss_base_score'] || 'none',
						detail['exploit_available'] || '.',
						detail['cve'] || '.',
						detail['risk_factor'] || '.',
						detail['cvss_vector'] || '.'
					]
				}
				print_good("Port Info")
				print_good "\n"
				print_line tbl.to_s
			end

			def cmd_nessus_scan_pause_all(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_scan_pause_all")
					print_status(" Example:> nessus_scan_pause_all")
					print_status()
					print_status("Pauses all currently running scans")
					print_status("use nessus_scan_list to list all running scans")
					return
				end

				if ! nessus_verify_token
					return
				end

				pause = @n.scan_pause_all

				print_status("All scans have been paused")
			end

			def cmd_nessus_scan_stop(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_scan_stop <scan id>")
					print_status(" Example:> nessus_scan_stop f0eabba3-4065-7d54-5763-f191e98eb0f7f9f33db7e75a06ca")
					print_status()
					print_status("Stops a currently running scans")
					print_status("use nessus_scan_list to list all running scans")
					return
				end

				if ! nessus_verify_token
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

			def cmd_nessus_scan_stop_all(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_scan_stop_all")
					print_status(" Example:> nessus_scan_stop_all")
					print_status()
					print_status("stops all currently running scans")
					print_status("use nessus_scan_list to list all running scans")
					return
				end

				if ! nessus_verify_token
					return
				end

				pause = @n.scan_stop_all

				print_status("All scans have been stopped")
			end

			def cmd_nessus_scan_resume_all(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_scan_resume_all")
					print_status(" Example:> nessus_scan_resume_all")
					print_status()
					print_status("resumes all currently running scans")
					print_status("use nessus_scan_list to list all running scans")
					return
				end

				if ! nessus_verify_token
					return
				end

				pause = @n.scan_resume_all

				print_status("All scans have been resumed")
			end

			def cmd_nessus_user_add(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_user_add <username> <password>")
					print_status(" Example:> nessus_user_add msf msf")
					print_status()
					print_status("Only adds non admin users. Must be an admin to add users.")
					print_status("use nessus_user_list to list all users")
					return
				end

				if ! nessus_verify_token
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

				u = @n.users_list
				u.each { |stuff|
					if stuff['name'] == user
						print_error("That user exists")
						return
					end
				}
				add = @n.user_add(user,pass)
				status = add.root.elements['status'].text if add
				if status == "OK"
					print_good("#{user} has been added")
				else
					print_error("#{user} was not added")
				end
			end

			def cmd_nessus_user_del(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_user_del <username>")
					print_status(" Example:> nessus_user_del msf")
					print_status()
					print_status("Only dels non admin users. Must be an admin to del users.")
					print_status("use nessus_user_list to list all users")
					return
				end

				if ! nessus_verify_token
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

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_user_passwd <username> <password>")
					print_status(" Example:> nessus_user_passwd msf newpassword")
					print_status()
					print_status("Changes the password of a user. Must be an admin to change passwords.")
					print_status("use nessus_user_list to list all users")
					return
				end

				if ! nessus_verify_token
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

			def cmd_nessus_admin(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_admin")
					print_status(" Example:> nessus_admin")
					print_status()
					print_status("Checks to see if the current user is an admin")
					print_status("use nessus_user_list to list all users")
					return
				end

				if ! nessus_verify_token
					return
				end

				if ! @n.is_admin
					print_error("Your Nessus user is not an admin")
				else
					print_good("Your Nessus user is an admin")
				end
			end

			def cmd_nessus_plugin_family(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_plugin_family <plugin family name>")
					print_status(" Example:> nessus_plugin_family \"Windows : Microsoft Bulletins\" ")
					print_status()
					print_status("Returns a list of all plugins in that family.")
					print_status("use nessus_plugin_list to list all plugins")
					return
				end

				if ! nessus_verify_token
					return
				end

				case args.length
				when 1
					fam = args[0]
				else
					print_status("Usage: ")
					print_status("       nessus_plugin_family <plugin family name>")
					print_status("       list all plugins from a Family from nessus_plugin_list")
					return
				end

				tbl = Rex::Ui::Text::Table.new(
					'Columns' => [
						'Plugin ID',
						'Plugin Name',
						'Plugin File Name'
					])

				family = @n.plugin_family(fam)

				family.each {|plugin|
					tbl << [ plugin['id'], plugin['name'], plugin['filename'] ]
				}
				print_good("#{fam} Info")
				print_good "\n"
				print_line tbl.to_s
			end

			def cmd_nessus_policy_list(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_policy_list")
					print_status(" Example:> nessus_policy_list")
					print_status()
					print_status("Lists all policies on the server")
					return
				end

				if ! nessus_verify_token
					return
				end

				tbl = Rex::Ui::Text::Table.new(
					'Columns' => [
						'ID',
						'Name',
						'Comments'
					])
				list=@n.policy_list_hash
				list.each {|policy|
					tbl << [ policy['id'], policy['name'], policy['comments'] ]
				}
				print_good("Nessus Policy List")
				print_good "\n"
				print_line tbl.to_s
			end

			def cmd_nessus_policy_del(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_policy_del <policy ID>")
					print_status(" Example:> nessus_policy_del 1")
					print_status()
					print_status("Must be an admin to del policies.")
					print_status("use nessus_policy_list to list all policies")
					return
				end

				if ! nessus_verify_token
					return
				end

				if ! @n.is_admin
					print_error("Your Nessus user is not an admin")
					return
				end

				case args.length
				when 1
					pid = args[0]
				else
					print_status("Usage: ")
					print_status("       nessus_policy_del <policy ID>")
					print_status("       nessus_policy_list to find the id.")
					return
				end


					del = @n.policy_del(pid)
					status = del.root.elements['status'].text
					if status == "OK"
						print_good("Policy number #{pid} has been deleted")
					else
						print_error("Policy number #{pid} was not deleted")
					end

				end

			def cmd_nessus_plugin_details(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_plugin_details <plugin file name>")
					print_status(" Example:> nessus_plugin_details ping_host.nasl ")
					print_status()
					print_status("Returns details on a particular plugin.")
					print_status("use nessus_plugin_list to list all plugins")
					return
				end

				if ! nessus_verify_token
					return
				end

				case args.length
				when 1
					pname = args[0]
				else
					print_status("Usage: ")
					print_status("       nessus_policy_del <plugin file name>")
					print_status("       nessus_plugin_list and then nessus_plugin_family to find the plugin file name.")
					return
				end

				tbl = Rex::Ui::Text::Table.new(
					'Columns' => [
						'',
						''
					])

				entry = @n.plugin_detail(pname)
				print_good("Plugin Details for #{entry['name']}")
				tbl << [ "Plugin ID", entry['id'] ]
				tbl << [ "Plugin Family", entry['family'] ]
				tbl << [ "CVSS Base Score", entry['cvss_base_score'] ]
				tbl << [ "CVSS Vector", entry['cvss_vector'] ]
				tbl << [ "CVSS Temporal Score", entry['cvss_temporal_score'] ]
				tbl << [ "CVSS Temporal Vector", entry['cvss_temporal_vector'] ]
				tbl << [ "Risk Factor", entry['risk_factor'] ]
				tbl << [ "Exploit Available", entry['exploit_available'] ]
				tbl << [ "Exploitability Ease", entry['exploit_ease'] ]
				tbl << [ "Synopsis", entry['synopsis'] ]
				tbl << [ "Description", entry['description'] ]
				tbl << [ "Solution", entry['solution'] ]
				tbl << [ "Plugin Pub Date", entry['plugin_publication_date'] ]
				tbl << [ "Plugin Modification Date", entry['plugin_modification_date'] ]
				print_good "\n"
				print_line tbl.to_s
			end

			def cmd_nessus_report_del(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_report_del <reportname>")
					print_status(" Example:> nessus_report_del f0eabba3-4065-7d54-5763-f191e98eb0f7f9f33db7e75a06ca")
					print_status()
					print_status("Must be an admin to del reports.")
					print_status("use nessus_report_list to list all reports")
					return
				end

				if ! nessus_verify_token
					return
				end

				if ! @n.is_admin
					print_error("Your Nessus user is not an admin")
					return
				end

				case args.length
				when 1
					rid = args[0]
				else
					print_status("Usage: ")
					print_status("       nessus_report_del <report ID>")
					print_status("       nessus_report_list to find the id.")
					return
				end


					del = @n.report_del(rid)
					status = del.root.elements['status'].text
					if status == "OK"
						print_good("Report #{rid} has been deleted")
					else
						print_error("Report #{rid} was not deleted")
					end
				end

			def cmd_nessus_server_prefs(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_server_prefs")
					print_status(" Example:> nessus_server_prefs")
					print_status()
					print_status("Returns a long list of server prefs.")
					return
				end

				if ! nessus_verify_token
					return
				end

				if ! @n.is_admin
					print_error("Your Nessus user is not an admin")
					return
				end

				tbl = Rex::Ui::Text::Table.new(
					'Columns' => [
						'Name',
						'Value'
					])
				prefs = @n.server_prefs
				prefs.each {|pref|
					tbl << [ pref['name'], pref['value'] ]
				}
				print_good("Nessus Server Pref List")
				print_good "\n"
				print_line tbl.to_s + "\n"

			end

			def cmd_nessus_plugin_prefs(*args)

				if args[0] == "-h"
					print_status("Usage: ")
					print_status("       nessus_plugin_prefs")
					print_status(" Example:> nessus_plugin_prefs")
					print_status()
					print_status("Returns a long list of plugin prefs.")
					return
				end

				if ! nessus_verify_token
					return
				end

				if ! @n.is_admin
					print_error("Your Nessus user is not an admin")
					return
				end

				tbl = Rex::Ui::Text::Table.new(
					'Columns' => [
						'Name',
						'Value',
						'Type'
					])
				prefs = @n.plugin_prefs
				prefs.each {|pref|
					tbl << [ pref['prefname'], pref['prefvalues'], pref['preftype'] ]
				}
				print_good("Nessus Plugins Pref List")
				print_good "\n"
				print_line tbl.to_s
			end
		end

		def initialize(framework, opts)
			super

			add_console_dispatcher(ConsoleCommandDispatcher)
			@nbver = "1.1" # Nessus Plugin Version.  Increments each time we commit to msf
			@xindex = "#{Msf::Config.get_config_root}/nessus_index" # location of the exploit index file used to speed up searching for valid exploits.
			@nessus_yaml = "#{Msf::Config.get_config_root}/nessus.yaml" #location of the nessus.yml containing saved nessus creds
			print_status("Nessus Bridge for Metasploit #{@nbver}")
			print_good("Type %bldnessus_help%clr for a command listing")
			#nessus_index
		end

		def cleanup
			remove_console_dispatcher('Nessus')
		end

		def name
			"nessus"
		end

		def desc
			"Nessus Bridge for Metasploit #{@nbver}"
		end
		protected
	end
end
