
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
				"ngetreport" => "Import a report from the nessus server in Nessus v2 format"
			}
		end
		
		def nessus_verify
			if ! n.logged_in
				print_error("No active Nessus instance has been configured, please use 'nconnect'")
				return false
			end

			if ! (framework.db and framework.db.usable)
				print_error("No database has been configured, please use db_create/db_connect first")
				return false
			end

			true
		end

		
		def cmd_nconnect(*args)
			if(args.length == 0 or args[0].empty? or args[0] == "-h")
				print_status("Usage: ")
				print_status("       nconnect username:password@hostname:port <ssl ok>")
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
				print_status("Usage: ")
				print_status("       nconnect username:password@hostname:port <ssl ok>")
				return
			else
				print_status("Usage: ")
				print_status("       nconnect username:password@hostname:port <ssl ok>")
				return
			end
			
			if /\/\//.match(@host)
				print_status("Usage: ")
				print_status("       nconnect username:password@hostname:port <ssl ok>")
				return
			end
			
			if ! ((@user and @user.length > 0) and (@host and @host.length > 0) and (@port and @port.length > 0 and @port.to_i > 0) and (@pass and @pass.length > 0))
				print_status("Usage: ")
				print_status("       nconnect username:password@hostname:port <ssl ok>")
				return
			end
			
			if(@host != "localhost" and @host != "127.0.0.1" and @sslv != "ok")
				print_error("Warning: SSL connections are not verified in this release, it is possible for an attacker")
				print_error("         with the ability to man-in-the-middle the Nessus traffic to capture the Nessus")
				print_error("         credentials. If you are running this on a trusted network, please pass in 'ok'")
				print_error("         as an additional parameter to this command.")
				return
			end
		end
		
		def nessus_login
			
			if ! ((@user and @user.length > 0) and (@host and @host.length > 0) and (@port and @port.length > 0 and @port.to_i > 0) and (@pass and @pass.length > 0))
				print_status("Usage: ")
				print_status("       nconnect username:password@hostname:port <ssl ok>")
				return
			end
			
			url = "https://#{@host}:#{@port}/"
			
			print_status("Connecting to #{url}") 
			@n=NessusXMLRPC::NessusXMLRPC.new(url,@user,@pass) 
			if @n.logged_in 
				print_status("OK!")
			else
				print_error("Error connecting/logging to the server!") 
				exit 2
			end
			
			#@n = n
		end
		
		def cmd_nreports
			nessus_login
			list=@n.report_list_hash
			print_status(" Report ID : Report Name : Report Status : Report Timestamp")
			print_status
			list.each {|report| 
				print_status("#{report['id']} : #{report['name']} : #{report['status']} : #{report['timestamp']}")
			}
			print_status
			print_status("Import Nessus report to database : ngetreport <reportid>")
		end
		
		def cmd_ngetreport(*args)
			nessus_login
			
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

		print_status("Nessus Bridge plugin loaded.")
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