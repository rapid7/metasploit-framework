# $Id$ $Revision$
require 'nessus_rest'
require 'rex/parser/nessus_xml'

module Msf

  PLUGIN_NAME        = 'Nessus'
  PLUGIN_DESCRIPTION = 'Nessus Bridge for Metasploit'

  class Plugin::Nessus < Msf::Plugin

    def name
      PLUGIN_NAME
    end

    def desc
      PLUGIN_DESCRIPTION
    end

    class ConsoleCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      def name
        PLUGIN_NAME
      end

      def xindex
        "#{Msf::Config.get_config_root}/nessus_index"
      end

      def nessus_yaml
        "#{Msf::Config.get_config_root}/nessus.yaml"
      end

      def msf_local
        "#{Msf::Config.local_directory}"
      end

      def commands
        {
          "nessus_connect" => "Connect to a nessus server: nconnect username:password@hostname:port <verify_ssl>",
          "nessus_admin" => "Checks if user is an admin",
          "nessus_help" => "Get help on all commands",
          "nessus_logout" => "Terminate the session",
          "nessus_server_status" => "Check the status of your Nessus server",
          "nessus_server_properties" => "Nessus server properties such as feed type, version, plugin set and server UUID",
          "nessus_report_download" => "Download a report from the nessus server in either Nessus, HTML, PDF, CSV, or DB format",
          "nessus_report_vulns" => "Get list of vulns from a report",
          "nessus_report_hosts" => "Get list of hosts from a report",
          "nessus_report_host_details" => "Get detailed information from a report item on a host",
          "nessus_scan_list" => "List of currently running Nessus scans",
          "nessus_scan_new" => "Create a new Nessus scan",
          "nessus_scan_launch" => "Launch a previously added scan",
          "nessus_scan_pause" => "Pause a running Nessus scan",
          "nessus_scan_pause_all" => "Pause all running Nessus scans",
          "nessus_scan_stop" => "Stop a running or paused Nessus scan",
          "nessus_scan_stop_all" => "Stop all running or paused Nessus scans",
          "nessus_scan_resume" => "Resume a paused Nessus scan",
          "nessus_scan_resume_all" => "Resume all paused Nessus scans",
          "nessus_scan_details" => "Return detailed information of a given scan",
          "nessus_scan_export" => "Export a scan result in either Nessus, HTML, PDF, CSV, or DB format",
          "nessus_scan_export_status" => "Check the status of scan export",
          "nessus_user_list" => "List of Nessus users",
          "nessus_user_add" => "Add a new Nessus user",
          "nessus_user_del" => "Delete a Nessus user",
          "nessus_user_passwd" => "Change Nessus Users Password",
          "nessus_plugin_details" => "List details of a particular plugin",
          "nessus_plugin_list" => "Display plugin details in a particular plugin family",
          "nessus_policy_list" => "List all polciies",
          "nessus_policy_del" => "Delete a policy",
          "nessus_index" => "Manually generates a search index for exploits",
          "nessus_template_list" => "List all the templates on the server",
          "nessus_db_scan" => "Create a scan of all IP addresses in db_hosts",
          "nessus_db_scan_workspace" => "Create a scan of all IP addresses in db_hosts for a given workspace",
          "nessus_db_import" => "Import Nessus scan to the Metasploit connected database",
          "nessus_save" => "Save credentials of the logged in user to nessus.yml",
          "nessus_folder_list" => "List folders configured on the Nessus server",
          "nessus_scanner_list" => "List the configured scanners on the Nessus server",
          "nessus_family_list" => "List all the plugin families along with their corresponding family IDs and plugin count"
        }
      end

      def ncusage
        print_status("%redYou must do this before any other commands.%clr")
        print_status("Usage: ")
        print_status("nessus_connect username:password@hostname:port <ssl_verify>")
        print_status("Example:> nessus_connect msf:msf@192.168.1.10:8834")
        print_status("OR")
        print_status("nessus_connect username@hostname:port ssl_verify")
        print_status("Example:> nessus_connect msf@192.168.1.10:8834 ssl_verify")
        print_status("OR")
        print_status("nessus_connect hostname:port ssl_verify")
        print_status("Example:> nessus_connect 192.168.1.10:8834 ssl_verify")
        print_status("OR")
        print_status("nessus_connect")
        print_status("Example:> nessus_connect")
        print_status("This only works after you have saved creds with nessus_save")
        return
      end

      #creates the index of exploit details to make searching for exploits much faster.
      def create_xindex
        start = Time.now
        print_status("Creating Exploit Search Index - (#{xindex}) - this won't take long.")
        count = 0
        #Use Msf::Config.get_config_root as the location.
        File.open("#{xindex}", "w+") do |f|
          #need to add version line.
          f.puts(Msf::Framework::Version)
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
        if File.exist?("#{xindex}")
          #check if it's version line matches current version.
          File.open("#{xindex}") { |f|
            line = f.readline
            line.chomp!
            if line.to_i == Msf::Framework::RepoRevision
              print_good("Exploit Index - (#{xindex}) - is valid.")
            else
              create_xindex
            end
          }
        else
          create_xindex
        end
      end

      def nessus_login
        if !((@user and @user.length > 0) and (@host and @host.length > 0) and (@port and @port.length > 0 and @port.to_i > 0) and (@pass and @pass.length > 0))
          print_status("You need to connect to a server first.")
          ncusage
          return
        end
        @url = "https://#{@host}:#{@port}/"
        print_status("Connecting to #{@url} as #{@user}")
        verify_ssl=false
        if @sslv == "verify_ssl" then
          verify_ssl=true
        end
        @n = NessusREST::Client.new(:url=>@url,:username=>@user,:password=>@pass,:ssl_verify=>verify_ssl)
        if @n.authenticated
          print_status("User #{@user} authenticated successfully.")
          @token = 1
        else
          print_error("Error connecting/logging to the server!")
          return
        end
      end

      def nessus_verify_token
        if @token.nil? or @token == ''
          ncusage
          return false
        end
        true
      end

      def valid_policy(*args)
        case args.length
        when 1
          pid = args[0]
        else
          print_error("No Policy ID supplied.")
          return
        end
        pol = @n.list_policies
        pol["policies"].each { |p|
        if p["template_uuid"] == pid
          return true
        end
        }
        return false
      end

      def nessus_verify_db
        if !(framework.db and framework.db.active)
          print_error("No database has been configured, please use db_create/db_connect first")
          return false
        end
        true
      end

      def check_scan(*args)
        case args.length
        when 1
          scan_id = args[0]
        else
          print_error("No scan ID supplied")
          return
        end
        scans = @n.scan_list
        scans.each { |scan|
        if scan["scans"]["id"] == scan_id && scan["scans"]["status"] == "completed"
          return true
        end
        }
        return false
      end

      def is_scan_complete(scan_id)
        complete = false
        status = @n.scan_list
        status["scans"].each { |scan|
        if scan["id"] == scan_id.to_i && (scan["status"] == "completed" || scan["status"] == "imported")
          complete = true
        end
        }
        complete
      end

      def cmd_nessus_help(*args)
        tbl = Rex::Text::Table.new(
          'Columns' => [
            "Command",
            "Help Text"
            ],
          'SortIndex' => -1
          )
        tbl << [ "Generic Commands", "" ]
        tbl << [ "-----------------", "-----------------"]
        tbl << [ "nessus_connect", "Connect to a Nessus server" ]
        tbl << [ "nessus_logout", "Logout from the Nessus server" ]
        tbl << [ "nessus_login", "Login into the connected Nesssus server with a different username and password"]
        tbl << [ "nessus_save", "Save credentials of the logged in user to nessus.yml"]
        tbl << [ "nessus_help", "Listing of available nessus commands" ]
        tbl << [ "nessus_server_properties", "Nessus server properties such as feed type, version, plugin set and server UUID." ]
        tbl << [ "nessus_server_status", "Check the status of your Nessus Server" ]
        tbl << [ "nessus_admin", "Checks if user is an admin" ]
        tbl << [ "nessus_template_list", "List scan or policy templates" ]
        tbl << [ "nessus_folder_list", "List all configured folders on the Nessus server" ]
        tbl << [ "nessus_scanner_list", "List all the scanners configured on the Nessus server" ]
        tbl << [ "Nessus Database Commands", "" ]
        tbl << [ "-----------------", "-----------------" ]
        tbl << [ "nessus_db_scan", "Create a scan of all IP addresses in db_hosts" ]
        tbl << [ "nessus_db_scan_workspace", "Create a scan of all IP addresses in db_hosts for a given workspace" ]
        tbl << [ "nessus_db_import", "Import Nessus scan to the Metasploit connected database" ]
        tbl << [ "", ""]
        tbl << [ "Reports Commands", "" ]
        tbl << [ "-----------------", "-----------------"]
        tbl << [ "nessus_report_hosts", "Get list of hosts from a report" ]
        tbl << [ "nessus_report_vulns", "Get list of vulns from a report" ]
        tbl << [ "nessus_report_host_details", "Get detailed information from a report item on a host" ]
        tbl << [ "", ""]
        tbl << [ "Scan Commands", "" ]
        tbl << [ "-----------------", "-----------------"]
        tbl << [ "nessus_scan_list", "List of all current Nessus scans" ]
        tbl << [ "nessus_scan_new", "Create a new Nessus Scan" ]
        tbl << [ "nessus_scan_launch", "Launch a newly created scan. New scans need to be manually launched through this command" ]
        tbl << [ "nessus_scan_pause", "Pause a running Nessus scan" ]
        tbl << [ "nessus_scan_pause_all", "Pause all running Nessus scans" ]
        tbl << [ "nessus_scan_stop", "Stop a running or paused Nessus scan" ]
        tbl << [ "nessus_scan_stop_all", "Stop all running or paused Nessus scans" ]
        tbl << [ "nessus_scan_resume", "Resume a pasued Nessus scan" ]
        tbl << [ "nessus_scan_resume_all", "Resume all paused Nessus scans" ]
        tbl << [ "nessus_scan_details", "Return detailed information of a given scan" ]
        tbl << [ "nessus_scan_export", "Export a scan result in either Nessus, HTML, PDF, CSV, or DB format" ]
        tbl << [ "nessus_scan_export_status", "Check the status of an exported scan" ]
        tbl << [ "", ""]
        tbl << [ "Plugin Commands", "" ]
        tbl << [ "-----------------", "-----------------"]
        tbl << [ "nessus_plugin_list", "List all plugins in a particular plugin family." ]
        tbl << [ "nessus_family_list", "List all the plugin families along with their corresponding family IDs and plugin count." ]
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
        print_line ""
        print_line tbl.to_s
        print_line ""
      end

      def cmd_nessus_index
        nessus_index
      end

      def cmd_nessus_connect(*args)
        # Check if config file exists and load it
        if !args[0]
          if File.exist?(nessus_yaml)
            lconfig = YAML.load_file(nessus_yaml)
            @user = lconfig['default']['username'].to_s
            @pass = lconfig['default']['password'].to_s
            @host = lconfig['default']['server'].to_s
            @port = lconfig['default']['port'].to_s
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
          print_status("nessus_connect username:password@hostname:port <ssl_verify/ssl_ignore>")
          print_status("%bldusername%clr and %bldpassword%clr are the ones you use to login to the nessus web front end")
          print_status("%bldhostname%clr can be an IP address or a DNS name of the Nessus server.")
          print_status("%bldport%clr is the RPC port that the Nessus web front end runs on. By default it is TCP port 8834.")
          print_status("The \"ssl_verify\" to verify the SSL certificate used by the Nessus front end. By default the server")
          print_status("use a self signed certificate, therefore, users should use ssl_ignore.")
          return
        end

        if !@token == ''
          print_error("You are already authenticated.  Call nessus_logout before authenticating again")
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
        if !@user
          print_error("Missing Username")
          ncusage
          return
        end
        if !@pass
          print_error("Missing Password")
          ncusage
          return
        end
        if !((@user and @user.length > 0) and (@host and @host.length > 0) and (@port and @port.length > 0 and @port.to_i > 0) and (@pass and @pass.length > 0))
          ncusage
          return
        end
        nessus_login
      end

      def cmd_nessus_logout
        logout = @n.user_logout
        status = logout.to_s
        if status == "200"
          print_good("User account logged out successfully")
          @token = ""
        elsif status == "403"
          print_status("No user session to logout")
        else
          print_error("There was some problem in logging out the user #{@user}")
        end
        return
      end

      def cmd_nessus_save(*args)
        #if we are logged in, save session details to nessus.yaml
        if args[0] == "-h"
          print_status(" nessus_save")
          return
        end
        if args[0]
          print_status("Usage: ")
          print_status("nessus_save")
          return
        end
        group = "default"
        if ((@user and @user.length > 0) and (@host and @host.length > 0) and (@port and @port.length > 0 and @port.to_i > 0) and (@pass and @pass.length > 0))
          config = Hash.new
          config = {"#{group}" => {'username' => @user, 'password' => @pass, 'server' => @host, 'port' => @port}}
          File.open("#{nessus_yaml}", "w+") do |f|
            f.puts YAML.dump(config)
          end
          print_good("#{nessus_yaml} created.")
        else
          print_error("Missing username/password/server/port - relogin and then try again.")
          return
        end
      end

      def cmd_nessus_server_properties(*args)
        search_term = nil
        while (arg = args.shift)
          case arg
          when '-h', '--help'
            print_status("nessus_server_properties")
            print_status("Example:> nessus_server_properties -S searchterm")
            print_status("Returns information about the feed type and server version.")
            return
          when '-S', '--search'
            search_term = /#{args.shift}/nmi
          end
        end

        resp = @n.server_properties
        tbl = Rex::Text::Table.new(
          'SearchTerm' => search_term,
          'Columns' => [
            'Feed',
            'Type',
            'Nessus Version',
            'Nessus Web Version',
            'Plugin Set',
            'Server UUID'
          ])
        tbl << [ resp["feed"], resp["nessus_type"], resp["server_version"], resp["nessus_ui_version"], resp["loaded_plugin_set"], resp["server_uuid"] ]
        print_line tbl.to_s
      end

      def cmd_nessus_server_status(*args)
        search_term = nil
        while (arg = args.shift)
          case arg
          when '-h', '--help'
            print_status("nessus_server_status")
            print_status("Example:> nessus_server_status -S searchterm")
            print_status("Returns some status items for the server..")
            return
          when '-S', '--search'
            search_term = /#{args.shift}/nmi
          end
        end

        tbl = Rex::Text::Table.new(
          'SearchTerm' => search_term,
          'Columns' => [
            'Status',
            'Progress'
          ])
        list = @n.server_status
        tbl << [ list["progress"], list["status"] ]
        print_line tbl.to_s
      end

      def cmd_nessus_admin(*args)
        while (arg = args.shift)
          case arg
          when '-h', '--help'
            print_status("nessus_admin")
            print_status("Example:> nessus_admin")
            print_status("Checks to see if the current user is an admin")
            print_status("Use nessus_user_list to list all users")
            return
          end
        end

        if !nessus_verify_token
          return
        end
        if !@n.is_admin
          print_error("Your Nessus user is not an admin")
        else
          print_good("Your Nessus user is an admin")
        end
      end

      def cmd_nessus_template_list(*args)
        search_term = nil
        while (arg = args.shift)
          case arg
          when '-h', '--help'
            print_status("nessus_template_list <scan> | <policy>")
            print_status("Example:> nessus_template_list scan -S searchterm")
            print_status("OR")
            print_status("nessus_template_list policy")
            print_status("Returns a list of information about the scan or policy templates..")
            return
          when '-S', '--search'
            search_term = /#{args.shift}/nmi
          else
            type = arg
          end
        end

        if !nessus_verify_token
          return
        end
        if type.in?(['scan', 'policy'])
          list=@n.list_templates(type)
        else
          print_error("Only scan and policy are valid templates")
          return
        end
        if list.empty?
          print_status("No templates created")
          return
        end
        tbl = Rex::Text::Table.new(
          'SearchTerm' => search_term,
          'Columns' => [
            'Name',
            'Title',
            'Description',
            'Subscription Only',
            'Cloud Only'
          ])
        list["templates"].each { |template|
        tbl << [ template["name"], template["title"], template["desc"], template["subscription_only"], template["cloud_only"] ]
        }
        print_line
        print_line tbl.to_s
      end

      def cmd_nessus_folder_list(*args)
        search_term = nil
        while (arg = args.shift)
          case arg
          when '-S', '--search'
            search_term = /#{args.shift}/nmi
          end
        end
        if !nessus_verify_token
          return
        end
        list = @n.list_folders
        tbl = Rex::Text::Table.new(
          'SearchTerm' => search_term,
          'Columns' => [
            "ID",
            "Name",
            "Type"
          ])
        list["folders"].each { |folder|
        tbl << [ folder["id"], folder["name"], folder["type"] ]
        }
        print_line
        print_line tbl.to_s
      end

      def cmd_nessus_scanner_list(*args)
        search_term = nil
        while (arg = args.shift)
          case arg
          when '-h', '--help'
            print_status("nessus_scanner_list")
            print_status("Example:> nessus_scanner_list -S searchterm")
            print_status("Returns information about the feed type and server version.")
            return
          when '-S', '--search'
            search_term = /#{args.shift}/nmi
          end
        end
        if !nessus_verify_token
          return
        end
        if !@n.is_admin
          return
        end
        list = @n.list_scanners
        tbl = Rex::Text::Table.new(
          'SearchTerm' => search_term,
          'Columns' => [
            "ID",
            "Name",
            "Status",
            "Platform",
            "Plugin Set",
            "UUID"
          ])
        list.each { |scanner|
        tbl << [ scanner["id"], scanner["name"], scanner["status"], scanner["platform"], scanner["loaded_plugin_set"], scanner["uuid"] ]
        }
        print_line tbl.to_s
      end

      def cmd_nessus_report_hosts(*args)
        search_term = nil
        scan_id = nil
        while (arg = args.shift)
          case arg
          when '-h', '--help'
            print_status("nessus_report_hosts <scan ID> -S searchterm")
            print_status("Use nessus_scan_list to get a list of all the scans. Only completed scans can be reported.")
            return
          when '-S', '--search'
            search_term = /#{args.shift}/nmi
          else
            scan_id = arg
          end
        end

        if scan_id.nil?
          print_status("Usage: ")
          print_status("nessus_report_hosts <scan ID> -S searchterm")
          print_status("Use nessus_scan_list to get a list of all the scans. Only completed scans can be reported.")
          return
        end

        tbl = Rex::Text::Table.new(
          'SearchTerm' => search_term,
          'Columns' => [
            "Host ID",
            "Hostname",
            "% of Critical Findings",
            "% of High Findings",
            "% of Medium Findings",
            "% of Low Findings"
          ])
        if is_scan_complete(scan_id)
          details = @n.scan_details(scan_id)
          details["hosts"].each { |host|
          tbl << [ host["host_id"], host["hostname"], host["critical"], host["high"], host["medium"], host["low"] ]
          }
          print_line
          print_line tbl.to_s
        else
          print_error("Only completed scans can be used for host reporting")
          return
        end
      end

      def cmd_nessus_report_vulns(*args)
        search_term = nil
        scan_id = nil
        while (arg = args.shift)
          case arg
          when '-h', '--help'
            print_status("nessus_report_vulns <scan ID> -S searchterm")
            print_status("Use nessus_scan_list to get a list of all the scans. Only completed scans can be reported.")
            return
          when '-S', '--search'
            search_term = /#{args.shift}/nmi
          else
            scan_id = arg
          end
        end
        if scan_id.nil?
          print_status("Usage: ")
          print_status("nessus_report_vulns <scan ID>")
          print_status("Use nessus_scan_list to get a list of all the scans. Only completed scans can be reported.")
          return
        end
        tbl = Rex::Text::Table.new(
          'SearchTerm' => search_term,
          'Columns' => [
            "Plugin ID",
            "Plugin Name",
            "Plugin Family",
            "Vulnerability Count"
          ])
        if is_scan_complete(scan_id)
          details = @n.scan_details(scan_id)
          details["vulnerabilities"].each { |vuln|
          tbl << [ vuln["plugin_id"], vuln["plugin_name"], vuln["plugin_family"], vuln["count"] ]
          }
          print_line
          print_line tbl.to_s
          return
        else
          print_error("Only completed scans can be used for vulnerability reporting")
          return
        end
      end

      def cmd_nessus_report_host_details(*args)
        search_term = nil
        search_vuln = nil
        scan_id = nil
        host_id = nil
        while (arg = args.shift)
          case arg
          when '-h', '--help'
            print_status("nessus_report_host_details <scan ID> <host ID>")
            print_status("Example:> nessus_report_host_details 10 5 -S hostinfo -SV vulninfo")
            print_status("Use nessus_scan_list to get list of all scans. Only completed scans can be used for reporting.")
            print_status("Use nessus_report_hosts to get a list of all the hosts along with their corresponding host IDs.")
            return
          when '-S', '--search'
            search_term = /#{args.shift}/nmi
          when '-SV', '--search-vuln'
            search_vuln = /#{args.shift}/nmi
          else
            scan_id = arg,
            host_id = args.shift
          end
        end

        if [scan_id, host_id].any?(&:nil?)
          print_status("Usage: ")
          print_status("nessus_report_host_detail <scan ID> <host ID>")
          print_status("Example:> nessus_report_host_detail 10 5")
          print_status("Use nessus_scan_list to get list of all scans. Only completed scans can be used for reporting.")
          print_status("Use nessus_report_hosts <scan ID> to get a list of all the hosts along with their corresponding host IDs.")
          return
        end
        tbl = Rex::Text::Table.new(
          'SearchTerm' => search_term,
          'Columns' => [
            'Plugin Name',
            'Plugin Famil',
            'Severity'
          ])
        details=@n.host_detail(scan_id, host_id)
        print_line
        print_status("Host information")
        print_line("IP Address: #{details['info']['host-ip']}")
        print_line("Hostname: #{details['info']['host-name']}")
        print_line("Operating System: #{details['info']['operating-system']}")
        print_line
        print_status("Vulnerability information")
        details["vulnerabilities"].each { |vuln|
        tbl << [ vuln["plugin_name"], vuln["plugin_family"], vuln["severity"] ]
        }
        print_line tbl.to_s
        tbl2 = Rex::Text::Table.new(
          'SearchTerm' => search_vuln,
          'Columns' => [
            'Plugin Name',
            'Plugin Famil',
            'Severity'
          ])
        print_status("Compliance information")
        details["compliance"].each { |comp|
        tbl2 << [ comp["plugin_name"], comp["plugin_family"], comp["severity"] ]
        }
        print_line tbl2.to_s
      end

      def cmd_nessus_report_download(*args)
        if args[0] == "-h"
          print_status("nessus_scan_report_download <scan_id> <file ID> ")
          print_status("Use nessus_scan_export_status <scan ID> <file ID> to check the export status.")
          print_status("Use nessus_scan_list -c to list all completed scans along with their corresponding scan IDs")
          return
        end
        if !nessus_verify_token
          return
        end
        case args.length
        when 2
          scan_id = args[0]
          file_id = args[1]
          if is_scan_complete(scan_id)
            report = @n.report_download(scan_id, file_id)
            File.open("#{msf_local}/#{scan_id}-#{file_id}","w+") do |f|
            f.puts report
            print_status("Report downloaded to #{msf_local} directory")
            end
          else
            print_error("Only completed scans can be downloaded")
          end
        else
          print_status("Usage: ")
          print_status("nessus_scan_report_download <scan_id> <file ID> ")
          print_status("Use nessus_scan_export_status <scan ID> <file ID> to check the export status.")
          print_status("Use nessus_scan_list -c to list all completed scans along with their corresponding scan IDs")
        end
      end

      def cmd_nessus_report_host_ports(*args)
        search_term = nil
        rid = nil
        host = nil
        while (arg = args.shift)
          case arg
          when '-h', '--help'
            print_status("nessus_report_host_ports <hostname> <report id>")
            print_status("Example:> nessus_report_host_ports 192.168.1.250 f0eabba3-4065-7d54-5763-f191e98eb0f7f9f33db7e75a06ca -S searchterm")
            print_status("Returns all the ports associated with a host and details about their vulnerabilities")
            print_status("Use nessus_report_hosts to list all available hosts for a report")
            return
          when '-S', '--search'
            search_term = /#{args.shift}/nmi
          else
            scan_id = arg
          end
        end

        if [host,rid].any?(&:nil?)
          print_status("Usage: ")
          print_status("nessus_report_host_ports <hostname> <report id>")
          print_status("Use nessus_report_list to list all available reports")
          return
        end
        tbl = Rex::Text::Table.new(
          'SearchTerm' => search_term,
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
        ports.each { |port|
        tbl << [ port['portnum'], port['protocol'], port['severity'], port['svcname'], port['sev0'], port['sev1'], port['sev2'], port['sev3'] ]
        }
        print_good("Host Info")
        print_good "\n"
        print_line tbl.to_s
        print_status("You can:")
        print_status("Get detailed scan infromation about a specfic port: nessus_report_host_detail <hostname> <port> <protocol> <report id>")
      end

      def cmd_nessus_report_del(*args)
        if args[0] == "-h"
          print_status("nessus_report_del <reportname>")
          print_status("Example:> nessus_report_del f0eabba3-4065-7d54-5763-f191e98eb0f7f9f33db7e75a06ca")
          print_status("Must be an admin to del reports.")
          print_status("Use nessus_report_list to list all reports")
          return
        end
        if !nessus_verify_token
          return
        end
        if !@n.is_admin
          print_error("Your Nessus user is not an admin")
          return
        end
        case args.length
        when 1
          rid = args[0]
        else
          print_status("Usage: ")
          print_status("nessus_report_del <report ID>")
          print_status("nessus_report_list to find the id.")
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

      def cmd_nessus_scan_list(*args)
        search_term = nil
        while (arg = args.shift)
          case arg
          when '-h', '--help'
            print_status("nessus_scan_list")
            print_status("Example:> nessus_scan_list -S searchterm")
            print_status("Returns a list of information about currently running scans.")
            return
          when '-S', '--search'
            search_term = /#{args.shift}/nmi
          end
        end

        if !nessus_verify_token
          return
        end
        list=@n.scan_list
        if list.to_s.empty?
          print_status("No scans performed.")
          return
        else
        tbl = Rex::Text::Table.new(
          'SearchTerm' => search_term,
          'Columns' => [
            'Scan ID',
            'Name',
            'Owner',
            'Started',
            'Status',
            'Folder'
          ])

        list["scans"].each { |scan|
        if args[0] == "-r"
          if scan["status"] == "running"
            tbl << [ scan["id"], scan["name"], scan["owner"], scan["starttime"], scan["status"], scan["folder_id"] ]
          end
          elsif args[0] == "-p"
            if scan["status"] == "paused"
              tbl << [ scan["id"], scan["name"], scan["owner"], scan["starttime"], scan["status"], scan["folder_id"] ]
            end
          elsif args[0] == "-c"
            if scan["status"] == "completed"
              tbl << [ scan["id"], scan["name"], scan["owner"], scan["starttime"], scan["status"], scan["folder_id"] ]
            end
          elsif args[0] == "-a"
            if scan["status"] == "canceled"
              tbl << [ scan["id"], scan["name"], scan["owner"], scan["starttime"], scan["status"], scan["folder_id"] ]
            end
          else
            tbl << [ scan["id"], scan["name"], scan["owner"], scan["starttime"], scan["status"], scan["folder_id"] ]
          end
          }
          print_line tbl.to_s
        end
      end

      def cmd_nessus_scan_new(*args)
        if args[0] == "-h"
          print_status("nessus_scan_new <UUID of Policy> <Scan name> <Description> <Targets>")
          print_status("Use nessus_policy_list to list all available policies with their corresponding UUIDs")
          return
        end
        if !nessus_verify_token
          return
        end
        case args.length
        when 4
          uuid = args[0]
          scan_name = args[1]
          description = args[2]
          targets = args[3]
        else
          print_status("Usage: ")
          print_status("nessus_scan_new <UUID of Policy> <Scan name> <Description> <Targets>")
          print_status("Use nessus_policy_list to list all available policies with their corresponding UUIDs")
          return
        end
        if valid_policy(uuid)
          print_status("Creating scan from policy number #{uuid}, called #{scan_name} - #{description} and scanning #{targets}")
          et = {
            'enabled'      => false,
            'launch'       => 'ONETIME',
            'name'         => scan_name,
            'text_targets' => targets,
            'description'  => description,
            'launch_now'   => false
          }
          scan = @n.scan_create(uuid, et)
          tbl = Rex::Text::Table.new(
            'Columns' => [
              "Scan ID",
              "Scanner ID",
              "Policy ID",
              "Targets",
              "Owner"
            ])
          print_status("New scan added")
          tbl << [ scan["scan"]["id"], scan["scan"]["scanner_id"], scan["scan"]["policy_id"], scan["scan"]["custom_targets"], scan["scan"]["owner"] ]
          print_status("Use nessus_scan_launch #{scan['scan']['id']} to launch the scan")
          print_line tbl.to_s
        else
          print_error("The policy does not exist")
        end
      end

      def cmd_nessus_scan_launch(*args)
        if args[0] == "-h"
          print_status("nessus_scan_launch <scan ID>")
          print_status("Use nessus_scan_list to list all the availabla scans with their corresponding scan IDs")
        end
        if !nessus_verify_token
          return
        end
        case args.length
        when 1
          scan_id = args[0]
        else
          print_status("Usage: ")
          print_status("nessus_scan_launch <scan ID>")
          print_status("Use nessus_scan_list to list all the availabla scans with their corresponding scan IDs")
          return
        end
        launch = @n.scan_launch(scan_id)
        print_good("Scan ID #{scan_id} successfully launched. The Scan UUID is #{launch['scan_uuid']}")
      end

      def cmd_nessus_scan_pause(*args)
        if args[0] == "-h"
          print_status("nessus_scan_pause <scan id>")
          print_status("Example:> nessus_scan_pause f0eabba3-4065-7d54-5763-f191e98eb0f7f9f33db7e75a06ca")
          print_status("Pauses a running scan")
          print_status("Use nessus_scan_list to list all available scans")
          return
        end
        if !nessus_verify_token
          return
        end
        case args.length
        when 1
          sid = args[0]
        else
          print_status("Usage: ")
          print_status("nessus_scan_pause <scan id>")
          print_status("Use nessus_scan_list to list all available scans")
          return
        end
        pause = @n.scan_pause(sid)
        if pause["error"]
          print_error "Invalid scan ID"
        else
          print_status("#{sid} has been paused")
        end
      end

      def cmd_nessus_db_scan(*args)
        if args[0] == "-h"
          print_status("nessus_db_scan <policy ID> <scan name> <scan description>")
          print_status("Creates a scan based on all the hosts listed in db_hosts.")
          print_status("Use nessus_policy_list to list all available policies with their corresponding policy IDs")
          return
        end
        if !nessus_verify_db
          return
        end
        if !nessus_verify_token
          return
        end
        case args.length
        when 3
          policy_id = args[0]
          name = args[1]
          desc = args[3]
        else
          print_status("Usage: ")
          print_status("nessus_db_scan <policy ID> <scan name> <scan description>")
          print_status("Use nessus_policy_list to list all available policies with their corresponding policy IDs")
          return
        end
        if !valid_policy(policy_id)
          print_error("That policy does not exist.")
          return
        end
        targets = ""
        framework.db.hosts.each do |host|
          targets << host.address
          targets << ","
        end
        targets.chop!
        print_status("Creating scan from policy #{policy_id}, called \"#{name}\" and scanning all hosts in all the workspaces")
        et = {
          'enabled'      => false,
          'launch'       => 'ONETIME',
          'name'         => name,
          'text_targets' => targets,
          'description'  => desc,
          'launch_now'   => true
        }
        scan = @n.scan_create(policy_id, et)
        if !scan["error"]
          scan = scan["scan"]
          print_status("Scan ID #{scan['id']} successfully created and launched")
        else
          print_error(JSON.pretty_generate(scan))
        end
      end

      def cmd_nessus_db_scan_workspace(*args)
        if args[0] == "-h"
          print_status("nessus_db_scan_workspace <policy ID> <scan name> <scan description> <workspace>")
          print_status("Creates a scan based on all the hosts listed in db_hosts for a given workspace.")
          print_status("Use nessus_policy_list to list all available policies with their corresponding policy IDs")
          return
        end
        if !nessus_verify_db
          return
        end
        if !nessus_verify_token
          return
        end
        case args.length
        when 4
          policy_id = args[0]
          name = args[1]
          desc = args[2]
          new_workspace = framework.db.find_workspace(args[3])
        else
          print_status("Usage: ")
          print_status("nessus_db_scan_workspace <policy ID> <scan name> <scan description> <workspace>")
          print_status("Use nessus_policy_list to list all available policies with their corresponding policy IDs")
          return
        end
        if !valid_policy(policy_id)
          print_error("That policy does not exist.")
          return
        end
        if new_workspace.nil?
          print_error("That workspace does not exist.")
          return
        end
        framework.db.workspace = new_workspace
        print_status("Switched workspace: #{framework.db.workspace.name}")
        targets = ""
        framework.db.hosts.each do |host|
          targets << host.address
          targets << ","
        print_status("Targets: #{targets}")
        end
        targets.chop!
        print_status("Creating scan from policy #{policy_id}, called \"#{name}\" and scanning all hosts in #{framework.db.workspace.name}")
        et = {
          'enabled'      => false,
          'launch'       => 'ONETIME',
          'name'         => name,
          'text_targets' => targets,
          'description'  => desc,
          'launch_now'   => false
        }
        scan = @n.scan_create(policy_id, et)
        if !scan["error"]
          scan = scan["scan"]
          print_status("Scan ID #{scan['id']} successfully created")
          print_status("Run nessus_scan_launch #{scan['id']} to launch the scan")
        else
          print_error(JSON.pretty_generate(scan))
        end
      end

      def cmd_nessus_db_import(*args)
        if args[0] == "-h"
          print_status("nessus_db_import <scan ID>")
          print_status("Example:> nessus_db_import 500")
          print_status("Use nessus_scan_list -c to list all completed scans")
        end
        if !nessus_verify_db
          return
        end
        if !nessus_verify_token
          return
        end
        case args.length
        when 1
          scan_id = args[0]
        else
          print_status("Usage: ")
          print_status("nessus_db_import <scan ID>")
          print_status("Example:> nessus_db_import 500")
          print_status("Use nessus_scan_list -c to list all completed scans")
        end
        if is_scan_complete(scan_id)
          print_status("Exporting scan ID #{scan_id} is Nessus format...")
          export = @n.scan_export(scan_id, 'nessus')
          if export["file"]
            file_id = export["file"]
            print_good("The export file ID for scan ID #{scan_id} is #{file_id}")
            print_status("Checking export status...")
            begin
              status = @n.scan_export_status(scan_id, file_id)
              print_status("Export status: " + status["status"])
              if status["status"]=="ready"
                break
              end     
              sleep(1)
            end while (status["status"]=="loading")
            if status["status"] == "ready"
              print_status("The status of scan ID #{scan_id} export is ready")
              select(nil, nil, nil, 5)
              report = @n.report_download(scan_id, file_id)
              print_status("Importing scan results to the database...")
              framework.db.import({:data => report}) do |type,data|
                case type
                when :address
                  print_status("Importing data of #{data}")
                end
              end
              print_good("Done")
            else
              print_error("There was some problem in exporting the scan. The error message is #{status}")
            end
          else
            print_error(export)
          end
        else
          print_error("Only completed scans could be used for import")
        end
      end

      def cmd_nessus_scan_pause_all(*args)
        scan_ids = Array.new
        if args[0] == "-h"
          print_status("nessus_scan_pause_all")
          print_status("Example:> nessus_scan_pause_all")
          print_status("Pauses all currently running scans")
          print_status("Use nessus_scan_list to list all running scans")
          return
        end
        if !nessus_verify_token
          return
        end
        list = @n.scan_list
        list["scans"].each { |scan|
        if scan["status"] == "running"
          scan_ids << scan["id"]
        end
        }
        if scan_ids.length > 0
          scan_ids.each { |scan_id|
          @n.scan_pause(scan_id)
          }
          print_status("All scans have been paused")
        else
          print_error("No running scans")
        end
      end

      def cmd_nessus_scan_stop(*args)
        if args[0] == "-h"
          print_status("nessus_scan_stop <scan id>")
          print_status("Example:> nessus_scan_stop f0eabba3-4065-7d54-5763-f191e98eb0f7f9f33db7e75a06ca")
          print_status("Stops a currently running scans")
          print_status("Use nessus_scan_list to list all running scans")
          return
        end
        if !nessus_verify_token
          return
        end
        case args.length
        when 1
          sid = args[0]
        else
          print_status("Usage: ")
          print_status("nessus_scan_stop <scan id>")
          print_status("Use nessus_scan_list to list all available scans")
          return
        end
        stop = @n.scan_stop(sid)
        if stop["error"]
          print_error "Invalid scan ID"
        else
          print_status("#{sid} has been stopped")
        end
      end

      def cmd_nessus_scan_stop_all(*args)
        scan_ids = Array.new
        if args[0] == "-h"
          print_status("nessus_scan_stop_all")
          print_status("Example:> nessus_scan_stop_all")
          print_status("stops all currently running scans")
          print_status("Use nessus_scan_list to list all running scans")
          return
        end
        if !nessus_verify_token
          return
        end
        list = @n.scan_list
        list["scans"].each { |scan|
        if scan["status"] == "running" || scan["status"] == "paused"
          scan_ids << scan["id"]
        end
        }
        if scan_ids.length > 0
          scan_ids.each { |scan_id|
          @n.scan_stop(scan_id)
          }
          print_status("All scans have been stopped")
        else
          print_error("No running or paused scans to be stopped")
        end
      end

      def cmd_nessus_scan_resume(*args)
        if args[0] == "-h"
          print_status("nessus_scan_resume <scan id>")
          print_status("Example:> nessus_scan_resume f0eabba3-4065-7d54-5763-f191e98eb0f7f9f33db7e75a06ca")
          print_status("resumes a running scan")
          print_status("Use nessus_scan_list to list all available scans")
          return
        end
        if !nessus_verify_token
          return
        end
        case args.length
        when 1
          sid = args[0]
        else
          print_status("Usage: ")
          print_status("nessus_scan_resume <scan id>")
          print_status("Use nessus_scan_list to list all available scans")
          return
        end
        resume = @n.scan_resume(sid)
        if resume["error"]
          print_error "Invalid scan ID"
        else
          print_status("#{sid} has been resumed")
        end
      end

      def cmd_nessus_scan_resume_all(*args)
        scan_ids = Array.new
        if args[0] == "-h"
          print_status("nessus_scan_resume_all")
          print_status("Example:> nessus_scan_resume_all")
          print_status("resumes all currently running scans")
          print_status("Use nessus_scan_list to list all running scans")
          return
        end
        if !nessus_verify_token
          return
        end
        list = @n.scan_list
        list["scans"].each { |scan|
        if scan["status"] == "paused"
          scan_ids << scan["id"]
        end
        }
        if scan_ids.length > 0
          scan_ids.each { |scan_id|
          @n.scan_resume(scan_id)
          }
          print_status("All scans have been resumed")
        else
          print_error("No running scans to be resumed")
        end
      end

      def cmd_nessus_scan_details(*args)
        valid_categories = ['info', 'hosts', 'vulnerabilities', 'history']
        search_term = nil
        scan_id = nil
        category = nil
        while (arg = args.shift)
          case arg
          when '-h', '--help'
            print_status("Usage: ")
            print_status("nessus_scan_details <scan ID> <category> -S searchterm")
            print_status("Availble categories are info, hosts, vulnerabilities, and history")
            print_status("Use nessus_scan_list to list all available scans with their corresponding scan IDs")
            return
          when '-S', '--search'
            search_term = /#{args.shift}/nmi
          else
            scan_id = arg
            if args[0].in?(valid_categories)
              category = args.shift
            else
              print_error("Invalid category. The available categories are info, hosts, vulnerabilities, and history")
              return
            end
          end
        end

        if !nessus_verify_token
           return
        end

        details = @n.scan_details(scan_id)
        if category == "info"
          tbl = Rex::Text::Table.new(
            'SearchTerm' => search_term,
            'Columns' => [
              "Status",
              "Policy",
              "Scan Name",
              "Scan Targets",
              "Scan Start Time",
              "Scan End Time"
            ])
         tbl << [ details["info"]["status"], details["info"]["policy"], details["info"]["name"], details["info"]["targets"], details["info"]["scan_start"], details["info"]["scan_end"] ]
        elsif category == "hosts"
          tbl = Rex::Text::Table.new(
            'SearchTerm' => search_term,
            'Columns' => [
              "Host ID",
              "Hostname",
              "% of Critical Findings",
              "% of High Findings",
              "% of Medium Findings",
              "% of Low Findings"
            ])
          details["hosts"].each { |host|
          tbl << [ host["host_id"], host["hostname"], host["critical"], host["high"], host["medium"], host["low"] ]
          }
        elsif category == "vulnerabilities"
          tbl = Rex::Text::Table.new(
            'SearchTerm' => search_term,
            'Columns' => [
              "Plugin ID",
              "Plugin Name",
              "Plugin Family",
              "Count"
            ])
          details["vulnerabilities"].each { |vuln|
          tbl << [ vuln["plugin_id"], vuln["plugin_name"], vuln["plugin_family"], vuln["count"] ]
          }
        elsif category == "history"
          tbl = Rex::Text::Table.new(
            'SearchTerm' => search_term,
            'Columns' => [
              "History ID",
              "Status",
              "Creation Date",
              "Last Modification Date"
            ])
          details["history"].each { |hist|
          tbl << [ hist["history_id"], hist["status"], hist["creation_date"], hist["modification_date"] ]
          }
        end
        print_line tbl.to_s
      end

      def cmd_nessus_scan_export(*args)
        if args[0] == "-h"
          print_status("nessus_scan_export <scan ID> <export format>")
          print_status("The available export formats are Nessus, HTML, PDF, CSV, or DB")
          print_status("Use nessus_scan_list to list all available scans with their corresponding scan IDs")
          return
        end
        if !nessus_verify_token
          return
        end
        case args.length
        when 2
          scan_id = args[0]
          format = args[1].downcase
        else
          print_status("Usage: ")
          print_status("nessus_scan_export <scan ID> <export format>")
          print_status("The available export formats are Nessus, HTML, PDF, CSV, or DB")
          print_status("Use nessus_scan_list to list all available scans with their corresponding scan IDs")
          return
        end
        if format.in?(['nessus','html','pdf','csv','db'])
          export = @n.scan_export(scan_id, format)
          if export["file"]
            file_id = export["file"]
            print_good("The export file ID for scan ID #{scan_id} is #{file_id}")
            print_status("Checking export status...")            
            begin
              status = @n.scan_export_status(scan_id, file_id)
              print_status("Export status: " + status["status"])
              if status["status"]=="ready"
                break
              end     
              sleep(1)
            end while (status["status"]=="loading")
            if status["status"] == "ready"
              print_good("The status of scan ID #{scan_id} export is ready")
            else
              print_error("There was some problem in exporting the scan. The error message is #{status}")
            end
          else
            print_error(export)
          end
        else
          print_error("Invalid export format. The available export formats are Nessus, HTML, PDF, CSV, or DB")
          return
        end
      end

      def cmd_nessus_scan_export_status(*args)
        if args[0] == "-h"
          print_status("nessus_scan_export_status <scan ID> <file ID>")
          print_status("Use nessus_scan_export <scan ID> <format> to export a scan and get its file ID")
        end
        if !nessus_verify_token
          return
        end
        case args.length
        when 2
          scan_id = args[0]
          file_id = args[1]
          begin
            status = @n.scan_export_status(scan_id, file_id)
            print_status("Export status: " + status["status"])
            if status["status"]=="ready"
              break
            end     
            sleep(1)
          end while (status["status"]=="loading")
          if status["status"] == "ready"
            print_status("The status of scan ID #{scan_id} export is ready")
          else
            print_error("There was some problem in exporting the scan. The error message is #{status}")
          end
        else
          print_status("Usage: ")
          print_status("nessus_scan_export_status <scan ID> <file ID>")
          print_status("Use nessus_scan_export <scan ID> <format> to export a scan and get its file ID")
        end
      end

      def cmd_nessus_plugin_list(*args)
        search_term = nil
        family_id = nil
        while (arg = args.shift)
          case arg
          when '-h', '--help'
            print_status("nessus_plugin_list <Family ID> -S searchterm")
            print_status("Example:> nessus_plugin_list 10")
            print_status("Returns a list of all plugins in that family.")
            print_status("Use nessus_family_list to display all the plugin families along with their corresponding family IDs")
            return
          when '-S', '--search'
            search_term = /#{args.shift}/nmi
          else
            family_id = arg
          end
        end

        if family_id.nil?
          print_status("Usage: ")
          print_status("nessus_plugin_list <Family ID>")
          print_status("Use nessus_family_list to display all the plugin families along with their corresponding family IDs")
          return
        end
        tbl = Rex::Text::Table.new(
          'SearchTerm' => search_term,
          'Columns' => [
            'Plugin ID',
            'Plugin Name'
          ])
        list = @n.list_plugins(family_id)
        list["plugins"].each { |plugin|
        tbl << [ plugin["id"], plugin["name"] ]
        }
        print_line
        print_good("Plugin Family Name: #{list['name']}")
        print_line
        print_line tbl.to_s
      end

      def cmd_nessus_family_list(*args)
        search_term = nil
        while (arg = args.shift)
          case arg
          when '-h', '--help'
            print_status("nessus_family_list")
            print_status("Example:> nessus_family_list -S searchterm")
            print_status("Returns a list of all the plugin families along with their corresponding family IDs and plugin count.")
            return
          when '-S', '--search'
            search_term = /#{args.shift}/nmi
          end
        end

        list = @n.list_families
        tbl = Rex::Text::Table.new(
          'SearchTerm' => search_term,
          'Columns' => [
            'Family ID',
            'Family Name',
            'Number of Plugins'
          ])
        list['families'].each { |family|
        tbl << [ family["id"], family["name"], family["count"] ]
        }
        print_line
        print_line tbl.to_s
      end

      def cmd_nessus_plugin_details(*args)
        search_term = nil
        plugin_id = nil
        while (arg = args.shift)
          case arg
          when '-h', '--help'
            print_status("nessus_plugin_details <Plugin ID>")
            print_status("Example:> nessus_plugin_details 10264 -S searchterm")
            print_status("Returns details on a particular plugin.")
            print_status("Use nessus_plugin_list to list all plugins and their corresponding plugin IDs belonging to a particular plugin family.")
            return
          when '-S', '--search'
            search_term = /#{args.shift}/nmi
          else
            plugin_id = arg
          end
        end

        if !nessus_verify_token
          return
        end

        if plugin_id.nil?
          print_status("Usage: ")
          print_status("nessus_plugin_details <Plugin ID>")
          print_status("Use nessus_plugin_list to list all plugins and their corresponding plugin IDs belonging to a particular plugin family.")
          return
        end
        tbl = Rex::Text::Table.new(
          'SearchTerm' => search_term,
          'Columns' => [
            'Reference',
            'Value'
          ])
        begin
          list = @n.plugin_details(plugin_id)
        rescue ::Exception => e
          if e.message =~ /unexpected token/
            print_error("No plugin info found")
            return
          else
            raise e
          end
        end
        list["attributes"].each { |attrib|
        tbl << [ attrib["attribute_name"], attrib["attribute_value"] ]
        }
        print_line
        print_good("Plugin Name: #{list['name']}")
        print_good("Plugin Family: #{list['family_name']}")
        print_line
        print_line tbl.to_s
      end

      def cmd_nessus_user_list(*args)
        scan_id = nil
        while (arg = args.shift)
          case arg
          when '-h', '--help'
            print_status("nessus_user_list")
            print_status("Example:> nessus_user_list -S searchterm")
            print_status("Returns a list of the users on the Nessus server and their access level.")
            return
          when '-S', '--search'
            search_term = /#{args.shift}/nmi
          end
        end

        if !nessus_verify_token
          return
        end
        if !@n.is_admin
          print_status("Your Nessus user is not an admin")
        end
        list=@n.list_users
        tbl = Rex::Text::Table.new(
          'SearchTerm' => search_term,
          'Columns' => [
            'ID',
            'Name',
            'Username',
            'Type',
            'Email',
            'Permissions'
          ])
        list["users"].each { |user|
        tbl << [ user["id"], user["name"], user["username"], user["type"], user["email"], user["permissions"] ]
        }
        print_line
        print_line tbl.to_s
      end

      def cmd_nessus_user_add(*args)
        if args[0] == "-h"
          print_status("nessus_user_add <username> <password> <permissions> <type>")
          print_status("Permissions are 32, 64, and 128")
          print_status("Type can be either local or LDAP")
          print_status("Example:> nessus_user_add msf msf 16 local")
          print_status("You need to be an admin in order to add accounts")
          print_status("Use nessus_user_list to list all users")
          return
        end
        if !nessus_verify_token
          return
        end
        if !@n.is_admin
          print_error("Your Nessus user is not an admin")
          return
        end
        case args.length
        when 4
          user = args[0]
          pass = args[1]
          permissions = args[2]
          type = args[3]
        else
          print_status("Usage")
          print_status("nessus_user_add <username> <password> <permissions> <type>")
          return
        end
        add = @n.user_add(user,pass,permissions,type)
        if add["id"]
          print_good("#{user} created successfully")
        else
          print_error(add.to_s)
        end
      end

      def cmd_nessus_user_del(*args)
        if args[0] == "-h"
          print_status("nessus_user_del <User ID>")
          print_status("Example:> nessus_user_del 10")
          print_status("This command can only delete non admin users. You must be an admin to delete users.")
          print_status("Use nessus_user_list to list all users with their corresponding user IDs")
          return
        end
        if !nessus_verify_token
          return
        end
        if !@n.is_admin
          print_error("Your Nessus user is not an admin")
          return
        end
        case args.length
        when 1
          user_id = args[0]
        else
          print_status("Usage: ")
          print_status("nessus_user_del <User ID>")
          print_status("This command can only delete non admin users")
          return
        end
        del = @n.user_delete(user_id)
        status = del.to_s
        if status == "200"
          print_good("User account having user ID #{user_id} deleted successfully")
        elsif status == "403"
          print_error("You do not have permission to delete the user account having user ID #{user_id}")
        elsif status == "404"
          print_error("User account having user ID #{user_id} does not exist")
        elsif status == "409"
          print_error("You cannot delete your own account")
        elsif status == "500"
          print_error("The server failed to delete the user account having user ID #{user_id}")
        else
          print_error("Unknown problem occured by deleting the user account having user ID #{user_id}.")
        end
      end

      def cmd_nessus_user_passwd(*args)
        if args[0] == "-h"
          print_status("nessus_user_passwd <User ID> <New Password>")
          print_status("Example:> nessus_user_passwd 10 mynewpassword")
          print_status("Changes the password of a user. You must be an admin to change passwords.")
          print_status("Use nessus_user_list to list all users with their corresponding user IDs")
          return
        end
        if !nessus_verify_token
          return
        end
        if !@n.is_admin
          print_error("Your Nessus user is not an admin")
          return
        end
        case args.length
        when 2
          user_id = args[0]
          pass = args[1]
        else
          print_status("Usage: ")
          print_status("nessus_user_passwd <User ID> <New Password>")
          print_status("Use nessus_user_list to list all users with their corresponding user IDs")
          return
        end
        pass = @n.user_chpasswd(user_id,pass)
        status = pass.to_s
        if status == "200"
          print_good("Password of account having user ID #{user_id} changed successfully")
        elsif status == "400"
          print_error("Password is too short")
        elsif status == "403"
          print_error("You do not have the permission to change password for the user having user ID #{user_id}")
        elsif status == "404"
          print_error("User having user ID #{user_id} does not exist")
        elsif status == "500"
          print_error("Nessus server failed to changed the user password")
        else
          print_error("Unknown problem occured while changing the user password")
        end
      end

      def cmd_nessus_policy_list(*args)
        search_term = nil
        while (arg = args.shift)
          case arg
          when '-h', '--help'
            print_status("nessus_policy_list")
            print_status("Example:> nessus_policy_list -S searchterm")
            print_status("Lists all policies on the server")
            return
          when '-S', '--search'
            search_term = /#{args.shift}/nmi
          end
        end

        if !nessus_verify_token
          return
        end
        list=@n.list_policies

        unless list["policies"]
          print_error("No policies found")
          return
        end

        tbl = Rex::Text::Table.new(
          'Columns' => [
            'Policy ID',
            'Name',
            'Policy UUID'
          ])
        list["policies"].each { |policy|
        tbl << [ policy["id"], policy["name"], policy["template_uuid"] ]
        }
        print_line tbl.to_s
      end

      def cmd_nessus_policy_del(*args)
        if args[0] == "-h"
          print_status("nessus_policy_del <policy ID>")
          print_status("Example:> nessus_policy_del 1")
          print_status("You must be an admin to delete policies.")
          print_status("Use nessus_policy_list to list all policies with their corresponding policy IDs")
          return
        end
        if !nessus_verify_token
          return
        end
        if !@n.is_admin
          print_error("Your Nessus user is not an admin")
          return
        end
        case args.length
        when 1
          policy_id = args[0]
        else
          print_status("Usage: ")
          print_status("nessus_policy_del <policy ID>")
          print_status("Use nessus_policy_list to list all the policies with their corresponding policy IDs")
          return
        end
        del = @n.policy_delete(policy_id)
        status = del.to_s
        if status == "200"
          print_good("Policy ID #{policy_id} successfully deleted")
        elsif status == "403"
          print_error("You do not have permission to delete policy ID #{policy_id}")
        elsif status == "404"
          print_error("Policy ID #{policy_id} does not exist")
        elsif status == "405"
          print_error("Policy ID #{policy_id} is currently in use and cannot be deleted")
        else
          print_error("Unknown problem occured by deleting the user account having user ID #{user_id}.")
        end
      end
    end

    def initialize(framework, opts)
      super
      add_console_dispatcher(ConsoleCommandDispatcher)
      print_status(PLUGIN_DESCRIPTION)
      print_status("Type %bldnessus_help%clr for a command listing")
    end

    def cleanup
      remove_console_dispatcher('Nessus')
    end
  end
end
