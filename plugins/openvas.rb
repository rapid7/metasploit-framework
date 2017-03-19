#
# This plugin provides integration with OpenVAS. Written by kost and
# averagesecurityguy.
#
# $Id$
# $Revision$
#
# Distributed under MIT license:
# http://www.opensource.org/licenses/mit-license.php
#

require 'openvas-omp'

module Msf
class Plugin::OpenVAS < Msf::Plugin
  class OpenVASCommandDispatcher
    include Msf::Ui::Console::CommandDispatcher

    def name
      "OpenVAS"
    end

    def commands
      {
        'openvas_help' => "Displays help",
        'openvas_version' => "Display the version of the OpenVAS server",
        'openvas_debug' => "Enable/Disable debugging",
        'openvas_connect' => "Connect to an OpenVAS manager using OMP",
        'openvas_disconnect' => "Disconnect from OpenVAS manager",

        'openvas_task_create' => "Create a task (name, comment, target, config)",
        'openvas_task_delete' => "Delete task by ID",
        'openvas_task_list' => "Display list of tasks",
        'openvas_task_start' => "Start task by ID",
        'openvas_task_stop' => "Stop task by ID",
        'openvas_task_pause' => "Pause task by ID",
        'openvas_task_resume' => "Resume task by ID",
        'openvas_task_resume_or_start' => "Resume task or start task by ID",

        'openvas_target_create' => "Create target (name, hosts, comment)",
        'openvas_target_delete' => "Delete target by ID",
        'openvas_target_list' => "Display list of targets",

        'openvas_config_list' => "Quickly display list of configs",

        'openvas_format_list' => "Display list of available report formats",

        'openvas_report_list' => "Display a list of available report formats",
        'openvas_report_delete' => "Delete a report specified by ID",
        'openvas_report_download' => "Save a report to disk",
        'openvas_report_import' => "Import report specified by ID into framework",
      }
    end

    def cmd_openvas_help()
      print_status("openvas_help                  Display this help")
      print_status("openvas_debug                 Enable/Disable debugging")
      print_status("openvas_version               Display the version of the OpenVAS server")
      print_status
      print_status("CONNECTION")
      print_status("==========")
      print_status("openvas_connect               Connects to OpenVAS")
      print_status("openvas_disconnect            Disconnects from OpenVAS")
      print_status
      print_status("TARGETS")
      print_status("=======")
      print_status("openvas_target_create         Create target")
      print_status("openvas_target_delete         Deletes target specified by ID")
      print_status("openvas_target_list           Lists targets")
      print_status
      print_status("TASKS")
      print_status("=====")
      print_status("openvas_task_create           Create task")
      print_status("openvas_task_delete           Delete a task and all associated reports")
      print_status("openvas_task_list             Lists tasks")
      print_status("openvas_task_start            Starts task specified by ID")
      print_status("openvas_task_stop             Stops task specified by ID")
      print_status("openvas_task_pause            Pauses task specified by ID")
      print_status("openvas_task_resume           Resumes task specified by ID")
      print_status("openvas_task_resume_or_start  Resumes or starts task specified by ID")
      print_status
      print_status("CONFIGS")
      print_status("=======")
      print_status("openvas_config_list           Lists scan configurations")
      print_status
      print_status("FORMATS")
      print_status("=======")
      print_status("openvas_format_list           Lists available report formats")
      print_status
      print_status("REPORTS")
      print_status("=======")
      print_status("openvas_report_list           Lists available reports")
      print_status("openvas_report_delete         Delete a report specified by ID")
      print_status("openvas_report_import         Imports an OpenVAS report specified by ID")
      print_status("openvas_report_download       Downloads an OpenVAS report specified by ID")
    end

    # Verify the database is connected and usable
    def database?
      if !(framework.db and framework.db.usable)
        return false
      else
        return true
      end
    end

    # Verify there is an active OpenVAS connection
    def openvas?
      if @ov
        return true
      else
        print_error("No OpenVAS connection available. Please use openvas_connect.")
        return false
      end
    end

    # Verify correct number of arguments and verify -h was not given. Return
    # true if correct number of arguments and help was not requested.
    def args?(args, min=1, max=nil)
      if not max then max = min end
      if (args.length < min or args.length > max or args[0] == "-h")
        return false
      end

      return true
    end

  #--------------------------
  # Basic Functions
  #--------------------------
    def cmd_openvas_debug(*args)
      return unless openvas?

      if args?(args)
        begin
          resp = @ov.debug(args[0].to_i)
          print_good(resp)
        rescue OpenVASOMP::OMPError => e
          print_error(e.to_s)
        end
      else
        print_status("Usage:")
        print_status("openvas_debug integer")
      end
    end

    def cmd_openvas_version()
      return unless openvas?

      begin
        ver = @ov.version_get
        print_good("Using OMP version #{ver}")
      rescue OpenVASOMP::OMPError => e
        print_error(e.to_s)
      end
    end


  #--------------------------
  # Connection Functions
  #--------------------------
    def cmd_openvas_connect(*args)
      # Is the database configured?
      if not database?
        print_error("No database has been configured.")
        return
      end

      # Don't allow duplicate sessions
      if @ov then
        print_error("Session already open, please use openvas_disconnect first.")
        return
      end

      # Make sure the correct number of arguments are present.
      if args?(args, 4, 5)

        user, pass, host, port, sslv = args

        # SSL warning. User is required to confirm.
        if(host != "localhost" and host != "127.0.0.1" and sslv != "ok")
          print_error("Warning: SSL connections are not verified in this release, it is possible for an attacker")
          print_error("         with the ability to man-in-the-middle the OpenVAS traffic to capture the OpenVAS")
          print_error("         credentials. If you are running this on a trusted network, please pass in 'ok'")
          print_error("         as an additional parameter to this command.")
          return
        end

        begin
          print_status("Connecting to OpenVAS instance at #{host}:#{port} with username #{user}...")
          ov = OpenVASOMP::OpenVASOMP.new('user' => user, 'password' => pass, 'host' => host, 'port' => port)
        rescue OpenVASOMP::OMPAuthError => e
          print_error("Authentication failed: #{e.reason}")
          return
        rescue OpenVASOMP::OMPConnectionError => e
          print_error("Connection failed: #{e.reason}")
          return
        end
        print_good("OpenVAS connection successful")
        @ov = ov

      else
        print_status("Usage:")
        print_status("openvas_connect username password host port <ssl-confirm>")
      end
    end

    # Disconnect from an OpenVAS manager
    def cmd_openvas_disconnect()
      return unless openvas?
      @ov.logout
      @ov = nil
    end


  #--------------------------
  # Target Functions
  #--------------------------
    def cmd_openvas_target_create(*args)
      return unless openvas?

      if args?(args, 3)
        begin
          resp = @ov.target_create('name' => args[0], 'hosts' => args[1], 'comment' => args[2])
          print_status(resp)
          cmd_openvas_target_list
        rescue OpenVASOMP::OMPError => e
          print_error(e.to_s)
        end

      else
        print_status("Usage: openvas_target_create <name> <hosts> <comment>")
      end
    end

    def cmd_openvas_target_delete(*args)
      return unless openvas?

      if args?(args)
        begin
          resp = @ov.target_delete(args[0])
          print_status(resp)
          cmd_openvas_target_list
        rescue OpenVASOMP::OMPError => e
          print_error(e.to_s)
        end
      else
        print_status("Usage: openvas_target_delete <target_id>")
      end
    end

    def cmd_openvas_target_list(*args)
      return unless openvas?

      begin
        tbl = Rex::Text::Table.new(
              'Columns' => ["ID", "Name", "Hosts", "Max Hosts", "In Use", "Comment"])
        @ov.target_get_all().each do |target|
          tbl << [ target["id"], target["name"], target["hosts"], target["max_hosts"],
          target["in_use"], target["comment"] ]
        end
        print_good("OpenVAS list of targets")
        print_line
        print_line tbl.to_s
        print_line
      rescue OpenVASOMP::OMPError => e
        print_error(e.to_s)
      end
    end

  #--------------------------
  # Task Functions
  #--------------------------
    def cmd_openvas_task_create(*args)
      return unless openvas?

      if args?(args, 4)
        begin
          resp = @ov.task_create('name' => args[0], 'comment' => args[1], 'config' => args[2], 'target'=> args[3])
          print_status(resp)
          cmd_openvas_task_list
        rescue OpenVASOMP::OMPError => e
          print_error(e.to_s)
        end

      else
        print_status("Usage: openvas_task_create <name> <comment> <config_id> <target_id>")
      end
    end

    def cmd_openvas_task_delete(*args)
      return unless openvas?

      if args?(args, 2)

        # User is required to confirm before deleting task.
        if(args[1] != "ok")
          print_error("Warning: Deleting a task will also delete all reports associated with the ")
          print_error("task, please pass in 'ok' as an additional parameter to this command.")
          return
        end

        begin
          resp = @ov.task_delete(args[0])
          print_status(resp)
          cmd_openvas_task_list
        rescue OpenVASOMP::OMPError => e
          print_error(e.to_s)
        end
      else
        print_status("Usage: openvas_task_delete <id> ok")
        print_error("This will delete the task and all associated reports.")
      end
    end

    def cmd_openvas_task_list(*args)
      return unless openvas?

      begin
        tbl = Rex::Text::Table.new(
              'Columns' => ["ID", "Name", "Comment", "Status", "Progress"])
        @ov.task_get_all().each do |task|
          tbl << [ task["id"], task["name"], task["comment"], task["status"], task["progress"] ]
        end
        print_good("OpenVAS list of tasks")
        print_line
        print_line tbl.to_s
        print_line
      rescue OpenVASOMP::OMPError => e
        print_error(e.to_s)
      end
    end

    def cmd_openvas_task_start(*args)
      return unless openvas?

      if args?(args)
        begin
          resp = @ov.task_start(args[0])
          print_status(resp)
        rescue OpenVASOMP::OMPError => e
          print_error(e.to_s)
        end
      else
        print_status("Usage: openvas_task_start <id>")
      end
    end

    def cmd_openvas_task_stop(*args)
      return unless openvas?

      if args?(args)
        begin
          resp = @ov.task_stop(args[0])
          print_status(resp)
        rescue OpenVASOMP::OMPError => e
          print_error(e.to_s)
        end
      else
        print_status("Usage: openvas_task_stop <id>")
      end
    end

    def cmd_openvas_task_pause(*args)
      return unless openvas?

      if args?(args)
        begin
          resp = @ov.task_pause(args[0])
          print_status(resp)
        rescue OpenVASOMP::OMPError => e
          print_error(e.to_s)
        end
      else
        print_status("Usage: openvas_task_pause <id>")
      end
    end

    def cmd_openvas_task_resume(*args)
      return unless openvas?

      if args?(args)
        begin
          resp = @ov.task_resume_paused(args[0])
          print_status(resp)
        rescue OpenVASOMP::OMPError => e
          print_error(e.to_s)
        end
      else
        print_status("Usage: openvas_task_resume <id>")
      end
    end

    def cmd_openvas_task_resume_or_start(*args)
      return unless openvas?

      if args?(args)
        begin
          resp = @ov.task_resume_or_start(args[0])
          print_status(resp)
        rescue OpenVASOMP::OMPError => e
          print_error(e.to_s)
        end
      else
        print_status("Usage: openvas_task_resume_or_start <id>")
      end
    end

  #--------------------------
  # Config Functions
  #--------------------------
    def cmd_openvas_config_list(*args)
      return unless openvas?

      begin
        tbl = Rex::Text::Table.new(
          'Columns' => [ "ID", "Name" ])

        @ov.config_get_all.each do |config|
          tbl << [ config["id"], config["name"] ]
        end
        print_good("OpenVAS list of configs")
        print_line
        print_line tbl.to_s
        print_line
      rescue OpenVASOMP::OMPError => e
        print_error(e.to_s)
      end
    end

  #--------------------------
  # Format Functions
  #--------------------------
    def cmd_openvas_format_list(*args)
      return unless openvas?

      begin
        tbl = Rex::Text::Table.new(
              'Columns' => ["ID", "Name", "Extension", "Summary"])
        format_get_all.each do |format|
          tbl << [ format["id"], format["name"], format["extension"], format["summary"] ]
        end
        print_good("OpenVAS list of report formats")
        print_line
        print_line tbl.to_s
        print_line
      rescue OpenVASOMP::OMPError => e
        print_error(e.to_s)
      end
    end

  #--------------------------
  # Report Functions
  #--------------------------
    def cmd_openvas_report_list(*args)
      return unless openvas?

      begin
        tbl = Rex::Text::Table.new(
              'Columns' => ["ID", "Task Name", "Start Time", "Stop Time"])

        resp = @ov.report_get_raw

        resp.elements.each("//get_reports_response/report") do |report|
          report_id = report.elements["report"].attributes["id"]
          report_task = report.elements["task/name"].get_text
          report_start_time = report.elements["creation_time"].get_text
          report_stop_time = report.elements["modification_time"].get_text

          tbl << [ report_id, report_task, report_start_time, report_stop_time ]
        end
        print_good("OpenVAS list of reports")
        print_line
        print_line tbl.to_s
        print_line
      rescue OpenVASOMP::OMPError => e
        print_error(e.to_s)
      end
    end

    def cmd_openvas_report_delete(*args)
      return unless openvas?

      if args?(args)
        begin
          resp = @ov.report_delete(args[0])
          print_status(resp)
          cmd_openvas_report_list
        rescue OpenVASOMP::OMPError => e
          print_error(e.to_s)
        end
      else
        print_status("Usage: openvas_report_delete <id>")
      end
    end

    def cmd_openvas_report_download(*args)
      return unless openvas?

      if args?(args, 4)
        begin
          report = @ov.report_get_raw("report_id"=>args[0],"format"=>args[1])
          ::FileUtils.mkdir_p(args[2])
          name = ::File.join(args[2], args[3])
          print_status("Saving report to #{name}")
          output = ::File.new(name, "w")
          data = nil
          report.elements.each("//get_reports_response"){|r| data = r.to_s}
          output.puts(data)
          output.close
        rescue OpenVASOMP::OMPError => e
          print_error(e.to_s)
        end
      else
        print_status("Usage: openvas_report_download <report_id> <format_id> <path> <report_name>")
      end
    end

    def cmd_openvas_report_import(*args)
      return unless openvas?

      if args?(args, 2)
        begin
          report = @ov.report_get_raw("report_id"=>args[0],"format"=>args[1])
          data = nil
          report.elements.each("//get_reports_response"){|r| data = r.to_s}
          print_status("Importing report to database.")
          framework.db.import({:data => data})
        rescue OpenVASOMP::OMPError => e
          print_error(e.to_s)
        end
      else
        print_status("Usage: openvas_report_import <report_id> <format_id>")
        print_status("Only the NBE and XML formats are supported for importing.")
      end
    end



    #--------------------------
    # Format Functions
    #--------------------------
    # Get a list of report formats
    def format_get_all
      begin
        resp = @ov.omp_request_xml("<get_report_formats/>")
        if @debug then print resp end

        list = Array.new
        resp.elements.each('//get_report_formats_response/report_format') do |report|
          td = Hash.new
          td["id"] = report.attributes["id"]
          td["name"] = report.elements["name"].text
          td["extension"] = report.elements["extension"].text
          td["summary"] = report.elements["summary"].text
          list.push td
        end
        @formats = list
        return list
      rescue
        raise OMPResponseError
      end
    end

  end # End OpenVAS class

#------------------------------
# Plugin initialization
#------------------------------

  def initialize(framework, opts)
    super
    add_console_dispatcher(OpenVASCommandDispatcher)
    print_status("Welcome to OpenVAS integration by kost and averagesecurityguy.")
    print_status
    print_status("OpenVAS integration requires a database connection. Once the ")
    print_status("database is ready, connect to the OpenVAS server using openvas_connect.")
    print_status("For additional commands use openvas_help.")
    print_status
    @ov = nil
    @formats = nil
    @debug = nil
  end

  def cleanup
    remove_console_dispatcher('OpenVAS')
  end

  def name
    "OpenVAS"
  end

  def desc
    "Integrates with the OpenVAS - open source vulnerability management"
  end
end
end
