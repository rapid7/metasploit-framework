# -*- coding: binary -*-
# CorrM @ fb.me/IslamNofl
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui
###
# Application controller - run, get app list, install and uninstall application.
# extension by Islam Nofl (@CorrM)
###
class Console::CommandDispatcher::AppApi
  include Console::CommandDispatcher

  #
  # List of supported commands.
  #
  def commands
    all = {
      "app_list"      => "List installed apps in the device",
      "app_run"       => "Start Main Activty for package name",
      "app_install"   => "Request to install apk file",
      "app_uninstall" => "Request to uninstall application"
    }
    reqs = {
      "app_list"      => [ "appapi_app_list" ],
      "app_run"       => [ "appapi_app_run" ],
      "app_install"   => [ "appapi_app_install" ],
      "app_uninstall" => [ "appapi_app_uninstall" ]
    }
    filter_commands(all, reqs)
  end

  #
  # Name for this dispatcher
  #
  def name
    "Applictions Controller"
  end

  #
  # Get lits of android device installed applications
  #
  def cmd_app_list(*args)
    #print_good(client.apps.methods.to_s)
    app_list_opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help Banner" ],
      "-u" => [ true, "Get User apps ONLY" ],
      "-s" => [ true, "Get System apps ONLY" ]
    )

    ret = []
    init = 0

    app_list_opts.parse(args) do |opt, _idx, val|
      case opt
      when "-h"
        print_line("Usage: app_list [options]")
        print_line("List installed apps in android device.")
        print_line(app_list_opts.usage)
        return
      when "-u"
        init = 1
      when "-s"
        init = 2
      end
    end

    ret = client.appapi.app_list(init)
    print_line(to_table(ret).to_s)
  end

  #
  # Request to unistall application (user mode => ask the use to uninstall)
  #
  def cmd_app_uninstall(*args)
    app_uninstall_opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help Banner" ],
      "-p" => [ false, "Package Name" ]
    )

    app_uninstall_opts.parse(args) do |opt, _idx, val|
      case opt
      when "-h"
        print_line("Usage: app_uninstall [options]")
        print_line("Request to uninstall application.")
        print_line("ex. app_uninstall -p com.corrm.clac")
        print_line(app_uninstall_opts.usage)
        return
      when "-p"
        client.appapi.app_uninstall(val)
        print_good('Request Done #!!!#')
        return
      end
    end
    print_error('Where Package Name.?')
  end

  #
  # Request to install application (user mode => ask the use to install)
  #
  def cmd_app_install(*args)
    app_uninstall_opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help Banner" ],
      "-p" => [ false, "File Name Or Full Path" ]
    )

    full_path = ''

    app_uninstall_opts.parse(args) do |opt, _idx, val|
      case opt
      when "-h"
        print_line("Usage: app_install [options]\n")
        print_line("Request to install application.")
        print_line("ex. app_install -p 'sdcard/Download/corrm.apk'")
        print_line("ex. app_install -p corrm.apk")
        print_line(app_uninstall_opts.usage)
        return
      when "-p"
        # Check IsFile Or Full Path
        if val.index("/") == 0
          full_path = val
        else
          full_path = "#{client.fs.dir.getwd}/#{val}"
        end

        case client.appapi.app_install(full_path)
        when 1
          print_good('Request Done #!!!#')
        when 2
          print_error('File Not Found #!!!#')
        end
        return
      end
    end
    print_error('Where APK File.?')
  end

  #
  # Start Main Activty for installed application by Package name
  #
  def cmd_app_run(*args)
    app_run_opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help Banner" ],
      "-p" => [ true, "Package Name" ]
    )

    app_run_opts.parse(args) do |opt, _idx, val|
      case opt
      when "-h"
        print_line("Usage: app_run [options]\n")
        print_line("Start Main Activty for package name.")
        print_line("ex. app_run -p com.corrm.clac")
        print_line(app_run_opts.usage)
        return
      when "-p"
        case client.appapi.app_run(val)
        when 1
          print_good("Main Activty for '#{val}' has started")
        when 2
          print_error("#{val} Not Found !###!")
        end
        return
      end
    end
    print_error('Where Package Name.?')
  end

  #
  # Function to help printing list of informations
  #
  def to_table(data)
    column_headers = [ "Name", "Package", "Running", "IsSystem" ]

    opts = {
      'Header' => 'Application List',
      'Indent' => 2,
      'Columns' => column_headers
    }

    tbl = Rex::Text::Table.new(opts)
    (0 ... data.length).step(4).each do |index|
      tbl << [data[index],
        (data[index + 1] == nil ? "" : data[index + 1]),
        (data[index + 2] == nil ? "" : data[index + 2]),
        (data[index + 3] == nil ? "" : data[index + 3])]
    end

    tbl
  end

end; end; end; end; end
