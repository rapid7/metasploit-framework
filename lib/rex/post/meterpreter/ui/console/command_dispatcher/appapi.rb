# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Application controller - run, get app list, install and uninstall applications.
# Extension by Islam Nofl (@CorrM)
#
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
    "Application Controller"
  end

  #
  # Get list of android device installed applications
  #
  def cmd_app_list(*args)
    app_list_opts = Rex::Parser::Arguments.new(
      "-h" => [ false, "Help Banner" ],
      "-u" => [ false,  "Get User apps ONLY" ],
      "-s" => [ false,  "Get System apps ONLY" ]
    )

    ret = []
    init = 0

    app_list_opts.parse(args) do |opt, _idx, val|
      case opt
      when "-h"
        print_line("Usage: app_list [options]")
        print_line("List the installed applications.")
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
    if (args.length < 1)
      print_line("[-] Usage: app_uninstall <packagename>")
      print_line("[-] Request to uninstall application.")
      print_line("[-] You can use 'app_list' to pick your packagename.")
      print_status("ex. app_uninstall com.corrm.clac")
      return
    end

    package_name = args[0]

    # Send uninstall request
    case client.appapi.app_uninstall(package_name)
    when 1
      print_good("Request Done.")
    when 2
      print_error("File Not Found.")
    when 11
      print_error("package '#{package_name}' not found.")
    end
  end

  #
  # Request to install application (user mode => ask the use to install)
  #
  def cmd_app_install(*args)
    if (args.length < 1)
      print_line("[-] Usage: app_install <filepath>")
      print_line("[-] Request to install application.")
      print_status("ex. app_install '/sdcard/Download/corrm.apk'")
      return
    end

    full_path = args[0]

    # Send install request
    case client.appapi.app_install(full_path)
    when 1
      print_good("Request Done.")
    when 2
      print_error("File Not Found.")
    when 3
      print_error("Root access rejected.")
    end
  end

  #
  # Start Main Activty for installed application by Package name
  #
  def cmd_app_run(*args)
    if (args.length < 1)
      print_line("[-] Usage: app_run <package_name>")
      print_line("[-] Start Main Activty for package name.")
      print_line("[-] You can use 'app_list' to pick your packagename.")
      print_status("ex. app_run com.corrm.clac")
      return
    end

    package_name = args[0]

    case client.appapi.app_run(package_name)
    when 1
      print_good("Main Activty for '#{package_name}' has started.")
    when 2
      print_error("'#{package_name}' Not Found.")
    end
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
