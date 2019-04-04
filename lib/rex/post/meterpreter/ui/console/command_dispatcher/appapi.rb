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
      "-u" => [ true,  "Get User apps ONLY" ],
      "-s" => [ true,  "Get System apps ONLY" ]
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
      "-r" => [ false, "Use root permissions to uninstall the app."],
      "-u" => [ false, "Use user interface app uninstaller."]
    )

    if (args.length < 1)
      print_line("[-] Usage: app_uninstall [options]")
      print_line("[-] Request to uninstall application.")
      print_line("[-] You can use 'app_list' to pick your packagename.")
      print_status("ex. app_uninstall com.corrm.clac -u")
      print_line(app_uninstall_opts.usage)
      return
    end

    package_name = args[0]
    use_root = false
    uninstall_method_picked = false

    # Check Package Name
    if package_name == ""
      print_error('Where Application file.?')
      return
    end

    app_uninstall_opts.parse(args) do |opt, _idx, val|
      case opt
      when "-r"
        if client.android.check_root
          uninstall_method_picked = true
          use_root = true
        else
          print_error("Device is not rooted, Use '-u' instead '-r'.")
          return
        end
      when "-u"
        uninstall_method_picked = true
        use_root = false
      end
    end

    # Check if user used '-r\-u' param (to be sure he use good method for his target)
    if uninstall_method_picked == false
      print_status("Please use '-r' or '-u', Use 'app_uninstall' to learn more.")
      return
    end

    # Send uninstall request 
    case client.appapi.app_uninstall(package_name, use_root)
    when 1
      if use_root
        print_good("Application uninstalled.")
      else
        print_good("Request Done.")
      end
    when 2
      print_error("File Not Found.")
    when 3
      print_error("Root access rejected.")
    when 11
      print_error("package '#{package_name}' not found.")
    end
  end

  #
  # Request to install application (user mode => ask the use to install)
  #
  def cmd_app_install(*args)
    app_install_opts = Rex::Parser::Arguments.new(
      "-r" => [ false, "Use root permissions to install the app."],
      "-u" => [ false, "Use user interface app installer."]
    )

    if (args.length < 1)
      print_line("[-] Usage: app_install <filepath> [options]")
      print_line("[-] install application.")
      print_line("[-] You can use 'cd' to go to the path and just use the file name.")
      print_status("ex. app_install '/sdcard/Download/corrm.apk' -u")
      print_line(app_install_opts.usage)
      return
    end
    
    full_path = args[0]
    use_root = false
    install_method_picked = false

    # Check path
    if full_path == ""
      print_error('Where Application file.?')
      return
    end

    app_install_opts.parse(args) do |opt, _idx, val|
      case opt
      when "-r"
        if client.android.check_root
          install_method_picked = true
          use_root = true
        else
          print_error("Device is not rooted, Use '-u' instead '-r'.")
          return
        end
      when "-u"
        install_method_picked = true
        use_root = false
      end
    end

    # Check if user used '-r\-u' param (to be sure he use good method for his target)
    if install_method_picked == false
      print_status("Please use '-r' or '-u', Use 'app_install' to learn more.")
      return
    end

    # Send install request 
    case client.appapi.app_install(full_path, use_root)
    when 1
      if use_root
        print_good("Application installed.")
      else
        print_good("Request Done.")
      end
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
      print_line(app_run_opts.usage)
      return
    end

    package_name = args[0]
    #print_error('Where Package Name.?')

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
