# -*- coding: binary -*-
require 'rex/post/meterpreter'
require 'rex/post/meterpreter/extensions/appapi/command_ids'

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
  include Rex::Post::Meterpreter::Extensions::AppApi

  #
  # List of supported commands.
  #
  def commands
    all = {
      'app_list'      => 'List installed apps in the device',
      'app_run'       => 'Start Main Activity for package name',
      'app_install'   => 'Request to install apk file',
      'app_uninstall' => 'Request to uninstall application'
    }
    reqs = {
      'app_list'      => [COMMAND_ID_APPAPI_APP_LIST],
      'app_run'       => [COMMAND_ID_APPAPI_APP_RUN],
      'app_install'   => [COMMAND_ID_APPAPI_APP_INSTALL],
      'app_uninstall' => [COMMAND_ID_APPAPI_APP_UNINSTALL]
    }
    filter_commands(all, reqs)
  end

  #
  # Name for this dispatcher
  #
  def name
    'Application Controller'
  end

  #
  # Get list of android device installed applications
  #
  def cmd_app_list(*args)
    app_list_opts = Rex::Parser::Arguments.new(
      '-h' => [false, 'Help Banner'],
      '-u' => [false, 'Get User apps ONLY'],
      '-s' => [false, 'Get System apps ONLY']
    )

    ret = []
    init = 0

    app_list_opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h'
        print_line('Usage: app_list [options]')
        print_line('List the installed applications.')
        print_line(app_list_opts.usage)
        return
      when '-u'
        init = 1
      when '-s'
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
      print_error('[-] Usage: app_uninstall <packagename>')
      print_error('[-] Request to uninstall application.')
      print_error('[-] You can use "app_list" to pick your packagename.')
      print_status('eg. app_uninstall com.corrm.clac')
      return
    end

    package_name = args[0]

    # Send uninstall request
    case client.appapi.app_uninstall(package_name)
    when 1
      print_good('Request Done.')
    when 2
      print_error('File Not Found.')
    when 11
      print_error("package '#{package_name}' not found.")
    end
  end

  #
  # Request to install application (user mode => ask the use to install)
  #
  def cmd_app_install(*args)
    if (args.length < 1)
      print_error('[-] Usage: app_install <filepath>')
      print_error('[-] Request to install application.')
      print_status('eg. app_install "/sdcard/Download/corrm.apk"')
      return
    end

    full_path = args[0]

    # Send install request
    case client.appapi.app_install(full_path)
    when 1
      print_good('Request Done.')
    when 2
      print_error('File Not Found.')
    when 3
      print_error('Root access rejected.')
    end
  end

  #
  # Start Main Activity for installed application by Package name
  #
  def cmd_app_run(*args)
    if (args.length < 1)
      print_error('[-] Usage: app_run <package_name>')
      print_error('[-] Start Main Activity for package name.')
      print_error('[-] You can use "app_list" to pick your packagename.')
      print_status('eg. app_run com.corrm.clac')
      return
    end

    package_name = args[0]

    case client.appapi.app_run(package_name)
    when 1
      print_good("Main Activity for '#{package_name}' has started.")
    when 2
      print_error("'#{package_name}' Not Found.")
    end
  end

  #
  # Function to help printing list of information
  #
  def to_table(data)
    column_headers = ['Name', 'Package', 'Running', 'IsSystem']

    opts = {
      'Header' => 'Application List',
      'Indent' => 2,
      'Columns' => column_headers
    }

    tbl = Rex::Text::Table.new(opts)
    (0 ... data.length).step(4).each do |index|
      tbl << [data[index],
        (data[index + 1] == nil ? '' : data[index + 1]),
        (data[index + 2] == nil ? '' : data[index + 2]),
        (data[index + 3] == nil ? '' : data[index + 3])]
    end

    tbl
  end

end; end; end; end; end
