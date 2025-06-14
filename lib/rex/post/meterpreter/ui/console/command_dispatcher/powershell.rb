# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Powershell extension - interact with a Powershell interpreter
#
###
class Console::CommandDispatcher::Powershell

  Klass = Console::CommandDispatcher::Powershell

  include Console::CommandDispatcher

  #
  # Name for this dispatcher
  #
  def name
    'Powershell'
  end

  #
  # List of supported commands.
  #
  def commands
    {
      'powershell_import'         => 'Import a PS1 script or .NET Assembly DLL',
      'powershell_shell'          => 'Create an interactive Powershell prompt',
      'powershell_execute'        => 'Execute a Powershell command string',
      'powershell_session_remove' => 'Remove/clear a session (other than default)',
    }
  end

  @@powershell_session_remove_opts = Rex::Parser::Arguments.new(
    '-s' => [true, 'Specify the id/name of the Powershell session to interact with (cannot be "default").'],
    '-h' => [false, 'Help banner']
  )

  def powershell_session_remove_usage
    print_line('Usage: powershell_session_remove -s session-id')
    print_line
    print_line('Removes a named session from the powershell instance.')
    print_line(@@powershell_session_remove_opts.usage)
  end

  def cmd_powershell_session_remove(*args)
    opts = {}

    @@powershell_session_remove_opts.parse(args) { |opt, idx, val|
      case opt
      when '-s'
        opts[:session_id] = val
      end
    }

    if opts[:session_id].nil? || opts[:session_id].downcase == 'default' || args.include?('-h')
      powershell_session_remove_usage
      return false
    else
      client.powershell.session_remove(opts)
      print_good("Session '#{opts[:session_id]}' removed.")
      return true
    end
  end

  @@powershell_shell_opts = Rex::Parser::Arguments.new(
    '-s' => [true, 'Specify the id/name of the Powershell session to interact with.'],
    '-h' => [false, 'Help banner']
  )

  def powershell_shell_usage
    print_line('Usage: powershell_shell [-s session-id]')
    print_line
    print_line('Creates an interactive Powershell prompt.')
    print_line(@@powershell_shell_opts.usage)
  end

  #
  # Create an interactive powershell prompts
  #
  def cmd_powershell_shell(*args)
    if args.include?('-h')
      powershell_shell_usage
      return false
    end

    opts = {}

    @@powershell_shell_opts.parse(args) { |opt, idx, val|
      case opt
      when '-s'
        opts[:session_id] = val
      end
    }

    result = client.powershell.shell(opts)

    channel = result[:channel]

    if result[:warning].present?
      print_warning(result[:warning])
    end

    shell.interact_with_channel(channel)
  end

  @@powershell_import_opts = Rex::Parser::Arguments.new(
    '-s' => [true, 'Specify the id/name of the Powershell session to run the command in.'],
    '-h' => [false, 'Help banner']
  )

  def powershell_import_usage
    print_line('Usage: powershell_import <path to file> [-s session-id]')
    print_line
    print_line('Imports a powershell script or assembly into the target.')
    print_line('The file must end in ".ps1" or ".dll".')
    print_line('Powershell scripts can be loaded into any session (via -s).')
    print_line('.NET assemblies are applied to all sessions.')
    print_line(@@powershell_import_opts.usage)
  end

  def cmd_powershell_import_tabs(str, words)
    if words.length == 1 # Just the command
      tab_complete_filenames(str, words)
    end
  end

  #
  # Import a script or assembly component into the target.
  #
  def cmd_powershell_import(*args)
    if args.length == 0 || args.include?('-h')
      powershell_import_usage
      return false
    end

    opts = {
      file: args.shift
    }

    @@powershell_import_opts.parse(args) { |opt, idx, val|
      case opt
      when '-s'
        opts[:session_id] = val
      end
    }

    result = client.powershell.import_file(opts)

    if result[:warning].present?
      print_warning(result[:warning])
    end

    if result[:loaded] == false
      print_error('File failed to load. The file must end in ".ps1" or ".dll".')
    elsif result[:loaded] == true || result[:output].empty?
      print_good("File successfully imported. No result was returned.")
    else
      print_good("File successfully imported. Result:\n#{result[:output]}")
    end
  end

  @@powershell_execute_opts = Rex::Parser::Arguments.new(
    '-s' => [true, 'Specify the id/name of the Powershell session to run the command in.'],
    '-h' => [false, 'Help banner']
  )

  def powershell_execute_usage
    print_line('Usage: powershell_execute <powershell code> [-s session-id]')
    print_line
    print_line('Runs the given Powershell string on the target.')
    print_line(@@powershell_execute_opts.usage)
  end

  #
  # Execute a simple Powershell command string
  #
  def cmd_powershell_execute(*args)
    if args.length == 0 || args.include?('-h')
      powershell_execute_usage
      return false
    end

    opts = {
      code: args.shift
    }

    @@powershell_execute_opts.parse(args) { |opt, idx, val|
      case opt
      when '-s'
        opts[:session_id] = val
      end
    }

    result = client.powershell.execute_string(opts)
    if result[:warning].present?
      print_warning(result[:warning])
    end
    print_good("Command execution completed:\n#{result[:output]}")
  end

end

end
end
end
end

