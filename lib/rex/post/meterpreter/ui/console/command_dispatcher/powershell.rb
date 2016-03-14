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
      'powershell_shell'    => 'Create an interactive Powershell prompt',
      'powershell_execute'  => 'Execute a Powershell command string'
    }
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

    channel = client.powershell.shell(opts)
    shell.interact_with_channel(channel)
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
    print_good("Command execution completed:\n#{result}")
  end

end

end
end
end
end

