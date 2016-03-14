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
      'powershell_execute'            => 'Execute a Powershell command string',
    }
  end

  @@powershell_execute_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help banner']
  )

  def powershell_execute_usage
    print_line('Usage: powershell_execute <powershell code>')
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

    code = args.shift

    @@powershell_execute_opts.parse(args) { |opt, idx, val|
      #case opt
      #when '-r'
      #  result_var = val
      #end
    }

    result = client.powershell.execute_string(code)
    print_good("Command execution completed:\n#{result}")
  end

end

end
end
end
end

