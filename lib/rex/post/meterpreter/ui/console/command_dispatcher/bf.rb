# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# BF extension - interact with a BF interpreter
#
###
class Console::CommandDispatcher::BF

  Klass = Console::CommandDispatcher::BF

  include Console::CommandDispatcher

  #
  # Name for this dispatcher
  #
  def name
    'BF'
  end

  #
  # List of supported commands.
  #
  def commands
    {
      'bf_execute'  => 'Execute a BF command string'
    }
  end

  @@bf_execute_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help banner']
  )

  def bf_execute_usage
    print_line('Usage: bf_execute <bf code>')
    print_line
    print_line('Runs the given BF string on the target.')
    print_line(@@bf_execute_opts.usage)
  end

  #
  # Execute a simple BF command string
  #
  def cmd_bf_execute(*args)
    if args.length == 0 || args.include?('-h')
      bf_execute_usage
      return false
    end

    opts = {
      code: args.shift
    }

    @@bf_execute_opts.parse(args) { |opt, idx, val|
      case opt
      when '-s'
        opts[:session_id] = val
      end
    }

    result = client.bf.execute_string(opts)
    print_good("Command execution completed:\n#{result}")
  end

end

end
end
end
end

