# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Unhook extension - unhook PSP products
#
###
class Console::CommandDispatcher::Unhook

  Klass = Console::CommandDispatcher::Unhook

  include Console::CommandDispatcher

  #
  # Name for this dispatcher
  #
  def name
    'Unhook'
  end

  #
  # List of supported commands.
  #
  def commands
    {
      'unhook_pe'  => 'Unhook the current process'
    }
  end

  @@bf_execute_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help banner']
  )

  def unhook_execute_usage
    print_line('Usage: unhook_pe')
    print_line
    print_line('Removes any runtime hooks placed by PSPs')
    print_line(@@bf_execute_opts.usage)
  end

  #
  # Execute a simple BF command string
  #
  def cmd_unhook_pe(*args)
    if args.include?('-h')
      unhook_execute_usage
      return false
    end

    result = client.unhook.unhook_pe

    print_good("Command execution completed:\n#{result}")
  end

end

end
end
end
end
