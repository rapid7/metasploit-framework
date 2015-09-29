# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Python extension - interact with a python interpreter
#
###
class Console::CommandDispatcher::Python

  Klass = Console::CommandDispatcher::Python

  include Console::CommandDispatcher

  #
  # Name for this dispatcher
  #
  def name
    'Python'
  end

  #
  # List of supported commands.
  #
  def commands
    {
      'python_execute'            => 'Execute a python command string'
    }
  end

  def python_execute_usage
    print_line('Usage: python_execute [python code]')
    print_line
    print_line('Runs the given python string on the target and returns the output.')
  end

  #
  # Execute a simple python command string
  #
  def cmd_python_execute(*args)
    if args.length == 0
      python_execute_usage
      return false
    end

    client.python.execute_string(args[0])
  end

end

end
end
end
end

