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
      'python_reset'              => 'Resets/restarts the Python interpreter',
      'python_execute'            => 'Execute a python command string'
    }
  end

  def cmd_python_reset(*args)
    client.python.reset
    print_good('Python interpreter successfully reset')
  end

  @@python_execute_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help banner'],
    '-r' => [true,  'Name of the variable containing the result']
  )

  def python_execute_usage
    print_line('Usage: python_execute <python code> [-r result var name]')
    print_line
    print_line('Runs the given python string on the target. If a result is required,')
    print_line('it should be stored in a python variable, and that variable should')
    print_line('passed using the -r parameter.')
    print_line(@@python_execute_opts.usage)
  end

  #
  # Execute a simple python command string
  #
  def cmd_python_execute(*args)
    if args.length == 0 || args.include?('-h')
      python_execute_usage
      return false
    end

    code = args.shift
    result_var = nil

    @@python_execute_opts.parse(args) { |opt, idx, val|
      case opt
      when '-r'
        result_var = val
      end
    }

    result = client.python.execute_string(code, result_var)
    if result[:result]
      print_good("#{result_var} = #{result[:result]}")
    elsif result[:stdout].length == 0 and result[:stderr].length == 0
      print_good("Command executed without returning a result")
    end

    if result[:stdout].length > 0
      print_good("Content written to stdout:\n#{result[:stdout]}")
    end

    if result[:stderr].length > 0
      print_error("Content written to stderr:\n#{result[:stderr]}")
    end
  end

end

end
end
end
end

