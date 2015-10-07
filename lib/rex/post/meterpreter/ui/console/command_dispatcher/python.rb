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
      'python_execute'            => 'Execute a python command string',
      'python_import'             => 'Import/run a python run'
    }
  end

  def cmd_python_reset(*args)
    client.python.reset
    print_good('Python interpreter successfully reset')
  end

  @@python_import_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help banner'],
    '-f' => [true,  'Path to the file (.py, .pyc) to import'],
    '-m' => [true,  'Name of the module (optional)'],
    '-r' => [true,  'Name of the variable containing the result (optional)']
  )

  def python_import_usage
    print_line('Usage: python_imoprt <-f file path> [-m mod name] [-r result var name]')
    print_line
    print_line('Loads a python code file from disk into memory on the target.')
    print_line(@@python_import_opts.usage)
  end

  #
  # Import/run a python file
  #
  def cmd_python_import(*args)
    if args.length == 0 || args.include?('-h')
      python_import_usage
      return false
    end

    result_var = nil
    file = nil
    mod_name = nil

    @@python_import_opts.parse(args) { |opt, idx, val|
      case opt
      when '-f'
        file = val
      when '-m'
        mod_name = val
      when '-r'
        result_var = val
      end
    }

    unless file
      print_error("File path must be specified")
      return false
    end

    result = client.python.import(file, mod_name, result_var)

    handle_exec_result(result, result_var)
  end

  @@python_execute_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help banner'],
    '-r' => [true,  'Name of the variable containing the result (optional)']
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

    handle_exec_result(result, result_var)
  end

private

  def handle_exec_result(result, result_var)
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

