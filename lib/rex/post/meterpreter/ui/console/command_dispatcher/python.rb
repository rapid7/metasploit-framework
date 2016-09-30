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
      'python_import'             => 'Import/run a python file or module'
    }
  end

  def cmd_python_reset(*args)
    client.python.reset
    print_good('Python interpreter successfully reset')
  end

  @@python_import_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help banner'],
    '-f' => [true,  'Path to the file (.py, .pyc), or module directory to import'],
    '-n' => [true,  'Name of the module (optional, for single files only)'],
    '-r' => [true,  'Name of the variable containing the result (optional, single files only)']
  )

  def python_import_usage
    print_line('Usage: python_import <-f file path> [-n mod name] [-r result var name]')
    print_line
    print_line('Loads a python code file or module from disk into memory on the target.')
    print_line('The module loader requires a path to a folder that contains the module,')
    print_line('and the folder name will be used as the module name. Only .py files will')
    print_line('work with modules.')
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
    source = nil
    mod_name = nil

    @@python_import_opts.parse(args) { |opt, idx, val|
      case opt
      when '-f'
        source = val
      when '-n'
        mod_name = val
      when '-r'
        result_var = val
      end
    }

    unless source
      print_error("The -f parameter must be specified")
      return false
    end

    if ::File.directory?(source)
      files = ::Find.find(source).select { |p| /.*\.py$/ =~ p }
      if files.length == 0
        fail_with("No .py files found in #{source}")
      end

      base_name = ::File.basename(source)
      unless source.end_with?('/')
        source << '/'
      end

      print_status("Importing #{source} with base module name #{base_name} ...")

      files.each do |file|
        rel_path = file[source.length, file.length - source.length]
        parts = rel_path.split('/')

        mod_parts = [base_name] + parts[0, parts.length - 1]

        if parts[-1] != '__init__.py'
          mod_parts << ::File.basename(parts[-1], '.*')
        end

        mod_name = mod_parts.join('.')
        print_status("Importing #{file} as #{mod_name} ...")
        result = client.python.import(file, mod_name, nil)
        handle_exec_result(result, nil)
      end
    else
      print_status("Importing #{source} ...")
      result = client.python.import(source, mod_name, result_var)
      handle_exec_result(result, result_var)
    end

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

