# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Bofloader extension - load and execute bof files
#
###
class Console::CommandDispatcher::Bofloader

  Klass = Console::CommandDispatcher::Bofloader

  include Console::CommandDispatcher

  #
  # Name for this dispatcher
  #
  def name
    'Beacon Object File Loader'
  end

  DEFAULT_ENTRY = 'go'

  @@bof_cmd_opts = Rex::Parser::Arguments.new(
    ['-h', '--help']          => [ false, "Help Banner" ],
    ['-a', '--arguments']     => [ true,  "List of command-line arguments to pass to the BOF" ],
    ['-b', '--bof-file']      => [ true,  "Local path to Beacon Object File" ],
    ['-e', '--entry']         => [ true,  "The entry point (default: #{DEFAULT_ENTRY})." ],
    ['-f', '--format-string'] => [ true,  "bof_pack compatible format-string. Choose combination of: b, i, s, z, Z" ],
    ['-j', '--json-file']     => [ true,  "Local path to JSON arguments file" ],
  )

  # TODO: Properly parse arguments (positional and named switches)

  #
  # List of supported commands.
  #
  def commands
    {
      'bof_cmd'                => 'Execute an arbitrary BOF file',
    }
  end

  def cmd_bof_cmd_help
    print_line('Usage:   bof_exec </path/to/bof_file.o> [fstring] [bof_arguments ...]')
    print_line("Example: bof_exec /root/dir.x64.o Zs C:\\ 0")
    print_line(@@bof_cmd_opts.usage)
  end

  # Tab complete the first argument as a file on the local filesystem
  def cmd_bof_cmd_tabs(str, words)
    fmt = {
      '-b'              => [ :file ],
      '--bof-file'      => [ :file ],
      '-a'              => [ true ],
      '--arguments'     => [ true ],
      '-e'              => [ true ],
      '--entry'         => [ true ],
      '-f'              => [ true ],
      '--format-string' => [ true ],
      '-j'              => [ :file ],
      '--json-file'     => [ :file ]
    }
    tab_complete_generic(fmt, str, words)
  end

  def cmd_bof_cmd(*args)
    if args.length == 0 || args.include?('-h') || args.include?('--help')
      cmd_bof_cmd_help
      return false
    end

    filename = nil
    entry = DEFAULT_ENTRY
    bof_args_format = nil
    bof_args = nil

    @@bof_cmd_opts.parse(args) { |opt, idx, val|
      case opt
      when '-a', '--arguments'
        bof_args = val
      when '-b', '--bof-file'
        filename = val
      when '-e', '--entry'
        bof_args = val
      when '-f', '--format-string'
        bof_args_format = val
      end
    }

    unless filename
      print_error("The -b / --bof-file argument is required")
      return
    end

    unless ::File.file?(filename) && ::File.readable?(filename)
      print_error("Unreadable file: #{filename}")
      return
    end

    if !!bof_args ^ !!bof_args_format
      print_error('-a / --arguments and -f / --format-string must be used together')
      return
    end

    output = client.bofloader.exec_cmd(filename, args_format: bof_args_format, args: bof_args, entry: entry)
    if output.nil?
      print_line("No (Nil?) output from BOF...")
    else
      print_line(output)
    end

  end

end

end
end
end
end
