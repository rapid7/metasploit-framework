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
    ['-e', '--entry']         => [ true,  "The entry point (default: #{DEFAULT_ENTRY})." ],
    ['-f', '--format-string'] => [ true,  "bof_pack compatible format-string. Choose combination of: b, i, s, z, Z" ],
  )

  # TODO: Properly parse arguments (positional and named switches)

  #
  # List of supported commands.
  #
  def commands
    {
      'execute_bof'                => 'Execute an arbitrary BOF file',
    }
  end

  def cmd_execute_bof_help
    print_line('Usage:   execute_bof </path/to/bof_file.o> [arguments [arguments]] --format-string [format-string]')
    print_line("Example: execute_bof /root/dir.x64.o C:\\ 0 --format-string Zs")
    print_line(@@bof_cmd_opts.usage)
  end

  # Tab complete the first argument as a file on the local filesystem
  def cmd_execute_bof_tabs(str, words)
    return tab_complete_filenames(str, words) if words.length == 1
    fmt = {
      '-a'              => [ true ],
      '--arguments'     => [ true ],
      '-e'              => [ true ],
      '--entry'         => [ true ],
      '-f'              => [ true ],
      '--format-string' => [ true ],
    }
    tab_complete_generic(fmt, str, words)
  end

  def cmd_execute_bof(*args)
    if args.length == 0 || args.include?('-h') || args.include?('--help')
      cmd_bof_cmd_help
      return false
    end

    bof_args = nil
    bof_args_format = nil
    bof_filename = args[0]
    bof_json_filename = nil
    entry = DEFAULT_ENTRY

    @@bof_cmd_opts.parse(args) { |opt, idx, val|
      case opt
      when '-f', '--format-string'
        bof_args_format = val
      when '-e', '--entry'
        entry = val
      when '-j', '--json-file'
        bof_json_filename = val
      end
    }

    unless ::File.file?(bof_filename) && ::File.readable?(bof_filename)
      print_error("Unreadable file: #{bof_filename}")
      return
    end

    if bof_args_format
      bof_args = args[1..bof_args_format.length]
    else
      print_status('No argument format specified executing bof with no arguments.')
    end

    bof_data = ::File.binread(bof_filename)
    parsed = Metasm::COFF.decode_header(bof_data[0...20])
    bof_arch = { # map of metasm to metasploit architectures
      'AMD64' => ARCH_X64,
      'I386'  => ARCH_X86
    }.fetch(parsed.header.machine, nil)

    unless bof_arch
      print_error('Unable to determine the file architecture.')
      return
    end
    unless bof_arch == client.arch
      print_error("The file architecture is incompatible with the current session (file: #{bof_arch} session: #{client.arch})")
      return
    end

    output = client.bofloader.execute(bof_data, args_format: bof_args_format, args: bof_args, entry: entry)
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
