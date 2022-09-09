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

  @@execute_bof_opts = Rex::Parser::Arguments.new(
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
    bof_cmdline = []
    entry = DEFAULT_ENTRY

    @@execute_bof_opts.parse(args) { |opt, idx, val|
      case opt
      when '-f', '--format-string'
        bof_args_format = val
      when '-e', '--entry'
        entry = val
      when nil
        bof_cmdline << val
      end
    }

    bof_filename = bof_cmdline[0]

    unless ::File.file?(bof_filename) && ::File.readable?(bof_filename)
      print_error("Unreadable file: #{bof_filename}")
      return
    end

    if bof_args_format
      if bof_args_format.length != bof_cmdline.length - 1
        print_error("Format string length must be the same as argument length: fstring:#{bof_args_format.length}, args:#{bof_cmdline.length - 1}")
        return
      end
      bof_args = bof_cmdline[1..]
    elsif bof_cmdline.length > 1
      print_error('Arguments detected and no format string specified.')
      return
    else
      print_status('No argument format specified executing bof with no arguments.')
    end

    bof_data = ::File.binread(bof_filename)

    # loading all data will hang on invalid files like DLLs, so only parse the 20-byte header at first
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

    parsed = Metasm::COFF.decode(bof_data)
    unless (executable_symbols = get_executable_symbols(parsed)).include?(entry)
      print_error("The specified entry point was not found: #{entry}")
      print_error("Available symbols: #{executable_symbols.join(', ')}")
      return
    end

    output = client.bofloader.execute(bof_data, args_format: bof_args_format, args: bof_args, entry: entry)
    if output.nil?
      print_status("No output returned from bof")
    else
      print_line(output)
    end

  end

  private

  def get_executable_symbols(coff)
    executable_symbols = []
    coff.symbols.each do |sym|
      next unless sym
      next unless sym.sec_nr.is_a? Integer

      section = coff.sections[sym.sec_nr - 1]
      next unless section

      next if section.name == sym.name
      next unless section.characteristics.include?('MEM_EXECUTE')
      next unless section.characteristics.include?('CONTAINS_CODE')

      # see: https://github.com/trustedsec/COFFLoader/blob/24da168356bd20438a4e66ef3261c5012344d362/COFFLoader.c#L182-L189
      unless client.arch == ARCH_X64
        next unless sym.name.start_with?('_')

        executable_symbols << sym.name[1..]
      else
        executable_symbols << sym.name
      end
    end

    executable_symbols
  end

end

end
end
end
end
