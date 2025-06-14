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

          def initialize(shell)
            super
            print_line
            print_line
            print_line('meterpreter                  ')
            print_line('   ▄▄▄▄    ▒█████    █████▒  ')
            print_line('  ▓█████▄ ▒██▒  ██▒▓██   ▒   ')
            print_line('  ▒██▒ ▄██▒██░  ██▒▒████ ░   ')
            print_line('  ▒██░█▀  ▒██   ██░░▓█▒  ░   ')
            print_line('  ░▓█  ▀█▓░ ████▓▒░░▒█░      ')
            print_line('  ░▒▓███▀▒░ ▒░▒░▒░  ▒ ░      ')
            print_line('  ▒░▒   ░   ░ ▒ ▒░  ░     ~ by @kev169, @GuhnooPluxLinux, @R0wdyJoe, @skylerknecht ~')
            print_line('   ░    ░ ░ ░ ░ ▒   ░ ░      ')
            print_line('   ░          ░ ░  loader    ')
            print_line('        ░                    ')
            print_line
          end

          DEFAULT_ENTRY = 'go'.freeze

          @@execute_bof_opts = Rex::Parser::Arguments.new(
            ['-h', '--help'] => [ false, 'Help Banner' ],
            ['-c', '--compile'] => [ false, 'Compile the input file (requires mingw).' ],
            ['-e', '--entry'] => [ true, "The entry point (default: #{DEFAULT_ENTRY})." ],
            ['-f', '--format-string'] => [ true, 'Argument format-string. Choose combination of: b, i, s, z, Z' ]
          )

          #
          # List of supported commands.
          #
          def commands
            {
              'execute_bof' => 'Execute an arbitrary BOF file'
            }
          end

          def cmd_execute_bof_help
            print_line('Usage:   execute_bof </path/to/bof_file> [bof_nonliteral_arguments] [--format-string] [-- bof_literal_arguments]')
            print_line(@@execute_bof_opts.usage)
            print_line(
              <<~HELP
                Examples:
                  execute_bof /bofs/dir.x64.o -- --help
                  execute_bof /bofs/dir.x64.o --format-string Zs C:\\\\ 0
                  execute_bof /bofs/upload.x64.o --format-string bZ file:/local/file.txt C:\\remote\\file.txt#{' '}
                  execute_bof /bofs/dir.x64.c --compile --format-string Zs -- C:\\\\ 0#{' '}
                #{'  '}

                Argument formats:
                  b       binary data (e.g. 01020304)
                  i       32-bit integer
                  s       16-bit integer
                  z       null-terminated utf-8 string
                  Z       null-terminated utf-16 string
              HELP
            )
          end

          # Tab complete the first argument as a file on the local filesystem
          def cmd_execute_bof_tabs(str, words)
            return if words.include?('--')
            return tab_complete_filenames(str, words) if words.length == 1

            if (str =~ /^file:(.*)/)
              files = tab_complete_filenames(Regexp.last_match(1), words)
              return files.map { |f| 'file:' + f }
            end
            fmt = {
              '-c' => [ nil ],
              '--compile' => [ nil ],
              '-e' => [ true ],
              '--entry' => [ true ],
              '-f' => [ true ],
              '--format-string' => [ true ]
            }
            tab_complete_generic(fmt, str, words)
          end

          def cmd_execute_bof(*args)
            if args.empty?
              cmd_execute_bof_help
              return false
            end

            bof_args_literal = []
            bof_args_nonliteral = []
            bof_args_format = nil
            entry = DEFAULT_ENTRY
            compile = false

            args, bof_args_literal = args.split('--') if args.include?('--')
            if args.include?('-h') || args.include?('--help')
              cmd_execute_bof_help
              return false
            end
            bof_filename = args.shift

            @@execute_bof_opts.parse(args) do |opt, _idx, val|
              case opt
              when '-c', '--compile'
                compile = true
              when '-f', '--format-string'
                bof_args_format = val
              when '-e', '--entry'
                entry = val
              when nil
                if val.start_with?('-')
                  print_error("Unknown argument: #{val}")
                  return false
                end
                bof_args_nonliteral << val
              end
            end

            bof_args = bof_args_nonliteral + bof_args_literal

            unless ::File.file?(bof_filename) && ::File.readable?(bof_filename)
              print_error("Unreadable file: #{bof_filename}")
              return
            end

            if bof_args_format
              if bof_args_format.length != bof_args.length
                print_error('Format string must be the same length as arguments.')
                return
              end

              bof_args_format.chars.each_with_index do |fmt, idx|
                bof_arg = bof_args[idx]
                case fmt
                when 'b'
                  if bof_arg.start_with?('file:')
                    local_filename = bof_arg.split('file:')[1]

                    unless ::File.file?(local_filename) && ::File.readable?(local_filename)
                      print_error("Argument ##{idx + 1} contains an unreadable file: #{local_filename}")
                      return false
                    end
                    bof_arg = ::File.binread(local_filename)
                  else
                    unless bof_arg.length.even?
                      print_error("Argument ##{idx + 1} was not appropriately padded to an even length string!")
                      return false
                    end
                    bytes = bof_arg.scan(/(?:[a-fA-F0-9]{2})/).map { |v| v.to_i(16) }
                    if (bof_arg.length / 2 != bytes.length)
                      print_error("Argument ##{idx + 1} contains invalid characters!")
                      return false
                    end
                    bof_arg = bytes.pack('C*')
                  end
                when 'i', 's'
                  if bof_arg =~ /^\d+$/
                    bof_arg = bof_arg.to_i
                  elsif bof_arg =~ /^0x[a-fA-F0-9]+$/
                    bof_arg = bof_arg[2..].to_i(16)
                  else
                    print_error("Argument ##{idx + 1} must be a number!")
                    return false
                  end
                end
                bof_args[idx] = bof_arg
              end
            elsif bof_args.length > 1
              print_error('Arguments detected but no format string specified.')
              return
            else
              print_status('No arguments specified, executing bof with no arguments.')
            end

            if compile
              bof_data = compile_c(bof_filename)
              return unless bof_data
            else
              bof_data = ::File.binread(bof_filename)
            end

            # loading all data will hang on invalid files like DLLs, so only parse the 20-byte header at first
            parsed = Metasm::COFF.decode_header(bof_data[0...20])
            bof_arch = { # map of metasm to metasploit architectures
              'AMD64' => ARCH_X64,
              'I386' => ARCH_X86
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

            begin
              output = client.bofloader.execute(bof_data, args_format: bof_args_format, args: bof_args, entry: entry)
            rescue Rex::Post::Meterpreter::Extensions::Bofloader::BofPackingError => e
              print_error("Error processing the specified arguments: #{e.message}")
              return
            end

            if output.nil?
              print_status('No output returned from bof')
            else
              print_line(output)
            end
          end

          private

          def compile_c(source)
            if client.arch == ARCH_X86
              mingw = Metasploit::Framework::Compiler::Mingw::X86.new
            elsif client.arch == ARCH_X64
              mingw = Metasploit::Framework::Compiler::Mingw::X64.new
            else
              print_error("Unsupported client architecture: #{client.arch}")
              return
            end

            unless mingw.class.available?
              print_error("#{mingw.mingw_bin} is unavailable, can not compile source code")
              return
            end

            ::Tempfile.create([::File.basename(source, '.c'), '.o']) do |destination|
              destination = destination.path
              output, status = Open3.capture2e(mingw.mingw_bin, '-c', source, '-I', Metasploit::Framework::Compiler::Mingw::INCLUDE_DIR, '-o', destination)
              unless status.exitstatus == 0
                print_error("Compilation exited with error code: #{status.exitstatus}")
                print_line(output) unless output.blank?
                return
              end

              return ::File.binread(destination)
            end
          end

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
              if client.arch == ARCH_X64
                executable_symbols << sym.name
              else
                next unless sym.name.start_with?('_')

                executable_symbols << sym.name[1..]
              end
            end

            executable_symbols
          end

        end
      end
    end
  end
end
