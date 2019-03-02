# -*- coding: binary -*-

require 'rex/parser/arguments'

module Msf
  module Ui
    module Console
      module CommandDispatcher
        ###
        # Payload module command dispatcher.
        ###
        class Payload
          include Msf::Ui::Console::ModuleCommandDispatcher

          # Load supported formats
          @@supported_formats = \
            Msf::Simple::Buffer.transform_formats + \
            Msf::Util::EXE.to_executable_fmt_formats

          @@generate_opts = Rex::Parser::Arguments.new(
            "-p" => [ true,  "The platform of the payload" ],
            "-n" => [ true,  "Prepend a nopsled of [length] size on to the payload" ],
            "-f" => [ true,  "Output format: #{@@supported_formats.join(',')}" ],
            "-E" => [ false, "Force encoding" ],
            "-e" => [ true,  "The encoder to use" ],
            "-s" => [ true,  "NOP sled length."                                     ],
            "-P" => [ true,  "Total desired payload size, auto-produce approproate NOPsled length"],
            "-S" => [ true,  "The new section name to use when generating (large) Windows binaries"],
            "-b" => [ true,  "The list of characters to avoid example: '\\x00\\xff'" ],
            "-i" => [ true,  "The number of times to encode the payload" ],
            "-x" => [ true,  "Specify a custom executable file to use as a template" ],
            "-k" => [ false, "Preserve the template behavior and inject the payload as a new thread" ],
            "-o" => [ true,  "The output file name (otherwise stdout)" ],
            "-O" => [ true,  "Deprecated: alias for the '-o' option" ],
            "-h" => [ false, "Show this message" ],
          )

          #
          # Returns the hash of commands specific to payload modules.
          #
          def commands
            super.update(
              "generate" => "Generates a payload",
              "to_handler" => "Creates a handler with the specified payload"
            )
          end

          def cmd_to_handler(*_args)
            handler = framework.modules.create('exploit/multi/handler')

            handler_opts = {
              'Payload'        => mod.refname,
              'LocalInput'     => driver.input,
              'LocalOutput'    => driver.output,
              'ExitOnSession'  => false,
              'RunAsJob'       => true
            }

            handler.datastore.merge!(mod.datastore)
            handler.exploit_simple(handler_opts)
            job_id = handler.job_id

            print_status "Payload Handler Started as Job #{job_id}"
          end

          #
          # Returns the command dispatcher name.
          #
          def name
            "Payload"
          end

          def cmd_generate_help
            print_line "Usage: generate [options]"
            print_line
            print_line "Generates a payload."
            print @@generate_opts.usage
          end

          #
          # Generates a payload.
          #
          def cmd_generate(*args)
            # Parse the arguments
            encoder_name = nil
            sled_size    = nil
            pad_nops     = nil
            sec_name     = nil
            option_str   = nil
            badchars     = nil
            format       = "ruby"
            ofile        = nil
            iter         = 1
            force        = nil
            template     = nil
            plat         = nil
            keep         = false

            @@generate_opts.parse(args) do |opt, _idx, val|
              case opt
              when '-b'
                badchars = Rex::Text.hex_to_raw(val)
              when '-e'
                encoder_name = val
              when '-E'
                force = true
              when '-n'
                sled_size = val.to_i
              when '-P'
                pad_nops = val.to_i
              when '-S'
                sec_name = val
              when '-f'
                format = val
              when '-o'
                if val.include?('=')
                  print("The -o parameter of 'generate' is now preferred to indicate the output file, like with msfvenom")
                  mod.datastore[key] = val
                else
                  ofile = val
                end
              when '-O'
                print("Usage of the '-O' parameter is deprecated, prefer '-o' to indicate the output file")
                ofile = val
              when '-i'
                iter = val
              when '-k'
                keep = true
              when '-p'
                plat = val
              when '-x'
                template = val
              when '-h'
                cmd_generate_help
                return false
              else
                (key, val) = val.split('=')
                if key && val
                  mod.datastore[key] = val
                else
                  cmd_generate_help
                  return false
                end
              end
            end
            if encoder_name.nil? && mod.datastore['ENCODER']
              encoder_name = mod.datastore['ENCODER']
            end

            # Generate the payload
            begin
              buf = mod.generate_simple(
                'BadChars'    => badchars,
                'Encoder'     => encoder_name,
                'Format'      => format,
                'NopSledSize' => sled_size,
                'PadNops'     => pad_nops,
                'SecName'     => sec_name,
                'OptionStr'   => option_str,
                'ForceEncode' => force,
                'Template'    => template,
                'Platform'    => plat,
                'KeepTemplateWorking' => keep,
                'Iterations' => iter
              )
            rescue
              log_error("Payload generation failed: #{$ERROR_INFO}")
              return false
            end

            if !ofile
              # Display generated payload
              print(buf)
            else
              print_status("Writing #{buf.length} bytes to #{ofile}...")
              fd = File.open(ofile, "wb")
              fd.write(buf)
              fd.close
            end
            true
          end

          def cmd_generate_tabs(str, words)
            fmt = {
              '-b' => [ true                                              ],
              '-E' => [ nil                                               ],
              '-e' => [ framework.encoders.map { |refname, mod| refname } ],
              '-h' => [ nil                                               ],
              '-o' => [ true                                              ],
              '-s' => [ true                                              ],
              '-P' => [ true                                              ],
              '-S' => [ true                                              ],
              '-f' => [ :file                                             ],
              '-t' => [ @@supported_formats                               ],
              '-p' => [ true                                              ],
              '-k' => [ nil                                               ],
              '-x' => [ :file                                             ],
              '-i' => [ true                                              ]
            }
            tab_complete_generic(fmt, str, words)
          end
        end
      end
    end
  end
end
