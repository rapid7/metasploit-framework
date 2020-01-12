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
            "-b" => [ true,  "The list of characters to avoid: '\\x00\\xff'"        ],
            "-E" => [ false, "Force encoding."                                      ],
            "-e" => [ true,  "The name of the encoder module to use."               ],
            "-h" => [ false, "Help banner."                                         ],
            "-o" => [ true,  "A comma separated list of options in VAR=VAL format." ],
            "-s" => [ true,  "NOP sled length."                                     ],
            "-f" => [ true,  "The output file name (otherwise stdout)"              ],
            "-t" => [ true,  "The output format: #{@@supported_formats.join(',')}"    ],
            "-p" => [ true,  "The Platform for output."                             ],
            "-k" => [ false, "Keep the template executable functional"              ],
            "-x" => [ true,  "The executable template to use"                       ],
            "-i" => [ true,  "the number of encoding iterations."                   ]
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

          #
          # Generates a payload.
          #
          def cmd_generate(*args)
            # Parse the arguments
            encoder_name = nil
            sled_size    = nil
            option_str   = nil
            badchars     = nil
            type         = "ruby"
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
              when '-o'
                option_str = val
              when '-s'
                sled_size = val.to_i
              when '-t'
                type = val
              when '-f'
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
                print(
                  "Usage: generate [options]\n\n" \
                  "Generates a payload.\n" +
                  @@generate_opts.usage
                )
                return true
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
                'Format'      => type,
                'NopSledSize' => sled_size,
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
              puts(buf)
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
