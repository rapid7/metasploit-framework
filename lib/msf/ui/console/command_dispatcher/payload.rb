# -*- coding: binary -*-

require 'rex/parser/arguments'

# Payload module command dispatcher.
class Msf::Ui::Console::CommandDispatcher::Payload
  include Msf::Ui::Console::ModuleCommandDispatcher

  #
  # Class Variables
  #

  # Load supported formats
  supported_formats = Msf::Simple::Buffer.transform_formats + Msf::Util::EXE.to_executable_fmt_formats

  @@generate_opts = Rex::Parser::Arguments.new(
    "-b" => [ true,  "The list of characters to avoid: '\\x00\\xff'"        ],
    "-E" => [ false, "Force encoding."                                      ],
    "-e" => [ true,  "The name of the encoder module to use."               ],
    "-h" => [ false, "Help banner."                                         ],
    "-o" => [ true,  "A comma separated list of options in VAR=VAL format." ],
    "-s" => [ true,  "NOP sled length."                                     ],
    "-f" => [ true,  "The output file name (otherwise stdout)"              ],
    "-t" => [ true,  "The output format: #{supported_formats.join(',')}"    ],
    "-p" => [ true,  "The Platform for output."                             ],
    "-k" => [ false, "Keep the template executable functional"              ],
    "-x" => [ true,  "The executable template to use"                       ],
    "-i" => [ true,  "the number of encoding iterations."                   ])

  #
  # Methods
  #

  #
  # Returns the hash of commands specific to payload modules.
  #
  def commands
    super.merge(
      "generate" => "Generates a payload",
    )
  end

  #
  # Returns the command dispatcher name.
  #
  def name
    return "Payload"
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

    @@generate_opts.parse(args) { |opt, idx, val|
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
            "Usage: generate [options]\n\n" +
            "Generates a payload.\n" +
            @@generate_opts.usage)
          return true
      end
    }
    if (encoder_name.nil? and self.driver.metasploit_instance.datastore['ENCODER'])
      encoder_name = self.driver.metasploit_instance.datastore['ENCODER']
    end


    # Generate the payload
    begin
      buf = self.driver.metasploit_instance.generate_simple(
        'BadChars'    => badchars,
        'Encoder'     => encoder_name,
        'Format'      => type,
        'NopSledSize' => sled_size,
        'OptionStr'   => option_str,
        'ForceEncode' => force,
        'Template'    => template,
        'Platform'    => plat,
        'KeepTemplateWorking' => keep,
        'Iterations'  => iter)
    rescue
      log_error("Payload generation failed: #{$!}")
      return false
    end

    if(not ofile)
      # Display generated payload
      print(buf)
    else
      print_status("Writing #{buf.length} bytes to #{ofile}...")
      fd = File.open(ofile, "wb")
      fd.write(buf)
      fd.close
    end

    return true

  end

end
