# -*- coding: binary -*-
require 'rex/parser/arguments'

module Msf
module Ui
module Console
module CommandDispatcher

###
#
# NOP module command dispatcher.
#
###
class Nop

  include Msf::Ui::Console::ModuleCommandDispatcher

  @@generate_opts = Rex::Parser::Arguments.new(
    "-b" => [ true,  "The list of characters to avoid: '\\x00\\xff'"  ],
    "-h" => [ false, "Help banner."                                   ],
    "-s" => [ true,  "The comma separated list of registers to save." ],
    "-t" => [ true,  "The output type: ruby, perl, c, or raw."        ])

  #
  # Returns the hash of supported commands.
  #
  def commands
    super.update({
      "generate" => "Generates a NOP sled",
    })
  end

  #
  # Returns the name of the command dispatcher.
  #
  def name
    "Nop"
  end

  #
  # Generates a NOP sled.
  #
  def cmd_generate(*args)

    # No arguments?  Tell them how to use it.
    if (args.length == 0)
      args << "-h"
    end

    # Parse the arguments
    badchars = nil
    saveregs = nil
    type     = "ruby"
    length   = 200

    @@generate_opts.parse(args) { |opt, idx, val|
      case opt
        when nil
          length = val.to_i
        when '-b'
          badchars = Rex::Text.dehex(val)
when "-s", "-c"  # 'c' is deprecated; remove later
  saveregs = val.split(/,\s?/)
          saveregs = val.split(/,\s?/)
        when '-t'
          type = val
        when '-h'
          print(
            "Usage: generate [options] length\n\n" +
            "Generates a NOP sled of a given length.\n" +
            @@generate_opts.usage)
          return false
      end
    }

    # Generate the sled
    begin
      sled = mod.generate_simple(
        length,
        'BadChars'      => badchars,
        'SaveRegisters' => saveregs,
        'Format'        => type)
    rescue
      log_error("Sled generation failed: #{$!}.")
      return false
    end

    # Display generated sled
    print(sled)

    return true
  end

end

end end end end
