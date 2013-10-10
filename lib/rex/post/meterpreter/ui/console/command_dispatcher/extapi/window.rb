# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Extended API window management user interface.
#
###
class Console::CommandDispatcher::Extapi::Window

  Klass = Console::CommandDispatcher::Extapi::Window

  include Console::CommandDispatcher

  #
  # List of supported commands.
  #
  def commands
    {
      "window_enum" => "Enumerate all current open windows"
    }
  end

  #
  # Name for this dispatcher
  #
  def name
    "Extapi: Window Management"
  end

  #
  # Options for the window_enum command.
  #
  @@window_enum_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ]
  )

  #
  # Enumerate top-level windows.
  #
  def cmd_window_enum(*args)

    @@window_enum_opts.parse(args) { |opt, idx, val|
      case opt
        when "-h"
          print(
            "\nUsage: window_enum [-h]\n\n" +
            "Enumerate the top-level windows on the current desktop.\n\n" +
            "Enumeration returns the Process ID and Window Handle for each top-level\n" +
            "window found. The Window Handle can be used for further calls to the\n" +
            "railgun API.\n\n")
            return true
      end
    }

    windows = client.extapi.window.window_enum()

    print_line()
    print_line("     PID |     Handle | Window title")
    print_line("---------+------------+--------------------------------------")

    windows.each do |w|
      print_line(sprintf("%8d | %10d | %s", w[:pid], w[:handle], w[:title]))
    end

    print_line()
    print_line("Total top-level Windows: #{windows.length}")
    print_line()

    return true
  end

end

end
end
end
end

