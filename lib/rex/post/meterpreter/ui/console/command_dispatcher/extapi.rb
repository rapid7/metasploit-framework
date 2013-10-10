# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Extended API user interface.
#
###
class Console::CommandDispatcher::Extapi

  Klass = Console::CommandDispatcher::Extapi

  include Console::CommandDispatcher

  #
  # Initializes an instance of the extended API command interaction.
  #
  def initialize(shell)
    super
  end

  #
  # Options for the window_enum command.
  #
  @@window_enum_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ]
  )

  #
  # Options for the service_enum command.
  #
  @@service_enum_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ]
  )

  #
  # List of supported commands.
  #
  def commands
    {
      "window_enum" => "Enumerate all current open windows",
      "service_enum" => "Enumerate all registered Windows services"
    }
  end


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

    windows = client.extapi.window_enum()

    print_line()
    print_line("     PID |     Handle | Window title")
    print_line("-------------------------------------------------------------")

    windows.each do |w|
      print_line(sprintf("%8d | %10d | %s", w[:pid], w[:handle], w[:title]))
    end

    print_line()
    print_line("Total top-level Windows: #{windows.length}")
    print_line()

    return true
  end

  def cmd_service_enum(*args)
    @@service_enum_opts.parse(args) { |opt, idx, val|
      case opt
        when "-h"
          print(
            "\nUsage: service_enum [-h]\n\n" +
            "Enumerate services installed on the target.\n\n" +
            "Enumeration returns the Process ID, Status, and name of each installed\n" +
            "service that is discovered. The 'Int?' value indicates if the service is\n" +
            "able to interact with the desktop.\n\n")
            return true
      end
    }

    status_map = {
      1 => "STOPPED",
      2 => "STRT_PEN",
      3 => "STOP_PEN",
      4 => "RUNNING",
      5 => "CONT_PEN",
      6 => "PAUS_PEN",
      7 => "PAUSED"
    }

    services = client.extapi.service_enum()

    print_line()
    print_line(" Int? |      PID | Status   | Name (Display Name)")
    print_line("-------------------------------------------------------------")

    services.each do |s|
      print_line(sprintf("%5s | %8d | %8s | %s (%s)",
                         s[:interactive] ? "Yes" : "No",
                         s[:pid], status_map[s[:status]],
                         s[:name], s[:display]))
    end

    print_line()
    print_line("Total services: #{services.length}")
    print_line()

    return true
  end

  #
  # Name for this dispatcher
  #
  def name
    "Extapi"
  end

end

end
end
end
end
