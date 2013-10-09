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
  # List of supported commands.
  #
  def commands
    {
      "window_enum" => "Enumerate all current open windows"
    }
  end


  def cmd_window_enum(*args)

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
