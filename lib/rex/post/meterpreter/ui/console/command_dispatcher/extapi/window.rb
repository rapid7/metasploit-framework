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
    "-h" => [ false, "Help banner" ],
    "-p" => [ true,  "Parent window handle, used to enumerate child windows" ],
    "-u" => [ false, "Include unknown/untitled windows in the result set" ]
  )

  def print_usage()
    print(
      "\nUsage: window_enum [-h] [-p parent_window] [-u]\n\n" +
      "Enumerate the windows on the target.\n\n" +
      "Enumeration returns the Process ID and Window Handle for each window\n" +
      "found. The Window Handle can be used for further calls to window_enum\n" +
      "or the the railgun API.\n\n" +
      "-p parent_window : specifies the parent window whose children are to\n" +
      "                   enumerated. All top-level windows are enumerated if\n" +
      "                   if this value is not given.\n" +
      "-u : include untitled/unknown windows in the result set.\n\n" +
      "Note: Not all windows can be enumerated. An attempt to enumerate\n" +
      "      the children of such a window will result in a failure with the\n"+
      "      message \"Operation failed: The parameter is incorrect.\"\n\n")
  end

  #
  # Enumerate top-level windows.
  #
  def cmd_window_enum(*args)
    parent_window = nil
    include_unknown = false

    @@window_enum_opts.parse(args) { |opt, idx, val|
      case opt
        when "-u"
          include_unknown = true
        when "-p"
          parent_window = val.to_i
          if parent_window == 0
            print_usage
            return true
          end
        when "-h"
          print_usage
          return true
      end
    }

    windows = client.extapi.window.window_enum(include_unknown, parent_window)

    print_line()
    if not parent_window.nil?
      print_line("Listing child windows of #{parent_window}")
      print_line()
    end
    print_line("     PID |     Handle | Window title")
    print_line("---------+------------+--------------------------------------")

    windows.each do |w|
      print_line(sprintf("%8d | %10d | %s", w[:pid], w[:handle], w[:title]))
    end
    print_line()

    if parent_window.nil?
      print_line("Total top-level Windows: #{windows.length}")
    else
      print_line("Total child Windows: #{windows.length}")
    end
    print_line()

    return true
  end

end

end
end
end
end

