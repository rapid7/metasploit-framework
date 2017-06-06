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
    all = {
      "window_enum" => "Enumerate all current open windows"
    }
    reqs = {
      "window_enum" => [ "extapi_window_enum" ],
    }
    filter_commands(all, reqs)
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

  def window_enum_usage
    print(
      "\nUsage: window_enum [-h] [-p parent_window] [-u]\n\n" +
      "Enumerate the windows on the target.\n\n" +
      "Enumeration returns the Process ID and Window Handle for each window\n" +
      "found. The Window Handle can be used for further calls to window_enum\n" +
      "or the railgun API.\n" +
      @@window_enum_opts.usage +
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
          window_enum_usage
          return true
        end
      when "-h"
        window_enum_usage
        return true
      end
    }

    windows = client.extapi.window.enumerate(include_unknown, parent_window)

    header = parent_window ? "Child windows of #{parent_window}" : "Top-level windows"

    table = Rex::Text::Table.new(
      'Header'    => header,
      'Indent'    => 0,
      'SortIndex' => 0,
      'Columns'   => [
        'PID', 'Handle', 'Title'
      ]
    )

    windows.each { |w|
      table << [w[:pid], w[:handle], w[:title]]
    }

    print_line
    print_line(table.to_s)

    if parent_window.nil?
      print_line("Total top-level Windows: #{windows.length}")
    else
      print_line("Total child Windows: #{windows.length}")
    end

    print_line

    return true
  end

end

end
end
end
end

