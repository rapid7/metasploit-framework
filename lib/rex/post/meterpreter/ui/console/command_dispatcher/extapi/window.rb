# -*- coding: binary -*-

require 'rex/post/meterpreter'
require 'rex/post/meterpreter/extensions/extapi/command_ids'

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
  include Rex::Post::Meterpreter::Extensions::Extapi

  #
  # List of supported commands.
  #
  def commands
    all = {
      'window_enum' => 'Enumerate all current open windows'
    }
    reqs = {
      'window_enum' => [COMMAND_ID_EXTAPI_WINDOW_ENUM]
    }
    filter_commands(all, reqs)
  end

  #
  # Name for this dispatcher
  #
  def name
    'Extapi: Window Management'
  end

  #
  # Options for the window_enum command.
  #
  @@window_enum_opts = Rex::Parser::Arguments.new(
    '-h' => [ false, 'Help banner' ],
    '-p' => [ true, 'Parent window handle, used to enumerate child windows' ],
    '-u' => [ false, 'Include unknown/untitled windows in the result set' ],
    '-c' => [ true, 'Specify the window class name to display. e.g. Edit,Button etc.' ]
  )

  def window_enum_usage
    print(
      "\nUsage: window_enum [-h] [-p parent_window] [-u]\n\n" \
      "Enumerate the windows on the target.\n\n" \
      "Enumeration returns the Process ID and Window Handle for each window\n" \
      "found. The Window Handle can be used for further calls to window_enum\n" \
      "or the railgun API.\n" +
      @@window_enum_opts.usage +
      "Note: Not all windows can be enumerated. An attempt to enumerate\n" \
      "      the children of such a window will result in a failure with the\n" \
      "      message \"Operation failed: The parameter is incorrect.\"\n"\
      "      Enumerable maximum text length is 256.\n\n"
    )
  end

  #
  # Enumerate top-level windows.
  #
  def cmd_window_enum(*args)
    parent_window = nil
    include_unknown = false
    window_class_name = nil

    @@window_enum_opts.parse(args) do |opt, _idx, val|
      case opt
      when '-u'
        include_unknown = true
      when '-p'
        parent_window = val.to_i
        if parent_window == 0
          window_enum_usage
          return true
        end
      when '-h'
        window_enum_usage
        return true
      when '-c'
        window_class_name = val.to_s
        if window_class_name == ''
          window_enum_usage
          return true
        end
      end
    end

    windows = client.extapi.window.enumerate(include_unknown, parent_window)

    header = parent_window ? "Child windows of #{parent_window}" : 'Top-level windows'
    columns = [ 'PID', 'Handle', 'ClassName', 'Title']
    table = Rex::Text::Table.new(
      'Header' => header,
      'Indent' => 0,
      'SortIndex' => columns.index('Handle'),
      'Columns' => columns
    )

    windows.each do |w|
      if window_class_name.nil?
        table << [w[:pid], w[:handle], w[:class_name], w[:title]]
      elsif (w[:class_name] == window_class_name)
        table << [w[:pid], w[:handle], w[:class_name], w[:title]]
      else
        next
      end
    end

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
