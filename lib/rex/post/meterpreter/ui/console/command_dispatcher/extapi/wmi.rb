# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Extended API WMI Querying interface.
#
###
class Console::CommandDispatcher::Extapi::Wmi

  Klass = Console::CommandDispatcher::Extapi::Wmi

  include Console::CommandDispatcher

  # Zero indicates "no limit"
  DEFAULT_MAX_RESULTS = 0
  DEFAULT_PAGE_SIZE   = 0

  #
  # List of supported commands.
  #
  def commands
    {
      "wmi_query" => "Perform a generic WMI query and return the results"
    }
  end

  #
  # Name for this dispatcher
  #
  def name
    "Extapi: WMI Querying"
  end

  #
  # Options for the wmi_query command.
  #
  @@wmi_query_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ],
    "-d" => [ true, "Specify a domain (defaults to 'CIMV2')" ]
  )

  def wmi_query_usage
    print(
      "\nUsage: wmi_query <query string> [-d domain]\n\n" +
      "Query the target and display the results.\n\n" +
      @@wmi_query_opts.usage)
  end

  #
  # Enumerate domain objects.
  #
  def cmd_wmi_query(*args)
    args.unshift("-h") if args.length < 1

    domain = nil

    @@wmi_query_opts.parse(args) { |opt, idx, val|
      case opt
      when "-d"
        domain = val
      when "-h"
        wmi_query_usage
        return true
      end
    }

    query = args.shift

    objects = client.extapi.wmi.query(query, domain)

    table = Rex::Ui::Text::Table.new(
      'Header'    => query,
      'Indent'    => 0,
      'SortIndex' => 0,
      'Columns'   => objects[:fields]
    )

    objects[:values].each do |c|
      table << c
    end

    print_line
    print_line(table.to_s)

    print_line("Total objects: #{objects[:results].length}")

    print_line

    return true
  end

end

end
end
end
end

