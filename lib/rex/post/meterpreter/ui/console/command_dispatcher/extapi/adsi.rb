# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Extended API ADSI management user interface.
#
###
class Console::CommandDispatcher::Extapi::Adsi

  Klass = Console::CommandDispatcher::Extapi::Adsi

  include Console::CommandDispatcher

  # Zero indicates "no limit"
  DEFAULT_MAX_RESULTS = 0
  DEFAULT_PAGE_SIZE   = 0

  #
  # List of supported commands.
  #
  def commands
    {
      "adsi_user_enum"     => "Enumerate all users on the specified domain.",
      "adsi_computer_enum" => "Enumerate all computers on the specified domain.",
      "adsi_domain_query"  => "Enumerate all objects on the specified domain that match a filter."
    }
  end

  #
  # Name for this dispatcher
  #
  def name
    "Extapi: ADSI Management"
  end

  #
  # Options for the adsi_user_enum command.
  #
  @@adsi_user_enum_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ],
    "-m" => [ true, "Maximum results to return." ],
    "-p" => [ true, "Result set page size." ]
  )

  def adsi_user_enum_usage
    print(
      "\nUsage: adsi_user_enum <domain> [-h] [-m maxresults] [-p pagesize]\n\n" +
      "Enumerate the users on the target domain.\n\n" +
      "Enumeration returns information such as the user name, SAM account name, locked\n" +
      "status, desc, and comment.\n" +
      @@adsi_user_enum_opts.usage)
  end

  #
  # Enumerate domain users.
  #
  def cmd_adsi_user_enum(*args)
    args.unshift("-h") if args.length == 0
    if args.include?("-h")
      adsi_user_enum_usage
      return true
    end

    domain = args.shift
    filter = "(objectClass=user)"
    fields = [
      "samaccountname",
      "name",
      "distinguishedname",
      "description",
      "comment"
      ]
    args = [domain, filter] + fields + args
    return cmd_adsi_domain_query(*args)
  end

  #
  # Options for the adsi_computer_enum command.
  #
  @@adsi_computer_enum_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ],
    "-m" => [ true, "Maximum results to return." ],
    "-p" => [ true, "Result set page size." ]
  )

  def adsi_computer_enum_usage
    print(
      "\nUsage: adsi_computer_enum <domain> [-h] [-m maxresults] [-p pagesize]\n\n" +
      "Enumerate the computers on the target domain.\n\n" +
      "Enumeration returns information such as the computer name, desc, and comment.\n" +
      @@adsi_computer_enum_opts.usage)
  end

  #
  # Enumerate domain computers.
  #
  def cmd_adsi_computer_enum(*args)
    args.unshift("-h") if args.length == 0
    if args.include?("-h")
      adsi_computer_enum_usage
      return true
    end

    domain = args.shift
    filter = "(objectClass=computer)"
    fields = [
      "name",
      "distinguishedname",
      "description",
      "comment"
      ]
    args = [domain, filter] + fields + args
    return cmd_adsi_domain_query(*args)
  end

  #
  # Options for the adsi_domain_query command.
  #
  @@adsi_domain_query_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ],
    "-m" => [ true, "Maximum results to return." ],
    "-p" => [ true, "Result set page size." ]
  )

  def adsi_domain_query_usage
    print(
      "\nUsage: adsi_domain_query <domain> <filter> <field 1> [field 2 [field ..]] [-h] [-m maxresults] [-p pagesize]\n\n" +
      "Enumerate the objects on the target domain.\n\n" +
      "Enumeration returns the set of fields that are specified.\n" +
      @@adsi_domain_query_opts.usage)
  end

  #
  # Enumerate domain objects.
  #
  def cmd_adsi_domain_query(*args)
    page_size = DEFAULT_PAGE_SIZE
    max_results = DEFAULT_MAX_RESULTS

    args.unshift("-h") if args.length < 3

    @@adsi_domain_query_opts.parse(args) { |opt, idx, val|
      case opt
      when "-s"
        page_size = val.to_i
      when "-m"
        max_results = val.to_i
      when "-h"
        adsi_domain_query_usage
        return true
      end
    }

    # Assume that the flags are passed in at the end. Safe?
    switch_index = args.index { |a| a.start_with?("-") }
    if switch_index
      args = args.first(switch_index)
    end

    domain = args.shift
    filter = args.shift

    objects = client.extapi.adsi.domain_query(domain, filter, max_results, page_size, args)

    table = Rex::Ui::Text::Table.new(
      'Header'    => "#{domain} Objects",
      'Indent'    => 0,
      'SortIndex' => 0,
      'Columns'   => objects[:fields]
    )

    objects[:results].each do |c|
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

