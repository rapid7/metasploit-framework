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

  #
  # List of supported commands.
  #
  def commands
    {
      "adsi_user_enum" => "Enumerate all users on the specified domain.",
      "adsi_computer_enum" => "Enumerate all computers on the specified domain."
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
    "-h" => [ false, "Help banner" ]
  )

  def adsi_user_enum_usage
    print(
      "\nUsage: adsi_user_enum <domain> [-h]\n\n" +
      "Enumerate the users on the target domain.\n\n" +
      "Enumeration returns information such as the user name, SAM account name, locked\n" +
      "status, desc, and comment.\n" +
      @@adsi_user_enum_opts.usage)
  end

  #
  # Enumerate domain users.
  #
  def cmd_adsi_user_enum(*args)
    parent_window = nil
    include_unknown = false

    args.unshift("-h") if args.length == 0

    @@adsi_user_enum_opts.parse(args) { |opt, idx, val|
      case opt
      when "-h"
        adsi_user_enum_usage
        return true
      end
    }

    domain = args.shift

    users = client.extapi.adsi.user_enumerate(domain)

    table = Rex::Ui::Text::Table.new(
      'Header'    => "#{domain} Users",
      'Indent'    => 0,
      'SortIndex' => 0,
      'Columns'   => users[:fields]
    )

    users[:results].each do |u|
      table << u
    end

    print_line
    print_line(table.to_s)

    print_line("Total users: #{users.length}")

    print_line

    return true
  end

  #
  # Options for the adsi_computer_enum command.
  #
  @@adsi_computer_enum_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ]
  )

  def adsi_computer_enum_usage
    print(
      "\nUsage: adsi_computer_enum <domain> [-h]\n\n" +
      "Enumerate the computers on the target domain.\n\n" +
      "Enumeration returns information such as the computer name, desc, and comment.\n" +
      @@adsi_computer_enum_opts.usage)
  end

  #
  # Enumerate domain computers.
  #
  def cmd_adsi_computer_enum(*args)
    parent_window = nil
    include_unknown = false

    args.unshift("-h") if args.length == 0

    @@adsi_computer_enum_opts.parse(args) { |opt, idx, val|
      case opt
      when "-h"
        adsi_computer_enum_usage
        return true
      end
    }

    domain = args.shift

    computers = client.extapi.adsi.computer_enumerate(domain)

    table = Rex::Ui::Text::Table.new(
      'Header'    => "#{domain} Computers",
      'Indent'    => 0,
      'SortIndex' => 0,
      'Columns'   => computers[:fields]
    )

    computers[:results].each do |c|
      table << c
    end

    print_line
    print_line(table.to_s)

    print_line("Total computers: #{computers.length}")

    print_line

    return true
  end

end

end
end
end
end

