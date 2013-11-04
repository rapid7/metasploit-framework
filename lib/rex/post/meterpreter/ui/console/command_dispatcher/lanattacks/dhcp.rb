# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# The DHCP portion of the lanattacks extension.
#
###
class Console::CommandDispatcher::Lanattacks::Dhcp

  Klass = Console::CommandDispatcher::Lanattacks::Dhcp

  include Console::CommandDispatcher

  #
  # List of supported commands.
  #
  def commands
    all = {
      "dhcp_start"        => "Start the DHCP server",
      "dhcp_stop"         => "Stop the DHCP server",
      "dhcp_reset"        => "Reset the DHCP server",
      "dhcp_set_option"   => "Set a DHCP server option",
      "dhcp_load_options" => "Load DHCP optionis from a datastore",
      "dhcp_log"          => "Log DHCP server activity"
    }

    reqs = {
      "dhcp_start"        => [ "lanattacks_start_dhcp" ],
      "dhcp_stop"         => [ "lanattacks_stop_dhcp" ],
      "dhcp_reset"        => [ "lanattacks_reset_dhcp" ],
      "dhcp_set_option"   => [ "lanattacks_set_dhcp_option" ],
      "dhcp_load_options" => [ "lanattacks_set_dhcp_option" ],
      "dhcp_log"          => [ "lanattacks_dhcp_log" ]
    }

    all.delete_if do |cmd, desc|
      del = false
      reqs[cmd].each do |req|
        next if client.commands.include? req
        del = true
        break
      end

      del
    end

    all
  end

  #
  # Name for this dispatcher.
  #
  def name
    "Lanattacks: DHCP"
  end

  @@dhcp_start_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner." ])

  def print_dhcp_start_usage
    print("dhcp_start [-h]\n\n" +
          "Starts a DHCP server in the current Meterpreter session.\n" +
          @@dhcp_start_opts.usage + "\n")
  end

  def cmd_dhcp_start(*args)
    @@dhcp_start_opts.parse(args) { |opt, idx, val|
      case opt
      when '-h'
        print_dhcp_start_usage
        return true
      end
    }

    print_status( "Starting DHCP server ...")
    client.lanattacks.dhcp.start
    print_good( "DHCP server startd.")
  end

  @@dhcp_stop_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner." ])

  def print_dhcp_stop_usage
    print("dhcp_stop [-h]\n\n" +
          "Stops the currently running DHCP server.\n" +
          @@dhcp_stop_opts.usage + "\n")
  end

  def cmd_dhcp_stop(*args)
    @@dhcp_stop_opts.parse(args) { |opt, idx, val|
      case opt
      when '-h'
        print_dhcp_stop_usage
        return true
      end
    }

    print_status( "Stopping DHCP server ...")
    client.lanattacks.dhcp.stop
    print_good( "DHCP server stopped.")
  end

  @@dhcp_reset_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner." ])

  def print_dhcp_reset_usage
    print("dhcp_reset [-h]\n\n" +
          "Resets the currently running DHCP server.\n" +
          @@dhcp_reset_opts.usage + "\n")
  end

  def cmd_dhcp_reset(*args)
    @@dhcp_reset_opts.parse(args) { |opt, idx, val|
      case opt
      when '-h'
        print_dhcp_reset_usage
        return true
      end
    }

    print_status( "Resetting DHCP server ...")
    client.lanattacks.dhcp.reset
    print_good( "DHCP server reset.")
  end

  @@dhcp_set_option_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner." ])

  @@dhcp_set_option_valid_options = [
    "BROADCAST", "DHCPIPEND", "DHCPIPSTART", "DNSSERVER",
    "FILENAME", "HOSTNAME", "HOSTSTART", "NETMASK",
    "PXE", "PXECONF", "ROUTER", "SERVEONCE", "SRVHOST"
  ]

  def print_dhcp_set_option_usage
    print("dhcp_set_option <name> <value> [-h]\n\n" +
          "Set a DHCP server option.\n\n" +
          "Valid names are:\n" +
          @@dhcp_set_option_valid_options.map {|o| "  - #{o}\n" }.join('') +
          @@dhcp_set_option_opts.usage + "\n")
  end

  def cmd_dhcp_set_option(*args)
    @@dhcp_set_option_opts.parse(args) { |opt, idx, val|
      case opt
      when '-h'
        print_dhcp_set_option_usage
        return true
      end
    }

    if args.length < 2
      print_dhcp_set_option_usage
      return true
    end


    name = args.shift.upcase
    value = args.shift

    if not @@dhcp_set_option_valid_options.include? name
      print_error( "Invalid option name '#{name}'." )
      return true
    end

    client.lanattacks.dhcp.set_option(name, value)
  end

  @@dhcp_load_options_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner." ])

  def print_dhcp_load_options_usage
    print("dhcp_load_options <datastore> [-h]\n\n" +
          "Load settings from a datstore to the active DHCP server.\n\n" +
          "The datastore must be a hash of name/value pairs.\n" +
          "Valid names are:\n" +
          @@dhcp_set_option_valid_options.map {|o| "  - #{o}\n" }.join('') +
          @@dhcp_set_option_opts.usage + "\n")
  end

  def cmd_dhcp_load_options(*args)
    @@dhcp_set_option_opts.parse(args) { |opt, idx, val|
      case opt
      when '-h'
        print_dhcp_set_option_usage
        return true
      end
    }

    if args.length < 1
      print_dhcp_load_options_usage
      return true
    end

    datastore = args.shift

    if not datastore.is_a?(Hash)
      print_dhcp_load_options_usage
      return true
    end

    client.lanattacks.dhcp.load_options(datastore)
  end

  @@dhcp_log_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner." ])

  def print_dhcp_log_usage
    print("dhcp_log [-h]\n\n" +
          "Logs the DHCP operations captured by the DHCP server.\n" +
          @@dhcp_log_opts.usage + "\n")
  end

  def cmd_dhcp_log(*args)
    @@dhcp_log_opts.parse(args) { |opt, idx, val|
      case opt
      when '-h'
        print_dhcp_log_usage
        return true
      end
    }

    log = client.lanattacks.dhcp.log

    table = Rex::Ui::Text::Table.new(
      'Header'    => 'DHCP Server Log',
      'Indent'    => 0,
      'SortIndex' => 0,
      'Columns'   => [ 'MAC Address', 'IP Address' ]
    )

    log.each { |l|
      table << [ l[:mac], l[:ip] ]
    }

    print_line
    print_line( table.to_s )
    print_line( "Total log entries: #{log.length}" )
    print_line
  end

end

end
end
end
end

