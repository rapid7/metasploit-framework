# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# The TFTP portion of the lanattacks extension.
#
###
class Console::CommandDispatcher::Lanattacks::Tftp

  Klass = Console::CommandDispatcher::Lanattacks::Tftp

  include Console::CommandDispatcher

  #
  # List of supported commands.
  #
  def commands
    all = {
      "tftp_start"    => "Start the TFTP server",
      "tftp_stop"     => "Stop the TFTP server",
      "tftp_reset"    => "Reset the TFTP server",
      "tftp_add_file" => "Add a file to the TFTP server"
    }

    reqs = {
      "tftp_start"    => [ "lanattacks_start_tftp" ],
      "tftp_stop"     => [ "lanattacks_stop_tftp" ],
      "tftp_reset"    => [ "lanattacks_reset_tftp" ],
      "tftp_add_file" => [ "lanattacks_add_tftp_file" ],
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
    "Lanattacks: TFTP"
  end

  @@tftp_start_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner." ])

  def print_tftp_start_usage
    print("tftp_start [-h]\n\n" +
          "Starts a TFTP server in the current Meterpreter session.\n" +
          @@tftp_start_opts.usage + "\n")
  end

  def cmd_tftp_start(*args)
    @@tftp_start_opts.parse(args) { |opt, idx, val|
      case opt
      when '-h'
        print_tftp_start_usage
        return true
      end
    }

    print_status( "Starting TFTP server ..." )
    client.lanattacks.tftp.start
    print_good( "TFTP server startd." )
  end

  @@tftp_stop_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner." ])

  def print_tftp_stop_usage
    print("tftp_stop [-h]\n\n" +
          "Stops the currently running TFTP server.\n" +
          @@tftp_stop_opts.usage + "\n")
  end

  def cmd_tftp_stop(*args)
    @@tftp_stop_opts.parse(args) { |opt, idx, val|
      case opt
      when '-h'
        print_tftp_stop_usage
        return true
      end
    }

    print_status( "Stopping TFTP server ..." )
    client.lanattacks.tftp.stop
    print_good( "TFTP server stopped." )
  end

  @@tftp_reset_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner." ])

  def print_tftp_reset_usage
    print("tftp_reset [-h]\n\n" +
          "Resets the currently running TFTP server.\n" +
          @@tftp_reset_opts.usage + "\n")
  end

  def cmd_tftp_reset(*args)
    @@tftp_reset_opts.parse(args) { |opt, idx, val|
      case opt
      when '-h'
        print_tftp_reset_usage
        return true
      end
    }

    print_status( "Resetting TFTP server ..." )
    client.lanattacks.tftp.reset
    print_good( "TFTP server reset." )
  end

  @@tftp_add_file_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner." ])

  def print_tftp_add_file_usage
    print("tftp_add_file <file> [-h]\n\n" +
          "Add a file to the currently running TFTP server.\n" +
          @@tftp_add_file_opts.usage + "\n")
  end

  def cmd_tftp_add_file(*args)
    @@tftp_add_file_opts.parse(args) { |opt, idx, val|
      case opt
      when '-h'
        print_tftp_add_file_usage
        return true
      end
    }

    name = args.shift

    print_status( "Adding file #{name} ..." )
    client.lanattacks.tftp.add_file(name, ::File.read(name))
    print_good( "File added." )
  end

end

end
end
end
end

