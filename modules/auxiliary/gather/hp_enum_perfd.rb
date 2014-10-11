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
        sock.put("\n#{cmd}\n")
        Rex.sleep(1)
        resp = sock.get_once

        if (resp && resp =~ /Welcome/)
          print_good("#{target_host}:#{rport}, Perfd server banner: #{resp}")
          report_service(:host => rhost, :port => rport, :name => "perfd", :proto => "tcp", :info => resp)
        else
          print_error("#{target_host}:#{rport}, Perfd server banner detection failed!")
        end
        disconnect

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => e
    rescue Timeout::Error => e
      print_error(e.message)
    end
  end
end
