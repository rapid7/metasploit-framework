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
      'Name'        => 'Enum Environment Perfd Daemon',
      'Description' => %q{
        Enum Environment Perfd Daemon.
        Commands: "u" Disks Share, "i" Disk space, "p" Process list, "a" Core CPU info, "g" Server status, "l" Network Interface (statistics in/out), "T" Scope transactions, "A" Others infos, "q" and "Q" => exit.
        },
      'Author'      => [ 'Roberto Soares Espreto <robertoespreto[at]gmail.com>' ],
      'License'     => MSF_LICENSE
    )

    register_options(
    [
      Opt::RPORT(5227),
      OptString.new("CMD", [true, 'Command to execute', 'p'])
    ], self.class)
  end

  def run_host(target_host)
    begin
        cmd = datastore['CMD']

        connect
        sock.put("\n"+cmd+"\n")
        select(nil,nil,nil,0.5)
        resp = sock.get_once

        if (resp and resp =~ /Welcome/)
          print_status("#{target_host}:#{rport}, Perfd server banner: #{resp}")
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
