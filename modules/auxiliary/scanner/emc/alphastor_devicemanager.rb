##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'           => 'EMC AlphaStor Device Manager Service',
      'Description'    => 'This module queries the remote host for the EMC Alphastor Device Management Service.',
      'Author'         => 'MC',
      'License'        => MSF_LICENSE
    )

    register_options([Opt::RPORT(3000),])
  end


  def run_host(ip)

    connect

    pkt = "\x68" + Rex::Text.rand_text_alphanumeric(5) + "\x00" * 512

    sock.put(pkt)

    select(nil,nil,nil,0.25)

    data = sock.get_once

    if ( data and data =~ /rrobotd:rrobotd/ )
        print_good("Host #{ip} is running the EMC AlphaStor Device Manager.")
        report_service(:host => rhost, :port => rport, :name => "emc-manager", :info => data)
    else
        print_error("Host #{ip} is not running the service...")
    end

    disconnect

  end
end
