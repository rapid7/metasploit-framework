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
      'Name'           => 'EMC AlphaStor Library Manager Service',
      'Description'    => 'This module queries the remote host for the EMC Alphastor Library Management Service.',
      'Author'         => 'MC',
      'License'        => MSF_LICENSE
    )

    register_options([Opt::RPORT(3500),])
  end


  def run_host(ip)

    connect

    pkt = "\x51" + "\x00" * 529

    sock.put(pkt)

    select(nil,nil,nil,1)

    data = sock.get_once

    if ( data and data =~ /robotd~robotd~CLIENT/ )
        print_good("Host #{ip} is running the EMC AlphaStor Library Manager.")
        report_service(:host => rhost, :port => rport, :name => "emc-library", :info => data)
    else
        print_error("Host #{ip} is not running the service...")
    end

    disconnect

  end
end
