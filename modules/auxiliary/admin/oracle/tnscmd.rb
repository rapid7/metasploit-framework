##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::TNS

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Oracle TNS Listener Command Issuer',
        'Description' => %q{
          This module allows for the sending of arbitrary TNS commands in order
          to gather information.
          Inspired from tnscmd.pl from www.jammed.com/~jwa/hacks/security/tnscmd/tnscmd
        },
        'Author' => ['MC'],
        'License' => MSF_LICENSE,
        'DisclosureDate' => '2009-02-01',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(1521),
        OptString.new('CMD', [ false, 'Something like ping, version, status, etc..', '(CONNECT_DATA=(COMMAND=VERSION))']),
      ]
    )
  end

  def run
    begin
      connect

      command = datastore['CMD']

      pkt = tns_packet(command)

      print_status("Sending '#{command}' to #{rhost}:#{rport}")
      sock.put(pkt)
      print_status("writing #{pkt.length} bytes.")

      select(nil, nil, nil, 0.5)

      print_status('reading')
      res = sock.get_once(-1, 5) || ''
      res = res.tr("[\200-\377]", "[\000-\177]")
      res = res.tr("[\000-\027\]", '.')
      res = res.tr("\177", '.')
      print_status(res)

      disconnect
    end
  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout => e
    print_error e.message
  rescue ::Timeout::Error, ::Errno::EPIPE, Errno::ECONNRESET => e
    print_error e.message
  end
end
