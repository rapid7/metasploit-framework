##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(
      info,
      'Name' => "Allegro Software RomPager 'Misfortune Cookie' (CVE-2014-9222) Scanner",
      'Description' => %q(
        This module scans for HTTP servers that appear to be vulnerable to the
        'Misfortune Cookie' vulnerability which affects Allegro Software
        Rompager versions before 4.34 and can allow attackers to authenticate
        to the HTTP service as an administrator without providing valid
        credentials.
      ),
      'Author' => [
        'Jon Hart <jon_hart[at]rapid7.com>', # metasploit module
        'Lior Oppenheim' # CVE-2014-9222
      ],
      'References' => [
        ['CVE', '2014-9222'],
        ['URL', 'http://mis.fortunecook.ie']
      ],
      'DisclosureDate' => 'Dec 17 2014',
      'License' => MSF_LICENSE
    ))

    register_options([
      OptString.new('TARGETURI', [true, 'Path to fingerprint RomPager from', '/Allegro'])
    ], self.class)
  end

  def check_host(ip)
    res = send_request_cgi('uri' => normalize_uri(target_uri.path.to_s), 'method' => 'GET')
    fp = http_fingerprint(response: res)
    if /RomPager\/(?<version>[\d\.]+)$/ =~ fp
      if Gem::Version.new(version) < Gem::Version.new('4.34')
        report_vuln(
          host: ip,
          port: rport,
          name: name,
          refs: references
        )
        return Exploit::CheckCode::Appears
      else
        return Exploit::CheckCode::Detected
      end
    else
      return Exploit::CheckCode::Safe
    end
  end

  def run_host(ip)
    print_good("#{peer} appears to be vulnerable") if check_host(ip) == Exploit::CheckCode::Appears
  end
end
