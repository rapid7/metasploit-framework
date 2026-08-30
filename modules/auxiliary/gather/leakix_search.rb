##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  LEAKIX_API_HOST = 'leakix.net'.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'LeakIX Search',
        'Description' => %q{
          This module uses the LeakIX API to search for exposed services and data leaks.
          LeakIX is a search engine focused on indexing internet-exposed services and
          leaked credentials/databases.

          An API key is required (free at https://leakix.net).

          Actions:
          SEARCH     - Query LeakIX with a search string and scope (leak or service).
          Paginated, 20 results per page, max 500 pages (10000 results).
          Free accounts have lower page limits.
          HOST       - Retrieve all known services and leaks for a given IP
          DOMAIN     - Retrieve all known services and leaks for a given domain
          SUBDOMAINS - List known subdomains for a given domain
          PLUGINS    - List all available LeakIX scanner plugins
          BULK       - Stream all leak results via the bulk API (Pro only, leak scope only).
          Use MAXRESULTS to limit the number of collected events.

          Query examples:
          +country:"France"
          +port:3306 +country:"Germany"
          plugin:HttpOpenProxy
          +software.name:"nginx" +country:"US"
        },
        'Author' => [
          'Valentin Lobstein <chocapikk[at]leakix.net>',
          'LeakIX <support[at]leakix.net>'
        ],
        'References' => [
          ['URL', 'https://leakix.net'],
          ['URL', 'https://docs.leakix.net']
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        },
        'Actions' => [
          ['SEARCH', { 'Description' => 'Search LeakIX for services or leaks' }],
          ['HOST', { 'Description' => 'Get details for a specific IP address' }],
          ['DOMAIN', { 'Description' => 'Get details for a specific domain' }],
          ['SUBDOMAINS', { 'Description' => 'List subdomains for a domain' }],
          ['PLUGINS', { 'Description' => 'List available LeakIX plugins' }],
          ['BULK', { 'Description' => 'Bulk search via streaming API (Pro only, leak scope only)' }]
        ],
        'DefaultAction' => 'SEARCH'
      )
    )

    register_options([
      OptString.new('LEAKIX_APIKEY', [true, 'The LeakIX API key']),
      OptString.new('QUERY', [false, 'The LeakIX search query'], conditions: ['ACTION', 'in', %w[SEARCH BULK]]),
      OptEnum.new('SCOPE', [true, 'Search scope (BULK only supports leak)', 'leak', ['leak', 'service']], conditions: ['ACTION', 'in', %w[SEARCH BULK]]),
      OptInt.new('MAXPAGE', [true, 'Max pages to collect (1-500, 20 results/page)', 1], conditions: %w[ACTION == SEARCH]),
      OptInt.new('MAXRESULTS', [false, 'Stop after collecting this many results (0 = unlimited)', 0], conditions: ['ACTION', 'in', %w[SEARCH BULK]]),
      OptString.new('TARGET_IP', [false, 'Target IP for HOST action'], conditions: %w[ACTION == HOST]),
      OptString.new('TARGET_DOMAIN', [false, 'Target domain for DOMAIN/SUBDOMAINS actions'], conditions: ['ACTION', 'in', %w[DOMAIN SUBDOMAINS]]),
      OptString.new('OUTFILE', [false, 'Path to the file to store results']),
      OptBool.new('DATABASE', [false, 'Add search results to the database', false])
    ])

    register_advanced_options([
      OptString.new('UserAgent', [false, 'The User-Agent header to use for all requests', 'LeakIX/Metasploit'])
    ])

    deregister_http_client_options
  end

  # ========================================================================
  # HTTP HELPERS
  # ========================================================================

  def resolve_host
    return @resolved_ip if @resolved_ip

    @resolved_ip = ::Addrinfo.getaddrinfo(LEAKIX_API_HOST, nil, :INET, :STREAM).first&.ip_address
    fail_with(Failure::Unreachable, "Unable to resolve #{LEAKIX_API_HOST}") unless @resolved_ip
    vprint_status("Resolved #{LEAKIX_API_HOST} to #{@resolved_ip}")
    @resolved_ip
  rescue ::SocketError => e
    fail_with(Failure::Unreachable, "Unable to resolve #{LEAKIX_API_HOST}: #{e}")
  end

  def leakix_headers
    {
      'Host' => LEAKIX_API_HOST,
      'api-key' => datastore['LEAKIX_APIKEY'],
      'Accept' => 'application/json'
    }
  end

  def leakix_connection_opts
    {
      'rhost' => resolve_host,
      'rport' => 443,
      'SSL' => true,
      'vhost' => LEAKIX_API_HOST
    }
  end

  def leakix_request(uri, params = {})
    res = send_request_cgi(
      leakix_connection_opts.merge(
        'method' => 'GET',
        'uri' => uri,
        'headers' => leakix_headers,
        'vars_get' => params
      )
    )

    handle_response_errors(res)
    return nil unless res&.code == 200

    begin
      ActiveSupport::JSON.decode(res.body)
    rescue StandardError
      nil
    end
  end

  def handle_response_errors(res)
    fail_with(Failure::Unreachable, 'No response from LeakIX API') unless res

    case res.code
    when 401
      fail_with(Failure::BadConfig, '401 Unauthorized. Your LEAKIX_APIKEY is invalid')
    when 429
      wait_seconds = res.headers['x-limited-for'] || 'unknown'
      print_warning("Rate limited. Wait #{wait_seconds} seconds before retrying.")
    end
  end

  # ========================================================================
  # EVENT PARSING & OUTPUT
  # ========================================================================

  def extract_event_fields(event)
    {
      ip: event['ip'] || '',
      port: event['port'] || '',
      host: event['host'] || '',
      protocol: event['protocol'] || '',
      event_type: event['event_type'] || '',
      event_source: event['event_source'] || '',
      country: event.dig('geoip', 'country_name') || '',
      org: event.dig('network', 'organization_name') || '',
      software: event.dig('service', 'software', 'name') || '',
      version: event.dig('service', 'software', 'version') || ''
    }
  end

  def software_label(fields)
    fields[:software].to_s.empty? ? '' : "#{fields[:software]} #{fields[:version]}".strip
  end

  def report_event(fields)
    return unless datastore['DATABASE']

    report_host(host: fields[:ip], name: fields[:host], comments: 'Added from LeakIX')

    return unless fields[:port].to_s =~ /^\d+$/ && fields[:port].to_i > 0

    report_service(host: fields[:ip], port: fields[:port], proto: 'tcp', name: fields[:protocol], info: software_label(fields))
  end

  def events_table(events)
    tbl = Rex::Text::Table.new(
      'Header' => 'LeakIX Results',
      'Indent' => 1,
      'Columns' => ['IP:Port', 'Protocol', 'Host', 'Country', 'Organization', 'Software', 'Type', 'Source']
    )

    events.each do |event|
      next unless event.is_a?(Hash)

      fields = extract_event_fields(event)
      tbl << [
        "#{fields[:ip]}:#{fields[:port]}",
        fields[:protocol],
        fields[:host],
        fields[:country],
        fields[:org],
        software_label(fields),
        fields[:event_type],
        fields[:event_source]
      ]
      report_event(fields)
    end

    tbl
  end

  def save_output(data)
    return unless datastore['OUTFILE']

    ::File.open(datastore['OUTFILE'], 'wb') do |f|
      f.write(data)
      print_status("Saved results in #{datastore['OUTFILE']}")
    end
  end

  def print_table(tbl)
    print_line(tbl.to_s)
    save_output(tbl)
  end

  def empty_array?(data)
    data.nil? || !data.is_a?(Array) || data.empty?
  end

  def display_events(events, label = nil)
    if events.empty?
      print_error('No results found.')
      return
    end

    print_status("#{label || 'Total'}: #{events.length} results")
    print_table(events_table(events))
  end

  def collect_host_events(data)
    events = []
    %w[Services Leaks services leaks].each do |key|
      events.concat(data[key]) if data[key].is_a?(Array)
    end
    events
  end

  def apply_maxresults(events, maxresults)
    return events unless maxresults > 0 && events.length >= maxresults

    print_status("Reached MAXRESULTS limit (#{maxresults})")
    events.first(maxresults)
  end

  # ========================================================================
  # ACTIONS
  # ========================================================================

  def action_search
    query = datastore['QUERY']
    scope = datastore['SCOPE']
    maxpage = datastore['MAXPAGE']
    maxresults = datastore['MAXRESULTS'].to_i
    all_events = []

    maxpage.times do |page|
      print_status("Fetching page #{page + 1}/#{maxpage}...")

      data = leakix_request('/search', { 'q' => query, 'scope' => scope, 'page' => page.to_s })

      if data.is_a?(Hash) && data['Error'] == 'Page limit'
        print_error("Page limit reached at page #{page + 1}")
        break
      end

      if empty_array?(data)
        print_warning("No more results at page #{page + 1}")
        break
      end

      all_events.concat(data)
      print_good("Got #{data.length} results from page #{page + 1} (total: #{all_events.length})")
      if maxresults > 0 && all_events.length >= maxresults
        all_events = apply_maxresults(all_events, maxresults)
        break
      end

      Rex.sleep(1.2) if page < maxpage - 1
    end

    display_events(all_events)
  end

  def action_bulk
    query = datastore['QUERY']
    maxresults = datastore['MAXRESULTS'].to_i

    print_status('Streaming bulk results (Pro API required, leak scope)...')

    cli = connect(leakix_connection_opts)
    req = cli.request_cgi(
      'method' => 'GET',
      'uri' => '/bulk/search',
      'headers' => leakix_headers,
      'vars_get' => { 'q' => query }
    )

    cli.send_request(req)

    head, body_start = read_stream_headers(cli.conn)
    status = head[%r{HTTP/[\d.]+ (\d+)}, 1].to_i

    case status
    when 401 then fail_with(Failure::BadConfig, '401 Unauthorized - invalid LEAKIX_APIKEY')
    when 429 then fail_with(Failure::NoAccess, '429 Rate limited')
    when 200 then nil
    else fail_with(Failure::UnexpectedReply, "HTTP #{status} - Pro API key required")
    end

    chunked = head =~ /transfer-encoding:\s*chunked/i
    all_events = []
    limit_reached = false

    stream_ndjson(cli.conn, body_start, chunked) do |line|
      break if limit_reached

      obj = ActiveSupport::JSON.decode(line)
      next unless obj.is_a?(Hash) && obj['events'].is_a?(Array)

      all_events.concat(obj['events'])
      obj['events'].each { |e| report_event(extract_event_fields(e)) }
      print_status("Streamed #{all_events.length} events...") if (all_events.length % 50).zero?

      if maxresults > 0 && all_events.length >= maxresults
        all_events = apply_maxresults(all_events, maxresults)
        limit_reached = true
      end
    rescue StandardError
      next
    end

    display_events(all_events, 'Bulk results')
  ensure
    cli&.close
  end

  def action_host_or_domain(type, target)
    print_status("Fetching #{type} details for #{target}...")
    data = leakix_request("/#{type}/#{target}")

    if data.nil?
      print_error("No information found for #{target}")
      return
    end

    display_events(collect_host_events(data), target)
  end

  def action_subdomains
    domain = datastore['TARGET_DOMAIN']
    print_status("Fetching subdomains for #{domain}...")
    data = leakix_request("/api/subdomains/#{domain}")

    if empty_array?(data)
      print_error("No subdomains found for #{domain}")
      return
    end

    tbl = Rex::Text::Table.new(
      'Header' => "Subdomains for #{domain}",
      'Indent' => 1,
      'Columns' => ['Subdomain', 'Distinct IPs', 'Last Seen']
    )

    seen = Set.new
    data.each do |entry|
      next unless entry.is_a?(Hash)

      subdomain = entry['subdomain'] || ''
      next if subdomain.empty? || seen.include?(subdomain)

      seen.add(subdomain)
      tbl << [subdomain, entry['distinct_ips'] || '', entry['last_seen'] || '']
    end

    print_status("Found #{seen.length} subdomains")
    print_table(tbl)
  end

  def action_plugins
    print_status('Fetching available plugins...')
    data = leakix_request('/api/plugins')

    if empty_array?(data)
      print_error('No plugins found')
      return
    end

    tbl = Rex::Text::Table.new(
      'Header' => 'LeakIX Plugins',
      'Indent' => 1,
      'Columns' => ['Plugin Name']
    )

    data.each do |plugin|
      name = plugin.is_a?(Hash) ? plugin['name'] : plugin.to_s
      tbl << [name] if name.present?
    end

    print_status("Found #{tbl.rows.length} plugins")
    print_table(tbl)
  end

  # ========================================================================
  # STREAMING HELPERS
  # ========================================================================

  def read_stream_headers(sock)
    buf = ''
    loop do
      chunk = sock.get_once(4096, 30)
      fail_with(Failure::Unreachable, 'Connection closed while reading headers') unless chunk

      buf << chunk
      break if buf.include?("\r\n\r\n")
    end
    buf.split("\r\n\r\n", 2)
  end

  def stream_ndjson(sock, initial, chunked, &block)
    if chunked
      stream_dechunk(sock, initial || '', &block)
    else
      stream_lines(sock, initial || '', &block)
    end
  end

  def stream_lines(sock, buf)
    loop do
      while (idx = buf.index("\n"))
        line = buf.slice!(0, idx + 1).strip
        yield line unless line.empty?
      end

      data = begin
        sock.get_once(4096, 30)
      rescue ::Errno::EPIPE, ::IOError
        nil
      end
      break unless data

      buf << data
    end
    yield buf.strip unless buf.strip.empty?
  end

  def stream_dechunk(sock, buf)
    line_acc = ''
    loop do
      buf << read_socket(sock) until buf.include?("\r\n")

      size_str, buf = buf.split("\r\n", 2)
      size = size_str.strip.to_i(16)
      break if size == 0

      buf << read_socket(sock) while buf.length < size + 2

      line_acc << buf.slice!(0, size)
      buf = buf[(2)..] || '' # trailing \r\n

      while (idx = line_acc.index("\n"))
        line = line_acc.slice!(0, idx + 1).strip
        yield line unless line.empty?
      end
    rescue ::Errno::EPIPE, ::IOError
      break
    end

    yield line_acc.strip unless line_acc.strip.empty?
  end

  def read_socket(sock)
    data = sock.get_once(4096, 30)
    raise ::EOFError, 'Connection closed' unless data

    data
  end

  # ========================================================================
  # MAIN
  # ========================================================================

  def validate
    super

    errors = {}

    case action.name
    when 'SEARCH', 'BULK'
      errors['QUERY'] = "QUERY is required for #{action.name} action" if datastore['QUERY'].blank?
    when 'HOST'
      errors['TARGET_IP'] = 'TARGET_IP is required for HOST action' if datastore['TARGET_IP'].blank?
    when 'DOMAIN', 'SUBDOMAINS'
      errors['TARGET_DOMAIN'] = "TARGET_DOMAIN is required for #{action.name} action" if datastore['TARGET_DOMAIN'].blank?
    end

    errors['SCOPE'] = 'BULK action only supports leak scope' if action.name == 'BULK' && datastore['SCOPE'] == 'service'
    errors['MAXPAGE'] = 'MAXPAGE must be between 1 and 500' unless datastore['MAXPAGE'].to_i.between?(1, 500)
    errors['MAXRESULTS'] = 'MAXRESULTS must be >= 0' if datastore['MAXRESULTS'].to_i < 0

    raise Msf::OptionValidateError, errors unless errors.empty?
  end

  def run
    case action.name
    when 'SEARCH' then action_search
    when 'BULK' then action_bulk
    when 'HOST' then action_host_or_domain('host', datastore['TARGET_IP'])
    when 'DOMAIN' then action_host_or_domain('domain', datastore['TARGET_DOMAIN'])
    when 'SUBDOMAINS' then action_subdomains
    when 'PLUGINS' then action_plugins
    end
  end
end
