##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  HIBR = 'HaveIBeenRansom'.freeze
  BREACH_HOUSE = 'Breach House'.freeze
  SEARCH_SOURCES = { 'ransomware' => 'ransomware', 'breaches' => 'breach', 'leads' => 'leads', 'stealers' => 'stealer' }.freeze
  class LookupError < StandardError; end

  # Rex no verifica por defecto la cadena TLS. Se valida antes de enviar el bearer.
  class VerifiedHttpClient < Rex::Proto::Http::Client
    def connect(timeout = -1)
      socket = super
      verify_peer!(socket)
      socket
    end

    def verify_peer!(socket)
      store = OpenSSL::X509::Store.new
      store.set_default_paths
      unless store.verify(socket.peer_cert, socket.peer_cert_chain) && OpenSSL::SSL.verify_certificate_identity(socket.peer_cert, hostname)
        close
        raise OpenSSL::SSL::SSLError, 'API certificate verification failed'
      end
    end
  end

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'DarkEye Domain Exposure Search',
        'Description' => %q{
          Looks up a domain in DarkEye's HaveIBeenRansom and Breach House APIs.
          Configure an API key for either product or both. Returns one JSON report
          containing listing metadata, with a product and category on each record.
          Only the API services are contacted; the queried domain is not contacted.
          Listings do not establish a confirmed incident or maliciousness, and an
          empty result does not establish that the domain is safe.
        },
        'Author' => ['DarkEye'], # Implementación del módulo
        'License' => MSF_LICENSE,
        'References' => [
          ['URL', 'https://darkeye.io/'],
          ['URL', 'https://haveibeenransom.com/howapi'],
          ['URL', 'https://breach.house/docs']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK],
          'Reliability' => []
        },
        'DefaultOptions' => { 'HttpClientTimeout' => 30 }
      )
    )
    register_options([
      OptString.new('DOMAIN', [true, 'Domain to look up (ASCII or punycode)']),
      OptString.new('HIBR_API_KEY', [false, 'HaveIBeenRansom API key']),
      OptString.new('BREACHHOUSE_API_KEY', [false, 'Breach House API key']),
      OptInt.new('MAX_PAGES', [true, 'Maximum HaveIBeenRansom pages (1-20)', 5]),
      OptInt.new('MAX_RECORDS', [true, 'Maximum records retained per product (1-500)', 100]),
      OptInt.new('SEARCH_LIMIT', [true, 'Breach House results requested per source (1-200)', 25])
    ])
    deregister_http_client_options
  end

  def normalize_domain(value)
    domain = value.to_s.strip.downcase.delete_suffix('.')
    labels = domain.split('.', -1)
    return nil unless domain.ascii_only? && domain.length <= 253 && labels.length >= 2
    return nil if labels.last.match?(/\A[0-9]+\z/)
    return nil unless labels.all? { |label| label.match?(/\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\z/) }

    domain
  end

  def validate
    super
    errors = {}
    errors['DOMAIN'] = 'Use a plain ASCII or punycode domain, without a URL or IP address' unless normalize_domain(datastore['DOMAIN'])
    keys = %w[HIBR_API_KEY BREACHHOUSE_API_KEY]
    errors['HIBR_API_KEY'] = 'Configure at least one product API key' if keys.all? { |name| datastore[name].to_s.strip.empty? }
    keys.each do |name|
      value = datastore[name].to_s
      errors[name] = 'Use printable ASCII without whitespace' unless value.empty? || value.match?(/\A[!-~]+\z/)
    end
    { 'MAX_PAGES' => 20, 'MAX_RECORDS' => 500, 'SEARCH_LIMIT' => 200, 'HttpClientTimeout' => 120 }.each do |name, maximum|
      errors[name] = "Must be between 1 and #{maximum}" unless datastore[name].to_f.between?(1, maximum)
    end
    raise Msf::OptionValidateError, errors unless errors.empty?
  end

  def api_request(host, path, key, params = {})
    connection = VerifiedHttpClient.new(host, 443, {}, true)
    connection.set_config('vhost' => host, 'ssl_server_name_indication' => host)
    response = send_request_cgi(
      'client' => connection, 'rhost' => host, 'rport' => 443, 'SSL' => true,
      'method' => 'GET', 'uri' => path, 'vars_get' => params,
      'cookie' => '', 'keep_cookies' => false, 'preferred_auth' => 'None',
      'headers' => { 'Authorization' => "Bearer #{key}", 'Accept' => 'application/json', 'User-Agent' => 'Metasploit/DarkEye' }
    )
    raise LookupError, 'API did not respond' unless response
    raise LookupError, "API returned HTTP #{response.code}" unless response.code == 200

    # Evita que get_json_document registre cuerpos malformados con datos sensibles.
    JSON.parse(response.body)
    data = response.get_json_document
    unless data.is_a?(Hash) && data['success'] != false && !data.key?('error')
      raise LookupError, 'API returned an invalid or unsuccessful response'
    end

    data
  rescue JSON::ParserError, TypeError
    raise LookupError, 'API returned invalid JSON'
  rescue Rex::ConnectionError, SocketError, IOError, SystemCallError, Timeout::Error, OpenSSL::SSL::SSLError
    raise LookupError, 'API connection or certificate verification failed'
  ensure
    connection&.close
  end

  def metadata_text(value)
    return '' unless value.is_a?(String) || value.is_a?(Integer)

    text = value.to_s.encode('UTF-8', invalid: :replace, undef: :replace).gsub(/[\p{Cc}\p{Cf}]/u, ' ').strip
    %w[HIBR_API_KEY BREACHHOUSE_API_KEY].each do |name|
      key = datastore[name].to_s
      text = text.gsub(key, '[REDACTED]') unless key.empty?
    end
    text[0, 512]
  end

  def metadata_record(product, category, item)
    {
      'product' => product, 'category' => category,
      'id' => metadata_text(item['id_source'] || item['victim_id'] || item['id']),
      'title' => metadata_text(item['post_title'] || item['name']),
      'website' => metadata_text(item['website']), 'group' => metadata_text(item['group_name']),
      'country' => metadata_text(item['country']), 'discovered' => metadata_text(item['discovered'])[0, 10]
    }
  end

  def domain_match?(record, domain)
    unless record['website'].empty?
      website = record['website']
      host = URI.parse(website.include?('://') ? website : "//#{website}").host
      normalized = normalize_domain(host)
      return normalized && (normalized == domain || normalized.end_with?(".#{domain}"))
    end
    record['title'].downcase.match?(/(?<![\p{L}\p{N}_-])#{Regexp.escape(domain)}(?![\p{L}\p{N}_-]|\.[\p{L}\p{N}])/u)
  rescue URI::InvalidURIError
    false
  end

  def hibr_lookup(domain, key)
    records = []
    seen = Set.new
    datastore['MAX_PAGES'].times do |index|
      parts = ['api', 'metadata', 'domain', domain]
      parts << (index + 1).to_s if index.positive?
      data = api_request('haveibeenransom.com', normalize_uri(*parts), key)
      items = data.key?('sources') ? data['sources'] : data['results']
      pagination = data.fetch('pagination', {})
      raise LookupError, 'Invalid metadata response' unless items.is_a?(Array) && pagination.is_a?(Hash)

      has_next = data.fetch('has_next', pagination['has_next'])
      unless [true, false].include?(has_next) && items.all? { |item| item.is_a?(Hash) }
        raise LookupError, 'Invalid metadata pagination or records'
      end

      items.each do |item|
        category = { 'ransomware_leak' => 'ransomware', 'traditional_breach' => 'breach' }.fetch(item['leak_type'], 'leak')
        record = metadata_record(HIBR, category, item)
        raise LookupError, 'Invalid metadata record' if %w[id title website].all? { |field| record[field].empty? }

        identity = record['id'].empty? ? record : record['id']
        next unless seen.add?(identity)
        return { records: records, truncated: true } if records.length == datastore['MAX_RECORDS']

        records << record
      end
      return { records: records, truncated: false } unless has_next
      return { records: records, truncated: true } if records.length == datastore['MAX_RECORDS']
    end
    { records: records, truncated: true }
  end

  def breach_house_lookup(domain, key)
    data = api_request('breach.house', normalize_uri('api', 'v1', 'search'), key, 'q' => domain, 'limit' => datastore['SEARCH_LIMIT'])
    records = []
    seen = Set.new
    truncated = false
    SEARCH_SOURCES.each do |source, category|
      section = data[source]
      total = section.is_a?(Hash) ? section['total'] : nil
      items = section.is_a?(Hash) ? section['results'] : section
      unless items.is_a?(Array) && items.all? { |item| item.is_a?(Hash) }
        raise LookupError, 'Invalid or missing search source'
      end
      if !total.nil? && (!total.is_a?(Integer) || total < items.length)
        raise LookupError, 'Invalid search total'
      end

      truncated ||= total.nil? ? items.length >= datastore['SEARCH_LIMIT'] : total > items.length
      items.each do |item|
        record = metadata_record(BREACH_HOUSE, category, item)
        next unless domain_match?(record, domain)

        identity = [category, record['id'].empty? ? record : record['id']]
        next unless seen.add?(identity)

        if records.length == datastore['MAX_RECORDS']
          truncated = true
        else
          records << record
        end
      end
    end
    { records: records, truncated: truncated }
  end

  def lookup(domain)
    report = { 'provider' => 'DarkEye', 'domain' => domain, 'products' => [], 'records' => [], 'errors' => [], 'truncated' => false }
    [[HIBR, 'HIBR_API_KEY', :hibr_lookup], [BREACH_HOUSE, 'BREACHHOUSE_API_KEY', :breach_house_lookup]].each do |product, option, operation|
      next if datastore[option].to_s.empty?

      begin
        result = public_send(operation, domain, datastore[option])
        report['products'] << product
        report['records'].concat(result[:records])
        report['truncated'] ||= result[:truncated]
      rescue LookupError => e
        report['errors'] << { 'product' => product, 'error' => e.message }
      end
    end
    report['count'] = report['records'].length
    report['status'] = report['errors'].any? || report['truncated'] ? 'partial' : 'complete'
    report
  end

  def run
    validate
    report = lookup(normalize_domain(datastore['DOMAIN']))
    report['errors'].each { |error| print_warning("#{error['product']}: #{error['error']}") }
    fail_with(Failure::UnexpectedReply, 'Every configured DarkEye lookup failed; no report was saved') if report['products'].empty?

    path = store_loot('darkeye.metadata', 'application/json', nil, JSON.pretty_generate(report), 'darkeye.json', 'DarkEye domain exposure metadata')
    print_status("DarkEye: #{report['count']} listing(s); status=#{report['status']}; products=#{report['products'].join(', ')}")
    print_warning('Results are incomplete; inspect errors and truncation in the report') if report['status'] == 'partial'
    print_status('Listings are unconfirmed exposure metadata, not a safety or maliciousness verdict')
    print_good("DarkEye report saved to #{path}")
  end
end
