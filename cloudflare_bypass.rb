require 'public_suffix'
require 'ipaddr'
require 'resolv'
require 'openssl'
require 'net/http'
require 'json'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::DNS::Enumeration
  include Msf::Auxiliary::Report

  # Predefined list of User Agents for HTTP requests
  USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59 Safari/537.36',
    'Mozilla/5.0 (Linux; Android 11; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0',
  ]

  # Predefined VHost list for enumeration
  VHOST_LIST = %w[dev staging api test beta mail www admin login]

  # Predefined SSRF payloads (less sensitive)
  SSRF_PAYLOADS = [
    '/health',
    '/status',
    '/api/health',
    '/metrics',
    '/info',
  ]

  # Common ports for dynamic scanning
  COMMON_PORTS = [80, 8080, 8443, 8000, 8888]

  # Random headers for realistic traffic
  ACCEPT_LANGUAGES = ['en-US,en;q=0.9', 'zh-CN,zh;q=0.9', 'es-ES,es;q=0.9', 'fr-FR,fr;q=0.9']
  REFERERS = ['https://www.google.com/', 'https://www.bing.com/', '']

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cloudflare Bypass',
        'Description' => %q{
          This module is an upgraded version specifically targeting Cloudflare protection to find the real IP address of a target host.
          It leverages key leakage vectors including DNS history, subdomains, MX/SPF records, SSL certificates, SSRF exploitation, certificate fingerprints,
          VHost enumeration, and dynamic port scanning. Optimized for 2025 methods with enhanced subdomain enumeration, rate limiting, and realistic HTTP headers.
          Non-Cloudflare IPs are marked in green, and successful bypass results are highlighted in yellow with a mocking message.
          Supports multiple fingerprint tags and strings for improved matching.
        },
        'Author' => [
          'ChillHack Hong Kong Web Development, Jake', # Upgraded version for Cloudflare bypass
          'Contact: info@chillhack.net',
          'Website: https://chillhack.net'
        ],
        'References' => [
          ['URL', 'https://citadelo.com/en/blog/cloudflare-how-to-do-it-right-and-do-not-reveal-your-real-ip/'],
          ['URL', 'https://brightdata.com/blog/web-data/bypass-cloudflare'],
          ['URL', 'https://www.zenrows.com/blog/bypass-cloudflare'],
          ['URL', 'https://blog.apify.com/bypass-cloudflare/'],
          ['URL', 'https://medium.com/@ibtissamhammadi1/how-to-find-a-websites-real-ip-behind-cloudflare-695dd179c977'],
          ['URL', 'https://securityonline.info/how-to-discover-real-ips-behind-cloudflare-protected-websites/'],
          ['URL', 'https://github.com/m0rtem/CloudFail'],
          ['URL', 'https://github.com/greycatz/CloudUnflare']
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options([
      OptString.new('HOSTNAME', [true, 'The hostname or domain name to find the real IP address', nil]),
      OptString.new('COMPSTR', [false, 'Custom string for HTTP response comparison', nil]),
      OptString.new('FINGERPRINT_STRINGS', [false, 'Comma-separated list of fingerprint strings for HTTP response comparison', nil]),
      OptString.new('FINGERPRINT_TAGS', [true, 'Comma-separated list of HTML tags for fingerprinting', 'title,meta,h1']),
      OptPath.new('IPBLACKLIST_FILE', [false, 'File containing IPs to blacklist, one per line', nil]),
      OptString.new('Proxies', [false, 'Proxy chain of format type:host:port[,type:host:port][...]', nil]),
      OptInt.new('RPORT', [true, 'Target TCP port for HTTP', 443]),
      OptBool.new('SSL', [true, 'Use SSL/TLS for HTTP connections', true]),
      OptInt.new('THREADS', [true, 'Threads for DNS enumeration', 4]),
      OptString.new('URIPATH', [true, 'URI path for HTTP comparison', '/']),
      OptPath.new('WORDLIST', [false, 'Wordlist for subdomain enumeration', ::File.join(Msf::Config.data_directory, 'wordlists', 'namelist.txt')]),
      OptString.new('USERAGENT', [false, 'Custom User-Agent for HTTP requests (if not set, a random one from the built-in list is used)', nil]),
      OptPath.new('USERAGENT_FILE', [false, 'File containing additional User-Agents, one per line', nil]),
      OptInt.new('HTTP_TIMEOUT', [true, 'HTTP request timeout', 10]),
      OptBool.new('CHECK_MX', [true, 'Check MX and SPF records for IPs', true])
    ])

    # Set VERBOSE to true by default
    datastore['VERBOSE'] = true
  end

  def setup_resolver
    print_status("Setting up DNS resolver...")
    dns_resolver = super
    dns_resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1']
    dns_resolver.port = 53
    @dns_resolver = dns_resolver
  end

  def load_user_agents
    agents = USER_AGENTS.dup
    if datastore['USERAGENT_FILE'] && File.readable?(datastore['USERAGENT_FILE'])
      print_status("Loading User-Agents from #{datastore['USERAGENT_FILE']}...")
      agents += File.readlines(datastore['USERAGENT_FILE'], chomp: true).reject(&:empty?)
    end
    agents.uniq
  end

  def select_user_agent
    if datastore['USERAGENT']
      datastore['USERAGENT']
    else
      load_user_agents.sample
    end
  end

  def random_headers
    referer = REFERERS.sample
    referer = "https://#{datastore['HOSTNAME']}/" if referer.empty? && datastore['HOSTNAME']
    {
      'Accept-Language' => ACCEPT_LANGUAGES.sample,
      'Referer' => referer
    }
  end

  def rate_limited_request(host, port, ssl, uri, vhost = nil, headers = {}, method = 'GET', data = nil)
    sleep(rand(1.0..3.0)) # Random delay between 1-3 seconds
    headers = headers.merge(random_headers)
    if method == 'POST'
      http_post_request_raw(host, port, ssl, uri, vhost, data, headers)
    else
      http_get_request_raw(host, port, ssl, uri, vhost, headers)
    end
  end

  def http_get_request_raw(host, port, ssl, uri, vhost = nil, headers = {})
    uri = uri + (uri.include?('?') ? '&' : '?') + "random=#{rand(1000000)}"
    begin
      cli = Rex::Proto::Http::Client.new(host, port, {}, ssl, nil, datastore['Proxies'])
      cli.connect
      request = cli.request_cgi({
        'method' => 'GET',
        'uri' => uri,
        'agent' => select_user_agent,
        'vhost' => vhost || host
      }.merge(headers))
      response = cli.send_recv(request, datastore['HTTP_TIMEOUT'])
      cli.close
      response
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT => e
      print_error("HTTP request to #{host}:#{port} failed: #{e.message}")
      nil
    end
  end

  def http_post_request_raw(host, port, ssl, uri, vhost = nil, data = '', headers = {})
    begin
      cli = Rex::Proto::Http::Client.new(host, port, {}, ssl, nil, datastore['Proxies'])
      cli.connect
      request = cli.request_cgi({
        'method' => 'POST',
        'uri' => uri,
        'agent' => select_user_agent,
        'vhost' => vhost || host,
        'data' => data
      }.merge(headers))
      response = cli.send_recv(request, datastore['HTTP_TIMEOUT'])
      cli.close
      response
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT => e
      print_error("POST request to #{host}:#{port} failed: #{e.message}")
      nil
    end
  end

  def cloudflare_ips
    print_status("Fetching Cloudflare IP ranges...")
    response = rate_limited_request('www.cloudflare.com', 443, true, '/ips-v4')
    return [] if response.nil?
    ranges = response.get_html_document.css('p').text.split("\n").map(&:strip).reject(&:empty?)
    ranges
  rescue => e
    print_error("Failed to fetch Cloudflare IPs: #{e.message}")
    []
  end

  def ssrf_exploitation(domain)
    print_status("Attempting SSRF exploitation on #{domain}...")
    ips = []
    SSRF_PAYLOADS.each do |payload|
      begin
        response = rate_limited_request(domain, datastore['RPORT'], datastore['SSL'], payload, domain)
        next unless response
        next if response.headers['Server']&.include?('cloudflare') || response.headers['CF-RAY']
        ips += response.body.scan(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/).uniq
      rescue => e
        print_error("SSRF exploitation error for #{payload}: #{e.message}")
      end
    end
    ips.uniq
  end

  def certificate_fingerprint_search(domain)
    print_status("Searching certificate fingerprints for #{domain}...")
    begin
      response = rate_limited_request(domain, datastore['RPORT'], true, '/', domain)
      return [] unless response
      cert = response.peer_cert
      return [] unless cert
      sha256 = OpenSSL::Digest::SHA256.hexdigest(cert.to_der)
      search_url = "/?q=#{sha256}&output=json"
      response = rate_limited_request('crt.sh', 443, true, search_url)
      return [] if response.nil? || response.code != 200
      json = JSON.parse(response.body.force_encoding('UTF-8')) rescue nil
      return [] if json.nil?
      domains = json.map { |entry| entry['name_value']&.split("\n") }&.flatten&.uniq || []
      ips = domains.map { |name|
        next if name.start_with?('*')
        Resolv.getaddresses(name) rescue []
      }.flatten.select { |ip| ip =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ }.uniq
      ips
    rescue => e
      print_error("Certificate fingerprint search error: #{e.message}")
      []
    end
  end

  def vhost_enumeration(domain)
    print_status("Enumerating VHosts for #{domain}...")
    ips = []
    VHOST_LIST.each do |vhost|
      subdomain = "#{vhost}.#{domain}"
      begin
        response = rate_limited_request(subdomain, datastore['RPORT'], datastore['SSL'], '/')
        next unless response
        next if response.headers['Server']&.include?('cloudflare') || response.headers['CF-RAY']
        ip = Resolv.getaddress(subdomain) rescue nil
        ips << ip if ip
      rescue => e
        print_error("VHost check error for #{subdomain}: #{e.message}")
      end
    end
    ips.uniq
  end

  def viewdns_ip_history(domain)
    print_status("Querying ViewDNS.info for IP history of #{domain}...")
    sleep(rand(5.0..10.0)) # Random delay to avoid rate limiting
    retries = 3
    begin
      response = rate_limited_request('viewdns.info', 443, true, "/iphistory/?domain=#{domain}")
      return [] if response.nil?
      html = response.get_html_document
      table = html.css('table')[3]
      return [] if table.nil?
      rows = table.css('tr')
      ips = rows.map { |row| row.css('td').map(&:text).to_s[/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/, 1] }.compact.uniq
      ips
    rescue => e
      retries -= 1
      print_warning("Retrying ViewDNS.info query (#{retries} attempts left)...")
      retry if retries > 0
      print_error("Failed to connect to viewdns.info: #{e.message}")
      []
    end
  end

  def crtsh_search(domain)
    print_status("Querying crt.sh for SSL certificates of #{domain}...")
    sleep(rand(5.0..10.0)) # Random delay to avoid rate limiting
    begin
      response = rate_limited_request('crt.sh', 443, true, "/?q=#{domain}&output=json")
      return [] if response.nil? || response.code != 200
      json = JSON.parse(response.body.force_encoding('UTF-8')) rescue nil
      return [] if json.nil?
      domains = json.map { |entry| entry['name_value']&.split("\n") }&.flatten&.uniq || []
      ips = domains.map { |name|
        next if name.start_with?('*')
        Resolv.getaddresses(name) rescue []
      }.flatten.select { |ip| ip =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ }.uniq
      ips
    rescue => e
      print_error("crt.sh search error: #{e.message}")
      []
    end
  end

  def get_mx_records(domain)
    print_status("Fetching MX and SPF records for #{domain}...")
    begin
      resolver = Resolv::DNS.new(nameserver: ['8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1'])
      mx_records = resolver.getresources(domain, Resolv::DNS::Resource::IN::MX)
      spf_records = resolver.getresources(domain, Resolv::DNS::Resource::IN::TXT)
      ips = []
      mx_records.each do |mx|
        hostname = mx.exchange.to_s
        ip = Resolv.getaddresses(hostname) rescue []
        ips += ip
      end
      spf_records.each do |txt|
        txt.strings.each do |str|
          if str =~ /include:(\S+)/
            included_domain = $1
            ip = Resolv.getaddresses(included_domain) rescue []
            ips += ip
          end
        end
      end
      ips.select { |ip| ip =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ }.uniq
    rescue => e
      print_error("MX/SPF records error: #{e.message}")
      []
    end
  end

  def dns_bruteforce(domain, wordlist, threads)
    sleep(rand(0.5..2.0)) # Rate limit DNS queries
    super(domain, wordlist, [threads, 4].min) # Limit to 4 threads
  end

  def check_subdomain_status(subdomain)
    print_status("Checking if #{subdomain} is behind Cloudflare...")
    begin
      response = rate_limited_request(subdomain, datastore['RPORT'], datastore['SSL'], '/')
      return false if response.nil?
      headers = response.headers
      !headers['Server']&.include?('cloudflare') && !headers['CF-RAY']
    rescue => e
      print_error("Subdomain check error for #{subdomain}: #{e.message}")
      false
    end
  end

  def check_bypass(fingerprint_strings, fingerprint_tags, ip)
    print_status("Checking IP #{ip} for Cloudflare bypass...")
    COMMON_PORTS.each do |port|
      begin
        response = rate_limited_request(ip, port, port == 443 ? datastore['SSL'] : false, datastore['URIPATH'], datastore['HOSTNAME'])
        next unless response
        headers = response.headers
        if headers['Server']&.include?('cloudflare') || headers['CF-RAY']
          next
        end
        print_good("Found non-Cloudflare IP: #{ip} on port #{port}")
        html = response.get_html_document
        body = response.body

        # Check custom fingerprint strings
        if fingerprint_strings && !fingerprint_strings.empty?
          fingerprint_strings.each do |fingerprint|
            if body.include?(fingerprint)
              print_warning("Found real IP of the target: #{ip} on port #{port} (matched fingerprint: #{fingerprint})")
              report_host(host: ip, name: datastore['HOSTNAME'])
              return true
            end
          end
        end

        # Check fingerprint tags
        fingerprint_tags.each do |tag|
          content = html.at(tag)&.to_s
          next unless content
          if fingerprint_strings.empty? && content
            print_warning("Found real IP of the target: #{ip} on port #{port} (matched tag: #{tag})")
            report_host(host: ip, name: datastore['HOSTNAME'])
            return true
          end
          fingerprint_strings.each do |fingerprint|
            if content.include?(fingerprint)
              print_warning("Found real IP of the target: #{ip} on port #{port} (matched tag: #{tag}, fingerprint: #{fingerprint})")
              report_host(host: ip, name: datastore['HOSTNAME'])
              return true
            end
          end
        end
      rescue => e
        print_error("Bypass check error for #{ip} on port #{port}: #{e.message}")
      end
    end
    false
  end

  def run
    print_status("Starting Cloudflare bypass for #{datastore['HOSTNAME']}...")
    begin
      domain_name = PublicSuffix.parse(datastore['HOSTNAME']).domain
    rescue PublicSuffix::DomainInvalid, PublicSuffix::DomainNotAllowed => e
      print_error("Invalid domain: #{datastore['HOSTNAME']}. Error: #{e.message}")
      return
    end

    ip_list = []

    # SSRF Exploitation
    ip_records = ssrf_exploitation(domain_name)
    ip_list |= ip_records if ip_records && !ip_records.empty?
    print_status("SSRF Exploitation: #{ip_records.count} IPs found")

    # Certificate Fingerprint Search
    ip_records = certificate_fingerprint_search(domain_name)
    ip_list |= ip_records if ip_records && !ip_records.empty?
    print_status("Certificate Fingerprint: #{ip_records.count} IPs found")

    # VHost Enumeration
    ip_records = vhost_enumeration(domain_name)
    ip_list |= ip_records if ip_records && !ip_records.empty?
    print_status("VHost Enumeration: #{ip_records.count} IPs found")

    # DNS / Subdomain History
    ip_records = viewdns_ip_history(domain_name)
    ip_list |= ip_records if ip_records && !ip_records.empty?
    print_status("ViewDNS.info: #{ip_records.count} IPs found")

    # SSL Certificates (crt.sh)
    ip_records = crtsh_search(domain_name)
    ip_list |= ip_records if ip_records && !ip_records.empty?
    print_status("crt.sh: #{ip_records.count} IPs found")

    # MX/SPF Records
    if datastore['CHECK_MX']
      ip_records = get_mx_records(domain_name)
      ip_list |= ip_records if ip_records && !ip_records.empty?
      print_status("MX/SPF Records: #{ip_records.count} IPs found")
    end

    # DNS Bruteforce
    unless dns_wildcard_enabled?(domain_name)
      print_status("Starting DNS bruteforce enumeration...")
      ip_records = dns_bruteforce(domain_name, datastore['WORDLIST'], datastore['THREADS'])
      ip_records.each do |subdomain, ip|
        next unless ip && subdomain =~ /^[a-zA-Z0-9\-\.]+$/
        ip_list |= [ip]
        print_status("Found #{subdomain}: #{ip}")
        if check_subdomain_status(subdomain)
          print_good("Subdomain #{subdomain} not behind Cloudflare: #{ip}")
        end
      end
      print_status("DNS Enumeration: #{ip_records.count} IPs found")
    end

    if ip_list.empty?
      print_bad('No IPs found.')
      return
    end

    print_status("Collected IPs before filtering: #{ip_list.join(', ')}")
    print_status("Filtering out Cloudflare and blacklisted IPs...")
    ip_blacklist = cloudflare_ips
    if datastore['IPBLACKLIST_FILE'] && File.readable?(datastore['IPBLACKLIST_FILE'])
      ip_blacklist |= File.readlines(datastore['IPBLACKLIST_FILE'], chomp: true)
    end

    records = ip_list.uniq.reject do |ip|
      next true unless ip =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
      ip_blacklist.any? do |range|
        begin
          IPAddr.new(range).include?(ip)
        rescue IPAddr::InvalidAddressError
          false
        end
      end
    end

    if records.empty?
      print_bad('No IPs found after filtering.')
      return
    end
    print_status("Total: #{records.count} IPs after filtering: #{records.join(', ')}")

    print_status("Acquiring website fingerprint...")
    fingerprint_strings = datastore['FINGERPRINT_STRINGS']&.split(',')&.map(&:strip) || [datastore['COMPSTR']].compact
    fingerprint_tags = datastore['FINGERPRINT_TAGS']&.split(',')&.map(&:strip) || ['title']

    print_status("Checking potential IPs for direct connection...")
    ret_value = false
    records.each do |ip|
      ret_value |= check_bypass(fingerprint_strings, fingerprint_tags, ip)
    end

    if ret_value
      print_status("Cloudflare thought it could hide, but we cracked it like an egg! Real IP exposed, baby! Jake & Grok say: 'Time to kick off the real hack!' 😎")
    else
      print_bad('No direct-connect IP found.')
    end
    print_status("Cloudflare bypass completed.")
  end
end
