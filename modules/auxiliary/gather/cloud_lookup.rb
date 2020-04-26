##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cloud Lookup (and bypass)',
        'Description' => %q{
          This module can be useful if you need to test the security of your server and your
          website behind a solution Cloud based. By discovering the origin IP address of the
          targeted host.

          More precisely, this module uses multiple data sources (in order ViewDNS.info, DNS enumeration
          and Censys) to collect assigned (or have been assigned) IP addresses from the targeted site or domain
          that uses the following:
            * Amazon Cloudflare, Amazon CloudFront, ArvanCloud, Envoy Proxy, Fastly, Stackpath Fireblade,
              Stackpath MaxCDN, Imperva Incapsula, InGen Security (BinarySec EasyWAF), KeyCDN, Microsoft AzureCDN,
              Netlify and Sucuri.
        },
        'Author' => [
          'mekhalleh (RAMELLA Sébastien)' # https://www.pirates.re/
        ],
        'References' => [
          ['URL', 'https://citadelo.com/en/blog/cloudflare-how-to-do-it-right-and-do-not-reveal-your-real-ip/']
        ],
        'License' => MSF_LICENSE,
        'Actions' => [
          ['Automatic', {}],
          ['Amazon CloudFlare', {
            'Description' => 'Cloud based Web application firewall of Amazon',
            'Signatures' => ['server: cloudflare']
          }],
          ['Amazon CloudFront', {
            'Description' => 'Content Delivery Network services of Amazon',
            'Signatures' => ['x-amz-cf-id:']
          }],
          ['ArvanCloud CDN', {
            'Description' => 'ArvanCloud CDN comprises tens of PoP sites in important locations all around the world to deliver online content to the users',
            'Signatures' => ['server: ArvanCloud']
          }],
          ['AzureCDN', {
            'Description' => 'Microsoft Azure Content Delivery Network (CDN) is a global content distribution network solution for delivering high bandwidth content',
            'Signatures' => []
          }],
          ['Envoy Proxy', {
            'Description' => 'An open source edge and service proxy, designed for Cloud-Native applications',
            'Signatures' => ['server: envoy']
          }],
          ['Fastly', {
            'Description' => 'Another widely used CDN/WAF solution',
            'Signatures' => ['Fastly-SSL']
          }],
          ['Imperva Incapsula', {
            'Description' => 'Cloud based Web application firewall of Imperva',
            'Signatures' => ['X-CDN: Incapsula']
          }],
          ['InGen Security (BinarySec EasyWAF)', { # Reunion island powa!
            'Description' => 'Cloud based Web application firewall of InGen Security and BinarySec',
            'Signatures' => ['binarysec', 'server: gatejs']
          }],
          ['KeyCDN', {
            'Description' => 'KeyCDN is a high performance content delivery network that has been built for the future', # lol
            'Signatures' => ['Server: keycdn-engine']
          }],
          ['Netlifi', {
            'Description' => 'One workflow, from local development to global deployment',
            'Signatures' => ['x-nf-request-id:']
          }],
          ['NoWAFBypass', {
            'Description' => 'Do NOT check any bypass method',
            'Signatures' => []
          }],
          ['Stackpath Fireblade', {
            'Description' => 'Enterprise Website Security & DDoS Protection',
            'Signatures' => ['Server: fbs']
          }],
          ['Stackpath MaxCDN', {
            'Description' => 'Speed Up your Content Delivery',
            'Signatures' => ['Server: NetDNA-cache']
          }],
          ['Sucuri', {
            'Description' => 'Cloud based Web application firewall of Sucuri',
            'Signatures' => ['x-sucuri-id:']
          }],
        ],
        'DefaultAction' => 'Automatic'
      )
    )

    register_options([
      OptString.new('CENSYS_SECRET', [false, 'The Censys API SECRET']),
      OptString.new('CENSYS_UID', [false, 'The Censys API UID']),
      OptString.new('COMPSTR', [false, 'You can use a custom string to perform the comparison (read documentation)']),
      OptString.new('HOSTNAME', [true, 'The hostname or domain name where we want to find the real IP address']),
      OptString.new('Proxies', [false, 'A proxy chain of format type:host:port[,type:host:port][...]']),
      OptInt.new('RPORT', [true, 'The target TCP port on which the protected website responds', 443]),
      OptBool.new('SSL', [true, 'Negotiate SSL/TLS for outgoing connections', true]),
      OptInt.new('THREADS', [true, 'Threads for DNS enumeration', 8]),
      OptString.new('URIPATH', [true, 'The URI path on which to perform the page comparison', '/']),
      OptPath.new('WORDLIST', [false, 'Wordlist of subdomains', ::File.join(Msf::Config.data_directory, 'wordlists', 'namelist.txt')])
    ])

    register_advanced_options([
      OptBool.new('ALLOW_NOWAF', [true, 'Automatically switch to NoWAFBypass when detection fails with the Automatic action', false]),
      OptBool.new('DNSENUM', [true, 'Set DNS enumeration as optional', true]),
      OptAddress.new('NS', [false, 'Specify the nameserver to use for queries (default is system DNS)']),
      OptBool.new('REPORT_LEAKS', [true, 'Set to write leaked ip addresses in notes', false]),
      OptString.new('USERAGENT', [true, 'Specify a personalized User-Agent header in HTTP requests', 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0']),
      OptEnum.new('TAG', [true, 'Specify the HTML tag in which you want to find the fingerprint', 'title', ['title', 'html']]),
      OptInt.new('TIMEOUT', [true, 'HTTP(s) request timeout', 8])
    ])
  end

  # ------------------------------------------------------------------------- #

  # auxiliary/gather/censys_search.rb
  def basic_auth_header(username, password)
    auth_str = username.to_s + ':' + password.to_s
    'Basic ' + Rex::Text.encode_base64(auth_str)
  end

  # auxiliary/gather/censys_search.rb
  def censys_search(keyword, search_type, uid, secret)
    begin
      payload = { 'query' => keyword }

      cli = Rex::Proto::Http::Client.new('www.censys.io', 443, {}, true, nil, datastore['Proxies'])
      cli.connect

      response = cli.request_cgi(
        'method' => 'POST',
        'uri' => "/api/v1/search/#{search_type}",
        'agent' => datastore['USERAGENT'],
        'headers' => {
          'Authorization' => basic_auth_header(uid, secret)
        },
        'data' => payload.to_json
      )
      results = cli.send_recv(response)
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error('HTTP connection failed to Censys.IO website.')
    end

    unless results
      print_error('Unable to retrieve any data from Censys.IO website.')
      return []
    end

    records = ActiveSupport::JSON.decode(results.body)
    results = records['results']

    parse_ipv4(results)
  end

  def check_tcp_port(ip, port)
    begin
      sock = Rex::Socket::Tcp.create(
        'PeerHost' => ip,
        'PeerPort' => port,
        'Proxies' => datastore['Proxies']
      )
    rescue ::Rex::ConnectionRefused, Rex::ConnectionError
      vprint_status(" * Closed: tcp://#{ip}:#{port}/")
      return false
    end

    sock.close
    return true
  end

  def wildcard(domain)
    ar_ips = []

    response = dns_query("#{rand(10000)}.#{domain}", 'A')
    if !response.answer.empty?
      print_warning('This domain has wildcards enabled!')
      response.answer.each do |rr|
        ar_ips << rr.address.to_s
      end
    end

    ar_ips
  end

  # auxiliary/gather/enum_dns.rb
  def dns_enumeration(domain, threads)
    wordlist = datastore['WORDLIST']
    return if wordlist.blank?

    ar_ips = wildcard(domain)
    return ar_ips if !ar_ips.empty?

    threads = 1 if threads <= 0
    queue = []
    File.foreach(wordlist) do |line|
      queue << "#{line.chomp}.#{domain}"
    end

    until queue.empty?
      t = []
      threads = 1 if threads <= 0

      if queue.length < threads
        # work around issue where threads not created as the queue isn't large enough
        threads = queue.length
      end

      begin
        1.upto(threads) do
          t << framework.threads.spawn("Module(#{refname})", false, queue.shift) do |test_current|
            Thread.current.kill unless test_current
            a = /(\d*\.\d*\.\d*\.\d*)/.match(dns_get_a(test_current).to_s)
            ar_ips.push(a) if a
          end
        end
        t.map(&:join)
      rescue ::Timeout::Error
        next
      ensure
        t.each { |x| x.kill rescue nil }
      end
    end

    ar_ips
  end

  # auxiliary/gather/enum_dns.rb
  def dns_get_a(fqdn)
    response = dns_query(fqdn, 'A')
    return if response.blank? || response.answer.blank?

    response.answer.each do |row|
      next unless row.class == Net::DNS::RR::A
    end
  end

  # auxiliary/gather/enum_dns.rb
  def dns_query(request, type)
    nameserver = datastore['NS']

    if nameserver.blank?
      dns = Net::DNS::Resolver.new
    else
      dns = Net::DNS::Resolver.new(nameservers: ::Rex::Socket.resolv_to_dotted(nameserver))
    end

    dns.use_tcp = false
    dns.udp_timeout = 8
    dns.retry_number = 2
    dns.retry_interval = 2
    dns.query(request, type)
  rescue ResolverArgumentError, Errno::ETIMEDOUT, ::NoResponseError, ::Timeout::Error => e
    print_error("Query #{request} DNS #{type} - exception: #{e}")
    return nil
  end

  def grab_domain_ip_history(domain)
    begin
      cli = Rex::Proto::Http::Client.new('viewdns.info', 443, {}, true, nil, datastore['Proxies'])
      cli.connect

      request = cli.request_cgi({
        'method' => 'GET',
        'uri' => "/iphistory/?domain=#{domain}",
        'agent' => datastore['USERAGENT']
      })
      response = cli.send_recv(request)
      cli.close
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error('HTTP connection failed to ViewDNS.info website.')
      return []
    end

    unless response
      print_error('Unable to retrieve any data from ViewDNS.info website.')
      return []
    end

    html = response.get_html_document
    table = html.css('table')[3]

    unless table.nil?
      rows = table.css('tr')

      ar_ips = []
      rows.each.map do |row|
        row = /(\d*\.\d*\.\d*\.\d*)/.match(row.css('td').map(&:text).to_s)
        unless row.nil?
          ar_ips.push(row)
        end
      end
    end

    if ar_ips.nil?
      print_bad('No domain IP(s) history founds.')
      return []
    end

    ar_ips
  end

  def http_get_request_raw(host, port, ssl, uri, vhost = nil)
    begin
      http = Rex::Proto::Http::Client.new(host, port, {}, ssl, nil, datastore['Proxies'])
      http.connect(datastore['TIMEOUT'])

      unless vhost.nil?
        http.set_config({ 'vhost' => vhost })
      end

      request = http.request_raw({
        'method' => 'GET',
        'uri' => uri,
        'agent' => datastore['USERAGENT']
      })
      response = http.send_recv(request)
      http.close
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT, StandardError => error
      print_error(error.message)
    end
    return false if response.nil?

    response
  end

  # auxiliary/gather/censys_search.rb
  def parse_ipv4(records)
    ip_list = []
    records.each do |ipv4|
      ip_list.push(ipv4['ip'])
    end
    ip_list
  end

  # auxiliary/gather/enum_dns.rb
  def save_note(hostname, ip, port, proto, ebypass)
    data = { 'vhost' => hostname, 'detected_ip' => ip, 'action' => @my_action.name, 'effective_bypass' => ebypass }
    report_note(
      host: hostname,
      service: proto,
      port: port,
      type: 'auxiliary.gather.cloud_lookup',
      data: data,
      update: :unique_data
    )
  end

  # ------------------------------------------------------------------------- #

  def check_bypass(fingerprint, ip)
    # Check for "misconfigured" web server on TCP/80.
    if check_tcp_port(ip, 80)
      ret_value ||= check_request(fingerprint, ip, 80, false)
    end

    # Check for "misconfigured" web server on TCP/443.
    if check_tcp_port(ip, 443)
      ret_value ||= check_request(fingerprint, ip, 443, true)
    end

    ret_value
  end

  def check_request(fingerprint, ip, port, ssl)
    proto = (ssl ? 'https' : 'http')

    vprint_status(" * Trying: #{proto}://#{ip}:#{port}/")
    response = http_get_request_raw(ip, port, ssl, datastore['URIPATH'], datastore['HOSTNAME'])

    if response
      return false if detect_signature(response)

      if response.code == 200
        found = false

        html = response.get_html_document
        begin
          # Searches for the chain to compare in the defined tag.
          found = true if html.at(datastore['TAG']).to_s.include? fingerprint.to_s.encode('utf-8')
        rescue NoMethodError, Encoding::CompatibilityError
          return false
        end

        if found
          print_good("A direct-connect IP address was found: #{proto}://#{ip}:#{port}/")
          if @my_action.name == 'NoWAFBypass'
            save_note(datastore['HOSTNAME'], ip, port, proto, 'manual check claimed')
          else
            save_note(datastore['HOSTNAME'], ip, port, proto, true)
          end
          return true
        end

      elsif response.redirect?
        found = false

        vprint_line("      --> responded with HTTP status code: #{response.code} to #{response.headers['location']}")
        begin
          found = true if response.headers['location'].include?(datastore['hostname'])
        rescue NoMethodError, Encoding::CompatibilityError
          return false
        end

        if found
          print_warning("A leaked IP address was found: #{proto}://#{ip}:#{port}/")
          save_note(datastore['HOSTNAME'], ip, port, proto, false) if datastore['REPORT_LEAKS']
        end

      else
        vprint_line("      --> responded with an unhandled HTTP status code: #{response.code}")
      end
    end

    return false
  end

  def detect_action(data)
    actions.each do |my_action|
      next if my_action.name == 'Automatic'

      my_action['Signatures'].each do |signature|
        return my_action if data.headers.to_s.downcase.include?(signature.downcase)
      end
    end
    return nil
  end

  def detect_signature(data)
    @my_action['Signatures'].each do |signature|
      return true if data.headers.to_s.downcase.include?(signature.downcase)
    end
    return false
  end

  def arvancloud_ips
    response = http_get_request_raw(
      'www.arvancloud.com',
      443,
      true,
      '/en/ips.txt'
    )
    return false if response.nil?

    response.get_html_document.text.split("\n")
  end

  # https://docs.microsoft.com/fr-fr/azure/cdn/cdn-pop-list-api
  def azurecdn_ips
    regions = {
      'region' => 'asiaeast', 'region' => 'asiasoutheast', 'region' => 'australiaeast', 'region' => 'australiasoutheast', 'region' => 'canadacentral',
      'region' => 'canadaeast', 'region' => 'chinaeast', 'region' => 'chinanorth', 'region' => 'europenorth', 'region' => 'europewest',
      'region' => 'germanycentral', 'region' => 'germanyn', 'region' => 'germanynortheast', 'region' => 'indiacentral', 'region' => 'indiasouth',
      'region' => 'indiawest', 'region' => 'japaneast', 'region' => 'japanwest', 'region' => 'brazilsouth', 'region' => 'koreasouth',
      'region' => 'koreacentral', 'region' => 'ukwest', 'region' => 'uksouth', 'region' => 'uscentral', 'region' => 'useast',
      'region' => 'useast2', 'region' => 'usnorth', 'region' => 'ussouth', 'region' => 'uswestcentral', 'region' => 'uswest',
      'region' => 'uswest2'
    }
    params = regions.merge({
      'complement' => 'on',
      'outputformat' => 'list-cidr'
    })

    begin
      cli = Rex::Proto::Http::Client.new('azurerange.azurewebsites.net', 443, {}, true, nil, datastore['Proxies'])
      cli.connect

      response = cli.request_cgi(
        'method' => 'GET',
        'uri' => '/Download/',
        'agent' => datastore['USERAGENT'],
        'vars_get' => params
      )
      results = cli.send_recv(response)
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error('HTTP connection failed to Azurerange website.')
    end

    unless results
      print_error('Unable to retrieve any data from Azurerange website.')
      return false
    end

    results.get_html_document.css('p').text.split("\r\n")
  end

  def cloudflare_ips
    response = http_get_request_raw(
      'www.cloudflare.com',
      443,
      true,
      '/ips-v4'
    )
    return false if response.nil?

    response.get_html_document.css('p').text.split("\n")
  end

  def cloudfront_ips
    response = http_get_request_raw(
      'd7uri8nf7uskq.cloudfront.net',
      443,
      true,
      '/tools/list-cloudfront-ips'
    )
    return false if response.nil?

    ip_list = response.get_json_document['CLOUDFRONT_GLOBAL_IP_LIST']
    ip_list += response.get_json_document['CLOUDFRONT_REGIONAL_EDGE_IP_LIST']

    ip_list.map { |ip| ip.gsub('"', '') }
  end

  def fastly_ips
    response = http_get_request_raw(
      'api.fastly.com',
      443,
      true,
      '/public-ip-list'
    )
    return false if response.nil?

    response.get_json_document['addresses'].map { |ip| ip.gsub('"', '') }
  end

  def incapsula_ips
    begin
      cli = Rex::Proto::Http::Client.new('my.incapsula.com', 443, {}, true, nil, datastore['Proxies'])
      cli.connect

      response = cli.request_cgi(
        'method' => 'POST',
        'uri' => '/api/integration/v1/ips',
        'agent' => datastore['USERAGENT'],
        'vars_post' => { 'resp_format' => 'json' }
      )
      results = cli.send_recv(response)
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error('HTTP connection failed to Incapsula website.')
    end

    unless results
      print_error('Unable to retrieve any data from Incapsula website.')
      return false
    end

    results.get_json_document['ipRanges'].map { |ip| ip.gsub('"', '') }
  end

  def stackpath_ips
    response = http_get_request_raw(
      'support.stackpath.com',
      443,
      true,
      nil,
      '/hc/en-us/article_attachments/360030796372/ipblocks.txt'
    )
    return false if response.nil?

    ip_list = []
    response.get_html_document.text.split("\n").each do |ip|
      ip_list.push(ip) if ip =~ /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))$/
    end

    ip_list
  end

  def pick_action
    return action if action.name != 'Automatic'

    response = http_get_request_raw(
      datastore['HOSTNAME'],
      datastore['RPORT'],
      datastore['SSL'],
      datastore['URIPATH']
    )
    return nil unless response

    detect_action(response)
  end

  # ------------------------------------------------------------------------- #

  def run
    # If the action can be detected automatically. (Action: Automatic)
    @my_action = pick_action
    if @my_action.nil?
      # If the automatic search fails, bye bye.
      unless datastore['ALLOW_NOWAF']
        print_error('Couldn\'t determine the action automatically.')
        return
      end
      # If allowed, and the automatic action fails, searches for all website occurrences without regard to filtering systems.
      actions.each do |my_action|
        @my_action = my_action if my_action.name == 'NoWAFBypass'
      end
    end
    vprint_status("Selected action: #{@my_action.name}")

    print_status('Passive gathering information...')

    domain_name = PublicSuffix.parse(datastore['HOSTNAME']).domain
    ip_list = []

    # Start collecting informations for grabbing all IP adress(es).

    # ViewDNS.info
    ip_records = grab_domain_ip_history(domain_name)
    if ip_records && !ip_records.empty?
      ip_list |= ip_records
    end
    print_status(" * ViewDNS.info: #{ip_records.count} IP address(es) found.")

    # DNS Enumeration
    if datastore['DNSENUM']
      ip_records = dns_enumeration(domain_name, datastore['THREADS'])
      if ip_records && !ip_records.empty?
        ip_list |= ip_records
      end
      print_status(" * DNS Enumeration: #{ip_records.count} IP address(es) found.")
    end

    # Censys search
    if [datastore['CENSYS_UID'], datastore['CENSYS_SECRET']].none?(&:nil?)
      ip_records = censys_search(domain_name, 'ipv4', datastore['CENSYS_UID'], datastore['CENSYS_SECRET'])
      if ip_records && !ip_records.empty?
        ip_list |= ip_records
      end
      print_status(" * Censys IPv4: #{ip_records.count} IP address(es) found.")
    end
    print_status

    # Exit if no IP address(es) has been found.
    if ip_list.empty?
      print_bad('No IP address found :-(')
      return
    end

    # Comparison to remove address(es) that match the security solution to be tested.
    # except:
    #  - the selected action is set to NoWAFBypass
    #  - addresses are not provided

    # Cleaning IP addresses if nessesary.
    case @my_action.name
    when /ArvanCloud/
      ip_blacklist = arvancloud_ips
    when /AzureCDN/
      ip_blacklist = azurecdn_ips
    when /CloudFlare/
      ip_blacklist = cloudflare_ips
    when /CloudFront/
      ip_blacklist = cloudfront_ips
    when /Fastly/
      ip_blacklist = fastly_ips
    when /Incapsula/
      ip_blacklist = incapsula_ips
    when /InGen Security/
      # Public address(es) not available, check for known provider DNS responses match  :-)
      ip_list.uniq.each do |ip|
        a = dns_get_a(ip.to_s)
        ['binarysec', 'easywaf', 'ingensec', '127.0.0.1'].each do |signature|
          ip_blacklist << ip.to_s if a.to_s.downcase.include? signature.downcase
        end
      end
    when /Stackpath/
      ip_blacklist = stackpath_ips
    end

    # Time to clean, removing bad address(es).
    records = []
    if ip_blacklist
      print_status("Clean #{@my_action.name} server(s)...")
      ip_list.uniq.each do |ip|
        is_listed = false

        ip_blacklist.each do |ip_range|
          if IPAddr.new(ip_range).include? ip.to_s
            is_listed = true
            break
          end
        end

        records << ip.to_s unless is_listed
      end
    else
      records.concat(ip_list.uniq.map { |ip| ip.to_s })
    end

    # Exit if no IP address(es) has been found after cleaning.
    if records.empty?
      print_bad('No IP address found after cleaning.')
      return
    end

    print_status(" * TOTAL: #{records.uniq.count} IP address(es) found after cleaning.")
    print_status

    # Processing bypass steps.

    print_status("Bypass #{action.name} is in progress...")
    if datastore['COMPSTR'].nil?
      # If no customized comparison string is entered by the user, search automatically into the user defined TAG (default: <title>).
      print_status(" * Initial request to the original server for <#{datastore['TAG']}> comparison")
      response = http_get_request_raw(
        datastore['HOSTNAME'],
        datastore['RPORT'],
        datastore['SSL'],
        datastore['URIPATH']
      )
      html = response.get_html_document
      begin
        fingerprint = html.at(datastore['TAG'])
      rescue NoMethodError
        print_bad('Please, considere COMPSTR option!')
        return
      end
    else
      # The user-defined comparison string does not require a request to initiate a connection to the target server.
      # The comparison is made by the check_bypass function in the user-defined TAG (default: <title>).
      fingerprint = datastore['COMPSTR']
    end

    # Loop for each unique IP:PORT candidate to check bypass.
    ret_value = false
    records.uniq.each do |ip|
      found = check_bypass(
        fingerprint,
        ip
      )
      ret_value = true if found
    end

    # message indicating that nothing was found.
    unless ret_value
      print_bad('No direct-connect IP address found :-(')
    end
  end

end
