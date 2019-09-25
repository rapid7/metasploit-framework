##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Cloud Lookup (and bypass)',
      'Description' => %q{
        This module can be useful if you need to test the security of your server and your
        website behind a solution Cloud based. By discovering the origin IP address of the
        targeted host.

        More precisely, I use multiple data sources (in order ViewDNS.info, DNS enumeration and Censys)
        to collect assigned (or have been assigned) IP addresses from the targeted site or domain
        that uses the following:
          * Amazon Cloudflare, Amazon CloudFront, ArvanCloud, Envoy Proxy, Fastly, Stackpath Fireblade,
            Stackpath MaxCDN, Imperva Incapsula, InGen Security (BinarySec EasyWAF), KeyCDN, Netlify and
            Sucuri.
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
        ['Amazon CloudFlare',
          {
            'Description' => 'Cloud based Web application firewall of Amazon',
            'Signatures' => ['server: cloudflare']
          }
        ],
        ['Amazon CloudFront',
          {
            'Description' => 'Content Delivery Network services of Amazon',
            'Signatures' => ['x-amz-cf-id:']
          }
        ],
        ['ArvanCloud CDN',
          {
            'Description' => 'ArvanCloud CDN comprises tens of PoP sites in important locations all around the world to deliver online content to the users',
            'Signatures' => ['server: ArvanCloud']
          }
        ],
        ['Envoy Proxy',
          {
            'Description' => 'An open source edge and service proxy, designed for Cloud-Native applications',
            'Signatures' => ['server: envoy']
          }
        ],
        ['Fastly',
          {
            'Description' => 'Another widely used CDN/WAF solution',
            'Signatures' => ['Fastly-SSL']
          }
        ],
        ['Imperva Incapsula',
          {
            'Description' => 'Cloud based Web application firewall of Imperva',
            'Signatures' => ['X-CDN: Incapsula']
          }
        ],
        ['InGen Security (BinarySec EasyWAF)', # Reunion island powa!
          {
            'Description' => 'Cloud based Web application firewall of InGen Security and BinarySec',
            'Signatures' => ['binarysec', 'server: gatejs']
          }
        ],
        ['KeyCDN',
          {
            'Description' => 'KeyCDN is a high performance content delivery network that has been built for the future', # lol
            'Signatures' => ['Server: keycdn-engine']
          }
        ],
        ['Netlifi',
          {
            'Description' => 'One workflow, from local development to global deployment',
            'Signatures' => ['x-nf-request-id:']
          }
        ],
        ['Stackpath Fireblade',
          {
            'Description' => 'Enterprise Website Security & DDoS Protection',
            'Signatures' => ['Server: fbs']
          }
        ],
        ['Stackpath MaxCDN',
          {
            'Description' => 'Speed Up your Content Delivery',
            'Signatures' => ['Server: NetDNA-cache']
          }
        ],
        ['Sucuri',
          {
            'Description' => 'Cloud based Web application firewall of Sucuri',
            'Signatures' => ['x-sucuri-id:']
          }
        ],
      ],
      'DefaultAction' => 'Automatic'
    ))

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
      OptBool.new('DNSENUM', [true, 'Set DNS enumeration as optional', true]),
      OptAddress.new('NS', [false, 'Specify the nameserver to use for queries (default is system DNS)']),
      OptBool.new('REPORT_LEAKS', [true, 'Set to write leaked ip addresses in notes', false]),
      OptString.new('USERAGENT', [true, 'Specify a personalized User-Agent header in HTTP requests', 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0']),
      OptEnum.new('TAG', [true, 'Specify the HTML tag in which you want to find the fingerprint', 'title', ['title', 'html']]),
      OptInt.new('TIMEOUT', [true, 'HTTP(s) request timeout', 8])
    ])
  end

  # ------------------------------------------------------------------------- #

  ## auxiliary/gather/censys_search.rb
  def basic_auth_header(username, password)
    auth_str = username.to_s + ":" + password.to_s
    return "Basic " + Rex::Text.encode_base64(auth_str)
  end

  ## auxiliary/gather/censys_search.rb
  def censys_search(keyword, search_type, uid, secret)
    begin
      payload = {'query' => keyword}

      cli = Rex::Proto::Http::Client.new('www.censys.io', 443, {}, true)
      cli.connect

      response = cli.request_cgi(
        'method' => 'POST',
        'uri' => "/api/v1/search/#{search_type}",
        'headers' => {
          'Authorization' => basic_auth_header(uid, secret)
        },
        'data' => payload.to_json
      )
      results = cli.send_recv(response)

    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error("HTTP Connection Failed")
    end

    unless(results)
      print_error('server_response_error')
      return false
    end

    records = ActiveSupport::JSON.decode(results.body)
    results = records['results']

    return parse_ipv4(results)
  end

  def check_tcp_port(ip, port)
    begin
      sock = Rex::Socket::Tcp.create(
        'PeerHost' => ip,
        'PeerPort' => port,
        'Proxies'  => datastore['Proxies']
      )
    rescue ::Rex::ConnectionRefused, Rex::ConnectionError
      return false
    end
    sock.close
    return true
  end

  ## auxiliary/gather/enum_dns.rb
  def dns_enumeration(domain, threads)
    wordlist = datastore['WORDLIST']
    return if wordlist.blank?
    threads = 1 if threads <= 0

    queue = []
    File.foreach(wordlist) do | line |
      queue << "#{line.chomp}.#{domain}"
    end

    ar_ips = []
    until queue.empty?
      t = []
      threads = 1 if threads <= 0

      if queue.length < threads
        # work around issue where threads not created as the queue isn't large enough
        threads = queue.length
      end

      begin
        1.upto(threads) do
          t << framework.threads.spawn("Module(#{refname})", false, queue.shift) do | test_current |
            Thread.current.kill unless test_current
            a = /(\d*\.\d*\.\d*\.\d*)/.match(dns_get_a(test_current, 'DNS bruteforce records').to_s)
            ar_ips.push(a) if a
          end
        end
        t.map(&:join)

      rescue ::Timeout::Error
      ensure
        t.each { | x | x.kill rescue nil }
      end
    end

    if ar_ips.empty?
      print_bad('No enumerated domain IP(s) founds.')
      return false
    end

    return ar_ips
  end

  ## auxiliary/gather/enum_dns.rb
  def dns_get_a(domain, type = 'DNS A records')
    response = dns_query(domain, 'A')
    return if response.blank? || response.answer.blank?

    response.answer.each do | row |
      next unless row.class == Net::DNS::RR::A
    end
  end

  ## auxiliary/gather/enum_dns.rb
  def dns_query(domain, type)
    nameserver = datastore['NS']

    if nameserver.blank?
      dns = Net::DNS::Resolver.new
    else
      dns = Net::DNS::Resolver.new(nameservers: ::Rex::Socket.resolv_to_dotted(nameserver))
    end

    dns.use_tcp        = false
    dns.udp_timeout    = 8
    dns.retry_number   = 2
    dns.retry_interval = 2
    dns.query(domain, type)
  rescue ResolverArgumentError, Errno::ETIMEDOUT, ::NoResponseError, ::Timeout::Error => e
    print_error("Query #{domain} DNS #{type} - exception: #{e}")
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
      return false
    end

    html = response.get_html_document
    table = html.css('table')[3]

    unless table.nil?
      rows = table.css('tr')

      ar_ips = []
      rows.each.map do | row |
        row = /(\d*\.\d*\.\d*\.\d*)/.match(row.css('td').map(&:text).to_s)
        unless row.nil?
          ar_ips.push(row)
        end
      end
    end

    if ar_ips.nil?
      print_bad('No domain IP(s) history founds.')
      return false
    end

    return ar_ips
  end

  def http_get_request_raw(host, port, ssl, host_header = nil, uri)
    begin
      http = Rex::Proto::Http::Client.new(host, port, {}, ssl, nil, datastore['Proxies'])
      http.connect(datastore['TIMEOUT'])

      unless host_header.eql? nil
        http.set_config({'vhost' => host_header})
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

    return response
  end

  ## auxiliary/gather/censys_search.rb
  def parse_ipv4(records)
    ip_list = []
    records.each do | ipv4 |
      ip_list.push(ipv4['ip'])
    end
    return ip_list
  end

  ## auxiliary/gather/enum_dns.rb
  def save_note(hostname, ip, port, sname, ebypass)
    data = {'vhost' => hostname, 'real_ip' => ip, 'action' => @my_action.name, 'effective_bypass' => ebypass}
    report_note(
      :host => hostname,
      :port => port,
      :type => 'Cloud Lookup (and bypass)',
      :data => data,
      update: :unique_data
    )
  end

  # ------------------------------------------------------------------------- #

  def check_bypass(fingerprint, ip)
    ret_value = false

    # Check for "misconfigured" web server on TCP/80.
    if(check_tcp_port(ip, 80))
      found = check_request(fingerprint, ip, 80, false)
    end
    ret_value = true if found

    # Check for "misconfigured" web server on TCP/443.
    if(check_tcp_port(ip, 443))
      found = check_request(fingerprint, ip, 443, true)
    end
    ret_value = true if found

    return ret_value
  end

  def check_request(fingerprint, ip, port, ssl)
    proto = (ssl ? 'https' : 'http')

    vprint_status(" * Trying: #{proto}://#{ip}:#{port}/")
    response = http_get_request_raw(ip, port, ssl, datastore['HOSTNAME'], datastore['URIPATH'])
    if response != false
      return false if detect_solution(response, @my_action.name)

      if response.code.eql? 200
        html = response.get_html_document
        begin
          if html.at(datastore['TAG']).to_s.include? fingerprint.to_s.encode('utf-8')
            print_good("A direct-connect IP address was found: #{proto}://#{ip}:#{port}/")
            save_note(datastore['HOSTNAME'], ip, port, proto, true)
            return true
          end
        rescue NoMethodError, Encoding::CompatibilityError
          return false
        end
      else
        if response.redirect?
          vprint_line("      --> responded with HTTP status code: #{response.code.to_s} to #{response.headers['location']}")
          begin
            if response.headers['location'].include?(datastore['hostname'])
              print_warning("A leaked IP address was found: #{proto}://#{ip}:#{port}/")
              save_note(datastore['HOSTNAME'], ip, port, proto, false) if datastore['REPORT_LEAKS'].eql? true
            end
          rescue NoMethodError, Encoding::CompatibilityError
            return false
          end
        else
          vprint_line("      --> responded with an unhandled HTTP status code: #{response.code.to_s}")
        end
      end
    end

    return false
  end

  def detect_solution(data, name = nil)
    if name.nil?
      actions.each do | my_action |
        unless my_action.name == 'Automatic'
          my_action['Signatures'].each do | signature |
            return my_action if data.headers.to_s.downcase.include?(signature.downcase)
          end
        end
      end
    else
      actions.each do | my_action |
        if my_action.name == name
          my_action['Signatures'].each do | signature |
            return true if data.headers.to_s.downcase.include?(signature.downcase)
          end
        end
      end
    end

    return nil
  end

  def get_arvancloud_ips
    response = http_get_request_raw(
      'www.arvancloud.com',
      443,
      true,
      nil,
      '/en/ips.txt'
    )
    return false if response.nil?

    ip_list  = []
    response.get_html_document.text.split("\n").each do | ip |
      ip_list.push(ip)
    end

    return ip_list
  end

  def get_cloudflare_ips
    response = http_get_request_raw(
      'www.cloudflare.com',
      443,
      true,
      nil,
      '/ips-v4'
    )
    return false if response.nil?

    ip_list  = []
    response.get_html_document.css('p').text.split("\n").each do | ip |
      ip_list.push(ip)
    end

    return ip_list
  end

  def get_cloudfront_ips
    response = http_get_request_raw(
      'd7uri8nf7uskq.cloudfront.net',
      443,
      true,
      nil,
      '/tools/list-cloudfront-ips'
    )
    return false if response.nil?

    ip_list = []
    response.get_json_document['CLOUDFRONT_GLOBAL_IP_LIST'].each do | ip |
      ip_list.push(ip.gsub('"', ''))
    end

    response.get_json_document['CLOUDFRONT_REGIONAL_EDGE_IP_LIST'].each do | ip |
      ip_list.push(ip.gsub('"', ''))
    end

    return ip_list
  end

  def get_fastly_ips
    response = http_get_request_raw(
      'api.fastly.com',
      443,
      true,
      nil,
      '/public-ip-list'
    )
    return false if response.nil?

    ip_list = []
    response.get_json_document['addresses'].each do | ip |
      ip_list.push(ip.gsub('"', ''))
    end

    return ip_list
  end

  def get_incapsula_ips
    begin
      cli = Rex::Proto::Http::Client.new('my.incapsula.com', 443, {}, true)
      cli.connect

      response = cli.request_cgi(
        'method' => 'POST',
        'uri' => '/api/integration/v1/ips',
        'vars_post' => {'resp_format' => 'json'}
      )
      results = cli.send_recv(response)

    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error("HTTP Connection Failed")
    end

    unless(results)
      print_error('server_response_error')
      return false
    end

    ip_list = []
    results.get_json_document['ipRanges'].each do | ip |
      ip_list.push(ip.gsub('"', ''))
    end

    return ip_list
  end

  def get_stackpath_ips
    response = http_get_request_raw(
      'support.stackpath.com',
      443,
      true,
      nil,
      '/hc/en-us/article_attachments/360030796372/ipblocks.txt'
    )
    return false if response.nil?

    ip_list  = []
    response.get_html_document.text.split("\n").each do | ip |
      ip_list.push(ip) if ip =~ /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))$/
    end

    return ip_list
  end

  def pick_action
    return action unless action.name.eql? 'Automatic'

    response = http_get_request_raw(
      datastore['HOSTNAME'],
      datastore['RPORT'],
      datastore['SSL'],
      nil,
      datastore['URIPATH']
    )
    return nil if response.nil?

    return detect_solution(response)
  end

  # ------------------------------------------------------------------------- #

  def run
    @my_action = pick_action
    if @my_action.nil?
      print_error("Couldn't determine the action automaticaly.")
      return
    end
    vprint_status("Selected action: #{@my_action.name}")

    print_status('Passive gathering information...')

    domain_name = PublicSuffix.parse(datastore['HOSTNAME']).domain
    ip_list = []

    # ViewDNS.info
    ip_records = grab_domain_ip_history(domain_name)
    ip_list |= ip_records unless ip_records.eql? false
    unless ip_records.eql? false
      print_status(" * ViewDNS.info: #{ip_records.count.to_s} IP address found(s).")
    end

    # DNS Enumeration
    if datastore['DNSENUM'].eql? true
      ip_records = dns_enumeration(domain_name, datastore['THREADS'])
      ip_list |= ip_records unless ip_records.eql? false
      unless ip_records.eql? false
        print_status(" * DNS Enumeration: #{ip_records.count.to_s} IP address found(s).")
      end
    end

    # Censys search
    if [datastore['CENSYS_UID'], datastore['CENSYS_SECRET']].none?(&:nil?)
      ip_records = censys_search(domain_name, 'ipv4', datastore['CENSYS_UID'], datastore['CENSYS_SECRET'])
      ip_list |= ip_records unless ip_records.eql? false
      unless ip_records.eql? false
        print_status(" * Censys IPv4: #{ip_records.count.to_s} IP address found(s).")
        print_status
      end
    end

    if ip_list.empty?
      print_bad('No IP address found :-(')
      return
    end

    # Cleaning IP addresses if nessesary
    case @my_action.name
    when /ArvanCloud/
      ip_blacklist = get_arvancloud_ips
    when /CloudFlare/
      ip_blacklist = get_cloudflare_ips
    when /CloudFront/
      ip_blacklist = get_cloudfront_ips
    when /Fastly/
      ip_blacklist = get_fastly_ips
    when /Incapsula/
      ip_blacklist = get_incapsula_ips
    when /InGen Security/
      ip_list.uniq.each do | ip |
        a = dns_get_a(ip.to_s)
        ['binarysec', 'easywaf', 'ingensec', '127.0.0.1'].each do | signature |
          ip_blacklist << ip.to_s if a.to_s.downcase.include? signature.downcase
        end
      end
    when /Stackpath/
      ip_blacklist = get_stackpath_ips
    end

    records = []
    if ip_blacklist
      print_status("Clean #{@my_action.name} server(s)...")
      ip_list.uniq.each do | ip |
        is_listed = false

        ip_blacklist.each do | ip_range |
          if IPAddr.new(ip_range).include? ip.to_s
            is_listed = true
            break
          end
        end

        unless is_listed.eql? true
          records << ip.to_s
        end
      end
    else
      ip_list.uniq.each do | ip |
        records << ip.to_s
      end
    end

    if records.empty?
      print_bad("No IP address found after cleaning.")
      return
    end

    print_status(" * TOTAL: #{records.uniq.count.to_s} IP address found(s) after cleaning.")
    print_status

    # Processing bypass...
    print_status("Bypass #{action.name} is in progress...")

    if datastore['COMPSTR'].nil?
      # Initial HTTP request to the server
      print_status(" * Initial request to the original server for <#{datastore['TAG']}> comparison")
      response = http_get_request_raw(
        datastore['HOSTNAME'],
        datastore['RPORT'],
        datastore['SSL'],
        nil,
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
      fingerprint = datastore['COMPSTR']
    end

    # Loop for each uniq IP candidate to check bypass
    ret_val = false
    records.uniq.each do | ip |
      found = check_bypass(
        fingerprint,
        ip
      )
      ret_val = true if found.eql? true
    end

    unless ret_val.eql? true
      print_bad('No direct-connect IP address found :-(')
    end
  end

end
