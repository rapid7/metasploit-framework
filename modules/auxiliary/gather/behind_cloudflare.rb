##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
# rev: 1.1.7

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Behind CloudFlare',
      'Description'    => %q{
        This module can be useful if you need to test
        the security of your server and your website
        behind CloudFlare by discovering the real IP address.
      },
      'Author'         => [
        'mekhalleh',
        'RAMELLA Sébastien <sebastien.ramella[at]Pirates.RE>'
      ],
      'References'     => [
        ['URL', 'http://www.crimeflare.com/cfs.html'],
        ['URL', 'https://github.com/HatBashBR/HatCloud'],
        ['URL', 'https://github.com/christophetd/CloudFlair']
      ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
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

    register_advanced_options(
      [
        OptBool.new('DNSENUM', [true, 'Set DNS enumeration as optional', true]),
        OptAddress.new('NS', [false, 'Specify the nameserver to use for queries (default is system DNS)']),
        OptInt.new('TIMEOUT', [true, 'HTTP(s) request timeout', 15])
      ])
  end

  def do_check_tcp_port(ip, port, proxies)
    begin
      sock = Rex::Socket::Tcp.create(
        'PeerHost' => ip,
        'PeerPort' => port,
        'Proxies'  => proxies
      )
    rescue ::Rex::ConnectionRefused, Rex::ConnectionError
      return false
    end
    sock.close
    return true
  end

  def do_grab_domain_ip_history(hostname, proxies)
    begin
      cli = Rex::Proto::Http::Client.new('viewdns.info', 443, {}, true, nil, proxies)
      cli.connect

      request = cli.request_cgi({
        'uri'    => "/iphistory/?domain=#{hostname}",
        'method' => 'GET'
      })
      response = cli.send_recv(request)
      cli.close

    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error('HTTP connection failed to ViewDNS.info website.')
      return false
    end

    html  = response.get_html_document
    table = html.css('table')[3]

    unless table.nil?
      rows   = table.css('tr')
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

  ## auxiliary/gather/enum_dns.rb
  def do_dns_enumeration(domain, threads)
    wordlist = datastore['WORDLIST']
    return if wordlist.blank?
    threads  = 1 if threads <= 0

    queue    = []
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
            a = /(\d*\.\d*\.\d*\.\d*)/.match(do_dns_get_a(test_current, 'DNS bruteforce records').to_s)
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
  def do_dns_get_a(domain, type='DNS A records')
    response = do_dns_query(domain, 'A')
    return if response.blank? || response.answer.blank?

    response.answer.each do | row |
      next unless row.class == Net::DNS::RR::A
    end
  end

  ## auxiliary/gather/enum_dns.rb
  def do_dns_query(domain, type)
    nameserver         = datastore['NS']

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

  ## auxiliary/gather/enum_dns.rb
  def do_save_note(hostname, ip, sname)
    data = { 'vhost' => hostname, 'real_ip' => ip, 'sname' => sname }
    report_note(
      :host  => hostname,
      :type  => "behind_cloudflare",
      :data  => data,
      update: :unique_data
    )
  end

  def do_simple_get_request_raw(host, port, ssl, host_header=nil, uri, proxies)
    begin
      http    = Rex::Proto::Http::Client.new(host, port, {}, ssl, nil, proxies)
      http.connect(datastore['TIMEOUT'])

      unless host_header.eql? nil
        http.set_config({ 'vhost' => host_header })
      end

      request = http.request_raw({
        'uri'     => uri,
        'method'  => 'GET',
        'agent'   => 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0'
      })
      response = http.send_recv(request)
      http.close

    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT, StandardError => error
      print_error(error.message)
    end
    return false if response.nil?

    return response
  end

  def get_cloudflare_ips
    response = do_simple_get_request_raw(
      'www.cloudflare.com',
      443,
      true,
      nil,
      '/ips-v4',
      datastore['PROXIES']
    )
    return false if response.nil?

    ip_list  = []
    response.get_html_document.css('p').text.split("\n").each do | ip |
      ip_list.push(ip)
    end

    return ip_list
  end

  def do_check_bypass(fingerprint, tag, host, ip, uri, proxies)
    ret_value = false

    # Check for "misconfigured" web server on TCP/80.
    if do_check_tcp_port(ip, 80, proxies)
      vprint_status(" * Trying: http://#{ip}:80/")
      response = do_simple_get_request_raw(ip, 80, false, host, uri, proxies)
      if response != false

        if response.code.eql? 200
          html = response.get_html_document

          if html.at(tag).to_s.include? fingerprint.to_s
            print_good("A direct-connect IP address was found: http://#{ip}:80/")
            do_save_note(host, ip, 'http')
            ret_value = true
          end
        else
          vprint_line("      --> responded with an unexpected HTTP status code: #{response.code.to_s}")
        end
      end
    end

    # Check for "misconfigured" web server on TCP/443.
    if do_check_tcp_port(ip, 443, proxies)
      vprint_status(" * Trying: https://#{ip}:443/")
      response = do_simple_get_request_raw(ip, 443, true, host, uri, proxies)
      if response != false

        if response.code.eql? 200
          if response != false
            html = response.get_html_document
            if html.at(tag).to_s.include? fingerprint.to_s
              print_good("A direct-connect IP address was found: https://#{ip}:443/")
              do_save_note(host, ip, 'https')
              ret_value = true
            end
          end
        else
          vprint_line("      --> responded with an unexpected HTTP status code: #{response.code.to_s}")
        end
      end
    end

    return ret_value
  end

  ## auxiliary/gather/censys_search.rb
  def basic_auth_header(username, password)
    auth_str = username.to_s + ":" + password.to_s
    auth_str = "Basic " + Rex::Text.encode_base64(auth_str)
  end

  ## auxiliary/gather/censys_search.rb
  def search(keyword, search_type, uid, secret)
    begin
      payload  = {
        'query' => keyword
      }

      cli      = Rex::Proto::Http::Client.new('www.censys.io', 443, {}, true)
      cli.connect

      response = cli.request_cgi(
        'method'  => 'post',
        'uri'     => "/api/v1/search/#{search_type}",
        'headers' => {
          'Authorization' => basic_auth_header(uid, secret)
        },
        'data'    => payload.to_json
      )
      results  = cli.send_recv(response)

    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error("HTTP Connection Failed")
    end

    unless results
      print_error('server_response_error')
      return false
    end

    records = ActiveSupport::JSON.decode(results.body)
    results = records['results']

    return parse_ipv4(results)
  end

  ## auxiliary/gather/censys_search.rb
  def parse_ipv4(records)
    ip_list = []
    records.each do | ipv4 |
      ip_list.push(ipv4['ip'])
    end
    return ip_list
  end

  ## auxiliary/gather/censys_search.rb
  def valid_domain?(domain)
    domain =~ /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/
  end

  def run
    print_status('Passive gathering information...')

    domain_name   = PublicSuffix.parse(datastore['HOSTNAME']).domain
    ip_list       = []

    # ViewDNS.info
    ip_records    = do_grab_domain_ip_history(domain_name, datastore['Proxies'])
    ip_list      |= ip_records unless ip_records.eql? false
    unless ip_records.eql? false
      print_status(" * ViewDNS.info: #{ip_records.count.to_s} IP address found(s).")
    end

    # DNS Enum.
    if datastore['DNSENUM'].eql? true
      ip_records   = do_dns_enumeration(domain_name, datastore['THREADS'])
      ip_list     |= ip_records unless ip_records.eql? false
      unless ip_records.eql? false
        print_status(" * DNS Enumeration: #{ip_records.count.to_s} IP address found(s).")
      end
    end

    # Censys search.
    if [datastore['CENSYS_UID'], datastore['CENSYS_SECRET']].none?(&:nil?)
      ip_records  = search(domain_name, 'ipv4', datastore['CENSYS_UID'], datastore['CENSYS_SECRET'])
      ip_list    |= ip_records unless ip_records.eql? false
      unless ip_records.eql? false
        print_status(" * Censys IPv4: #{ip_records.count.to_s} IP address found(s).")
        print_status()
      end
    end

    if ip_list.empty?
      print_bad('No IP address found :-(')
      return
    end

    # Cleaning the results.
    print_status("Clean cloudflare server(s)...")
    ip_blacklist = get_cloudflare_ips
    records      = []
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

    if records.empty?
      print_bad("No IP address found after cleaning.")
      return
    end

    print_good(" * TOTAL: #{records.uniq.count.to_s} IP address found(s) after cleaning.")
    print_status()

    # Processing bypass...
    print_status('Bypass cloudflare is in progress...')

    if datastore['COMPSTR'].nil?
      tag         = 'title'

      # Initial HTTP request to the server (for <title> comparison).
      print_status(' * Initial request to the original server for comparison')
      response    = do_simple_get_request_raw(
        datastore['HOSTNAME'],
        datastore['RPORT'],
        datastore['SSL'],
        nil,
        datastore['URIPATH'],
        datastore['PROXIES']
      )
      html        = response.get_html_document
      fingerprint = html.at(tag).text
      if fingerprint.eql? 'Attention Required! | Cloudflare'
        tag         = 'html'
        fingerprint = datastore['HOSTNAME']
      end
    else
      tag         = 'html'
      fingerprint = datastore['COMPSTR']
    end

    ret_val  = false
    records.uniq.each do | ip |

      found = do_check_bypass(
        fingerprint,
        tag,
        datastore['HOSTNAME'],
        ip,
        datastore['URIPATH'],
        datastore['PROXIES']
      )
      ret_val = true if found.eql? true
    end

    unless ret_val.eql? true
      print_bad('No direct-connect IP address found :-(')
    end

  end
end
