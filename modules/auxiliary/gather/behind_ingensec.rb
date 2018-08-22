##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Behind BinarySec/IngenSecurity',
      'Version'        => '$Release: 1.0.3',
      'Description'    => %q{
        This module can be useful if you need to test
        the security of your server and your website
        behind BinarySec/IngenSec by discovering the real IP address.
      },
      'Author'         => [
        'mekhalleh',
        'RAMELLA Sébastien <sebastien.ramella[at]Pirates.RE>'
      ],
      'References'     => [
        ['URL', 'https://www.ingensecurity.com/fct_apercu.html'],
        ['URL', 'https://reunion.orange.fr/actu/reunion/binarysec-une-start-up-reunionnaise-tres-surveillee.html']
      ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('HOSTNAME', [true, 'The hostname or domain name where we want to find the real IP address', 'www.ingensec.com']),
        OptString.new('URIPATH', [true, 'The URI path on which to perform the page comparison', '/']),
        OptInt.new('RPORT', [true, 'The target TCP port on which the protected website responds', 443]),
        OptBool.new('SSL', [true, 'Negotiate SSL/TLS for outgoing connections', true]),
        OptString.new('Proxies', [false, 'A proxy chain of format type:host:port[,type:host:port][...]']),
        OptInt.new('THREADS', [true, 'Threads for DNS enumeration', 15]),
        OptPath.new('WORDLIST', [true, 'Wordlist of subdomains', ::File.join(Msf::Config.data_directory, 'wordlists', 'namelist.txt')])
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
      cli = Rex::Proto::Http::Client.new('www.prepostseo.com', 443, {}, true, nil, proxies)
      cli.connect

      request = cli.request_cgi({
        'uri'    => '/domain-ip-history-checker',
        'method' => 'POST',
        'data'   => "url=#{hostname}&submit=Check+Reverse+Ip+Domains"
      })
      response = cli.send_recv(request)
      cli.close

    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error('HTTP connection failed to PrePost SEO website.')
      return false
    end

    html  = response.get_html_document
    table = html.css('table.table').first
    rows  = table.css('tr')

    ar_ips = []
    rows.each_with_index.map do | row, index |
      row = /(\d*\.\d*\.\d*\.\d*)/.match(row.css('td').map(&:text).to_s)
      unless row.nil?
        ar_ips.push(row)
      end
    end

    if ar_ips.empty?
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
    begin
      dns                = Net::DNS::Resolver.new
      dns.use_tcp        = false
      dns.udp_timeout    = 8
      dns.retry_number   = 2
      dns.retry_interval = 2
      dns.query(domain, type)
    rescue ResolverArgumentError, Errno::ETIMEDOUT, ::NoResponseError, ::Timeout::Error => e
      print_error("Query #{domain} DNS #{type} - exception: #{e}")
      return nil
    end
  end

  ## auxiliary/gather/enum_dns.rb
  def do_save_note(hostname, ip)
    data = { 'target' => hostname, 'real_ip' => ip }
    report_note(host: hostname, type: 'direct-connect IP', data: data)
  end

  def do_simple_get_request_raw(host, port, ssl, host_header=nil, uri, proxies)
    begin
      http    = Rex::Proto::Http::Client.new(host, port, {}, ssl, nil, proxies)
      http.connect

      unless host_header.eql? nil
        http.set_config({ 'vhost' => host_header })
      end

      request = http.request_raw({
        'uri'     => uri,
        'method'  => 'GET'
      })
      response = http.send_recv(request)
      http.close

    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error('HTTP Connection Failed')
      return false
    end

    return response
  end

  def do_check_bypass(fingerprint, host, ip, uri, proxies)
    ret_value = false

    # Check for "misconfigured" web server on TCP/80.
    if do_check_tcp_port(ip, 80, proxies)
      response = do_simple_get_request_raw(ip, 80, false, host, uri, proxies)

      if response != false
        unless response.headers.to_s.include? 'Server: gatejs'
          html = response.get_html_document
          if html.at('head').to_s.include? host
            print_good("A direct-connect IP address was found: #{ip}:80")
            do_save_note(host, ip)
            ret_value = true
          end
        end
      end
    end

    # Check for "misconfigured" web server on TCP/443.
    if do_check_tcp_port(ip, 443, proxies)
      response = do_simple_get_request_raw(ip, 443, true, host, uri, proxies)

      if response != false
        unless response.headers.to_s.include? 'Server: gatejs'
          html = response.get_html_document
          if html.at('head').to_s.include? host
            print_good("A direct-connect IP address was found: #{ip}:443")
            do_save_note(host, ip)
            ret_value = true
          end
        end
      end
    end

    return ret_value
  end

  def run
    print_status('Passive gathering information...')

    domain_name  = PublicSuffix.parse(datastore['HOSTNAME']).domain
    ip_list      = []

    # PrePost SEO
    ip_records   = do_grab_domain_ip_history(domain_name, datastore['Proxies'])
    ip_list     |= ip_records unless ip_records.eql? false
    unless ip_records.eql? false
      print_status(" * PrePost SEO: #{ip_records.count.to_s} IP address found(s).")
    end

    # DNS Enum.
    ip_records   = do_dns_enumeration(domain_name, datastore['THREADS'])
    ip_list     |= ip_records unless ip_records.eql? false
    unless ip_records.eql? false
      print_status(" * DNS Enumeration: #{ip_records.count.to_s} IP address found(s).")
      print_status()
    end

    unless ip_list.empty?

      # Cleaning the results.
      print_status("Clean binarysec/ingensec server(s)...")
      records      = []
      ip_list.each do | ip |
        a = do_dns_get_a(ip.to_s)
        unless a.to_s.include? "binarysec"
          unless a.to_s.include? "ingensec"
            unless ip.to_s.eql? "127.0.0.1"
              records |= ip.to_a
            end
          end
        end
      end

      if records.empty?
        print_bad(" * TOTAL: #{records.count.to_s} IP address found(s) after cleaning.")
      else
        print_good(" * TOTAL: #{records.count.to_s} IP address found(s) after cleaning.")
        print_status()

        # Processing bypass...
        print_status('Bypass BinarySec/IngenSec is in progress...')

        # Initial HTTP request to the server (for <head> comparison).
        print_status(' * Initial request to the original server for comparison')
        response = do_simple_get_request_raw(
          datastore['HOSTNAME'],
          datastore['RPORT'],
          datastore['SSL'],
          nil,
          datastore['URIPATH'],
          datastore['PROXIES']
        )

        html     = response.get_html_document
        head     = html.at('head')

        ret_val  = false
        records.each_with_index do | ip, index |
          vprint_status(" * Trying: #{ip}")

          ret_val = do_check_bypass(
            head,
            datastore['HOSTNAME'],
            ip,
            datastore['URIPATH'],
            datastore['PROXIES']
          )
          break if ret_val.eql? true
        end

        if ret_val.eql? false
          print_bad('No direct-connect IP address found :-(')
        end

      end
    end
  end
end
