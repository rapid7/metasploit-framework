##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Behind CloudFlare',
      'Version'        => '$Release: 1.0.2',
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
        ['URL', 'https://github.com/HatBashBR/HatCloud']
      ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('HOSTNAME', [true, 'The hostname to find real IP', 'discordapp.com']),
        OptString.new('URIPATH', [true, 'The URI path (for custom comparison)', '/']),
        OptInt.new('RPORT', [true, 'The target port (for custom comparison)', '443']),
        OptBool.new('SSL', [true, 'Negotiate SSL/TLS for outgoing connections (for custom comparison)', true]),
        OptString.new('Proxies', [false, 'A proxy chain of format type:host:port[,type:host:port][...]'])
      ])
  end

  def do_crimflare_request(hostname, proxies)
    begin
      cli = Rex::Proto::Http::Client.new('www.crimeflare.us', 82, {}, false, nil, proxies)
      cli.connect

      request = cli.request_cgi({
        'uri'    => '/cgi-bin/cfsearch.cgi',
        'method' => 'POST',
        'data'   => "cfS=#{hostname}"
      })
      response = cli.send_recv(request)
      cli.close

    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error('HTTP connection failed to Crimflare website.')
      return false
    end

    html  = response.get_html_document
    unless /No working nameservers are registered/.match(html).nil? then
      print_bad('No working nameservers are registered! :(')
      return false
    end

    arIps = []
    rows  = html.search('li')
    rows.each_with_index do | row, index |
      date = /(\d*\-\d*\-\d*)/.match(row)
      arIps.push(/(\d*\.\d*\.\d*\.\d*)/.match(row))
      print_status(" * #{date} | #{arIps[index]}")
    end

    if arIps.empty?
      print_bad('No previous lookups founds.')
      return false
    end

    return arIps
  end

  def do_check_bypass(fingerprint, host, ip, uri, proxies)

    # Check for "misconfigured" web server on TCP/80.
    if do_check_tcp_port(ip, 80, proxies)
      response = do_simple_get_request_raw(ip, 80, false, host, uri, proxies)

      if response != false
        html = response.get_html_document
        if fingerprint.to_s.eql? html.at('head').to_s
          print_good("A direct-connect IP address was found: #{ip}")
          return true
        end
      end
    end

    # Check for "misconfigured" web server on TCP/443.
    if do_check_tcp_port(ip, 443, proxies)
      response = do_simple_get_request_raw(ip, 443, true, host, uri, proxies)

      if response != false
        html = response.get_html_document
        if fingerprint.to_s.eql? html.at('head').to_s
          print_good("A direct-connect IP address was found: #{ip}")
          return true
        end
      end
    end

    return false
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

  ## TODO: Improve on-demand response (send_recv? Timeout).
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

  ## TODO: Improve the efficiency by mixing the sources (dnsenum, censys, shodan, ...).
  def run
    domain_name = PublicSuffix.parse(datastore['HOSTNAME']).domain

    print_status('Previous lookups from Crimeflare...')
    ip_list     = do_crimflare_request(datastore['HOSTNAME'], datastore['PROXIES'])
    print_status()

    unless ip_list.eql? false
      print_status('Bypass Cloudflare is in progress...')

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
      ip_list.each_with_index do | ip, index |
        vprint_status(" * Trying: #{ip[index].to_s}")

        ret_val = do_check_bypass(
          head,
          datastore['HOSTNAME'],
          ip[index].to_s,
          datastore['URIPATH'],
          datastore['PROXIES']
        )
        break if ret_val.eql? true
      end
    end

    if ret_val.eql? false
      print_bad('No direct-connect IP address found :-(')
    end
  end

end
