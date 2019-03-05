##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Search Engine Subdomains Collector',
      'Description' => %q(
        This module can be used to gather subdomains about a domain
        from Yahoo, Bing.
      ),
      'Author' => [ 'Nixawk' ],
      'License' => MSF_LICENSE))

    deregister_http_client_options

    register_options(
      [
        OptString.new('TARGET', [ true, "The target to locate subdomains for, ex: rapid7.com, 8.8.8.8"]),
        OptBool.new('IP_SEARCH', [ false, "Enable ip of subdomains to locate subdomains", true]),
        OptBool.new('ENUM_BING', [ true, "Enable Bing Search Subdomains", true]),
        OptBool.new('ENUM_YAHOO', [ true, "Enable Yahoo Search Subdomains", true])
      ])
  end

  def rhost_yahoo
    'search.yahoo.com'
  end

  def rport_yahoo
    80
  end

  def rhost_bing
    'global.bing.com'
  end

  def rport_bing
    80
  end

  def valid_result?(target, subdomain)
    data = Rex::Socket.is_ipv4?(target) ? domain2ip(subdomain) : subdomain
    data && data.include?(target) ? true : false
  end

  def domain2ip(domain)
    ips = []
    begin
      ips = Rex::Socket.getaddresses(domain)
    rescue SocketError
    end
    ips
  end

  def uri2domain(uri)
    begin
      URI(uri).host
    rescue URI::InvalidURIError
      nil
    end
  end

  def bing_search(dork)
    print_status("Searching Bing for subdomains from #{dork}")
    results = []

    begin
      searches = ['1', '51', '101', '151', '201', '251', '301', '351', '401', '451']
      searches.each do |num|
        resp = send_request_cgi!(
          'rhost' => rhost_bing,
          'rport' => rport_bing,
          'vhost' => rhost_bing,
          'method' => 'GET',
          'uri' => '/search',
          'vars_get' => {
            'FROM' => 'HPCNEN',
            'setmkt' => 'en-us',
            'setlang' => 'en-us',
            'first' => num,
            'q' => dork
          })

        next unless resp && resp.code == 200
        html = resp.get_html_document
        matches = html.search('cite')
        matches.each do |match|
          result = uri2domain(match.text)
          next unless result
          result.to_s.downcase!
          results << result
        end
      end
    rescue ::Exception => e
      print_error("#{dork} - #{e.message}")
    end
    results
  end

  def yahoo_search(dork)
    print_status("Searching Yahoo for subdomains from #{dork}")
    results = []

    begin
      searches = ["1", "101", "201", "301", "401", "501"]
      searches.each do |num|
        resp = send_request_cgi!(
          'rhost' => rhost_yahoo,
          'rport' => rport_yahoo,
          'vhost' => rhost_yahoo,
          'method' => 'GET',
          'uri' => '/search',
          'vars_get' => {
            'pz' => 100,
            'p' => dork,
            'b' => num
          })

        next unless resp && resp.code == 200
        html = resp.get_html_document
        matches = html.search('span[@class=" fz-15px fw-m fc-12th wr-bw lh-15"]')
        matches.each do |match|
          result = match.text
          result = result.split('/')[0]
          result = result.split(':')[0]
          next unless result
          result.to_s.downcase!
          results << result
        end
      end
    rescue ::Exception => e
      print_error("#{dork} - #{e.message}")
    end
    results
  end

  def search_subdomains(target)
    domains = {}
    ipv4 = Rex::Socket.is_ipv4?(target)
    dork = ipv4 ? "ip:#{target}" : "domain:#{target}"

    results = [] # merge results to reduce query times
    results |= bing_search(dork) if datastore['ENUM_BING']
    results |= yahoo_search(dork) if datastore['ENUM_YAHOO']

    return domains if results.nil? || results.empty?
    results.each do |subdomain|
      next if domains.include?(subdomain)
      next unless valid_result?(target, subdomain)
      print_good("#{dork} subdomain: #{subdomain}")
      if ipv4
        domains[subdomain] = [target]
      else
        ips = domain2ip(subdomain)
        next if ips.empty?
        domains[subdomain] = ips
        ips.each { |ip| search_subdomains(ip) } if !ips.empty? && datastore['IP_SEARCH']
      end
    end
    return if domains.empty?
    report_note(host: target, type: 'Subdomains', update: :unique_data, data: domains)
  end

  def run
    search_subdomains(datastore['TARGET'])
  end
end
