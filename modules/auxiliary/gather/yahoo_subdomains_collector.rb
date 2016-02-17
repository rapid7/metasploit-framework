##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Yahoo Search Engine Subdomains Collector',
      'Description' => %q(
        This module can be used to gather subdomains about a domain
        from Yahoo Search Results.
      ),
      'Author' => [ 'Nixawk' ],
      'License' => MSF_LICENSE))

    register_options(
      [
        OptString.new('TARGET', [ true, "The target to locate subdomains for, ex: rapid7.com, 8.8.8.8"]),
        OptBool.new('IP_SEARCH', [ false, "Enable ip of subdomains to locate subdomains", true])
      ], self.class)

    deregister_options('RHOST', 'RPORT', 'VHOST', 'SSL', 'Proxies')
  end

  def rhost_yahoo
    'search.yahoo.com'
  end

  def rport_yahoo
    80
  end

  def valid?(ip, domain)
    begin
      ips = Rex::Socket.getaddresses(domain)
      true if ips.include?(ip)
    rescue SocketError
    ensure
      false
    end
  end

  def yahoo_search(dork)
    print_status("Searching Yahoo for subdomains from #{dork}")
    results = []
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
    results
  end

  def yahoo_search_domain(domain)
    domains = {}
    dork = "domain:#{domain}"
    results = yahoo_search(dork)
    results.each do |subdomain|
      next if domains.include?(subdomain)
      next unless subdomain.include?(domain)
      ips = Rex::Socket.getaddresses(subdomain)
      ips.each do |ip|
        report_host(host: ip, name: subdomain)
        print_good("#{dork} subdomain: #{subdomain} - #{ip}")
        yahoo_search_ip(ip) if datastore['IP_SEARCH']
      end
      domains[subdomain] = ips
    end

    return unless domains
    report_note(
      host: domain,
      type: 'Yahoo Search Subdomains',
      update: :unique_data,
      data: domains)
    domains
  end

  def yahoo_search_ip(ip)
    dork = "ip:#{ip}"
    domains = {}

    results = yahoo_search(dork)
    results.each do |subdomain|
      next if domains.include?(subdomain)
      next unless valid?(ip, subdomain)
      report_host(host: ip, name: subdomain)
      print_good("#{dork} subdomain: #{subdomain}")
      domains[subdomain] = ip
    end
    return unless domains
    report_note(
      host: ip,
      type: 'Yahoo Search Subdomains',
      update: :unique_data,
      data: domains)
    domains
  end

  def run
    target = datastore['TARGET']
    if Rex::Socket.is_ipv4?(target)
      yahoo_search_ip(target)
    else
      yahoo_search_domain(target)
    end
  end
end
