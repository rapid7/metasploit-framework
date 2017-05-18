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
      'Name' => 'Bing Search Engine Subdomains Collector',
      'Description' => %q(
        This module can be used to gather subdomains about a domain
        from Bing Search Results.
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

  def rhost_bing
    'global.bing.com'
  end

  def rport_bing
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

  def uri2domain(uri)
    begin
      URI(uri).host
    rescue URI::InvalidURIError
      nil
    end
  end

  def bing_search(dork)
    results = []
    searches = ['1', '51', '101', '151', '201', '251', '301', '351', '401', '451']
    searches.each do |num|
      resp = send_request_cgi!(
        'rhost' => rhost_bing,
        'rport' => rport_bing,
        'vhost' => rhost_bing,
        'method' => 'GET',
        'uri' => '/search',
        'vars_get' => {
          'FROM'     => 'HPCNEN',
          'setmkt'   => 'en-us',
          'setlang'  => 'en-us',
          'first'    => num,
          'q'        => dork
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
    results
  end

  def bing_search_domain(domain)
    print_status("Searching Bing for subdomains from #{domain}")
    dork = "domain:#{domain}"
    domains = {}

    results = bing_search(dork)
    results.each do |subdomain|
      next if domains.include?(subdomain)
      next unless subdomain.include?(domain)
      ips = Rex::Socket.getaddresses(subdomain)
      ips.each do |ip|
        report_host(host: ip, name: subdomain)
        print_good("#{dork} subdomain: #{subdomain} - #{ip}")
        bing_search_ip(ip) if datastore['IP_SEARCH']
      end
      domains[subdomain] = ips
    end

    return if domains.empty?
    report_note(
      host: domain,
      type: 'Bing Search Subdomains',
      update: :unique_data,
      data: domains)
    domains
  end

  def bing_search_ip(ip)
    print_status("Searching Bing for subdomains from #{ip}")
    dork = "ip:#{ip}"
    domains = {}

    results = bing_search(dork)
    results.each do |subdomain|
      next if domains.include?(subdomain)
      next unless valid?(ip, subdomain)
      report_host(host: ip, name: subdomain)
      print_good("#{dork} suddomain: #{subdomain}")
      domains[subdomain] = ip
    end
    return if domains.empty?
    report_note(
      host: ip,
      type: 'Bing Search Subdomains',
      update: :unique_data,
      data: domains)
    domains
  end

  def run
    target = datastore['TARGET']
    if Rex::Socket.is_ipv4?(target)
      bing_search_ip(target)
    else
      bing_search_domain(target)
    end
  end
end
