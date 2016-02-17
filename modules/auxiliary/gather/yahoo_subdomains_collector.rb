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
        OptString.new('DOMAIN', [ true, "The domain name to locate subdomains for"])
      ], self.class)

    deregister_options('RHOST', 'RPORT', 'VHOST', 'SSL', 'Proxies')
  end

  def rhost_yahoo
    'search.yahoo.com'
  end

  def rport_yahoo
    80
  end

  def yahoo_search(domain)
    print_status("Searching Yahoo for subdomains from #{domain}")
    domains = {}

    searches = ["1", "101", "201", "301", "401", "501"]
    searches.each do |num|
      resp = send_request_cgi(
        'rhost' => rhost_yahoo,
        'rport' => rport_yahoo,
        'vhost' => rhost_yahoo,
        'method' => 'GET',
        'uri' => '/search',
        'vars_get' => {
          'pz' => 100,
          'p' => "domain:#{domain}",
          'b' => num
        })

      next unless resp && resp.code == 200
      html = resp.get_html_document
      matches = html.search('span[@class=" fz-15px fw-m fc-12th wr-bw lh-15"]')
      matches.each do |match|
        subdomain = match.text.split('/')[0]
        subdomain = subdomain.split(':')[0]
        subdomain.downcase!

        next if domains.include?(subdomain)
        next unless subdomain.include?(domain)
        ips = Rex::Socket.getaddresses(subdomain)
        ips.each do |ip|
          report_host(host: ip, name: subdomain)
        end
        domains[subdomain] = ips
        print_good("#{domain} subdomain: #{subdomain} - #{ips.join(',')}")
      end
    end
    report_note(
      host: domain,
      type: 'Yahoo Search Engine Subdomains Collector',
      update: :unique_data,
      data: domains)
    domains
  end

  def run
    yahoo_search(datastore['domain'])
  end
end
