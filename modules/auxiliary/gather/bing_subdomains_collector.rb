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
        OptString.new('DOMAIN', [ true, "The domain name to locate subdomains for"])
      ], self.class)

    deregister_options('RHOST', 'RPORT', 'VHOST', 'SSL', 'Proxies')
  end

  def rhost_bing
    'www.bing.com'
  end

  def rport_bing
    80
  end

  def bing_search(domain)
    print_status("Searching Bing for subdomains from #{domain}")
    domains = {}

    searches = ['1', '51', '101', '151', '201', '251', '301', '351', '401', '451']
    searches.each do |num|
      resp = send_request_cgi!(
        'rhost' => rhost_bing,
        'rport' => rport_bing,
        'vhost' => rhost_bing,
        'method' => 'GET',
        'uri' => '/search',
        'vars_get' => {
          'first' => num,
          'q' => "domain:#{domain}"
        })

      next unless resp && resp.code == 200
      html = resp.get_html_document
      matches = html.search('cite')
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

    return unless domains
    report_note(
      host: domain,
      type: 'Bing Search Subdomains',
      update: :unique_data,
      data: domains)
    domains
  end

  def run
    bing_search(datastore['domain'])
  end
end
