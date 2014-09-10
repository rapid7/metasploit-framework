##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'net/dns/resolver'

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'DNS Non-Recursive Record Scraper',
      'Description' => %q{
        This module can be used to scrape records that have been cached
        by a specific nameserver. The module allows the user to test
        every record from a specified file.
      },
      'Author' => [
          'Brandon McCann "zeknox" <bmccann[at]accuvant.com>',
          'Rob Dixon "304geek" <rob.dixon[at]accuvant.com>'
      ],
      'License' => MSF_LICENSE,
      'References' => [
        ['URL', 'http://304geeks.blogspot.com/2013/01/dns-scraping-for-corporate-av-detection.html'],
        ['URL', 'http://www.rootsecure.net/content/downloads/pdf/dns_cache_snooping.pdf']
      ]))

    register_options([
        OptString.new('DOMAIN', [ false, "Domain name to query for"]),
        OptPath.new('WORDLIST', [ false, "Wordlist for domain name queries", ::File.join(Msf::Config.data_directory, "wordlists", "av-update-urls.txt")]),
        OptAddress.new('NS', [ true, "Specify the nameserver to use for queries" ]),
      ], self.class)

    register_advanced_options([
        OptBool.new('TCP_DNS', [false, "Run queries over TCP", false]),
        OptInt.new('DNS_TIMEOUT', [true, "DNS Timeout in seconds", 5])
      ], self.class)
  end

  # method to scrape dns
  def scrape_dns(domain)

    # dns request with recursive disabled
    use_tcp = datastore['TCP_DNS']
    res = Net::DNS::Resolver.new(:nameservers => "#{datastore['NS']}", :recursive => false, :use_tcp => use_tcp)
    use_tcp ? res.tcp_timeout = datastore['DNS_TIMEOUT'] : res.udp_timeout = datastore['DNS_TIMEOUT']

    # query dns
    begin
      query = res.send(domain)
    rescue ResolverArgumentError
      print_error("Invalid domain: #{domain}")
      return
    rescue NoResponseError
      print_error("DNS Timeout Issue: #{domain}")
      return
    end

    # found or not found
    if query.answer.empty?
      vprint_status("#{domain} - Not Found")
      return
    end

    @is_vulnerable = true
    print_good("#{domain} - Found")
    report_goods(domain)
  end

  # method to read each line from file
  def read_file
    ::File.open("#{datastore['WORDLIST']}", "rb").each_line do |line|
      scrape_dns(line.chomp)
    end
  end

  # log results to database
  def report_goods(domain)
    if datastore['TCP_DNS']
      proto = "tcp"
    else
      proto = "udp"
    end

    report_note(
      :host => datastore['NS'],
      :name => "dns",
      :port => 53,
      :proto => proto,
      :type => "dns.cache.scrape",
      :data => "#{domain} cached",
      :update => :unique_data
    )
  end

  # main control method
  def run
    @is_vulnerable = false

    print_status("Making queries against #{datastore['NS']}")

    if datastore['DOMAIN'].blank?
      read_file
    else
      scrape_dns(datastore['DOMAIN'])
    end

    report_vuln(
      :host => datastore['NS'],
      :name => "DNS Cache Snooping",
    ) if @is_vulnerable
  end
end

