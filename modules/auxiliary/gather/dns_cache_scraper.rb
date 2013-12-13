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
      'Description'  => %q{
        This module can be used to scrape records that have been cached
        by a specific nameserver. The module allows the user to test
        every record from a specified file.
      },
      'Author'=> [
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
        OptPath.new('WORDLIST', [ true, "Wordlist for domain name queries", ::File.join(Msf::Config.install_root, "data", "wordlists", "av-update-urls.txt")]),
        OptAddress.new('NS', [ true, "Specify the nameserver to use for queries" ]),
      ], self.class)

    register_advanced_options([
        OptBool.new('TCP_DNS', [false, "Run queries over TCP", false]),
      ], self.class)
  end

  # method to scrape dns
  def scrape_dns(domain)

    # dns request with recursive disabled
    use_tcp = datastore['TCP_DNS'] == true
    res = Net::DNS::Resolver.new(:nameservers => "#{datastore['NS']}", :recursive => false, :use_tcp => use_tcp)

    # query dns
    begin
      query = res.send(domain)
    rescue
      print_error("Issues with #{domain}")
      return
    end

    # found or not found
    if query.answer.empty?
      vprint_status("#{domain} - Not Found")
      return
    end

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
    report_service(
      :host => datastore['NS'],
      :name => "dns",
      :port => 53,
      :proto => "udp",
      :info => "#{domain} cached"
    )

    report_note(
      :host => datastore['NS'],
      :name => "dns",
      :port => 53,
      :proto => "udp",
      :type => "dns.cache.scrape",
      :data => "#{domain} cached"
    )

    report_host(
      :address => datastore['NS'],
      :info => "#{domain} cached",
      :comments => "DNS Cache Scraper"
    )
  end

  # main control method
  def run
    print_status("Making queries against #{datastore['NS']}")

    if datastore['DOMAIN'].blank?
      read_file
    else
      scrape_dns(datastore['DOMAIN'])
    end
  end
end

