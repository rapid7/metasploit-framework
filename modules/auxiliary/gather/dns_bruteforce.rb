##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require "net/dns/resolver"
require 'rex'

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'		   => 'DNS Brutefoce Enumeration',
      'Description'	=> %q{
          This module uses a dictionary to perform a bruteforce attack to enumerate
        hostnames and subdomains available under a given domain.
      },
      'Author'		=> [ 'Carlos Perez <carlos_perez[at]darkoperator.com>' ],
      'License'		=> BSD_LICENSE
    ))

    register_options(
      [
        OptString.new('DOMAIN', [ true, "The target domain name"]),
        OptAddress.new('NS', [ false, "Specify the name server to use for queries, otherwise use the system DNS" ]),
        OptPath.new('WORDLIST', [ true, "Wordlist file for domain name brute force.",
              File.join(Msf::Config.data_directory, "wordlists", "namelist.txt")])
      ], self.class)

    register_advanced_options(
      [
        OptInt.new('RETRY', [ false, "Number of tries to resolve a record if no response is received.", 2]),
        OptInt.new('RETRY_INTERVAL', [ false, "Number of seconds to wait before doing a retry.", 2]),
        OptInt.new('THREADS', [ true, "Number of threads", 1])
      ], self.class)
  end

  def run
    print_status("Enumerating #{datastore['DOMAIN']}")
    @res = Net::DNS::Resolver.new()
    @res.retry = datastore['RETRY'].to_i unless datastore['RETRY'].nil?
    @res.retry_interval = datastore['RETRY_INTERVAL'].to_i unless datastore['RETRY_INTERVAL'].nil?
    wildcard(datastore['DOMAIN'])
    switchdns() unless datastore['NS'].nil?
    dnsbrt(datastore['DOMAIN'])
  end

  def wildcard(target)
    rendsub = rand(10000).to_s
    query = @res.query("#{rendsub}.#{target}", "A")
    if query.answer.length != 0
      print_status("This Domain has wild-cards enabled!!")
      query.answer.each do |rr|
        print_warning("Wild-card IP for #{rendsub}.#{target} is: #{rr.address.to_s}") if rr.class != Net::DNS::RR::CNAME
      end
      return true
    else
      return false
    end
  end

  def get_ip(host)
    results = []
    query = @res.search(host, "A")
    if (query)
      query.answer.each do |rr|
        if rr.type == "CNAME"
          results = results + get_ip(rr.cname)
        else
          record = {}
          record[:host] = host
          record[:type] = "AAAA"
          record[:address] = rr.address.to_s
          results << record
        end
      end
    end
    query1 = @res.search(host, "AAAA")
    if (query1)
      query1.answer.each do |rr|
        if rr.type == "CNAME"
          results = results + get_ip(rr.cname)
        else
          record = {}
          record[:host] = host
          record[:type] = "AAAA"
          record[:address] = rr.address.to_s
          results << record
        end
      end
    end
    return results
  end

  def switchdns()
    print_status("Using DNS server: #{datastore['NS']}")
    @res.nameserver=(datastore['NS'])
    @nsinuse = datastore['NS']
  end

  def dnsbrt(domain)
    print_status("Performing bruteforce against #{domain}")
    queue = []
    File.open(datastore['WORDLIST'], 'rb').each_line do |testd|
      queue << testd.strip
    end
    while(not queue.empty?)
      tl = []
      1.upto(datastore['THREADS']) do
        tl << framework.threads.spawn("Module(#{self.refname})-#{domain}", false, queue.shift) do |testf|
          Thread.current.kill if not testf
          vprint_status("Testing #{testf}.#{domain}")
          get_ip("#{testf}.#{domain}").each do |i|
            print_good("Host #{i[:host]} with address #{i[:address]} found")
            report_host(
              :host => i[:address].to_s,
              :name => i[:host].gsub(/\.$/,'')
            )
          end
        end
      end
      if(tl.length == 0)
        break
      end
      tl.first.join
      tl.delete_if { |t| not t.alive? }
    end
  end
end

