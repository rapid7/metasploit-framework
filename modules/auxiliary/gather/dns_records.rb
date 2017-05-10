
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'net/dns/resolver'
require 'rex'

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Collect DNS Records Information',
      'Description'    => %q{
        This module can collect dns records (a, aaaa, mx, ns and so on).
        Dns query and dns bruteforce will be used.
      },
      'Author'         => [ 'Nixawk' ],
      'License'        => MSF_LICENSE)
         )

    register_options(
      [
        OptString.new('DOMAIN', [ true, "The target domain name" ]),
        OptAddress.new('NS', [ false, "Specify nameserver for dns queries" ]),
        OptPath.new('WORDLIST', [ false, "Wordlist file for subdomain bruteforce", ""]),
        OptInt.new('TIMEOUT', [ false, "Dns response timeout", "4"]),
        OptInt.new('THREADS', [ false, "Number of threads for subdomain bruteforce", 1]),
        OptInt.new('RETRIES', [ false, "Times to retry (nameservers give us no response)", 2]),
        OptInt.new('RETRY_INTERVAL', [ false, "Times to wait between first and second try)", 2])
      ], self.class)
  end

  def run
    domain = datastore['DOMAIN'].to_s
    nameserver = datastore['NS'].to_s
    wordlist = datastore['WORDLIST'].to_s
    threads = datastore['THREADS'].to_i
    threads = 1 if threads == 0

    @dns = Net::DNS::Resolver.new

    retry_interval = datastore['RETRY_INTERVAL'].to_i
    @dns.retry_interval = 1 if retry_interval == 0

    udp_timeout = datastore['TIMEOUT'].to_i
    @dns.udp_timeout = 4 if udp_timeout == 0

    retry_number = datastore['RETRIES'].to_i
    @dns.retry_number = 2 if retry_number == 0

    dns_ns_set(nameserver) unless nameserver.blank?
    dns_wildcard(domain)
    get_ns(domain, "NS")
    get_a(domain, "A")
    get_a(domain, "AAAA")
    get_cname(domain, "CNAME")
    get_mx(domain, "MX")
    get_soa(domain, "SOA")
    get_txt(domain, "TXT")

    dns_bruteforce(domain, wordlist, threads) unless wordlist.blank?
  end

  def dns_ns_set(nameserver)
    print_status("set dns nameserver : #{nameserver}")
    @dns.nameserver = (nameserver.to_s)
  end

  def dns_query(domain, type = "A")
    print_status("enumerate [#{domain}] - #{type} record ")
    @dns.query(domain, type)
  end

  def dns_wildcard(domain)
    prefix = Rex::Text.rand_text_alpha(30) # random domain for dns wildcard check
    result = get_a("#{prefix}.#{domain}")

    if result[:address].blank?
      print_good("dns wildcard is disable")
      return true
    else
      print_good("dns wildcard is enable / dns server is faked")
      return false
    end
  end

  def dns_bruteforce(domain, wordlist, threadnum)
    queue = ::Queue.new

    File.foreach(wordlist) do |line|
      queue << "#{line.chomp}.#{domain}"
    end

    until queue.empty?
      threads = []
      1.upto(threadnum.to_i) do
        threads << framework.threads.spawn("Module(#{refname})-#{domain}", false, queue.shift) do |target|
          Thread.current.kill unless target

          get_a(target, "A")
        end
      end
      threads.each(&:join)
    end
  end

  def db_filter(host)
    framework.db.hosts.each do |dbhost|
      if dbhost.address.to_s.include? host.to_s
        return true
      end
    end
    return false
  end

  def db_record(domain, temp)
    record = {}
    record[:host] = domain
    record[:type] = type
    record[:address] = temp.join(", ")
    return record
  end

  def get_a(domain, type = "A")
    record = {}
    result = dns_query(domain, type)
    return record unless result
    if result.answer.blank?
      return record
    else
      temp = []

      result.answer.each do |r|
        if r.class == Net::DNS::RR::A
          print_good("#{domain}: #{r.address}")
          temp << r.address

          # save A record to database
          unless db_filter(r.address)
            report_host(host: r.address, name: domain)
          end

        elsif r.class == Net::DNS::RR::CNAME
          print_good("#{domain}: #{r.cname}")
        else
          next
        end
      end
      return db_record(domain, temp)
    end
  end

  def get_cname(domain, type = "CNAME")
    record = {}
    result = dns_query(domain, type)

    return record unless result
    if result.answer.blank?
      return record
    else
      temp = []

      result.answer.each do |r|
        if r.class == Net::DNS::RR::CNAME
          print_good("#{domain}: #{r.cname}")
          temp << r.cname
        else
          next
        end
      end
      return db_record(domain, temp)
    end
  end

  def get_ns(domain, type = "NS")
    record = {}
    result = dns_query(domain, type)

    return record unless result
    if result.answer.blank?
      return record
    else
      temp = []

      result.answer.each do |r|
        if r.class == Net::DNS::RR::NS
          print_good("#{domain}: #{r.nsdname}")
          temp << r.nsdname

          unless db_filter(r.nsdname) # save NS record to database
            report_host(host: r.nsdname)
            report_service(host: r.nsdname, name: "dns", port: 53, proto: "udp", info: "nameserver")
          end
        else
          next
        end
      end
      return db_record(domain, temp)
    end
  end

  def get_mx(domain, type = "MX")
    record = {}
    result = dns_query(domain, type)

    return record unless result
    if result.answer.blank?
      return record
    else
      temp = []
      result.answer.each do |r|
        if r.class == Net::DNS::RR::CNAME
          print_good("#{domain}: #{r.cname}")
        elsif r.class == Net::DNS::RR::MX
          print_good("#{domain}: #{r.exchange}")
          temp << r.exchange
          unless db_filter(r.exchange) # save MX record to database
            report_host(host: r.exchange)
            report_service(host: r.exchange, name: "smtp", port: 25, proto: "tcp")
          end
        else
          next
        end
      end

      return db_record(domain, temp)
    end
  end

  def get_soa(domain, type = "SOA")
    record = {}
    result = dns_query(domain, type)

    return record unless result
    if result.answer.blank?
      return record
    else
      temp = []

      result.answer.each do |r|
        if r.class == Net::DNS::RR::SOA
          print_good("#{domain}: #{r.mname}")
          temp << r.mname

          report_host(host: r.mname) # save SOA record to database
        else
          next
        end
      end
      return db_record(domain, temp)
    end
  end

  def get_txt(domain, type = "TXT")
    record = {}
    result = dns_query(domain, type)

    return record unless result
    if result.answer.blank?
      return record
    else
      temp = []
      result.answer.each do |r|
        if r.class == Net::DNS::RR::TXT
          print_good("#{domain}: #{r.txt}")
          temp << r.txt
          unless db_filter(domain) # save SOA record to database
            report_service(host: domain, name: "dns", port: 53, proto: "udp", info: "#{r.txt}")
          end
        else
          next
        end
      end
      return db_record(domain, temp)
    end
  end
end
