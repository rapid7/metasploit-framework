# -*- coding: binary -*-
module Msf

###
#
# This module provides methods for implementing DNS stuff
#
###
module Auxiliary::Dns

  def initialize(info = {})
    super
    register_options(
      [
        OptAddress.new('NS', [false, 'Specify the nameserver to use for queries (default is system DNS)']),
        OptPath.new('WORDLIST', [false, 'Wordlist of subdomains', ::File.join(Msf::Config.data_directory, 'wordlists', 'namelist.txt')])
      ]
    )
  end

  def dns_enumeration(domain, threads)
    wordlist = datastore['WORDLIST']
    return if wordlist.blank?

    ar_ips = dns_wildcard(domain)
    return ar_ips if !ar_ips.empty?

    threads = 1 if threads <= 0
    queue = []
    File.foreach(wordlist) do |line|
      queue << "#{line.chomp}.#{domain}"
    end

    until queue.empty?
      t = []
      threads = 1 if threads <= 0

      if queue.length < threads
        # work around issue where threads not created as the queue isn't large enough
        threads = queue.length
      end

      begin
        1.upto(threads) do
          t << framework.threads.spawn("Module(#{refname})", false, queue.shift) do |test_current|
            Thread.current.kill unless test_current
            a = /(\d*\.\d*\.\d*\.\d*)/.match(dns_get_a(test_current).to_s)
            ar_ips.push(a) if a
          end
        end
        t.map(&:join)
      rescue ::Timeout::Error
        next
      ensure
        t.each { |x| x.kill rescue nil }
      end
    end

    ar_ips
  end

  def dns_get_a(fqdn)
    response = dns_query(fqdn, 'A')
    return if response.blank? || response.answer.blank?

    response.answer.each do |row|
      next unless row.class == Net::DNS::RR::A
    end
  end

  def dns_get_mx(domain)
    begin
      response = dns_query(domain, 'MX')
      return [] if response.blank? || response.answer.blank?

      records = []
      response.answer.each do |r|
        next unless r.class == Net::DNS::RR::MX

        records << r.exchange.to_s
      end
    rescue SocketError
    end
    return [] if records.blank?

    records
  end

  def dns_query(request, type)
    nameserver = datastore['NS']

    if nameserver.blank?
      dns = Net::DNS::Resolver.new
    else
      dns = Net::DNS::Resolver.new(nameservers: ::Rex::Socket.resolv_to_dotted(nameserver))
    end

    dns.use_tcp = false
    dns.udp_timeout = 8
    dns.retry_number = 2
    dns.retry_interval = 2
    dns.query(request, type)
  rescue ResolverArgumentError, Errno::ETIMEDOUT, ::NoResponseError, ::Timeout::Error => e
    print_error("Query #{request} DNS #{type} - exception: #{e}")
    return nil
  end

  def dns_wildcard(domain)
    ar_ips = []

    response = dns_query("#{rand(10000)}.#{domain}", 'A')
    if !response.answer.empty?
      print_warning('This domain has wildcards enabled!')
      response.answer.each do |rr|
        ar_ips << rr.address.to_s
      end
    end

    ar_ips
  end

end
end
