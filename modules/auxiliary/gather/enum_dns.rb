
##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'net/dns/resolver'

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'DNS Record Scanner and Enumerator',
      'Description'    => %q(
        This module can be used to gather information about a domain from a
        given DNS server by performing various DNS queries such as zone
        transfers, reverse lookups, SRV record bruteforcing, and other techniques.
    ),
      'Author'         => [
        'Carlos Perez <carlos_perez[at]darkoperator.com>',
        'Nixawk'
      ],
      'License'        => MSF_LICENSE,
      'References' 	   => [
        ['CVE', '1999-0532'],
        ['OSVDB', '492']
      ]))

    register_options(
      [
        OptString.new('DOMAIN', [true, 'The target domain']),
        OptBool.new('ENUM_AXFR', [true, 'Initiate a zone transfer against each NS record', true]),
        OptBool.new('ENUM_BRT', [true, 'Brute force subdomains and hostnames via the supplied wordlist', false]),
        OptBool.new('ENUM_A', [true, 'Enumerate DNS A record', true]),
        OptBool.new('ENUM_CNAME', [true, 'Enumerate DNS CNAME record', true]),
        OptBool.new('ENUM_MX', [true, 'Enumerate DNS MX record', true]),
        OptBool.new('ENUM_NS', [true, 'Enumerate DNS NS record', true]),
        OptBool.new('ENUM_SOA', [true, 'Enumerate DNS SOA record', true]),
        OptBool.new('ENUM_TXT', [true, 'Enumerate DNS TXT record', true]),
        OptBool.new('ENUM_RVL', [ true, 'Reverse lookup a range of IP addresses', false]),
        OptBool.new('ENUM_TLD', [true, 'Perform a TLD expansion by replacing the TLD with the IANA TLD list', true]),
        OptBool.new('ENUM_SRV', [true, 'Enumerate the most common SRV records', true]),
        OptBool.new('STOP_WLDCRD', [true, 'Stops bruteforce enumeration if wildcard resolution is detected', false]),
        OptBool.new('STORE_LOOT', [true, 'Store acquired DNS records as loot', true]),
        OptAddress.new('NS', [false, 'Specify the nameserver to use for queries (default is system DNS)']),
        OptAddressRange.new('IPRANGE', [false, "The target address range or CIDR identifier"]),
        OptInt.new('THREADS', [false, 'Threads for ENUM_BRT', 1]),
        OptPath.new('WORDLIST', [false, 'Wordlist of subdomains', ::File.join(Msf::Config.data_directory, 'wordlists', 'namelist.txt')])
      ], self.class)

    register_advanced_options(
      [
        OptInt.new('TIMEOUT', [false, 'DNS TIMEOUT', 8]),
        OptInt.new('RETRY', [false, 'Number of times to try to resolve a record if no response is received', 2]),
        OptInt.new('RETRY_INTERVAL', [false, 'Number of seconds to wait before doing a retry', 2]),
        OptBool.new('TCP_DNS', [false, 'Run queries over TCP', false])
      ], self.class)
  end

  def run
    domain = datastore['DOMAIN']
    is_wildcard = dns_wildcard_enabled?(domain)

    axfr(domain) if datastore['ENUM_AXFR']
    get_a(domain) if datastore['ENUM_A']
    get_cname(domain) if datastore['ENUM_CNAME']
    get_ns(domain) if datastore['ENUM_NS']
    get_mx(domain) if datastore['ENUM_MX']
    get_soa(domain) if datastore['ENUM_SOA']
    get_txt(domain) if datastore['ENUM_TXT']
    get_tld(domain) if datastore['ENUM_TLD']
    get_srv(domain) if datastore['ENUM_SRV']
    threads = datastore['THREADS']
    dns_reverse(datastore['IPRANGE'], threads) if datastore['ENUM_RVL']

    return unless datastore['ENUM_BRT']
    if is_wildcard
      dns_bruteforce(domain, threads) unless datastore['STOP_WLDCRD']
    else
      dns_bruteforce(domain, threads)
    end
  end

  def dns_query(domain, type)
    begin
      dns = Net::DNS::Resolver.new
      nameserver = "#{datastore['NS']}"
      unless nameserver.blank?
        dns.nameservers -= dns.nameservers
        dns.nameservers = "#{datastore['NS']}"
      end
      dns.use_tcp = datastore['TCP_DNS']
      dns.udp_timeout = datastore['TIMEOUT']
      dns.retry_number = datastore['RETRY']
      dns.retry_interval = datastore['RETRY_INTERVAL']
      dns.query(domain, type)
    rescue Errno::ETIMEDOUT
    rescue ::NoResponseError
    rescue ::Timeout::Error
    end
  end

  def dns_bruteforce(domain, threads)
    wordlist = datastore['WORDLIST']
    return if wordlist.blank?
    threads = 1 if threads <= 0

    queue = []
    File.foreach(wordlist) do |line|
      queue << "#{line.chomp}.#{domain}"
    end

    records = []
    until queue.empty?
      t = []
      threads = 1 if threads <= 0

      if queue.length < threads
        # work around issue where threads not created as the queue isn't large enough
        threads = queue.length
      end

      begin
        1.upto(threads) do
          t << framework.threads.spawn("Module(#{self.refname})", false, queue.shift) do |test_current|
            Thread.current.kill unless test_current
            a = get_a(test_current)
            records |= a if a
          end
        end
        t.map{ |x| x.join }

      rescue ::Timeout::Error
      ensure
        t.each { |x| x.kill rescue nil }
      end
    end
    records
  end

  def dns_reverse(cidr, threads)
    iplst = []
    ipadd = Rex::Socket::RangeWalker.new(cidr)
    numip = ipadd.num_ips
    while iplst.length < numip
      ipa = ipadd.next_ip
      break unless ipa
      iplst << ipa
    end

    records = []
    while !iplst.nil? && !iplst.empty?
      t = []
      threads = 1 if threads <= 0
      begin
        1.upto(threads) do
          t << framework.threads.spawn("Module(#{self.refname})", false, iplst.shift) do |ip_text|
            next if ip_text.nil?
            a = get_ptr(ip_text)
            records |= a if a
          end
        end
        t.map { |x| x.join }

      rescue ::Timeout::Error
      ensure
        t.each { |x| x.kill rescue nil }
      end
    end
    records
  end

  def dns_wildcard_enabled?(domain)
    records = get_a("#{Rex::Text.rand_text_alpha(16)}.#{domain}")
    if records.blank?
      false
    else
      print_warning('dns wildcard is enable OR fake dns server')
      true
    end
  end

  def save_loot(ltype, ctype, host, data,
                filename = nil, info = nil, service = nil)
    return unless datastore['STORE_LOOT']
    path = store_loot(ltype, ctype, host, data, filename, info, service)
    print_good('saved file to: ' + path)
  end

  def get_ptr(ip)
    resp = dns_query(ip, nil)
    return if resp.blank? || resp.answer.blank?

    records = []
    resp.answer.each do |r|
      next unless r.class == Net::DNS::RR::PTR
      records << "#{r.ptr}"
      report_host(host: ip, name: "#{r.ptr}", info: 'ip reverse')
      print_good("#{ip}: PTR: #{r.ptr} ")
    end
    return if records.none?
    records
  end

  def get_a(domain)
    resp = dns_query(domain, 'A')
    return if resp.blank? || resp.answer.blank?

    records = []
    resp.answer.each do |r|
      next unless r.class == Net::DNS::RR::A
      records << "#{r.address}"
      report_host(host: r.address, name: domain, info: 'A')
      print_good("#{domain}: A: #{r.address} ") if datastore['ENUM_BRT']
    end
    return if records.none?
    records
  end

  def get_cname(domain)
    resp = dns_query(domain, 'CNAME')
    return if resp.blank? || resp.answer.blank?

    records = []
    resp.answer.each do |r|
      next unless r.class == Net::DNS::RR::CNAME
      records << r.cname
      print_good("#{domain}: CNAME: #{r.cname}")
    end
    return if records.none?
    save_loot('ENUM_CNAME', domain, 'text/plain', domain, "#{records.join(',')}", domain)
    records
  end

  def get_ns(domain)
    resp = dns_query(domain, 'NS')
    return if resp.blank? || resp.answer.blank?

    records = []
    resp.answer.each do |r|
      next unless r.class == Net::DNS::RR::NS
      records << "#{r.nsdname}"
      report_host(host: r.nsdname, name: domain, info: 'NS')
      print_good("#{domain}: NS: #{r.nsdname}")
    end
    return if records.none?

    save_loot('ENUM_NS', 'text/plain', domain, "#{records.join(',')}", domain)
    records
  end

  def get_mx(domain)
    begin
      resp = dns_query(domain, 'MX')
      return if resp.blank? || resp.answer.blank?

      records = []
      resp.answer.each do |r|
        next unless r.class == Net::DNS::RR::MX
        records << "#{r.exchange}"
        report_host(host: r.exchange, name: domain, info: 'MX')
        print_good("#{domain}: MX: #{r.exchange}")
      end
      return if records.none?
      save_loot('ENUM_MX', 'text/plain', domain, "#{records.join(',')}", domain)
      records
    rescue SocketError => e
      print_error("Query #{domain} DNS MX - exception: #{e}")
    end
  end

  def get_soa(domain)
    resp = dns_query(domain, 'SOA')
    return if resp.blank? || resp.answer.blank?

    records = []
    resp.answer.each do |r|
      next unless r.class == Net::DNS::RR::SOA
      records << r.mname
      report_host(host: r.mname, info: 'SOA')
      print_good("#{domain}: SOA: #{r.mname}")
    end
    return if records.none?
    save_loot('ENUM_SOA', 'text/plain', domain, "#{records.join(',')}", domain)
    records
  end

  def get_txt(domain)
    resp = dns_query(domain, 'TXT')
    return if resp.blank? || resp.answer.blank?

    records = []
    resp.answer.each do |r|
      next unless r.class == Net::DNS::RR::TXT
      records << r.txt
      print_good("#{domain}: TXT: #{r.txt}")
    end
    return if records.none?
    save_loot('ENUM_TXT', 'text/plain', domain, "#{records.join(',')}", domain)
    records
  end

  def get_tld(domain)
    begin
      print_status("query DNS TLD: #{domain}")
      domain_ = domain.split('.')
      domain_.pop
      domain_ = domain_.join('.')

      tlds = [
        'com', 'org', 'net', 'edu', 'mil', 'gov', 'uk', 'af', 'al', 'dz',
        'as', 'ad', 'ao', 'ai', 'aq', 'ag', 'ar', 'am', 'aw', 'ac', 'au',
        'at', 'az', 'bs', 'bh', 'bd', 'bb', 'by', 'be', 'bz', 'bj', 'bm',
        'bt', 'bo', 'ba', 'bw', 'bv', 'br', 'io', 'bn', 'bg', 'bf', 'bi',
        'kh', 'cm', 'ca', 'cv', 'ky', 'cf', 'td', 'cl', 'cn', 'cx', 'cc',
        'co', 'km', 'cd', 'cg', 'ck', 'cr', 'ci', 'hr', 'cu', 'cy', 'cz',
        'dk', 'dj', 'dm', 'do', 'tp', 'ec', 'eg', 'sv', 'gq', 'er', 'ee',
        'et', 'fk', 'fo', 'fj', 'fi', 'fr', 'gf', 'pf', 'tf', 'ga', 'gm',
        'ge', 'de', 'gh', 'gi', 'gr', 'gl', 'gd', 'gp', 'gu', 'gt', 'gg',
        'gn', 'gw', 'gy', 'ht', 'hm', 'va', 'hn', 'hk', 'hu', 'is', 'in',
        'id', 'ir', 'iq', 'ie', 'im', 'il', 'it', 'jm', 'jp', 'je', 'jo',
        'kz', 'ke', 'ki', 'kp', 'kr', 'kw', 'kg', 'la', 'lv', 'lb', 'ls',
        'lr', 'ly', 'li', 'lt', 'lu', 'mo', 'mk', 'mg', 'mw', 'my', 'mv',
        'ml', 'mt', 'mh', 'mq', 'mr', 'mu', 'yt', 'mx', 'fm', 'md', 'mc',
        'mn', 'ms', 'ma', 'mz', 'mm', 'na', 'nr', 'np', 'nl', 'an', 'nc',
        'nz', 'ni', 'ne', 'ng', 'nu', 'nf', 'mp', 'no', 'om', 'pk', 'pw',
        'pa', 'pg', 'py', 'pe', 'ph', 'pn', 'pl', 'pt', 'pr', 'qa', 're',
        'ro', 'ru', 'rw', 'kn', 'lc', 'vc', 'ws', 'sm', 'st', 'sa', 'sn',
        'sc', 'sl', 'sg', 'sk', 'si', 'sb', 'so', 'za', 'gz', 'es', 'lk',
        'sh', 'pm', 'sd', 'sr', 'sj', 'sz', 'se', 'ch', 'sy', 'tw', 'tj',
        'tz', 'th', 'tg', 'tk', 'to', 'tt', 'tn', 'tr', 'tm', 'tc', 'tv',
        'ug', 'ua', 'ae', 'gb', 'us', 'um', 'uy', 'uz', 'vu', 've', 'vn',
        'vg', 'vi', 'wf', 'eh', 'ye', 'yu', 'za', 'zr', 'zm', 'zw', 'int',
        'gs', 'info', 'biz', 'su', 'name', 'coop', 'aero']

      records = []
      tlds.each do |tld|
        tldr = get_a("#{domain_}.#{tld}")
        next if tldr.blank?
        records |= tldr

        report_note(
          host: "#{domain}",
          proto: 'udp',
          sname: "#{domain_}.#{tld}",
          port: '53',
          type: 'ENUM_TLD',
          data: tldr)
        print_good("#{domain_}.#{tld}: TLD: #{tldr.join(',')}")
      end
      return if records.none?
      save_loot('ENUM_TLD', 'text/plain', domain, "#{records.join(',')}", domain)
      records
    rescue ArgumentError => e
      print_error("Query #{domain} DNS TLD - exception: #{e}")
    end
  end

  def get_srv(domain)
    print_status("query DNS SRV: #{domain}")
    srvs = [
      '_gc._tcp.', '_kerberos._tcp.', '_kerberos._udp.', '_ldap._tcp.',
      '_test._tcp.',  '_sips._tcp.', '_sip._udp.', '_sip._tcp.',
      '_aix._tcp.',  '_aix._tcp.', '_finger._tcp.', '_ftp._tcp.',
      '_http._tcp.', '_nntp._tcp.', '_telnet._tcp.', '_whois._tcp.',
      '_h323cs._tcp.',  '_h323cs._udp.', '_h323be._tcp.', '_h323be._udp.',
      '_h323ls._tcp.', '_h323ls._udp.',  '_sipinternal._tcp.',
      '_sipinternaltls._tcp.', '_sip._tls.', '_sipfederationtls._tcp.',
      '_jabber._tcp.', '_xmpp-server._tcp.', '_xmpp-client._tcp.',
      '_imap._tcp.', '_certificates._tcp.',  '_crls._tcp.', '_pgpkeys._tcp.',
      '_pgprevokations._tcp.', '_cmp._tcp.', '_svcp._tcp.', '_crl._tcp.',
      '_ocsp._tcp.', '_PKIXREP._tcp.', '_smtp._tcp.', '_hkp._tcp.',
      '_hkps._tcp.', '_jabber._udp.',  '_xmpp-server._udp.',
      '_xmpp-client._udp.', '_jabber-client._tcp.', '_jabber-client._udp.']

    records = []
    srvs.each do |srv|
      resp = dns_query("#{srv}#{domain}", Net::DNS::SRV)
      next if resp.blank? || resp.answer.blank?
      resp.answer.each do |r|
        next if r.type == Net::DNS::RR::CNAME
        report_note(
          host: domain,
          proto: 'udp',
          sname: r.host,
          port: r.port,
          type: 'ENUM_SRV',
          data: "#{r.priority}")
        print_good("#{domain} : SRV: (Host: #{r.host}, Port: #{r.port}, Priority: #{r.priority})")
      end
    end
    return if records.none?
    save_loot('ENUM_SRV', 'text/plain', domain, "#{records.join(',')}", domain)
    records
  end

  def axfr(domain)
    nameservers = get_ns(domain)
    return if nameservers.blank?
    records = []
    nameservers.each do |nameserver|
      dns = Net::DNS::Resolver.new
      dns.use_tcp = datastore['TCP_DNS']
      dns.udp_timeout = datastore['TIMEOUT']
      dns.retry_number = datastore['RETRY']
      dns.retry_interval = datastore['RETRY_INTERVAL']

      next if nameserver.blank?
      ns = get_a(nameserver)
      next if ns.blank?

      ns.each do |r|
        begin
          dns.nameservers -= dns.nameservers
          dns.nameservers = "#{r}"
          zone = dns.axfr(domain)
        rescue Errno::ETIMEDOUT
        rescue ::NoResponseError
        rescue ::Timeout::Error
        end
        next if zone.blank?
        records << "#{zone}"
        print_good("#{domain}: Zone Transfer: #{zone}")
      end
    end
    return if records.none?
    save_loot('ENUM_AXFR', 'text/plain', domain, "#{records.join(',')}", domain)
    records
  end
end
