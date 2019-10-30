##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'net/dns/resolver'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'DNS Record Scanner and Enumerator',
      'Description'    => %q(
        This module can be used to gather information about a domain from a
        given DNS server by performing various DNS queries such as zone
        transfers, reverse lookups, SRV record brute forcing, and other techniques.
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
        OptBool.new('ENUM_TLD', [true, 'Perform a TLD expansion by replacing the TLD with the IANA TLD list', false]),
        OptBool.new('ENUM_SRV', [true, 'Enumerate the most common SRV records', true]),
        OptBool.new('STOP_WLDCRD', [true, 'Stops bruteforce enumeration if wildcard resolution is detected', false]),
        OptAddress.new('NS', [false, 'Specify the nameserver to use for queries (default is system DNS)']),
        OptAddressRange.new('IPRANGE', [false, "The target address range or CIDR identifier"]),
        OptInt.new('THREADS', [false, 'Threads for ENUM_BRT', 1]),
        OptPath.new('WORDLIST', [false, 'Wordlist of subdomains', ::File.join(Msf::Config.data_directory, 'wordlists', 'namelist.txt')])
      ])

    register_advanced_options(
      [
        OptInt.new('TIMEOUT', [false, 'DNS TIMEOUT', 8]),
        OptInt.new('RETRY', [false, 'Number of times to try to resolve a record if no response is received', 2]),
        OptInt.new('RETRY_INTERVAL', [false, 'Number of seconds to wait before doing a retry', 2]),
        OptBool.new('TCP_DNS', [false, 'Run queries over TCP', false])
      ])
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
      nameserver = datastore['NS']
      if nameserver.blank?
        dns = Net::DNS::Resolver.new
      else
        dns = Net::DNS::Resolver.new(nameservers: ::Rex::Socket.resolv_to_dotted(nameserver))
      end
      dns.use_tcp = datastore['TCP_DNS']
      dns.udp_timeout = datastore['TIMEOUT']
      dns.retry_number = datastore['RETRY']
      dns.retry_interval = datastore['RETRY_INTERVAL']
      dns.query(domain, type)
    rescue ResolverArgumentError, Errno::ETIMEDOUT, ::NoResponseError, ::Timeout::Error => e
      print_error("Query #{domain} DNS #{type} - exception: #{e}")
      return nil
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
          t << framework.threads.spawn("Module(#{refname})", false, queue.shift) do |test_current|
            Thread.current.kill unless test_current
            a = get_a(test_current, 'DNS bruteforce records')
            records |= a if a
          end
        end
        t.map(&:join)

      rescue ::Timeout::Error
      ensure
        t.each { |x| x.kill rescue nil }
      end
    end
    records
  end

  def dns_reverse(cidr, threads)
    unless cidr
      print_error 'ENUM_RVL enabled, but no IPRANGE specified'
      return
    end

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
          t << framework.threads.spawn("Module(#{refname})", false, iplst.shift) do |ip_text|
            next if ip_text.nil?
            a = get_ptr(ip_text)
            records |= a if a
          end
        end
        t.map(&:join)

      rescue ::Timeout::Error
      ensure
        t.each { |x| x.kill rescue nil }
      end
    end
    records
  end

  def dns_wildcard_enabled?(domain)
    records = get_a("#{Rex::Text.rand_text_alpha(16)}.#{domain}", 'DNS wildcard records')
    if records.blank?
      false
    else
      print_warning('dns wildcard is enable OR fake dns server')
      true
    end
  end

  def get_ptr(ip)
    resp = dns_query(ip, nil)
    return if resp.blank? || resp.answer.blank?

    records = []
    resp.answer.each do |r|
      next unless r.class == Net::DNS::RR::PTR
      records << r.ptr.to_s
      print_good("#{ip}: PTR: #{r.ptr} ")
    end
    return if records.blank?
    save_note(ip, 'DNS PTR records', records)
    records
  end

  def get_a(domain, type='DNS A records')
    resp = dns_query(domain, 'A')
    return if resp.blank? || resp.answer.blank?

    records = []
    resp.answer.each do |r|
      next unless r.class == Net::DNS::RR::A
      records << r.address.to_s
      print_good("#{domain} A: #{r.address} ") if datastore['ENUM_BRT']
    end
    return if records.blank?
    save_note(domain, type, records)
    records
  end

  def get_cname(domain)
    print_status("querying DNS CNAME records for #{domain}")
    resp = dns_query(domain, 'CNAME')
    return if resp.blank? || resp.answer.blank?

    records = []
    resp.answer.each do |r|
      next unless r.class == Net::DNS::RR::CNAME
      records << r.cname.to_s
      print_good("#{domain} CNAME: #{r.cname}")
    end
    return if records.blank?
    save_note(domain, 'DNS CNAME records', records)
    records
  end

  def get_ns(domain)
    print_status("querying DNS NS records for #{domain}")
    resp = dns_query(domain, 'NS')
    return if resp.blank? || resp.answer.blank?

    records = []
    resp.answer.each do |r|
      next unless r.class == Net::DNS::RR::NS
      records << r.nsdname.to_s
      print_good("#{domain} NS: #{r.nsdname}")
    end
    return if records.blank?
    save_note(domain, 'DNS NS records', records)
    records
  end

  def get_mx(domain)
    print_status("querying DNS MX records for #{domain}")
    begin
      resp = dns_query(domain, 'MX')
      return if resp.blank? || resp.answer.blank?

      records = []
      resp.answer.each do |r|
        next unless r.class == Net::DNS::RR::MX
        records << r.exchange.to_s
        print_good("#{domain} MX: #{r.exchange}")
      end
    rescue SocketError => e
      print_error("Query #{domain} DNS MX - exception: #{e}")
    ensure
      return if records.blank?
      save_note(domain, 'DNS MX records', records)
      records
    end
  end

  def get_soa(domain)
    print_status("querying DNS SOA records for #{domain}")
    resp = dns_query(domain, 'SOA')
    return if resp.blank? || resp.answer.blank?

    records = []
    resp.answer.each do |r|
      next unless r.class == Net::DNS::RR::SOA
      records << r.mname.to_s
      print_good("#{domain} SOA: #{r.mname}")
    end
    return if records.blank?
    save_note(domain, 'DNS SOA records', records)
    records
  end

  def get_txt(domain)
    print_status("querying DNS TXT records for #{domain}")
    resp = dns_query(domain, 'TXT')
    return if resp.blank? || resp.answer.blank?

    records = []
    resp.answer.each do |r|
      next unless r.class == Net::DNS::RR::TXT
      records << r.txt.to_s
      print_good("#{domain} TXT: #{r.txt}")
    end
    return if records.blank?
    save_note(domain, 'DNS TXT records', records)
    records
  end

  def get_tld(domain)
    begin
      print_status("querying DNS TLD records for #{domain}")
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
        tldr = get_a("#{domain_}.#{tld}", 'DNS TLD records')
        next if tldr.blank?
        records |= tldr
        print_good("#{domain_}.#{tld}: TLD: #{tldr.join(',')}")
      end
    rescue ArgumentError => e
      print_error("Query #{domain} DNS TLD - exception: #{e}")
    ensure
      return if records.blank?
      records
    end
  end

  def get_srv(domain)
    print_status("querying DNS SRV records for #{domain}")
    srv_protos = %w(tcp udp tls)
    srv_record_types = %w(
      gc kerberos ldap test sips sip aix finger ftp http
      nntp telnet whois h323cs h323be h323ls sipinternal sipinternaltls
      sipfederationtls jabber jabber-client jabber-server xmpp-server xmpp-client
      imap certificates crls pgpkeys pgprevokations cmp svcp crl oscp pkixrep
      smtp hkp hkps)

    srv_records_data = []
    srv_record_types.each do |srv_record_type|
      srv_protos.each do |srv_proto|
        srv_record = "_#{srv_record_type}._#{srv_proto}.#{domain}"
        resp = dns_query(srv_record, Net::DNS::SRV)
        next if resp.blank? || resp.answer.blank?
        srv_record_data = []
        resp.answer.each do |r|
          next if r.type == Net::DNS::RR::CNAME
          host = r.host.gsub(/\.$/, '')
          data = {
            host: host,
            port: r.port,
            priority: r.priority
          }
          print_good("#{srv_record} SRV: #{data}")
          srv_record_data << data
        end
        srv_records_data << {
          srv_record => srv_record_data
        }
        report_note(
          type: srv_record,
          data: srv_record_data
        )
      end
    end
    return if srv_records_data.empty?
  end

  def axfr(domain)
    nameservers = get_ns(domain)
    return if nameservers.blank?
    records = []
    nameservers.each do |nameserver|
      next if nameserver.blank?
      print_status("Attempting DNS AXFR for #{domain} from #{nameserver}")
      dns = Net::DNS::Resolver.new
      dns.use_tcp = datastore['TCP_DNS']
      dns.udp_timeout = datastore['TIMEOUT']
      dns.retry_number = datastore['RETRY']
      dns.retry_interval = datastore['RETRY_INTERVAL']

      ns_a_records = []
      # try to get A record for nameserver from target NS, which may fail
      target_ns_a = get_a(nameserver, 'DNS AXFR records')
      ns_a_records |= target_ns_a if target_ns_a
      ns_a_records << ::Rex::Socket.resolv_to_dotted(nameserver)
      begin
        dns.nameservers -= dns.nameservers
        dns.nameservers = ns_a_records
        zone = dns.axfr(domain)
      rescue ResolverArgumentError, Errno::ECONNREFUSED, Errno::ETIMEDOUT, ::NoResponseError, ::Timeout::Error => e
        print_error("Query #{domain} DNS AXFR - exception: #{e}")
      end
      next if zone.blank?
      records << zone
      print_good("#{domain} Zone Transfer: #{zone}")
    end
    return if records.blank?
    save_note(domain, 'DNS AXFR recods', records)
    records
  end

  def save_note(target, type, records)
    data = { 'target' => target, 'records' => records }
    report_note(host: target, sname: 'dns', type: type, data: data, update: :unique_data)
  end
end
