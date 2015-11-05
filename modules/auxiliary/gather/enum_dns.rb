
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
      'Name'           => 'DNS Record Scanner and Enumerator',
      'Description'    => %q{
        This module can be used to gather information about a domain from a
        given DNS server by performing various DNS queries such as zone
        transfers, reverse lookups, SRV record bruteforcing, and other techniques.
      },
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
        OptBool.new('ENUM_STD', [true, 'Enumerate standard record types (A,MX,NS,TXT and SOA)', true]),
        OptBool.new('ENUM_BRT', [true, 'Brute force subdomains and hostnames via the supplied wordlist', false]),
        OptBool.new('ENUM_TLD', [true, 'Perform a TLD expansion by replacing the TLD with the IANA TLD list', false]),
        OptBool.new('ENUM_SRV', [true, 'Enumerate the most common SRV records', true]),
        OptBool.new('STOP_WLDCRD', [true, 'Stops bruteforce enumeration if wildcard resolution is detected', false]),
        OptAddress.new('NS', [false, 'Nameserver for query']),
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
    return if domain.blank?

    dns_wildcard(domain) unless datastore['STOP_WLDCRD']

    if datastore['ENUM_STD']
      get_a(domain)
      get_cname(domain)
      get_ns(domain)
      get_mx(domain)
      get_soa(domain)
      get_txt(domain)
    end

    get_tld(domain) if datastore['ENUM_TLD']
    get_srv(domain) if datastore['ENUM_SRV']
    axfr(domain) if datastore['ENUM_AXFR']
    dns_bruteforce(domain) if datastore['ENUM_BRT']
  end

  def dns_query(domain, type)
    begin
      dns = Net::DNS::Resolver.new
      nameserver = "#{datastore['NS']}"
      unless nameserver.blank?
        dns.nameservers -= dns.nameservers
        dns.nameservers = ("#{datastore['NS']}")
      end
      dns.use_tcp = datastore['TCP_DNS']
      dns.udp_timeout = datastore['TIMEOUT']
      dns.retry_number = datastore['RETRY']
      dns.retry_interval = datastore['RETRY_INTERVAL']
      dns.query(domain, type)
    rescue ::Rex::ConnectionError
    rescue ::Rex::ConnectionRefused
    rescue ::Rex::ConnectionTimeout
    rescue ::Rex::SocketError
    rescue ::Rex::TimeoutError
    rescue ::Timeout::Error
    end
  end

  def dns_bruteforce(domain)
    wordlist = datastore['WORDLIST'].to_s
    return if wordlist.blank?

    threadnm = datastore['THREADS'].to_i
    return if threadnm == 0

    queue = ::Queue.new
    File.foreach(wordlist) do |line|
      queue << "#{line.chomp}.#{domain}"
    end

    records = []
    until queue.empty?
      tl = []
      1.upto(threadnm) do
        tl << framework.threads.spawn(
          "Module(#{refname})-#{domain}", false, queue.shift) do |target|
            Thread.current.kill unless target
            a = get_a(target)
            records |= a if a
          end
      end
      break if tl.length == 0
      tl.first.join
      tl.delete_if { |t| !t.alive? }
    end
    records
  end

  def dns_wildcard(domain)
    records = get_a("#{Rex::Text.rand_text_alpha(16)}.#{domain}")
    if records.blank?
      vprint_warning('dns wildcard is disable')
      false
    else
      vprint_warning('dns wildcard is enable OR fake dns server')
      true
    end
  end

  def get_a(domain)
    resp = dns_query(domain, 'A')
    return if resp.blank? || resp.answer.blank?

    records = []
    resp.answer.each do |r|
      next unless r.class == Net::DNS::RR::A
      records << "#{r.address}"
      report_host(host: r.address, name: domain, info: 'A')
      vprint_good("#{domain}: A: #{r.address} ")
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
      vprint_good("#{domain}: CNAME: #{r.cname}")
    end
    return if records.none?
    path = store_loot(
      'ENUM_CNAME',
      'text/plain',
      domain,
      records,
      'ENUM_CNAME')
    print_good('Saved file to: ' + path)
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
      report_service(
        host: r.nsdname,
        name: 'dns',
        port: 53,
        proto: 'udp',
        info: 'nameserver')
      vprint_good("#{domain}: NS: #{r.nsdname}")
    end
    return if records.none?
    path = store_loot(
      'ENUM_NS',
      'text/plain',
      domain,
      records,
      'ENUM_NS')
    print_good('Saved file to: ' + path)
    records
  end

  def get_mx(domain)
    resp = dns_query(domain, 'MX')
    return if resp.blank? || resp.answer.blank?

    records = []
    resp.answer.each do |r|
      next unless r.class == Net::DNS::RR::MX
      records << "#{r.exchange}"
      report_host(host: r.exchange, name: domain, info: 'MX')
      report_service(host: r.exchange, name: 'smtp', port: 25, proto: 'tcp')
      vprint_good("#{domain}: MX: #{r.exchange}")
    end
    return if records.none?
    path = store_loot(
      'ENUM_MX',
      'text/plain',
      domain,
      records,
      'ENUM_MX')
    print_good('Saved file to: ' + path)
    records
  end

  def get_soa(domain)
    resp = dns_query(domain, 'SOA')
    return if resp.blank? || resp.answer.blank?

    records = []
    resp.answer.each do |r|
      next unless r.class == Net::DNS::RR::SOA
      records << r.mname
      report_host(host: r.mname, info: 'SOA')
      vprint_good("#{domain}: SOA: #{r.mname}")
    end
    return if records.none?
    path = store_loot(
      'ENUM_SOA',
      'text/plain',
      domain,
      records,
      'ENUM_SOA')
    print_good('Saved file to: ' + path)
    records
  end

  def get_txt(domain)
    resp = dns_query(domain, 'TXT')
    return if resp.blank? || resp.answer.blank?

    records = []
    resp.answer.each do |r|
      next unless r.class == Net::DNS::RR::TXT
      records << r.txt
      report_service(
        host: domain,
        name: 'dns',
        port: 53,
        proto: 'udp',
        info: "#{r.txt}")
      vprint_good("#{domain}: TXT: #{r.txt}")
    end
    return if records.none?
    path = store_loot(
      'ENUM_TXT',
      'text/plain',
      domain,
      records,
      'ENUM_TXT')
    print_good('Saved file to: ' + path)
    records
  end

  def get_tld(domain)
    domain = domain.split('.')
    domain.pop
    domain = domain.join('.')

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
      vprint_status("#{domain}.#{tld}")
      tldr = get_a("#{domain}.#{tld}")
      next if tldr.blank?
      records |= tldr
      report_note(
        host: domain,
        proto: 'udp',
        sname: "#{domain}.#{tld}",
        port: '53',
        type: 'ENUM_TLD',
        data: "#{tldr.join(',')}")
      vprint_good("#{domain}.#{tld}: #{tldr.join(',')}")
    end
    return if records.none?
    path = store_loot(
      'ENUM_TLD',
      'text/plain',
      domain,
      records,
      'ENUM_TLD')
    print_good('Saved file to: ' + path)
    records
  end

  def get_srv(domain)
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
      vprint_status("#{srv}#{domain}")
      resp = dns_query("#{srv}#{domain}", Net::DNS::SRV)
      next if resp.blank? || resp.answer.blank?
      resp.answer.each do |r|
        next if r.type == Net::DNS::RR::CNAME
        report_note(
          host: domain,
          proto: 'udp',
          sname: r.host,
          port: '53',
          type: 'ENUM_SRV',
          data: "#{r.priority}")
        vprint_good("Host: #{r.host} Port: #{r.port} Priority: #{r.priority}")
      end
    end
    return if records.none?
    path = store_loot(
      'ENUM_SRV',
      'text/plain',
      domain,
      records,
      'ENUM_SRV')
    print_good('Saved file to: ' + path)
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
        rescue ::Rex::ConnectionError
        rescue ::Rex::ConnectionRefused
        rescue ::Rex::ConnectionTimeout
        rescue ::Rex::SocketError
        rescue ::Rex::TimeoutError
        rescue ::NoResponseError
        rescue ::Timeout::Error
        end
        next if zone.blank?
        records << "#{zone}"
        vprint_good("#{zone}")
      end
    end
    return if records.none?
    path = store_loot(
      'ENUM_AXFR',
      'text/plain',
      domain,
      records,
      'ENUM_AXFR')
    print_good('Saved file to: ' + path)
    records
  end
end
