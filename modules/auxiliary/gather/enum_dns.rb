##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::DNS::Enumeration

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'DNS Record Scanner and Enumerator',
        'Description' => %q{
          This module can be used to gather information about a domain from a
          given DNS server by performing various DNS queries such as zone
          transfers, reverse lookups, SRV record brute forcing, and other techniques.
        },
        'Author' => [
          'Carlos Perez <carlos_perez[at]darkoperator.com>',
          'Nixawk'
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '1999-0532'],
          ['OSVDB', '492']
        ],
        'Notes' => {
          'Reliability' => UNKNOWN_RELIABILITY,
          'Stability' => UNKNOWN_STABILITY,
          'SideEffects' => UNKNOWN_SIDE_EFFECTS
        }
      )
    )

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
        OptAddressRange.new('IPRANGE', [false, "The target address range or CIDR identifier"]),
        OptInt.new('THREADS', [false, 'Threads for ENUM_BRT', 1]),
        OptPath.new('WORDLIST', [false, 'Wordlist of subdomains', ::File.join(Msf::Config.data_directory, 'wordlists', 'namelist.txt')])
      ]
    )

    register_advanced_options(
      [
        OptInt.new('TIMEOUT', [false, 'DNS TIMEOUT', 8]),
        OptInt.new('RETRY', [false, 'Number of times to try to resolve a record if no response is received', 2]),
        OptInt.new('RETRY_INTERVAL', [false, 'Number of seconds to wait before doing a retry', 2]),
        OptBool.new('TCP_DNS', [false, 'Run queries over TCP', false])
      ]
    )
    deregister_options('DnsClientUdpTimeout', 'DnsClientRetry', 'DnsClientRetryInterval', 'DnsClientTcpDns')
  end

  def run
    datastore['DnsClientUdpTimeout'] = datastore['TIMEOUT']
    datastore['DnsClientRetry'] = datastore['RETRY']
    datastore['DnsClientRetryInterval'] = datastore['RETRY_INTERVAL']
    datastore['DnsClientTcpDns'] = datastore['TCP_DNS']

    begin
      setup_resolver
    rescue RuntimeError => e
      fail_with(Failure::BadConfig, "Resolver setup failed - exception: #{e}")
    end

    domain = datastore['DOMAIN']
    is_wildcard = dns_wildcard_enabled?(domain)

    # All exceptions should be being handled by the library
    # but catching here as well, just in case.
    begin
      dns_axfr(domain) if datastore['ENUM_AXFR']
    rescue => e
      print_error("AXFR failed: #{e}")
    end
    dns_get_a(domain) if datastore['ENUM_A']
    dns_get_cname(domain) if datastore['ENUM_CNAME']
    dns_get_ns(domain) if datastore['ENUM_NS']
    dns_get_mx(domain) if datastore['ENUM_MX']
    dns_get_soa(domain) if datastore['ENUM_SOA']
    dns_get_txt(domain) if datastore['ENUM_TXT']
    dns_get_tld(domain) if datastore['ENUM_TLD']
    dns_get_srv(domain) if datastore['ENUM_SRV']
    threads = datastore['THREADS']
    dns_reverse(datastore['IPRANGE'], threads) if datastore['ENUM_RVL']

    return unless datastore['ENUM_BRT']

    if is_wildcard
      dns_bruteforce(domain, datastore['WORDLIST'], threads) unless datastore['STOP_WLDCRD']
    else
      dns_bruteforce(domain, datastore['WORDLIST'], threads)
    end
  end

  def save_note(target, type, records)
    data = { 'target' => target, 'records' => records }
    report_note(host: target, sname: 'dns', type: type, data: data, update: :unique_data)
  end
end
