##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require "net/dns/resolver"
require 'rex'

class MetasploitModule < Msf::Auxiliary
  include Msf::Module::Deprecated
  include Msf::Auxiliary::Report

  deprecated(Date.new(2016, 6, 12), 'auxiliary/gather/enum_dns')

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'DNS Common Service Record Enumeration',
      'Description' => %q{
          This module enumerates common DNS service records in a given domain. By setting
        the ALL_DNS to true, all the name servers of a given domain are used for
        enumeration. Otherwise only the system dns is used for enumration. in order to get
        all the available name servers for the given domain the SOA and NS records are
        queried. In order to convert from domain names to IP addresses queries for A and
        AAAA (IPv6) records are used. For Active Directory, it is possible to specify sites.
      },
      'Author'      => [
        'Carlos Perez <carlos_perez[at]darkoperator.com>', # First and main.
        'Fabrice RAFART'                                   # mainly change for AD and report.
      ],
      'License'     => BSD_LICENSE
    ))

    register_options(
      [
        OptString.new('DOMAIN', [true, "The target domain name."]),
        OptString.new('SITES', [false, "The Active Directory site names to test (comma-separated)."]),
        OptBool.new('ALL_NS', [false, "Run against all name servers for the given domain.", false])
      ], self.class)

    register_advanced_options(
      [
        OptInt.new('RETRY', [false, "Number of times to try to resolve a record if no response is received.", 2]),
        OptInt.new('RETRY_INTERVAL', [false, "Number of seconds to wait before doing a retry.", 2])
      ], self.class)
  end

  def run
    records = []
    @res = Net::DNS::Resolver.new()
    if datastore['RETRY']
      @res.retry = datastore['RETRY'].to_i
    end

    if datastore['RETRY_INTERVAL']
      @res.retry_interval = datastore['RETRY_INTERVAL'].to_i
    end

    print_status("Enumerating SRV Records for #{datastore['DOMAIN']}")
    records = records + srvqry(datastore['DOMAIN'])
    if datastore["ALL_NS"]
      get_soa(datastore['DOMAIN']).each do |s|
        switchdns(s[:address])
        records = records + srvqry(datastore['DOMAIN'])
      end
      get_ns(datastore['DOMAIN']).each do |ns|
        switchdns(ns[:address])
        records =records + srvqry(datastore['DOMAIN'])
      end
    end

    records.uniq!
    records.each do |r|
      print_good("Host: #{r[:host]} IP: #{r[:address].to_s} Service: #{r[:service]} Protocol: #{r[:proto]} Port: #{r[:port]} Query: #{r[:query]}")
      report_host(
        :host => r[:address].to_s,
        :name => r[:host]
      )
      report_service(
        :host=> r[:address].to_s,
        :port => r[:port].to_i,
        :proto => r[:proto],
        :name => r[:service],
        :host_name => r[:host]
      )
      report_note(
        :type => 'SRV record',
        :host => r[:address].to_s,
        :port => r[:port].to_i,
        :proto => r[:proto],
        :data => r[:query]
      )
    end

  end

  def get_soa(target)
    results = []
    query = @res.query(target, "SOA")
    return results if not query
    (query.answer.select { |i| i.class == Net::DNS::RR::SOA}).each do |rr|
      if Rex::Socket.dotted_ip?(rr.mname)
        record = {}
        record[:host] = rr.mname
        record[:type] = "SOA"
        record[:address] = rr.mname
        results << record
      else
        get_ip(rr.mname).each do |ip|
          record = {}
          record[:host] = rr.mname.gsub(/\.$/,'')
          record[:type] = "SOA"
          record[:address] = ip[:address].to_s
          results << record
        end
      end
    end
    return results
  end

  def srvqry(dom)
    results = []
    # Most common SRV Records
    srvrcd = [
      '_aix._tcp.',
      '_aix._tcp.',
      '_certificates._tcp.',
      '_cmp._tcp.',
      '_crl._tcp.',
      '_crls._tcp.',
      '_finger._tcp.',
      '_ftp._tcp.',
      '_gc._tcp.',
      '_gc._tcp.Default-First-Site-Name._sites.',
      '_h323be._tcp.',
      '_h323be._udp.',
      '_h323cs._tcp.',
      '_h323cs._udp.',
      '_h323ls._tcp.',
      '_h323ls._udp.',
      '_hkp._tcp.',
      '_hkps._tcp.',
      '_http._tcp.',
      '_imap.tcp.',
      '_jabber-client._tcp.',
      '_jabber-client._udp.',
      '_jabber._tcp.',
      '_jabber._udp.',
      '_kerberos._tcp.',
      '_kerberos._tcp.dc._msdcs.',
      '_kerberos._tcp.Default-First-Site-Name._sites.',
      '_kerberos._udp.',
      '_kerberos.tcp.Default-First-Site-Name._sites.dc._msdcs.',
      '_kpasswd._tcp.',
      '_kpasswd._udp.',
      '_ldap._tcp.',
      '_ldap._tcp.dc._msdcs.',
      '_ldap._tcp.Default-First-Site-Name._sites.',
      '_ldap._tcp.Default-First-Site-Name._sites.dc._msdcs.',
      '_ldap._tcp.Default-First-Site-Name._sites.gc._msdcs.',
      '_ldap._tcp.ForestDNSZones.',
      '_ldap._tcp.gc._msdcs.',
      '_ldap._tcp.pdc._msdcs.',
      '_nntp._tcp.',
      '_ocsp._tcp.',
      '_pgpkeys._tcp.',
      '_pgprevokations._tcp.',
      '_PKIXREP._tcp.',
      '_sip._tcp.',
      '_sip._tls.',
      '_sip._udp.',
      '_sipfederationtls._tcp.',
      '_sipinternal._tcp.',
      '_sipinternaltls._tcp.',
      '_sips._tcp.',
      '_smtp._tcp.',
      '_svcp._tcp.',
      '_telnet._tcp.',
      '_test._tcp.',
      '_whois._tcp.',
      '_xmpp-client._tcp.',
      '_xmpp-client._udp.',
      '_xmpp-server._tcp.',
      '_xmpp-server._udp.'
    ]

    sites = []
    if datastore['SITES']
      sites = datastore['SITES'].split(',')
    end

    sites.each do |site|
      srvrcd = srvrcd + [
        '_gc._tcp.'+site+'._sites.',
        '_kerberos._tcp.'+site+'._sites.',
        '_kerberos.tcp.'+site+'._sites.dc._msdcs.',
        '_ldap._tcp.'+site+'._sites.',
        '_ldap._tcp.'+site+'._sites.dc._msdcs.',
        '_ldap._tcp.'+site+'._sites.gc._msdcs.'
      ]
    end

    srvrcd.each do |srvt|
      trg = "#{srvt}#{dom}"
      begin
        query = @res.query(trg , Net::DNS::SRV)
        next unless query
        query.answer.each do |srv|
          if Rex::Socket.dotted_ip?(srv.host)
            record = {}
            srv_info = srvt.scan(/^_(\S*)\._(tcp|udp)\./)[0]
            record[:query] = "#{srvt}#{dom}"
            record[:host] = srv.host.gsub(/\.$/,'')
            record[:type] = "SRV"
            record[:address] = srv.host
            record[:srv] = srvt
            record[:service] = srv_info[0]
            record[:proto] = srv_info[1]
            record[:port] = srv.port
            record[:priority] = srv.priority
            results << record
            vprint_status("SRV Record: #{trg} Host: #{srv.host.gsub(/\.$/,'')} IP: #{srv.host} Port: #{srv.port} Priority: #{srv.priority}")
          else
            get_ip(srv.host.gsub(/\.$/,'')).each do |ip|
              record = {}
              srv_info = srvt.scan(/^_(\S*)\._(tcp|udp)\./)[0]
              record[:query] = "#{srvt}#{dom}"
              record[:host] = srv.host.gsub(/\.$/,'')
              record[:type] = "SRV"
              record[:address] = ip[:address]
              record[:srv] = srvt
              record[:service] = srv_info[0]
              record[:proto] = srv_info[1]
              record[:port] = srv.port
              record[:priority] = srv.priority
              results << record
              vprint_status("SRV Record: #{trg} Host: #{srv.host} IP: #{ip[:address]} Port: #{srv.port} Priority: #{srv.priority}")
            end
          end
        end
      rescue
      end
    end
    return results
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

  def switchdns(ns)
    vprint_status("Enumerating SRV Records on: #{ns}")
    @res.nameserver=(ns)
    @nsinuse = ns
  end

  def get_ns(target)
    results = []
    query = @res.query(target, "NS")
    return results if not query
    (query.answer.select { |i| i.class == Net::DNS::RR::NS}).each do |rr|
      get_ip(rr.nsdname).each do |r|
        record = {}
        record[:host] = rr.nsdname.gsub(/\.$/,'')
        record[:type] = "NS"
        record[:address] = r[:address].to_s
        results << record
      end
    end
    return results
  end
end
