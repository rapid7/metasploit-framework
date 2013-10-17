##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require "net/dns/resolver"

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'		   => 'DNS Record Scanner and Enumerator ',
      'Description'	=> %q{
        This module can be used to gather information about a domain from a
        given DNS server by performing various DNS queries such as zone
        transfers, reverse lookups, SRV record bruteforcing, and other techniques.

      },
      'Author'		=> [ 'Carlos Perez <carlos_perez[at]darkoperator.com>' ],
      'License'		=> MSF_LICENSE,
      'References' 	=>
        [
          ['CVE', '1999-0532'],
          ['OSVDB', '492'],
        ]
      ))

    register_options(
      [
        OptString.new('DOMAIN', [ true, "The target domain name"]),
        OptBool.new('ENUM_AXFR', [ true, 'Initiate a zone transfer against each NS record', true]),
        OptBool.new('ENUM_TLD', [ true, 'Perform a TLD expansion by replacing the TLD with the IANA TLD list', false]),
        OptBool.new('ENUM_STD', [ true, 'Enumerate standard record types (A,MX,NS,TXT and SOA)', true]),
        OptBool.new('ENUM_BRT', [ true, 'Brute force subdomains and hostnames via the supplied wordlist', false]),
        OptBool.new('ENUM_IP6', [ true, 'Brute force hosts with IPv6 AAAA records',false]),
        OptBool.new('ENUM_RVL', [ true, 'Reverse lookup a range of IP addresses', false]),
        OptBool.new('ENUM_SRV', [ true, 'Enumerate the most common SRV records', true]),
        OptPath.new('WORDLIST', [ false, "Wordlist for domain name bruteforcing", ::File.join(Msf::Config.install_root, "data", "wordlists", "namelist.txt")]),
        OptAddress.new('NS', [ false, "Specify the nameserver to use for queries (default is system DNS)" ]),
        OptAddressRange.new('IPRANGE', [false, "The target address range or CIDR identifier"]),
        OptBool.new('STOP_WLDCRD', [ true, 'Stops bruteforce enumeration if wildcard resolution is detected', false])
      ], self.class)

    register_advanced_options(
      [
        OptInt.new('RETRY', [ false, "Number of times to try to resolve a record if no response is received", 2]),
        OptInt.new('RETRY_INTERVAL', [ false, "Number of seconds to wait before doing a retry", 2]),
        OptBool.new('TCP_DNS', [false, "Run queries over TCP", false]),
      ], self.class)
  end

  #---------------------------------------------------------------------------------
  def switchdns(target)
    if not datastore['NS'].nil?
      print_status("Using DNS Server: #{datastore['NS']}")
      @res.nameserver=(datastore['NS'])
      @nsinuse = datastore['NS']
    else
      querysoa = @res.query(target, "SOA")
      if (querysoa)
        (querysoa.answer.select { |i| i.class == Net::DNS::RR::SOA}).each do |rr|
          query1soa = @res.search(rr.mname)
          if (query1soa and query1soa.answer[0])
            print_status("Setting DNS Server to #{target} NS: #{query1soa.answer[0].address}")
            @res.nameserver=(query1soa.answer[0].address)
            @nsinuse = query1soa.answer[0].address
          end
        end
      end
    end
  end
  #---------------------------------------------------------------------------------
  def wildcard(target)
    rendsub = rand(10000).to_s
    query = @res.query("#{rendsub}.#{target}", "A")
    if query.answer.length != 0
      print_status("This domain has wildcards enabled!!")
      query.answer.each do |rr|
        print_status("Wildcard IP for #{rendsub}.#{target} is: #{rr.address.to_s}") if rr.class != Net::DNS::RR::CNAME
      end
      return true
    else
      return false
    end
  end
  #---------------------------------------------------------------------------------
  def genrcd(target)
    print_status("Retrieving general DNS records")
    query = @res.search(target)
    if (query)
      query.answer.each do |rr|
        next unless rr.class == Net::DNS::RR::A
        print_status("Domain: #{target} IP address: #{rr.address} Record: A ")
        report_note(:host => @nsinuse.to_s,
          :proto => 'udp',
          :sname => 'dns',
          :port => 53 ,
          :type => 'dns.enum',
          :update => :unique_data,
          :data => "#{rr.address.to_s},#{target},A")
      end
    end
    query = @res.query(target, "SOA")
    if (query)
      (query.answer.select { |i| i.class == Net::DNS::RR::SOA}).each do |rr|
        query1 = @res.search(rr.mname)
        if (query1)
          query1.answer.each do |ip|
            print_status("Start of Authority: #{rr.mname} IP address: #{ip.address} Record: SOA")
            report_note(:host => @nsinuse.to_s,
              :proto => 'udp',
              :sname => 'dns',
              :port => 53 ,
              :type => 'dns.enum',
              :update => :unique_data,
              :data => "#{ip.address.to_s},#{rr.mname},SOA")
          end
        end
      end
    end
    query = @res.query(target, "NS")
    if (query)
      (query.answer.select { |i| i.class == Net::DNS::RR::NS}).each do |rr|
        query1 = @res.search(rr.nsdname)
        if (query1)
          query1.answer.each do |ip|
            next unless ip.class == Net::DNS::RR::A
            print_status("Name Server: #{rr.nsdname} IP address: #{ip.address} Record: NS")
            report_note(:host => @nsinuse.to_s,
              :proto => 'udp',
              :sname => 'dns',
              :port => 53 ,
              :type => 'dns.enum',
              :update => :unique_data,
              :data => "#{ip.address.to_s},#{rr.nsdname},NS")
          end
        end
      end
    end
    query = @res.query(target, "MX")
    if (query)
      (query.answer.select { |i| i.class == Net::DNS::RR::MX}).each do |rr|
        print_status("Name: #{rr.exchange} Preference: #{rr.preference} Record: MX")
        report_note(:host => @nsinuse.to_s,
          :proto => 'udp',
          :sname => 'dns',
          :port => 53 ,
          :type => 'dns.enum',
          :update => :unique_data,
          :data => "#{rr.exchange},MX")
      end
    end
    query = @res.query(target, "TXT")
    if (query)
      query.answer.each do |rr|
        print_status(rr.inspect)
        print_status("Text: #{rr.inspect}")
        report_note(:host => @nsinuse.to_s,
          :proto => 'udp',
          :sname => 'dns',
          :port => 53 ,
          :type => 'dns.enum',
          :update => :unique_data,
          :data => rr.inspect)
      end
    end
  end
  #---------------------------------------------------------------------------------
  def tldexpnd(targetdom,nssrv)
    target = targetdom.scan(/(\S*)[.]\w*\z/).join
    target.chomp!
    if not nssrv.nil?
      @res.nameserver=(nssrv)
      @nsinuse = nssrv
    end
    i, a = 0, []
    tlds = [
      "com", "org", "net", "edu", "mil", "gov", "uk", "af", "al", "dz",
      "as", "ad", "ao", "ai", "aq", "ag", "ar", "am", "aw", "ac","au",
      "at", "az", "bs", "bh", "bd", "bb", "by", "be", "bz", "bj", "bm",
      "bt", "bo", "ba", "bw", "bv", "br", "io", "bn", "bg", "bf", "bi",
      "kh", "cm", "ca", "cv", "ky", "cf", "td", "cl", "cn", "cx", "cc",
      "co", "km", "cd", "cg", "ck", "cr", "ci", "hr",	"cu", "cy", "cz",
      "dk", "dj", "dm", "do", "tp", "ec", "eg", "sv", "gq", "er", "ee",
      "et", "fk", "fo", "fj",	"fi", "fr", "gf", "pf", "tf", "ga", "gm",
      "ge", "de", "gh", "gi", "gr", "gl", "gd", "gp", "gu", "gt", "gg",
      "gn", "gw", "gy", "ht", "hm", "va", "hn", "hk", "hu", "is", "in",
      "id", "ir", "iq", "ie", "im", "il", "it", "jm", "jp", "je", "jo",
      "kz", "ke", "ki", "kp", "kr", "kw", "kg", "la", "lv", "lb", "ls",
      "lr", "ly", "li", "lt", "lu", "mo", "mk", "mg", "mw", "my", "mv",
      "ml", "mt", "mh", "mq", "mr", "mu", "yt", "mx", "fm", "md", "mc",
      "mn", "ms", "ma", "mz", "mm", "na", "nr", "np", "nl", "an", "nc",
      "nz", "ni", "ne", "ng", "nu", "nf", "mp", "no", "om", "pk", "pw",
      "pa", "pg", "py", "pe", "ph", "pn", "pl", "pt", "pr", "qa", "re",
      "ro", "ru", "rw", "kn", "lc", "vc", "ws", "sm", "st", "sa", "sn",
      "sc", "sl", "sg", "sk", "si", "sb", "so", "za", "gz", "es", "lk",
      "sh", "pm", "sd", "sr", "sj", "sz", "se", "ch", "sy", "tw", "tj",
      "tz", "th", "tg", "tk", "to", "tt", "tn", "tr", "tm", "tc", "tv",
      "ug", "ua", "ae", "gb", "us", "um", "uy", "uz", "vu", "ve", "vn",
      "vg", "vi", "wf", "eh", "ye", "yu", "za", "zr", "zm", "zw", "int",
      "gs", "info", "biz", "su", "name", "coop", "aero" ]
    print_status("Performing Top Level Domain expansion using #{tlds.size} TLDs")

    tlds.each do |tld|
      query1 = @res.search("#{target}.#{tld}")
      if (query1)
        query1.answer.each do |rr|
          print_status("Domain: #{target}.#{tld} Name: #{rr.name} IP address: #{rr.address} Record: A ") if rr.class == Net::DNS::RR::A
          report_note(:host => @nsinuse.to_s,
            :proto => 'udp',
            :sname => 'dns',
            :port => 53,
            :type => 'dns.enum',
            :update => :unique_data,
            :data => "#{rr.address.to_s},#{target}.#{tld},A") if rr.class == Net::DNS::RR::A
        end
      end
    end

  end

  #-------------------------------------------------------------------------------
  def dnsbrute(target, wordlist, nssrv)
    print_status("Running bruteforce against domain #{target}")
    arr = []
    i, a = 0, []
    ::File.open(wordlist, "rb").each_line do |line|
      if not nssrv.nil?
        @res.nameserver=(nssrv)
        @nsinuse = nssrv
      end
      query1 = @res.search("#{line.chomp}.#{target}")
      if (query1)
        query1.answer.each do |rr|
          if rr.class == Net::DNS::RR::A
            print_status("Hostname: #{line.chomp}.#{target} IP address: #{rr.address.to_s}")
            report_note(:host => @nsinuse.to_s,
              :proto => 'udp',
              :sname => 'dns',
              :port => 53 ,
              :type => 'dns.enum',
              :update => :unique_data,
              :data => "#{rr.address.to_s},#{line.chomp}.#{target},A")
            next unless rr.class == Net::DNS::RR::CNAME
          end
        end
      end
    end
  end

  #-------------------------------------------------------------------------------
  def bruteipv6(target, wordlist, nssrv)
    print_status("Bruteforcing IPv6 addresses against domain #{target}")
    arr = []
    i, a = 0, []
    arr = IO.readlines(wordlist)
    if not nssrv.nil?
      @res.nameserver=(nssrv)
      @nsinuse = nssrv
    end
    arr.each do |line|
      query1 = @res.search("#{line.chomp}.#{target}", "AAAA")
      if (query1)
        query1.answer.each do |rr|
          if rr.class == Net::DNS::RR::AAAA
            print_status("Hostname: #{line.chomp}.#{target} IPv6 Address: #{rr.address.to_s}")
            report_note(:host => @nsinuse.to_s,
              :proto => 'udp',
              :sname => 'dns',
              :port => 53 ,
              :type => 'dns.enum',
              :update => :unique_data,
              :data => "#{rr.address.to_s},#{line.chomp}.#{target},AAAA")
            next unless rr.class == Net::DNS::RR::CNAME
          end
        end
      end

    end
  end



  #-------------------------------------------------------------------------------
  def reverselkp(iprange,nssrv)
    print_status("Running reverse lookup against IP range #{iprange}")
    if not nssrv.nil?
      @res.nameserver = (nssrv)
      @nsinuse = nssrv
    end
    ar = Rex::Socket::RangeWalker.new(iprange)
    tl = []
    while (true)
      # Spawn threads for each host
      while (tl.length < @threadnum)
        ip = ar.next_ip
        break if not ip
        tl << framework.threads.spawn("Module(#{self.refname})-#{ip}", false, ip.dup) do |tip|
          begin
            query = @res.query(tip)
            query.each_ptr do |addresstp|
              print_status("Hostname: #{addresstp} IP address: #{tip.to_s}")
              report_note(:host => @nsinuse.to_s,
                :proto => 'udp',
                :sname => 'dns',
                :port => 53 ,
                :type => 'dns.enum',
                :update => :unique_data,
                :data => "#{addresstp},#{tip},A")
            end
          rescue ::Interrupt
            raise $!
          rescue ::Rex::ConnectionError
          rescue ::Exception => e
            print_error("Error: #{tip}: #{e.message}")
            elog("Error running against host #{tip}: #{e.message}\n#{e.backtrace.join("\n")}")
          end
        end
      end
      # Exit once we run out of hosts
      if(tl.length == 0)
        break
      end
      tl.first.join
      tl.delete_if { |t| not t.alive? }
    end
  end
  #-------------------------------------------------------------------------------
  #SRV Record Enumeration
  def srvqry(dom,nssrv)
    print_status("Enumerating SRV records for #{dom}")
    i, a = 0, []
    #Most common SRV Records
    srvrcd = [
      "_gc._tcp.","_kerberos._tcp.", "_kerberos._udp.","_ldap._tcp","_test._tcp.",
      "_sips._tcp.","_sip._udp.","_sip._tcp.","_aix._tcp.","_aix._tcp.","_finger._tcp.",
      "_ftp._tcp.","_http._tcp.","_nntp._tcp.","_telnet._tcp.","_whois._tcp.","_h323cs._tcp.",
      "_h323cs._udp.","_h323be._tcp.","_h323be._udp.","_h323ls._tcp.","_h323ls._udp.",
      "_sipinternal._tcp.","_sipinternaltls._tcp.","_sip._tls.","_sipfederationtls._tcp.",
      "_jabber._tcp.","_xmpp-server._tcp.","_xmpp-client._tcp.","_imap._tcp.","_certificates._tcp.",
      "_crls._tcp.","_pgpkeys._tcp.","_pgprevokations._tcp.","_cmp._tcp.","_svcp._tcp.","_crl._tcp.",
      "_ocsp._tcp.","_PKIXREP._tcp.","_smtp._tcp.","_hkp._tcp.","_hkps._tcp.","_jabber._udp.",
      "_xmpp-server._udp.","_xmpp-client._udp.","_jabber-client._tcp.","_jabber-client._udp."]
    srvrcd.each do |srvt|
      trg = "#{srvt}#{dom}"
      query = @res.query(trg , Net::DNS::SRV)
      if query
        query.answer.each do |srv|
          print_status("SRV Record: #{trg} Host: #{srv.host} Port: #{srv.port} Priority: #{srv.priority}") if srv.type != "CNAME"
        end
      end
    end
  end

  #-------------------------------------------------------------------------------
  #For Performing Zone Transfers
  def axfr(target, nssrv)
    print_status("Performing zone transfer against all nameservers in #{target}")
    if not nssrv.nil?
      @res.nameserver=(nssrv)
      @nsinuse = nssrv
    end
    @res.tcp_timeout=15
    query = @res.query(target, "NS")
    if (query.answer.length != 0)
      (query.answer.select { |i| i.class == Net::DNS::RR::NS}).each do |nsrcd|
        print_status("Testing nameserver: #{nsrcd.nsdname}")
        nssrvquery = @res.query(nsrcd.nsdname, "A")
        if nssrvquery.answer.length == 0
          nssrvip = Rex::Socket.gethostbyname(nsrcd.nsdname)[3].bytes.reduce {|a,b| [a,b].join(".")}
        else
          nssrvip = nssrvquery.answer[0].address.to_s
        end
        begin
          @res.nameserver=(nssrvip)
          @nsinuse = nssrvip
          zone = []
          zone = @res.axfr(target)
          if zone.length != 0
            print_status("Zone transfer successful")
            report_note(:host => nssrvip,
              :proto => 'udp',
              :sname => 'dns',
              :port => 53 ,
              :type => 'dns.enum',
              :update => :unique_data,
              :data => "Zone transfer successful")
            #Prints each record according to its type
            zone.each do |response|
              response.answer.each do |rr|
                begin
                case rr.type
                when "A"
                  print_status("Name: #{rr.name} IP address: #{rr.address} Record: A ")
                  report_note(:host => nssrvip,
                    :proto => 'udp',
                    :sname => 'dns',
                    :port => 53 ,
                    :type => 'dns.enum',
                    :update => :unique_data,
                    :data => "#{rr.address.to_s},#{rr.name},A")
                when "SOA"
                  print_status("Name: #{rr.mname} Record: SOA")
                  report_note(:host => nssrvip,
                    :proto => 'udp',
                    :sname => 'dns',
                    :port => 53 ,
                    :type => 'dns.enum',
                    :update => :unique_data,
                    :data => "#{rr.name},SOA")
                when "MX"
                  print_status("Name: #{rr.exchange} Preference: #{rr.preference} Record: MX")
                  report_note(:host => nssrvip,
                    :proto => 'udp',
                    :sname => 'dns',
                    :port => 53 ,
                    :type => 'dns.enum',
                    :update => :unique_data,
                    :data => "#{rr.exchange},MX")
                when "CNAME"
                  print_status("Name: #{rr.cname} Record: CNAME")
                  report_note(:host => nssrvip,
                    :proto => 'udp',
                    :sname => 'dns',
                    :port => 53 ,
                    :type => 'dns.enum',
                    :update => :unique_data,
                    :data => "#{rr.cname},CNAME")
                when "HINFO"
                  print_status("CPU: #{rr.cpu} OS: #{rr.os} Record: HINFO")
                  report_note(:host => nssrvip,
                    :proto => 'udp',
                    :sname => 'dns',
                    :port => 53 ,
                    :type => 'dns.enum',
                    :update => :unique_data,
                    :data => "CPU:#{rr.cpu},OS:#{rr.os},HINFO")
                when "AAAA"
                  print_status("IPv6 Address: #{rr.address} Record: AAAA")
                  report_note(:host => nssrvip,
                    :proto => 'udp',
                    :sname => 'dns',
                    :port => 53 ,
                    :type => 'dns.enum',
                    :update => :unique_data,
                    :data => "#{rr.address.to_s}, AAAA")
                when "NS"
                  print_status("Name: #{rr.nsdname} Record: NS")
                  report_note(:host =>  nssrvip,
                    :proto => 'udp',
                    :sname => 'dns',
                    :port => 53 ,
                    :type => 'dns.enum',
                    :update => :unique_data,
                    :data => "#{rr.nsdname},NS")
                when "TXT"
                  print_status("Text: #{rr.inspect}")
                  report_note(:host =>  nssrvip,
                    :proto => 'udp',
                    :sname => 'dns',
                    :port => 53 ,
                    :type => 'dns.enum',
                    :update => :unique_data,
                    :data => rr.inspect)
                when "SRV"
                  print_status("Host: #{rr.host} Port: #{rr.port} Priority: #{rr.priority} Record: SRV")
                  report_note(:host =>  nssrvip,
                    :proto => 'udp',
                    :sname => 'dns',
                    :port => 53 ,
                    :type => 'dns.enum',
                    :update => :unique_data,
                    :data => "#{rr.host},#{rr.port},#{rr.priority},SRV")
                end
                rescue ActiveRecord::RecordInvalid
                  #Do nothing. Probably tried to store :host => 127.0.0.1
                end
              end
            end
          else
            print_error("Zone transfer failed (length was zero)")
          end
        rescue Exception => e
          print_error("Error executing zone transfer: #{e.message}")
          elog("Error executing zone transfer: #{e.message}\n#{e.backtrace.join("\n")}")
        end
      end

    else
      print_error("Could not resolve domain #{target}")
    end
  end

  def run
    @res = Net::DNS::Resolver.new()
    if datastore['TCP_DNS']
      vprint_status("Using DNS/TCP")
      @res.use_tcp = true
    end
    @res.retry = datastore['RETRY'].to_i
    @res.retry_interval = datastore['RETRY_INTERVAL'].to_i
    @threadnum = datastore['THREADS'].to_i
    wldcrd = wildcard(datastore['DOMAIN'])
    switchdns(datastore['DOMAIN'])

    if(datastore['ENUM_STD'])
      genrcd(datastore['DOMAIN'])
    end

    if(datastore['ENUM_TLD'])
      tldexpnd(datastore['DOMAIN'],datastore['NS'])
    end

    if(datastore['ENUM_BRT'])
      if wldcrd and datastore['STOP_WLDCRD']
        print_error("Wildcard record found!")
      else
        dnsbrute(datastore['DOMAIN'],datastore['WORDLIST'],datastore['NS'])
      end
    end

    if(datastore['ENUM_IP6'])
      if wldcrd and datastore['STOP_WLDCRD']
        print_status("Wildcard Record Found!")
      else
        bruteipv6(datastore['DOMAIN'],datastore['WORDLIST'],datastore['NS'])
      end
    end

    if(datastore['ENUM_AXFR'])
      axfr(datastore['DOMAIN'],datastore['NS'])
    end

    if(datastore['ENUM_SRV'])
      srvqry(datastore['DOMAIN'],datastore['NS'])
    end

    if(datastore['ENUM_RVL'] and datastore['IPRANGE'] and not datastore['IPRANGE'].empty?)
      reverselkp(datastore['IPRANGE'],datastore['NS'])
    end
  end
end
