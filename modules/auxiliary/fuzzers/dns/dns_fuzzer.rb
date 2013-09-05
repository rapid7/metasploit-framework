##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'bit-struct'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Udp
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Fuzzer
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'DNS and DNSSEC Fuzzer',
      'Description'    => %q{
        This module will connect to a DNS server and perform DNS and
        DNSSEC protocol-level fuzzing. Note that this module may inadvertently
        crash the target server.
      },
    'Author'         => [ 'pello <fropert[at]packetfault.org>' ],
    'License'        => MSF_LICENSE
    )

    register_options([
      Opt::RPORT(53),
      OptInt.new('STARTSIZE', [ false, "Fuzzing string startsize.",0]),
      OptInt.new('ENDSIZE', [ false, "Max Fuzzing string size. (L2 Frame size)",500]),
      OptInt.new('STEPSIZE', [ false, "Increment fuzzing string each attempt.",100]),
      OptInt.new('ERRORHDR', [ false, "Introduces byte error in the DNS header.", 0]),
      OptBool.new('CYCLIC', [ false, "Use Cyclic pattern instead of A's (fuzzing payload).",true]),
      OptInt.new("ITERATIONS", [true, "Number of iterations to run by test case", 5]),
      OptString.new('DOMAIN', [ false, "Force DNS zone domain name."]),
      OptString.new('IMPORTENUM', [ false, "Import dns_enum database output and automatically use existing RR."]),
      OptEnum.new('METHOD', [false, 'Underlayer protocole to use', 'UDP', ['UDP', 'TCP', 'AUTO']]),
      OptBool.new('DNSSEC', [ false, "Add DNSsec to each question (UDP payload size, EDNS0, ...)",false]),
      OptBool.new('TRAILINGNUL', [ false, "NUL byte terminate DNS names",true]),
      OptBool.new('RAWPADDING', [ false, "Generate totally random data from STARTSIZE to ENDSIZE",false]),
      OptString.new('OPCODE', [ false, "Comma separated list of opcodes to fuzz. Leave empty to fuzz all fields.",'' ]),
      # OPCODE accepted values: QUERY,IQUERY,STATUS,UNASSIGNED,NOTIFY,UPDATE
      OptString.new('CLASS', [ false, "Comma separated list of classes to fuzz. Leave empty to fuzz all fields.",'' ]),
      # CLASS accepted values: IN,CH,HS,NONE,ANY
      OptString.new('RR', [ false, "Comma separated list of requests to fuzz. Leave empty to fuzz all fields.",'' ])
      # RR accepted values: A,CNAME,MX,PTR,TXT,AAAA,HINFO,SOA,NS,WKS,RRSIG,DNSKEY,DS,NSEC,NSEC3,NSEC3PARAM
      # RR accepted values: AFSDB,ISDN,RP,RT,X25,PX,SRV,NAPTR,MD,MF,MB,MG,MR,NULL,MINFO,NSAP,NSAP-PTR,SIG
      # RR accepted values: KEY,GPOS,LOC,NXT,EID,NIMLOC,ATMA,KX,CERT,A6,DNAME,SINK,OPT,APL,SSHFP,IPSECKEY
      # RR accepted values: DHCID,HIP,NINFO,RKEY,TALINK,SPF,UINFO,UID,GID,UNSPEC,TKEY,TSIG,IXFR,AXFR,MAILB
      # RR accepted values: MAIL,*,TA,DLV,RESERVED
    ], self.class)
  end

  class Dns_header < BitStruct
    unsigned :txid, 16, { :default => rand(0xffff) }
    unsigned :qr, 1, { :default => 0 }
    unsigned :opcode, 4, { :default => 0 }
    unsigned :aa, 1, { :default => 0 }
    unsigned :tc, 1, { :default => 0 }
    unsigned :rd, 1, { :default => 0 }
    unsigned :ra, 1, { :default => 0 }
    unsigned :z, 3, { :default => 0 }
    unsigned :rcode, 4, { :default => 0 }
    unsigned :questions, 16, { :default => 1 }
    unsigned :answerRR, 16, { :default => 0 }
    unsigned :authorityRR, 16, { :default => 0 }
    unsigned :additionalRR, 16, { :default => 0 }
    rest :payload

    def initialize(*args)
      @options = []
      super
    end

  end

  class Dns_add_rr < BitStruct
    unsigned :name, 8, { :default => 0 }
    unsigned :type, 16, { :default => 0x0029 }
    unsigned :payloadsize, 16, { :default => 0x1000 }
    unsigned :highercode, 8, { :default => 0 }
    unsigned :ednsversion, 8, { :default => 0 }
    unsigned :zlow, 8, { :default => 0 }
    unsigned :zhigh,8, { :default => 0x80 }
    unsigned :datalength, 16, { :default => 0 }

    def initialize(*args)
      @options = []
      super
    end

  end

  def msg
    "#{rhost}:#{rport} - DNS -"
  end

  def check_response_construction(pkt)
    # check if RCODE is not in the unassigned/reserved range
    if pkt[4].to_i >= 0x17 || (pkt[4].to_i >= 0x0b && pkt[4].to_i <= 0x0f)
      print_error("#{msg} Server replied incorrectly to the following request:\n#{@lastdata.unpack('H*')}")
      return false
    else
      return true
    end
  end

  def dns_alive(method)
    connect_udp if method == "UDP" || method == "AUTO"
    connect if method == "TCP"

    payload = ""
    domain = ""
    if @domain == nil
      domain << Rex::Text.rand_text_alphanumeric(rand(2)+2)
      domain << "."
      domain << Rex::Text.rand_text_alphanumeric(rand(6)+3)
      domain << "."
      domain << Rex::Text.rand_text_alphanumeric(2)
    else
      domain << Rex::Text.rand_text_alphanumeric(rand(2)+2)
      domain << "."
      domain << @domain
    end
    splitFQDN = domain.split('.')
    payload = splitFQDN.inject("") { |a,x| a + [x.length,x].pack("CA*") }
    pkt = Dns_header.new
    pkt.txid = rand(0xffff)
    pkt.opcode = 0x0000
    pkt.payload = payload + "\x00" + "\x00\x01" + "\x00\x01"
    testingPkt = pkt.to_s
    udp_sock.put(testingPkt) if method == "UDP"
    sock.put(testingPkt) if method == "TCP"

    res, addr = udp_sock.recvfrom(65535,5) if method == "UDP"
    res, addr = sock.get_once(-1,5) if method == "TCP"

    disconnect_udp if method == "UDP"
    disconnect if method == "TCP"

    if res && res.empty?
      print_error("#{msg} The remote server is not responding to DNS requests.")
      return false
    else
      return true
    end
  end

  def fuzz_padding(payload, size)
    padding = size - payload.length
    if padding <= 0 then return payload end
    if datastore['CYCLIC']
      @fuzzdata = Rex::Text.rand_text_alphanumeric(padding)
    else
      @fuzzdata = 'A' * padding
    end
    payload = payload.ljust(padding, @fuzzdata)
    return payload
  end

  def corrupt_header(pkt,nb)
    len = pkt.length - 1
    for i in 0..nb - 1
      selectByte = rand(len)
      pkt[selectByte] = [rand(255).to_s].pack('H')
    end
    return pkt
  end

  def random_payload(size)
    pkt = Array.new
    for i in 0..size - 1
      pkt[i] = [rand(255).to_s].pack('H')
    end
    return pkt
  end

  def setup_fqdn(domain,entry)
    if domain == nil
      domain = ""
      domain << Rex::Text.rand_text_alphanumeric(rand(62)+2)
      domain << "."
      domain << Rex::Text.rand_text_alphanumeric(rand(61)+3)
      domain << "."
      domain << Rex::Text.rand_text_alphanumeric(rand(62)+2)
    elsif @dnsfile
      domain = entry + "." + domain
    else
      domain = Rex::Text.rand_text_alphanumeric(rand(62)+2) + "." + domain
    end
    return domain
  end

  def import_enum_data(dnsfile)
    enumdata = Array.new(count = File.foreach(dnsfile).inject(0) {|c, line| c+1}, 0)
    idx = 0
    File.open(dnsfile,"rb").each_line do |line|
      line = line.split(",")
      enumdata[idx] = Hash.new
      enumdata[idx][:name] = line[0].strip
      enumdata[idx][:rr] = line[1].strip
      enumdata[idx][:class] = line[2].strip
      idx = idx + 1
    end
    return enumdata
  end

  def setup_nsclass(nsclass)
    classns = ""
    for idx in nsclass
      classns << {
        "IN" => 0x0001, "CH" => 0x0003, "HS" => 0x0004,
        "NONE" => 0x00fd, "ANY" => 0x00ff
      }.values_at(idx).pack("n")
    end
    return classns
  end

  def setup_opcode(nsopcode)
    opcode = ""
    for idx in nsopcode
      opcode << {
        "QUERY" => 0x0000, "IQUERY" => 0x0001, "STATUS" => 0x0002,
        "UNASSIGNED" => 0x0003, "NOTIFY" => 0x0004, "UPDATE" => 0x0005
      }.values_at(idx).pack("n")
    end
    return opcode
  end

  def setup_reqns(nsreq)
    reqns= ""
    for idx in nsreq
      reqns << {
        "A" => 0x0001, "NS" => 0x0002, "MD" => 0x0003, "MF" => 0x0004,
        "CNAME" => 0x0005, "SOA" => 0x0006, "MB" => 0x0007, "MG" => 0x0008,
        "MR" => 0x0009, "NULL" => 0x000a, "WKS" => 0x000b, "PTR" => 0x000c,
        "HINFO" => 0x000d, "MINFO" => 0x000e, "MX" => 0x000f, "TXT" => 0x0010,
        "RP" => 0x0011, "AFSDB" => 0x0012, "X25" => 0x0013, "ISDN" => 0x0014,
        "RT" => 0x0015, "NSAP" => 0x0016, "NSAP-PTR" => 0x0017, "SIG" => 0x0018,
        "KEY" => 0x0019, "PX" => 0x001a, "GPOS" => 0x001b, "AAAA" => 0x001c,
        "LOC" => 0x001d, "NXT" => 0x001e, "EID" => 0x001f, "NIMLOC" => 0x0020,
        "SRV" => 0x0021, "ATMA" => 0x0022, "NAPTR" => 0x0023, "KX" => 0x0024,
        "CERT" => 0x0025, "A6" => 0x0026, "DNAME" => 0x0027, "SINK" => 0x0028,
        "OPT" => 0x0029, "APL" => 0x002a, "DS" => 0x002b, "SSHFP" => 0x002c,
        "IPSECKEY" => 0x002d, "RRSIG" => 0x002e, "NSEC" => 0x002f, "DNSKEY" => 0x0030,
        "DHCID" => 0x0031, "NSEC3" => 0x0032, "NSEC3PARAM" => 0x0033, "HIP" => 0x0037,
        "NINFO" => 0x0038, "RKEY" => 0x0039, "TALINK" => 0x003a, "SPF" => 0x0063,
        "UINFO" => 0x0064, "UID" => 0x0065, "GID" => 0x0066, "UNSPEC" => 0x0067,
        "TKEY" => 0x00f9, "TSIG" => 0x00fa, "IXFR" => 0x00fb, "AXFR" => 0x00fc,
        "MAILA" => 0x00fd, "MAILB" => 0x00fe, "*" => 0x00ff, "TA" => 0x8000,
        "DLV" => 0x8001, "RESERVED" => 0xffff
      }.values_at(idx).pack("n")
    end
    return reqns
  end

  def build_packet(dnsOpcode,dnssec,trailingnul,reqns,classns,payload)
    pkt = Dns_header.new
    pkt.opcode = dnsOpcode
    if trailingnul
      if @dnsfile
        pkt.payload = payload + "\x00" + reqns + classns
      else
        pkt.payload = payload + "\x00" + [reqns].pack("n") + [classns].pack("n")
      end
    else
      if @dnsfile
        pkt.payload = payload + [(rand(255) + 1).to_s].pack('H') + reqns + classns
      else
        pkt.payload = payload + [(rand(255) + 1).to_s].pack('H') + [dnsReq].pack("n") + [dnsClass].pack("n")
      end
    end
    if dnssec
      dnssecpkt = Dns_add_rr.new
      pkt.additionalRR = 1
      pkt = pkt + dnssecpkt
    end
    return pkt
  end

  def dns_send(data,method)
    method = "UDP" if (method == "AUTO" && data.length < 512)
    method = "TCP" if (method == "AUTO" && data.length >= 512)

    connect_udp if method == "UDP"
    connect if method == "TCP"
    udp_sock.put(data) if method == "UDP"
    sock.put(data) if method == "TCP"

    res, addr = udp_sock.recvfrom(65535,1) if method == "UDP"
    res, addr = sock.get_once(-1,1) if method == "TCP"

    disconnect_udp if method == "UDP"
    disconnect if method == "TCP"

    if res && res.length == 0
      @failCount += 1
      if @failCount == 1
        @probablyVuln = @lastdata if @lastdata != nil
        return true
      elsif @failCount >= 3
        if dns_alive(method) == false
          print_error("#{msg} DNS is DOWN since the request:\n#{@lastdata.unpack('H*')}")
          return false
        else
          return true
        end
      else
        return true
      end
    elsif res && res.length > 0
      @lastdata = data
      if res[3].to_i >= 0x8000 # ignore server response as a query
        @failCount = 0
        return true
      end
      if @rawpadding
        @failCount = 0
        return true
      end
      if check_response_construction(res)
        @failCount = 0
        return true
      else
        return false
      end
    end
  end

  def fix_variables
    if datastore['OPCODE'] == ""
      datastore['OPCODE'] = "QUERY,IQUERY,STATUS,UNASSIGNED,NOTIFY,UPDATE"
    end
    if datastore['CLASS'] == ""
      datastore['CLASS'] = "IN,CH,HS,NONE,ANY"
    end
    if datastore['RR'] == ""
      datastore['RR'] = "A,NS,MD,MF,CNAME,SOA,MB,MG,MR,NULL,WKS,PTR,"
      datastore['RR'] << "HINFO,MINFO,MX,TXT,RP,AFSDB,X25,ISDN,RT,"
      datastore['RR'] << "NSAP,NSAP-PTR,SIG,KEY,PX,GPOS,AAAA,LOC,NXT,"
      datastore['RR'] << "EID,NIMLOC,SRV,ATMA,NAPTR,KX,CERT,A6,DNAME,"
      datastore['RR'] << "SINK,OPT,APL,DS,SSHFP,IPSECKEY,RRSIG,NSEC,"
      datastore['RR'] << "DNSKEY,DHCID,NSEC3,NSEC3PARAM,HIP,NINFO,RKEY,"
      datastore['RR'] << "TALINK,SPF,UINFO,UID,GID,UNSPEC,TKEY,TSIG,"
      datastore['RR'] << "IXFR,AXFR,MAILA,MAILB,*,TA,DLV,RESERVED"
    end
  end

  def run_host(ip)
    msg = "#{ip}:#{rhost} - DNS -"
    begin
      @lastdata = nil
      @probablyVuln = nil
      @startsize = datastore['STARTSIZE']
      @stepsize = datastore['STEPSIZE']
      @endsize = datastore['ENDSIZE']
      @underlayerProtocol = datastore['METHOD']
      @failCount = 0
      @domain = datastore['DOMAIN']
      @dnsfile = datastore['IMPORTENUM']
      @rawpadding = datastore['RAWPADDING']
      iter = datastore['ITERATIONS']
      dnssec = datastore['DNSSEC']
      errorhdr = datastore['ERRORHDR']
      trailingnul = datastore['TRAILINGNUL']

      fix_variables

      if !dns_alive(@underlayerProtocol) then return false end

      print_status("#{msg} Fuzzing DNS server, this may take a while.")

      if @startsize < 12 && @startsize > 0
        print_status("#{msg} STARTSIZE must be at least 12. STARTSIZE value has been modified.")
        @startsize = 12
      end

      if @rawpadding
        if @domain == nil
          print_status("DNS Fuzzer: DOMAIN could be set for health check but not mandatory.")
        end
        nsopcode=datastore['OPCODE'].split(",")
        opcode = setup_opcode(nsopcode)
        opcode.unpack("n*").each do |dnsOpcode|
          1.upto(iter) do
            while @startsize <= @endsize
              data = random_payload(@startsize).to_s
              data[2] = 0x0
              data[3] = dnsOpcode
              if !dns_send(data,@underlayerProtocol) then return false end
              @lastdata = data
              @startsize += @stepsize
            end
            @startsize = datastore['STARTSIZE']
          end
        end
        return
      end

      if @dnsfile
        if @domain == nil
          print_error("DNS Fuzzer: Domain variable must be set.")
          return
        end

        dnsenumdata = import_enum_data(@dnsfile)
        nsreq = []
        nsclass = []
        nsentry = []
        for req, value in dnsenumdata
          nsreq << req[:rr]
          nsclass << req[:class]
          nsentry << req[:name]
        end
        nsopcode=datastore['OPCODE'].split(",")
      else
        nsreq=datastore['RR'].split(",")
        nsopcode=datastore['OPCODE'].split(",")
        nsclass=datastore['CLASS'].split(",")
        begin
          classns = setup_nsclass(nsclass)
          raise ArgumentError, "Invalid CLASS: #{nsclass.inspect}" unless classns
          opcode = setup_opcode(nsopcode)
          raise ArgumentError, "Invalid OPCODE: #{opcode.inspect}" unless nsopcode
          reqns = setup_reqns(nsreq)
          raise ArgumentError, "Invalid RR: #{nsreq.inspect}" unless nsreq
        rescue ::Exception => e
          print_error("DNS Fuzzer error, aborting: #{e}")
          return
        end
      end

      for question in nsreq
        case question
        when "RRSIG", "DNSKEY", "DS", "NSEC", "NSEC3", "NSEC3PARAM"
          dnssec = true
        end
      end

      if @dnsfile
        classns = setup_nsclass(nsclass)
        reqns = setup_reqns(nsreq)
        opcode = setup_opcode(nsopcode)
        opcode.unpack("n*").each do |dnsOpcode|
          for i in 0..nsentry.length - 1
            reqns = setup_reqns(nsreq[i])
            classns = setup_nsclass(nsclass[i])
            1.upto(iter) do
              payload = ""
              nsdomain = setup_fqdn(@domain,nsentry[i])
              splitFQDN = nsdomain.split('.')
              payload = splitFQDN.inject("") { |a,x| a + [x.length,x].pack("CA*") }
              pkt = build_packet(dnsOpcode,dnssec,trailingnul,reqns,classns,payload)
              pkt = corrupt_header(pkt,errorhdr) if errorhdr > 0
              if @startsize == 0
                if !dns_send(pkt,@underlayerProtocol) then return end
              else
                while @startsize <= @endsize
                  pkt = fuzz_padding(pkt, @startsize)
                  if !dns_send(pkt,@underlayerProtocol) then return end
                  @startsize += @stepsize
                end
                @startsize = datastore['STARTSIZE']
              end
            end
          end
        end
      else
        classns.unpack("n*").each do |dnsClass|
          opcode.unpack("n*").each do |dnsOpcode|
            reqns.unpack("n*").each do |dnsReq|
              1.upto(iter) do
                payload = ""
                nsdomain = setup_fqdn(@domain,"")
                splitFQDN = nsdomain.split('.')
                payload = splitFQDN.inject("") { |a,x| a + [x.length,x].pack("CA*") }
                pkt = build_packet(dnsOpcode,dnssec,trailingnul,dnsReq,dnsClass,payload)
                pkt = corrupt_header(pkt,errorhdr) if errorhdr > 0
                if @startsize == 0
                  if !dns_send(pkt,@underlayerProtocol) then return end # If then return end?
                else
                  while @startsize <= @endsize
                    pkt = fuzz_padding(pkt, @startsize)
                    if !dns_send(pkt,@underlayerProtocol) then return end
                    @startsize += @stepsize
                  end
                  @startsize = datastore['STARTSIZE']
                end
              end
            end
          end
        end
      end
    end
  end
end
