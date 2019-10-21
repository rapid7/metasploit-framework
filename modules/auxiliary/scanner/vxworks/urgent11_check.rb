##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Capture

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'URGENT/11 Scanner, Based on Detection Tool by Armis',
      'Description'    => %q{
        This module detects VxWorks and the IPnet IP stack, along with devices
        vulnerable to CVE-2019-12258.
      },
      'Author'         => [
        'Ben Seri',   # Upstream tool
        'Brent Cook', # Metasploit module
        'wvu'         # Metasploit module
      ],
      'References'     => [
        ['CVE', '2019-12258'],
        ['URL', 'https://armis.com/urgent11'],
        ['URL', 'https://github.com/ArmisSecurity/urgent11-detector']
      ],
      'DisclosureDate' => '2019-08-09', # NVD entry publication
      'License'        => MSF_LICENSE,
      'Notes'          => {'Stability' => [CRASH_SAFE]}
    ))

    register_options([
      OptString.new('RPORTS', required: true, default: "21 22 23 80 443", desc: 'Target ports for TCP detections')
    ])

    register_advanced_options([
      Opt::RPORT(80, true, 'Target port for TCP detections'),
      OptInt.new('RetransmissionRate', required: true, default: 3, desc: 'Send n TCP packets')
    ])

    deregister_options('PCAPFILE', 'FILTER')
  end

  #
  # Utility methods
  #

  def rport
    datastore['RPORT']
  end

  def rports
    datastore['RPORTS'].gsub(/\s+/m, ' ').strip.split(' ').collect{|i| (i.to_i.to_s == i) ? i.to_i : nil}.compact
  end

  def filter(ip)
    "src host #{ip} and dst host #{Rex::Socket.source_address(ip)}"
  end

  #
  # Scanner methods
  #

  def run_host(ip)
    # XXX: Configuring Ethernet and IP headers sends a UDP packet!
    @config = PacketFu::Utils.whoami?(target: ip)

    open_pcap
    capture.setfilter(filter(ip))

    port_open = false
    rports.each do |rport|
      datastore['RPORT'] = rport
      port_open |= run_detections(ip, rport)
    end
    raise RuntimeError.new("No ports open on #{ip} from #{datastore['RPORTS']}") if !port_open
  rescue RuntimeError => e
    fail_with(Failure::BadConfig, e.message)
  ensure
    close_pcap
  end

  def detections
    %w[
      tcp_dos_detection
      tcp_malformed_options_detection
      icmp_code_detection
      icmp_timestamp_detection
    ]
  end

  def run_detections(ip, port)
    print_status("#{ip}:#{port} being checked")

    final_ipnet_score        = 0
    final_vxworks_score      = 0
    affected_vulnerabilities = []

    begin
      sock = Rex::Socket::Tcp.create(
        'PeerHost' => ip,
        'PeerPort' => port
      )
    rescue
      vprint_bad("Could not connect to #{ip}:#{port}, cannot verify vulnerability")
      return false
    end

    detections.each do |detection|
      @ipnet_score     = 0
      @vxworks_score   = 0
      @vulnerable_cves = []

      detection_name = detection.camelize

      begin
        send(detection, sock, ip, port)
      rescue StandardError => e
        vprint_error("#{detection_name} failed: #{e.message}")
        next
      end

      vprint_status(
        "\t#{detection_name.ljust(30)}" \
        "\tVxWorks: #{@vxworks_score}" \
        "\tIPnet: #{@ipnet_score}"
      )

      final_ipnet_score        += @ipnet_score
      final_vxworks_score      += @vxworks_score
      affected_vulnerabilities += @vulnerable_cves
    end

    sock.close

    if final_ipnet_score > 0
      vprint_good("#{ip}:#{port} detected as IPnet")
    elsif final_ipnet_score < 0
      vprint_error("#{ip}:#{port} detected as NOT IPnet")
    end

    if final_vxworks_score > 100
      vprint_good("#{ip}:#{port} detected as VxWorks")
    elsif final_vxworks_score < 0
      vprint_error("#{ip}:#{port} detected as NOT VxWorks")
    end

    affected_vulnerabilities.each do |vuln|
      msg = "#{ip}:#{port} affected by #{vuln}"
      print_good(msg)
      report_vuln(
        host: ip,
        name: name,
        refs: references,
        info: msg
      )
    end
    true
  end

  #
  # TCP detection methods
  #

  def tcp_malformed_options_detection(sock, ip, port)
    pkt = PacketFu::TCPPacket.new(config: @config)

    # IP destination address
    pkt.ip_daddr = ip

    # TCP SYN with malformed options
    pkt.tcp_dst       = port
    pkt.tcp_flags.syn = 1
    pkt.tcp_opts      = [2, 4, 1460].pack('CCn') + # MSS
                        [1].pack('C') +            # NOP
                        [3, 2].pack('CC') +        # WSCALE with invalid length
                        [3, 3, 0].pack('CCC')      # WSCALE with valid length
    pkt.recalc

    res = nil

    datastore['RetransmissionRate'].times do
      pkt.to_w
      res = inject_reply(:tcp)

      break unless res
    end

    unless res
      return @vxworks_score = 0,
             @ipnet_score   = 50
    end

    if res.tcp_flags.rst == 1 &&
      res.tcp_dst == pkt.tcp_src && res.tcp_dst == pkt.tcp_src

      return @vxworks_score = 100,
             @ipnet_score   = 100
    end

    return @vxworks_score = -100,
           @ipnet_score   = -100
  end

  def tcp_dos_detection(sock, ip, port)
    pkt = PacketFu::TCPPacket.new(config: @config)

    # IP destination address
    pkt.ip_daddr = ip

    # TCP SYN with malformed (truncated) WS option
    pkt.tcp_src       = sock.getlocalname.last
    pkt.tcp_dst       = sock.peerport
    pkt.tcp_seq       = rand(0xffffffff + 1)
    pkt.tcp_ack       = rand(0xffffffff + 1)
    pkt.tcp_flags.syn = 1
    pkt.tcp_opts      = [3, 2].pack('CC') +    # WSCALE with invalid length
                        [1, 0].pack('CC')      # NOP + EOL
    pkt.recalc

    res = nil

    datastore['RetransmissionRate'].times do
      pkt.to_w
      res = inject_reply(:tcp)

      break unless res
    end

    unless res
      return @vxworks_score = 0,
             @ipnet_score   = 0
    end

    if res.tcp_flags.rst == 1 &&
      res.tcp_dst == pkt.tcp_src && res.tcp_dst == pkt.tcp_src

      return @vxworks_score   = 100,
             @ipnet_score     = 100,
             @vulnerable_cves = ['CVE-2019-12258']
    end

    return @vxworks_score = 0,
           @ipnet_score   = 0
  end

  #
  # ICMP detection methods
  #

  def icmp_code_detection(sock, ip, _port = nil)
    pkt = PacketFu::ICMPPacket.new(config: @config)

    # IP destination address
    pkt.ip_daddr = ip

    # ICMP echo request with non-zero code
    pkt.icmp_type = 8
    pkt.icmp_code = rand(0x01..0xff)
    pkt.payload   = capture_icmp_echo_pack
    pkt.recalc

    pkt.to_w
    res = inject_reply(:icmp)

    unless res
      return @ipnet_score = 0
    end

    # Echo reply with zeroed code
    if res.icmp_type == 0 && res.icmp_code == 0
      return @ipnet_score = 20
    end

    @ipnet_score = -20
  end

  def icmp_timestamp_detection(sock, ip, _port = nil)
    pkt = PacketFu::ICMPPacket.new(config: @config)

    # IP destination address
    pkt.ip_daddr = ip

    # Truncated ICMP timestamp request
    pkt.icmp_type = 13
    pkt.icmp_code = 0
    pkt.payload   = "\x00" * 4
    pkt.recalc

    pkt.to_w
    res = inject_reply(:icmp)

    unless res
      return @ipnet_score = 0
    end

    # Timestamp reply
    if res.icmp_type == 14
      return @ipnet_score = 90
    end

    @ipnet_score = -30
  end

end
