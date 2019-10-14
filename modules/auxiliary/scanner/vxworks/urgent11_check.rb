##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

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
      'DisclosureDate' => '2019-08-09', # NVD published date
      'License'        => MSF_LICENSE
    ))

    register_options([
      Opt::RPORT(80, true, 'Target port for TCP detections')
    ])

    deregister_options('INTERFACE', 'PCAPFILE', 'FILTER')
  end

  #
  # Utility methods
  #

  def rport
    datastore['RPORT']
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

    run_detections(ip, rport)
  rescue RuntimeError => e
    fail_with(Failure::BadConfig, e.message)
  ensure
    close_pcap
  end

  def detections
    %w[
      tcp_malformed_options_detection
      tcp_dos_detection
      icmp_code_detection
      icmp_timestamp_detection
    ]
  end

  def run_detections(ip, port)
    print_status("Running against #{ip}:#{port}")

    final_ipnet_score        = 0
    final_vxworks_score      = 0
    affected_vulnerabilities = []

    detections.each do |detection|
      @ipnet_score     = 0
      @vxworks_score   = 0
      @vulnerable_cves = []

      # Sorry, I used ActiveSupport
      detection_name = detection.camelize

      begin
        send(detection, ip, port)
      rescue NotImplementedError
        print_warning("#{detection_name} is not implemented yet")
        next
      end

      print_status(
        "\t#{detection_name.ljust(30)}" \
        "\tVxWorks: #{@vxworks_score}" \
        "\tIPnet: #{@ipnet_score}"
      )

      final_ipnet_score        += @ipnet_score
      final_vxworks_score      += @vxworks_score
      affected_vulnerabilities += @vulnerable_cves
    end

    if final_ipnet_score > 0
      print_good("IP #{ip} detected as IPnet")
    elsif final_ipnet_score < 0
      print_error("IP #{ip} detected as NOT IPnet")
    end

    if final_vxworks_score > 100
      print_good("IP #{ip} detected as VxWorks")
    elsif final_vxworks_score < 0
      print_error("IP #{ip} detected as NOT VxWorks")
    end

    affected_vulnerabilities.each do |vuln|
      msg = "IP #{ip} affected by #{vuln}"
      print_good(msg)
      report_vuln(
        host: ip,
        name: name,
        refs: references,
        info: msg
      )
    end
  end

  #
  # TCP detection methods
  #

  def tcp_malformed_options_detection(ip, port)
    raise NotImplementedError
  end

  def tcp_dos_detection(ip, port)
    raise NotImplementedError
  end

  #
  # ICMP detection methods
  #

  def icmp_code_detection(ip, _port = nil)
    pkt = PacketFu::ICMPPacket.new(config: @config)

    # IP destination address
    pkt.ip_daddr = ip

    # ICMP echo request with non-zero code
    pkt.icmp_type = 8
    pkt.icmp_code = rand(0x01..0xff)
    pkt.payload   = capture_icmp_echo_pack
    pkt.recalc

    vprint_line(pkt.inspect)
    pkt.to_w

    res = inject_reply(:icmp)
    vprint_line(res.inspect)

    unless res
      return @ipnet_score = 0
    end

    # Echo reply with zeroed code
    if res.icmp_type == 0 && res.icmp_code == 0
      return @ipnet_score = 20
    end

    @ipnet_score = -20
  end

  def icmp_timestamp_detection(ip, _port = nil)
    pkt = PacketFu::ICMPPacket.new(config: @config)

    # IP destination address
    pkt.ip_daddr = ip

    # Truncated ICMP timestamp request
    pkt.icmp_type = 13
    pkt.icmp_code = 0
    pkt.payload   = "\x00" * 4
    pkt.recalc

    vprint_line(pkt.inspect)
    pkt.to_w

    res = inject_reply(:icmp)
    vprint_line(res.inspect)

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
