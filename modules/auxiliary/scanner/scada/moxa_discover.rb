##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'Moxa UDP Device Discovery',
        'Description'    => %q(
          The Moxa protocol listens on 4800/UDP and will respond to broadcast
          or direct traffic.  The service is known to be used on Moxa devices
          in the NPort, OnCell, and MGate product lines.

          A discovery packet compels a Moxa device to respond to the sender
          with some basic device information that is needed for more advanced
          functions.  The discovery data is 8 bytes in length and is the most
          basic example of the Moxa protocol.  It may be sent out as a
          broadcast (destination 255.255.255.255) or to an individual device.

          Devices that respond to this query may be vulnerable to serious
          information disclosure vulnerabilities, such as CVE-2016-9361.

          The module is the work of Patrick DeSantis of Cisco Talos and is
          derived from original work by K. Reid Wightman. Tested and validated
          on a Moxa NPort 6250 with firmware versions 1.13 and 1.15.
        ),
        'Author'         => 'Patrick DeSantis <p[at]t-r10t.com>',
        'License'        => MSF_LICENSE,
        'References'     =>
        [
          [ 'CVE', '2016-9361'],
          [ 'URL', 'https://www.digitalbond.com/blog/2016/10/25/serial-killers/'],
          [ 'URL', 'http://www.moxa.com/support/faq/faq_detail.aspx?id=646' ],
        ]
      )
    )

    register_options(
    [
      # Moxa protocol listens on 4800/UDP by default
      Opt::RPORT(4800)
    ])
  end

  # The data to be sent via UDP
  def build_probe
    # Function Code (first byte) 0x01: Moxa discovery/identify
    # The fourth byte is the length of the full data payload
    @probe ||= "\x01\x00\x00\x08\x00\x00\x00\x00"
  end

  # Called for each response packet
  def scanner_process(response, src_host, _src_port)
    # The first byte of a response will always be the func code + 0x80
    # (the most significant bit of the byte is set to 1, so 0b00000001
    # becomes 0b10000001, or 0x81).
    # A valid response is 24 bytes, starts with 0x81, and contains the values
    # 0x00, 0x90, 0xe8 (the Moxa OIU) in bytes 14, 15, and 16.
    return unless response[0] == "\x81" && response[14..16] == "\x00\x90\xe8" && response.length == 24
    @results[src_host] ||= []
    @results[src_host] << response
  end

  # Called after the scan block
  def scanner_postscan(_batch)
    @results.each_pair do |host, response|
      peer = "#{host}:#{rport}"

      # Report the host
      report_host(
        :host => host,
        :info => "Moxa Device",
        )

      # Report the service
      report_service(
        host: host,
        proto: 'udp',
        port: rport,
        name: 'Moxa Protocol',
      )

      if response.empty?
        vprint_status("#{peer} No Moxa Devices Found.")
      else
        print_good("#{peer} Moxa Device Found!")

        # Report vuln
        report_vuln(
          host: host,
          port: rport,
          proto: 'udp',
          name: 'Moxa Protocol Use',
          refs: references
        )
      end
    end
  end
end
