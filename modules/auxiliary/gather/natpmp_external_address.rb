##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::UDPScanner
  include Msf::Auxiliary::NATPMP
  include Rex::Proto::NATPMP

  def initialize
    super(
      'Name'        => 'NAT-PMP External Address Scanner',
      'Description' => 'Scan NAT devices for their external address using NAT-PMP',
      'Author'      => 'Jon Hart <jhart[at]spoofed.org>',
      'License'     => MSF_LICENSE
    )

  end

  def scan_host(ip)
    scanner_send(@probe, ip, datastore['RPORT'])
  end

  def scanner_prescan(batch)
    @probe = external_address_request
  end

  def scanner_process(data, shost, sport)
    (ver, op, result, epoch, external_address) = parse_external_address_response(data)

    peer = "#{shost}:#{sport}"
    if (ver == 0 && op == 128 && result == 0)
      print_good("#{peer} -- external address #{external_address}")
      # report its external address as alive
      if inside_workspace_boundary?(external_address)
        report_host(
          :host   => external_address,
          :state => Msf::HostState::Alive
        )
      end
    else
      print_error("#{peer} -- unexpected version/opcode/result/address: #{ver}/#{op}/#{result}/#{external_address}")
    end

    # report the host we scanned as alive
    report_host(
      :host   => shost,
      :state => Msf::HostState::Alive
    )

    # report NAT-PMP as being open
    report_service(
      :host   => shost,
      :port   => sport,
      :proto  => 'udp',
      :name   => 'natpmp',
      :state  => Msf::ServiceState::Open
    )
  end
end
