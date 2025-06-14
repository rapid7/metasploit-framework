##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::RDP
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Identify endpoints speaking the Remote Desktop Protocol (RDP)',
        'Description' => %q{
          This module attempts to connect to the specified Remote Desktop Protocol port
          and determines if it speaks RDP.

          When available, the Credential Security Support Provider (CredSSP) protocol will be used to identify the
          version of Windows on which the server is running. Enabling the DETECT_NLA option will cause a second
          connection to be made to the server to identify if Network Level Authentication (NLA) is required.
        },
        'Author' => 'Jon Hart <jon_hart[at]rapid7.com>',
        'References' => [
          ['URL', 'https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/5073f4ed-1e93-45e1-b039-6e30c385867c']
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(3389),
        OptBool.new('DETECT_NLA', [true, 'Detect Network Level Authentication (NLA)', true])
      ]
    )
  end

  def check_rdp
    begin
      rdp_connect
      is_rdp, version_info = rdp_fingerprint
    rescue ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError
      return false, nil
    ensure
      rdp_disconnect
    end

    service_info = nil
    if is_rdp
      product_version = (version_info && version_info[:product_version]) ? version_info[:product_version] : 'N/A'
      info = "Detected RDP on #{peer} "
      info << "(name:#{version_info[:nb_name]}) " if version_info[:nb_name]
      info << "(domain:#{version_info[:nb_domain]}) " if version_info[:nb_domain]
      info << "(domain_fqdn:#{version_info[:dns_domain]}) " if version_info[:dns_domain]
      info << "(server_fqdn:#{version_info[:dns_server]}) " if version_info[:dns_server]
      info << "(os_version:#{product_version})"

      if datastore['DETECT_NLA']
        service_info = "Requires NLA: #{(!version_info[:product_version].nil? && requires_nla?) ? 'Yes' : 'No'}"
        info << " (#{service_info})"
      end

      print_status(info)
    end

    return is_rdp, service_info
  end

  def requires_nla?
    begin
      rdp_connect
      is_rdp, server_selected_proto = rdp_check_protocol
    rescue ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError
      return false
    ensure
      rdp_disconnect
    end

    return false unless is_rdp

    return [RDPConstants::PROTOCOL_HYBRID, RDPConstants::PROTOCOL_HYBRID_EX].include? server_selected_proto
  end

  def run_host(_ip)
    is_rdp = false
    begin
      rdp_connect
      is_rdp, service_info = check_rdp
    rescue Rex::ConnectionError => e
      vprint_error("Error while connecting and negotiating RDP: #{e}")
      return
    ensure
      rdp_disconnect
    end
    return unless is_rdp

    report_service(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: 'RDP',
      info: service_info
    )
  end
end
