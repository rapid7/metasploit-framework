##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Exploit::Remote::RDP
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'Identify endpoints speaking the Remote Desktop Protocol (RDP)',
        'Description'    => %q(
          This module attempts to connect to the specified Remote Desktop Protocol port
          and determines if it speaks RDP.

          When available, the Credential Security Support Provider (CredSSP) protocol will be used to identify the
          version of Windows on which the server is running. Enabling the DETECT_NLA option will cause a second
          connection to be made to the server to identify if Network Level Authentication (NLA) is required.
        ),
        'Author'         => 'Jon Hart <jon_hart[at]rapid7.com>',
        'References'     =>
          [
            ['URL', 'https://msdn.microsoft.com/en-us/library/cc240445.aspx']
          ],
        'License'        => MSF_LICENSE
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
      nsock = connect
    rescue ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError
      return false, nil
    end

    is_rdp, version_info = rdp_fingerprint(nsock)
    disconnect

    service_info = nil
    if is_rdp
      product_version = (version_info && version_info[:product_version]) ? version_info[:product_version] : 'N/A'
      info = "Detected RDP on #{peer} (Windows v#{product_version})"

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
      nsock = connect
    rescue ::Errno::ETIMEDOUT, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError
      return false
    end

    is_rdp, server_selected_proto = rdp_check_protocol
    disconnect

    return false unless is_rdp
    return [RDPConstants::PROTOCOL_HYBRID, RDPConstants::PROTOCOL_HYBRID_EX].include? server_selected_proto
  end

  def run_host(_ip)
    is_rdp = false
    begin
      connect
      is_rdp, service_info = check_rdp
    rescue Rex::ConnectionError => e
      vprint_error("Error while connecting and negotiating RDP: #{e}")
      return
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
