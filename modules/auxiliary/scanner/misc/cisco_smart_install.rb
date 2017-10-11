##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'Identify Cisco Smart Install endpoints',
        'Description'    => %q(
          This module attempts to connect to the specified Cisco Smart Install port
          and determines if it speaks the Smart Install Protocol.  Exposure of SMI
          to untrusted networks can allow complete compromise of the switch.
        ),
        'Author'         => 'Jon Hart <jon_hart[at]rapid7.com>',
        'References'     =>
          [
            ['URL', 'https://blog.talosintelligence.com/2017/02/cisco-coverage-for-smart-install-client.html'],
            ['URL', 'https://blogs.cisco.com/security/cisco-psirt-mitigating-and-detecting-potential-abuse-of-cisco-smart-install-feature'],
            ['URL', 'https://tools.cisco.com/security/center/content/CiscoSecurityResponse/cisco-sr-20170214-smi'],
            ['URL', 'https://github.com/Cisco-Talos/smi_check'],
            ['URL', 'https://github.com/Sab0tag3d/SIET']

          ],
        'License'        => MSF_LICENSE
      )
    )

    register_options(
      [
        Opt::RPORT(4786)
      ]
    )
  end

  # thanks to https://github.com/Cisco-Talos/smi_check/blob/master/smi_check.py#L52-L53
  SMI_PROBE = "\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x04\x00\x00\x00\x08\x00\x00\x00\x01\x00\x00\x00\x00".freeze
  SMI_RE = /^\x00{3}\x04\x00{7}\x03\x00{3}\x08\x00{3}\x01\x00{4}$/
  def smi?
    sock.puts(SMI_PROBE)
    response = sock.get_once(-1)
    if response
      if SMI_RE.match?(response)
        print_good("Fingerprinted the Cisco Smart Install protocol")
        return true
      else
        vprint_status("No match for '#{response}'")
      end
    else
      vprint_status("No response")
    end
  end

  def run_host(_ip)
    begin
      connect
      return unless smi?
    rescue Rex::AddressInUse, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, \
           ::Errno::ETIMEDOUT, ::Timeout::Error, ::EOFError => e
      vprint_error("error while connecting and negotiating Cisco Smart Install: #{e}")
      return
    ensure
      disconnect
    end

    service = report_service(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: 'Smart Install'
    )

    report_vuln(
      host: rhost,
      service: service,
      name: name,
      info: "Fingerprinted the Cisco Smart Install Protocol",
      refs: references,
      exploited_at: Time.now.utc
    )
  end
end
