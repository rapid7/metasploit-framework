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
        'Name'           => 'Identify endpoints speaking the Remote Desktop Protocol (RDP)',
        'Description'    => %q(
          This module attempts to connect to the specified Remote Desktop Protocol port
          and determines if it speaks RDP.
        ),
        'Author'         => 'Jon Hart <jon_hart[at]rapid7.com>',
        'References'     =>
          [
          ],
        'License'        => MSF_LICENSE
      )
    )

    register_options(
      [
        Opt::RPORT(3389)
        # XXX: add options to turn on/off TLS, CredSSP, early user, cookies, etc.
      ]
    )
  end

  # simple TPKT v3 + x.224 COTP Connect Request + RDP negotiation request with TLS and CredSSP requested
  RDP_PROBE = "\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
  # any TPKT v3 + x.2224 COTP Connect Confirm
  RDP_RE = /^\x03\x00.{3}\xd0.{7}.*$/
  def rdp?
    sock.put(RDP_PROBE)
    response = sock.get_once(-1)
    if response
      if RDP_RE.match?(response)
        # XXX: it might be helpful to decode the response and show what was selected.
        print_good("Identified RDP")
        return true
      else
        vprint_status("No match for '#{Rex::Text.to_hex_ascii(response)}'")
      end
    else
      vprint_status("No response")
    end
  end

  def run_host(_ip)
    begin
      connect
      return unless rdp?
    rescue Rex::AddressInUse, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, \
           ::Errno::ETIMEDOUT, ::Timeout::Error, ::EOFError => e
      vprint_error("error while connecting and negotiating RDP: #{e}")
      return
    ensure
      disconnect
    end

    service = report_service(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: 'RDP'
    )
  end
end
