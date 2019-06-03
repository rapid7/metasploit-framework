##
# This module requires Metasploit: https://metasploit.com/download
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

          The CredSSP and EarlyUser options are related to Network Level Authentication.
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
        OptBool.new('TLS', [true, 'Whether or not request TLS security', true]),
        OptBool.new('CredSSP', [true, 'Whether or not to request CredSSP', true]),
        OptBool.new('EarlyUser', [true, 'Whether to support Early User Authorization Result PDU', false])
      ]
    )
  end

  # any TPKT v3 + x.2224 COTP Connect Confirm
  RDP_RE = /^\x03\x00.{3}\xd0.{5}.*$/
  def rdp?
    sock.put(@probe)
    response = sock.get_once(-1)
    if response
      if RDP_RE.match(response)
        # XXX: it might be helpful to decode the response and show what was selected.
        print_good("Identified RDP")
        return true
      else
        vprint_status("No match for '#{Rex::Text.to_hex_ascii(response)}'")
      end
    else
      vprint_status("No response")
    end

    false
  end

  def setup
    # build a simple TPKT v3 + x.224 COTP Connect Request.  optionally append
    # RDP negotiation request with TLS, CredSSP and Early User as requested
    requested_protocols = 0
    if datastore['TLS']
      requested_protocols = requested_protocols ^ 0b1
    end
    if datastore['CredSSP']
      requested_protocols = requested_protocols ^ 0b10
    end
    if datastore['EarlyUser']
      requested_protocols = requested_protocols ^ 0b1000
    end

    if requested_protocols == 0
      tpkt_len = 11
      cotp_len = 6
      pack = [ 3, 0, tpkt_len, cotp_len, 0xe0, 0, 0, 0 ]
      pack_string = "CCnCCnnC"
    else
      tpkt_len = 19
      cotp_len = 14
      pack  = [ 3, 0, tpkt_len, cotp_len, 0xe0, 0, 0, 0, 1, 0, 8, 0, requested_protocols ]
      pack_string = "CCnCCnnCCCCCV"
    end
    @probe = pack.pack(pack_string)
  end

  def run_host(_ip)
    begin
      connect
      return unless rdp?
    rescue Rex::ConnectionError => e
      vprint_error("error while connecting and negotiating RDP: #{e}")
      return
    ensure
      disconnect
    end

    report_service(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: 'RDP'
    )
  end
end
