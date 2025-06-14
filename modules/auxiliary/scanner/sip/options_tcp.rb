##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::SIP

  def initialize
    super(
      'Name'        => 'SIP Endpoint Scanner (TCP)',
      'Description' => 'Scan for SIP devices using OPTIONS requests',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    register_options(
    [
      OptString.new('TO',   [false, 'The destination username to probe at each host', 'nobody']),
      Opt::RPORT(5060)
    ])
  end

  # Operate on a single system at a time
  def run_host(ip)
    begin
      connect
      sock.put(create_probe(ip, 'tcp'))
      res = sock.get_once(-1, 5)
      report_response(res, rhost, 'tcp') if res
    rescue ::Interrupt
      raise $ERROR_INFO
    ensure
      disconnect
    end
  end
end
