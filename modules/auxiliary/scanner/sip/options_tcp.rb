# encoding: UTF-8
##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex/proto/sip'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Rex::Proto::SIP

  def initialize
    super(
      'Name'        => 'SIP Endpoint Scanner (TCP)',
      'Description' => 'Scan for SIP devices using OPTIONS requests',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    register_options(
    [
      OptInt.new('BATCHSIZE', [true, 'The number of hosts to probe in each set', 256]),
      OptString.new('TO',   [false, 'The destination username to probe at each host', 'nobody']),
      Opt::RPORT(5060)
    ], self.class)
  end

  # Operate on a single system at a time
  def run_host(ip)
    connect
    sock.put(create_probe(ip, 'TCP'))
    res = sock.get_once(-1, 5)
    parse_reply(res) if res
   rescue ::Interrupt
    raise $ERROR_INFO
  ensure
    disconnect
  end
end
