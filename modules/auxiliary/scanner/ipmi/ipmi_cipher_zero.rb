##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'rex/proto/ipmi'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner

  def initialize
    super(
      'Name'        => 'IPMI 2.0 RAKP Cipher Zero Authentication Bypass Scanner',
      'Description' => %q|
        This module identifies IPMI 2.0 compatible systems that are vulnerable
        to an authentication bypass vulnerability through the use of cipher
        zero.
        |,
      'Author'      => [ 'Dan Farmer <zen[at]fish2.com>', 'hdm' ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['URL', 'http://fish2.com/ipmi/cipherzero.html'],
          ['OSVDB', '93038'],
          ['OSVDB', '93039'],
          ['OSVDB', '93040'],

        ],
      'DisclosureDate' => 'Jun 20 2013'
    )

    register_options(
    [
      Opt::RPORT(623)
    ], self.class)

  end

  def scanner_prescan(batch)
    print_status("Sending IPMI requests to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
    @res = {}
  end

  def scan_host(ip)
    console_session_id = Rex::Text.rand_text(4)
    scanner_send(
      Rex::Proto::IPMI::Utils.create_ipmi_session_open_cipher_zero_request(console_session_id),
      ip, datastore['RPORT']
    )
  end

  def scanner_process(data, shost, sport)
    info = Rex::Proto::IPMI::Open_Session_Reply.new(data) rescue nil
    return if not info
    return if not info.session_payload_type == Rex::Proto::IPMI::PAYLOAD_RMCPPLUSOPEN_REP

    # Ignore duplicate replies
    return if @res[shost]

    @res[shost] ||= info

    if info.error_code == 0
      print_good("#{shost}:#{sport} - IPMI - VULNERABLE: Accepted a session open request for cipher zero")
      report_vuln(
        :host  => shost,
        :port  => datastore['RPORT'].to_i,
        :proto => 'udp',
        :sname => 'ipmi',
        :name  => 'IPMI 2.0 RAKP Cipher Zero Authentication Bypass',
        :info  => "Accepted a session open request for cipher zero",
        :refs  => self.references
      )
    else
      vprint_status("#{shost}:#{sport} - IPMI - NOT VULNERABLE: Rejected cipher zero with error code #{info.error_code}")
    end
  end
end
