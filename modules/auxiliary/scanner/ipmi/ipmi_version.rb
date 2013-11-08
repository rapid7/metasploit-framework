##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'rex/proto/ipmi'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner

  def initialize
    super(
      'Name'        => 'IPMI Information Discovery',
      'Description' => 'Discover host information through IPMI Channel Auth probes',
      'Author'      => [ 'Dan Farmer <zen[at]fish2.com>', 'hdm' ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['URL', 'http://fish2.com/ipmi/']
        ]
    )

    register_options(
    [
      Opt::RPORT(623)
    ], self.class)

  end

  def rport
    datastore['RPORT']
  end

  def scanner_prescan(batch)
    print_status("Sending IPMI requests to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
    @res = {}
  end

  def scan_host(ip)
    vprint_status "#{ip}:#{rport} - IPMI - Probe sent"
    scanner_send(Rex::Proto::IPMI::Utils.create_ipmi_getchannel_probe, ip, rport)
  end

  def scanner_process(data, shost, sport)
    info = Rex::Proto::IPMI::Channel_Auth_Reply.new(data) rescue nil

    # Ignore invalid responses
    return unless info
    unless info.ipmi_command == 56
      vprint_error "#{shost}:#{rport} - IPMI - Invalid response"
      return
    end

    # Ignore duplicate replies
    return if @res[shost]

    @res[shost] ||= info

    banner = info.to_banner

    print_good("#{shost}:#{rport} - IPMI - #{banner}")

    report_service(
      :host  => shost,
      :port  => rport,
      :proto => 'udp',
      :name  => 'ipmi',
      :info  => banner
    )

    # Potential improvements:
    # - Report a vulnerablity if info.ipmi_user_anonymous has been set
    # - Report a vulnerability if ipmi 2.0 and kg is set to default (almost always the case)
    # - Report a vulnerability if info.ipmi_user_null has been set (null username)

  end

end
