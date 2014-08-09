##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::UDPScanner
  include Msf::Auxiliary::NTP

  def initialize
    super(
      'Name'        => 'NTP Mode 6 REQ_NONCE DRDoS Scanner',
      'Description' => %q{
        This module identifies NTP servers which permit mode 6 REQ_NONCE requests that
        can be used to conduct DRDoS attacks.  In some configurations, NTP servers will
        respond to REQ_NONCE requests with a response larger than the request,
        allowing remote attackers to cause a denial of services (traffic
        amplification) via spoofed requests.
      },
      'References'  =>
        [
        ],
      'Author'      => 'Jon Hart <jon_hart[at]rapid7.com>',
      'License'     => MSF_LICENSE
    )
  end

  # Called for each IP in the batch
  def scan_host(ip)
    scanner_send(@probe, ip, datastore['RPORT'])
  end

  # Called for each response packet
  def scanner_process(data, shost, sport)
    this_peer = "#{shost}:#{sport}"
    # sanity check that the reply is not overly large/small
    if data.length < 12
      print_error("#{this_peer} -- suspiciously small (#{data.length} bytes) NTP req_nonce response")
      return
    elsif data.length > 500
      print_error("#{this_peer} -- suspiciously large (#{data.length} bytes) NTP req_nonce response")
      return
    end

    # try to parse this response, alerting and aborting if it is invalid
    response = Rex::Proto::NTP::NTPControl.new(data)
    if [ @probe.version, @probe.operation ] == [ response.version, response.operation ]
      @results[shost] ||= []
      @results[shost] << response
    else
      print_error("#{this_peer} -- unexpected NTP req_nonce response: #{response.inspect}")
    end
  end

  # Called before the scan block
  def scanner_prescan(batch)
    @results = {}
    @probe = Rex::Proto::NTP::NTPControl.new
    @probe.version = 2
    @probe.operation = 12
    vprint_status("Sending probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
  end

  # Called after the scan block
  def scanner_postscan(batch)
    @results.keys.each do |k|
      packets = @results[k]
      report_service(
        :host  => k,
        :proto => 'udp',
        :port  => rport,
        :name  => 'ntp'
      )
      report_note(
        :host  => k,
        :proto => 'udp',
        :port  => rport,
        :type  => 'ntp.req_nonce',
        :data  => {:req_nonce => @results[k]}
      )
      total_size = packets.map(&:size).reduce(:+)
      if packets.size > 1 || total_size > @probe.size
        print_good("#{k}:#{rport} NTP req_nonce request permitted with amplified response (#{packets.size} packets, #{total_size} bytes)")
      end
    end
  end
end
