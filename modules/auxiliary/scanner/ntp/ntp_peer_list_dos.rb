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
      'Name'        => 'NTP PEER_LIST DoS Scanner',
      'Description' => %q{
        This module identifies NTP servers which permit "PEER_LIST" queries and
        return responses that are larger in size or greater in quantity than
        the request, allowing remote attackers to cause a denial of service
        (traffic amplification) via spoofed requests.
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
    @probes.each do |probe|
      scanner_send(probe, ip, datastore['RPORT'])
    end
  end

  # Called before the scan block
  def scanner_prescan(batch)
    # build a probe for all possible variations of the PEER_LIST request, which
    # means using all combinations of NTP version, mode 7 implementations and
    # with and without payloads.
    @probes = []
    versions = datastore['VERSIONS'].split(/,/).map { |v| v.strip.to_i }
    implementations = datastore['IMPLEMENTATIONS'].split(/,/).map { |i| i.strip.to_i }
    payloads = ['', "\x00"*40]
    versions.each do |v|
      implementations.each do |i|
        payloads.each do |p|
          @probes << Rex::Proto::NTP.ntp_private(v, i, 0, p)
        end
      end
    end
    @results = {}
    vprint_status("Sending #{@probes.size} NTP PEER_LIST probes to #{batch[0]}->#{batch[-1]} (#{batch.length} hosts)")
  end

  # Called for each response packet
  def scanner_process(data, shost, sport)
    @results[shost] ||= []
    @results[shost] << Rex::Proto::NTP::NTPPrivate.new(data)
  end

  # Called after the scan block
  def scanner_postscan(batch)
    @results.keys.each do |k|
      packets = @results[k]
      # TODO: check to see if any of the responses are actually NTP before reporting
      report_service(
        :host  => k,
        :proto => 'udp',
        :port  => rport,
        :name  => 'ntp'
      )
    end
  end
end
