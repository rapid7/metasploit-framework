##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'timeout'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Capture
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'IPID Sequence Scanner',
      'Description' => %q{
        This module will probe hosts' IPID sequences and classify
        them using the same method Nmap uses when it's performing
        its IPID Idle Scan (-sI) and OS Detection (-O).

        Nmap's probes are SYN/ACKs while this module's are SYNs.
        While this does not change the underlying functionality,
        it does change the chance of whether or not the probe
        will be stopped by a firewall.

        Nmap's Idle Scan can use hosts whose IPID sequences are
        classified as "Incremental" or "Broken little-endian incremental".
      },
      'Author'      => 'kris katterjohn',
      'License'     => MSF_LICENSE
    )

    register_options([
      Opt::RPORT(80),
      OptInt.new('TIMEOUT', [true, "The reply read timeout in milliseconds", 500]),
      OptString.new('INTERFACE', [false, 'The name of the interface'])
    ])

    register_advanced_options([
      OptInt.new('SAMPLES', [true, "The IPID sample size", 6])
    ])

    deregister_options('FILTER','PCAPFILE')
  end

  def rport
    datastore['RPORT'].to_i
  end

  def run_host(ip)
    open_pcap

    raise "SAMPLES option must be >= 2" if datastore['SAMPLES'] < 2

    pcap = self.capture

    shost = Rex::Socket.source_address(ip)

    to = (datastore['TIMEOUT'] || 500).to_f / 1000.0

    ipids = []

    pcap.setfilter(getfilter(shost, ip, rport))

    datastore['SAMPLES'].times do
      sport = rand(0xffff - 1025) + 1025

      probe = buildprobe(shost, sport, ip, rport)

      capture_sendto(probe, ip)

      reply = probereply(pcap, to)

      next if not reply

      ipids << reply.ip_id
    end

    close_pcap

    return if ipids.empty?

    print_status("#{ip}'s IPID sequence class: #{analyze(ipids)}")

    #Add Report
    report_note(
      :host	=> ip,
      :proto	=> 'ip',
      :type	=> 'IPID sequence',
      :data	=> "IPID sequence class: #{analyze(ipids)}"
    )
  end

  # Based on Nmap's get_ipid_sequence() in osscan2.cc
  def analyze(ipids)
    allzeros = true
    allsame = true
    mul256 = true
    inc = true

    # ipids.each do |ipid|
    #	print_status("Got IPID ##{ipid}")
    # end

    return "Unknown" if ipids.size < 2

    diffs = []
    i = 1

    while i < ipids.size
      p = ipids[i - 1]
      c = ipids[i]

      if p != 0 or c != 0
        allzeros = false
      end

      if p <= c
        diffs[i - 1] = c - p
      else
        diffs[i - 1] = c - p + 65536
      end

      if ipids.size > 2 and diffs[i - 1] > 20000
        return "Randomized"
      end

      i += 1
    end

    return "All zeros" if allzeros

    diffs.each do |diff|
      if diff > 1000 and ((diff % 256) != 0 or ((diff % 256) == 0 and diff >= 25600))
        return "Random positive increments"
      end

      allsame = false if diff != 0

      mul256 = false if diff > 5120 or (diff % 256) != 0

      inc = false if diff >= 10
    end

    return "Constant" if allsame

    return "Broken little-endian incremental!" if mul256

    return "Incremental!" if inc

    "Unknown"
  end

  def getfilter(shost, dhost, dport)
    "tcp and src host #{dhost} and src port #{dport} and " +
    "dst host #{shost}"
  end

  # This gets set via the usual capture_sendto interface
  def buildprobe(shost, sport, dhost, dport)
    p = PacketFu::TCPPacket.new
    p.ip_saddr = shost
    p.ip_daddr = dhost
    p.tcp_sport = sport
    p.tcp_dport = dport
    p.tcp_flags.syn = 1
    p.recalc
    p
  end

  def probereply(pcap, to)
    reply = nil

    begin
      Timeout.timeout(to) do
        pcap.each do |r|
          pkt = PacketFu::Packet.parse(r)
          next unless pkt.is_tcp?
          next unless pkt.tcp_flags.syn == 1 || pkt.tcp_flags.rst == 1
          reply = pkt
          break
        end
      end
    rescue Timeout::Error
    end

    return reply
  end

end
