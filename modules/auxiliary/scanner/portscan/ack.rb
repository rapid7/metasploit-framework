##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Capture
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'TCP ACK Firewall Scanner',
      'Description' => %q{
        Map out firewall rulesets with a raw ACK scan.  Any
        unfiltered ports found means a stateful firewall is
        not in place for them.
      },
      'Author'      => 'kris katterjohn',
      'License'     => MSF_LICENSE
    )

    register_options([
      OptString.new('PORTS', [true, "Ports to scan (e.g. 22-25,80,110-900)", "1-10000"]),
      OptInt.new('TIMEOUT', [true, "The reply read timeout in milliseconds", 500]),
      OptInt.new('BATCHSIZE', [true, "The number of hosts to scan per set", 256]),
      OptInt.new('DELAY', [true, "The delay between connections, per thread, in milliseconds", 0]),
      OptInt.new('JITTER', [true, "The delay jitter factor (maximum value by which to +/- DELAY) in milliseconds.", 0]),
      OptString.new('INTERFACE', [false, 'The name of the interface'])
    ])

    deregister_options('FILTER','PCAPFILE')
  end

  # No IPv6 support yet
  def support_ipv6?
    false
  end

  def run_batch_size
    datastore['BATCHSIZE'] || 256
  end

  def run_batch(hosts)

    ports = Rex::Socket.portspec_crack(datastore['PORTS'])
    if ports.empty?
      raise Msf::OptionValidateError.new(['PORTS'])
    end

    jitter_value = datastore['JITTER'].to_i
    if jitter_value < 0
      raise Msf::OptionValidateError.new(['JITTER'])
    end

    delay_value = datastore['DELAY'].to_i
    if delay_value < 0
      raise Msf::OptionValidateError.new(['DELAY'])
    end

    open_pcap

    pcap = self.capture

    to = (datastore['TIMEOUT'] || 500).to_f / 1000.0

    # we copy the hosts because some may not be reachable and need to be ejected
    host_queue = hosts.dup
    # Spread the load across the hosts
    ports.each do |dport|
      host_queue.each do |dhost|
        shost, sport = getsource(dhost)

        pcap.setfilter(getfilter(shost, sport, dhost, dport))

        # Add the delay based on JITTER and DELAY if needs be
        add_delay_jitter(delay_value,jitter_value)

        begin
          probe = buildprobe(shost, sport, dhost, dport)

          unless capture_sendto(probe, dhost)
            host_queue.delete(dhost)
            next
          end

          reply = probereply(pcap, to)

          next if not reply

          print_status(" TCP UNFILTERED #{dhost}:#{dport}")

          #Add Report
          report_note(
            :host	=> dhost,
            :proto	=> 'tcp',
            :port	=> dport,
            :type	=> "TCP UNFILTERED #{dhost}:#{dport}",
            :data	=> "TCP UNFILTERED #{dhost}:#{dport}"
          )

        rescue ::Exception
          print_error("Error: #{$!.class} #{$!}")
        end
      end
    end

    close_pcap
  end

  def getfilter(shost, sport, dhost, dport)
    # Look for associated RSTs
    "tcp and (tcp[13] & 0x04) != 0 and " +
    "src host #{dhost} and src port #{dport} and " +
    "dst host #{shost} and dst port #{sport}"
  end

  def getsource(dhost)
    # srcip, srcport
    [ Rex::Socket.source_address(dhost), rand(0xffff - 1025) + 1025 ]
  end

  def buildprobe(shost, sport, dhost, dport)
    p = PacketFu::TCPPacket.new
    p.ip_saddr = shost
    p.ip_daddr = dhost
    p.tcp_sport = sport
    p.tcp_ack = rand(0x100000000)
    p.tcp_flags.ack = 1
    p.tcp_dport = dport
    p.tcp_win = 3072
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
          reply = pkt
          break
        end
      end
    rescue Timeout::Error
    end
    return reply
  end
end
