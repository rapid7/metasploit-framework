# encoding: UTF-8
##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex/proto/sip'

class Metasploit3 < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Rex::Proto::SIP

  def initialize
    super(
      'Name'        => 'SIP Endpoint Scanner (UDP)',
      'Description' => 'Scan for SIP devices using OPTIONS requests',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    register_options(
    [
      OptInt.new('BATCHSIZE', [true, 'The number of hosts to probe in each set', 256]),
      OptString.new('TO',   [false, 'The destination username to probe at each host', 'nobody']),
      Opt::RPORT(5060),
      Opt::CHOST,
      Opt::CPORT(5060)
    ], self.class)
  end

  # Define our batch size
  def run_batch_size
    datastore['BATCHSIZE'].to_i
  end

  # Operate on an entire batch of hosts at once
  def run_batch(batch)
    udp_sock = nil
    idx = 0
    # Create an unbound UDP socket if no CHOST is specified, otherwise
    # create a UDP socket bound to CHOST (in order to avail of pivoting)
    udp_sock = Rex::Socket::Udp.create(

        'LocalHost' => datastore['CHOST'] || nil,
        'LocalPort' => datastore['CPORT'].to_i,
        'Context' => { 'Msf' => framework, 'MsfExploit' => self }

    )
    add_socket(udp_sock)
    batch.each do |ip|
      data = create_probe(ip, 'UDP')
      begin
        udp_sock.sendto(data, ip, datastore['RPORT'].to_i, 0)
      rescue ::Interrupt
        raise $ERROR_INFO
      rescue ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionRefused
        nil
      end
      handle_replies(udp_sock) if idx % 10 == 0
      idx += 1
    end

    begin
      handle_replies(udp_sock)
    rescue ::Interrupt
      raise $ERROR_INFO
    rescue => e
      print_error("Unknown error: #{e.class} #{e}")
    ensure
      udp_sock.close if udp_sock
    end
  end

  def handle_replies(udp_sock)
    r = read_reply(udp_sock)
    while r && r[1]
      handle_reply(r)
      r = read_reply(udp_sock)
    end
  end

  def read_reply(udp_sock)
    udp_sock.recvfrom(65535, 0.01)
  end

  def handle_reply(pkt)
    return unless pkt[1]

    pkt[1].sub!(/^::ffff:/, '')

    resp  = pkt[0].split(/\s+/)[1]
    parse_reply(resp, 'udp')
  end
end
