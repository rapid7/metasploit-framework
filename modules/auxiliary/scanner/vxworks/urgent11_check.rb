##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'packetfu'

class MetasploitModule < Msf::Auxiliary
  def initialize
    super(
      'Name'        => 'Urgent/11 Scanner, based on detection tool by Armis',
      'Description' => %q{
        This module detects VXWorks and the IPNet IP stack, along with CVE-2019-12258-vulnerable devices.
      },
      'References'  =>
        [
          [ 'URL', 'https://armis.com/urgent11' ],
          [ 'URL', 'https://github.com/ArmisSecurity/urgent11-detector' ],
          [ 'CVE', '2019-12258' ]
        ],
      'Author'      => [
        'Ben Seri', # Upstream tool
        'Brent Cook' # Metasploit module
        ],
      'License'     => MSF_LICENSE
      )

    register_options(
      [
        OptString.new('INTERFACE', [ true, 'Set an interface', 'eth0' ]),
        OptInt.new('ANSWERTIME', [ true, 'Seconds to wait for answers, set longer on slower networks', 2 ]),
        Opt::RPORT(80)
      ]
    )
  end

  def bin_to_hex(s)
    s.each_byte.map { |b| b.to_s(16).rjust(2, '0') }.join
  end

  def receive(iface, answertime)
    capture = PacketFu::Capture.new(iface: iface, start: true, filter: 'ether proto 0x0800')
    sleep answertime
    capture.save
    capture.array.each do |packet|
      data = bin_to_hex(packet).downcase
      mac = data[0..1] + ':' + data[2..3] + ':' + data[4..5] + ':' + data[6..7] + ':' + data[8..9] + ':' + data[10..11]
      print_good("Parsing packet from #{mac}")
    end
  end

  def run
    iface = datastore['INTERFACE']
    answertime = datastore['ANSWERTIME']

    tcp_pkt = PacketFu::TCPPacket.new()
    print_status("Sending packet out to #{iface}")
    tcp_pkt.to_w(iface)

    receive(iface, answertime)
  end
end
