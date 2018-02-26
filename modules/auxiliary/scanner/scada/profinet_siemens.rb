##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'packetfu'

class MetasploitModule < Msf::Auxiliary
  def initialize
    super(
      'Name'        => 'Siemens Profinet Scanner',
      'Description' => %q{
          This module will use Layer2 packets, known as Profinet Discovery packets,
        to detect all Siemens (and sometimes other) devices on a network.
        It is perfectly SCADA-safe, as there will only be ONE single packet sent out.
        Devices will respond with their IP configuration and hostnames.
        Created by XiaK Industrial Security Research Center (www[dot]xiak[dot]be))
      },
      'References'  =>
        [
          [ 'URL', 'https://wiki.wireshark.org/PROFINET/DCP' ],
          [ 'URL', 'https://github.com/tijldeneut/ICSSecurityScripts' ]
        ],
      'Author'      => 'Tijl Deneut <tijl.deneut[at]howest.be>',
      'License'     => MSF_LICENSE
      )

    register_options(
      [
        OptString.new('INTERFACE', [ true, 'Set an interface', 'eth0' ]),
        OptInt.new('ANSWERTIME', [ true, 'Seconds to wait for answers, set longer on slower networks', 2 ])
      ], self.class
    )
  end

  def hex_to_bin(s)
    s.scan(/../).map { |x| x.hex.chr }.join
  end

  def bin_to_hex(s)
    s.each_byte.map { |b| b.to_s(16).rjust(2, '0') }.join
  end

  def hexint_to_str(s)
    s.to_i(16).to_s
  end

  def hex_to_address(s)
    hexint_to_str(s[0..1]) + '.' + hexint_to_str(s[2..3]) + '.' + hexint_to_str(s[4..5]) + '.' + hexint_to_str(s[6..7])
  end

  def parse_devicerole(role)
    arr = { "01" => "IO-Device", "02" => "IO-Controller", "04" => "IO-Multidevice", "08" => "PN-Supervisor" }
    return arr[role] unless arr[role].nil?
    'Unknown'
  end

  def parse_vendorid(id)
    return 'Siemens' if id == '002a'
    'Unknown'
  end

  def parse_deviceid(id)
    arr = { "0a01" => "Switch", "0202" => "PC Simulator", "0203" => "S7-300 CPU", \
            "0101" => "S7-300", "010e" => "S7-1500", "010d" => "S7-1200", "0301" => "HMI", \
            "0403" => "HMI", "010b" => "ET200S" }
    return arr[id] unless arr[id].nil?
    'Unknown'
  end

  def parse_block(block, block_length)
    block_id = block[0..2 * 2 - 1]
    case block_id
    when '0201'
      type_of_station = hex_to_bin(block[4 * 2..4 * 2 + block_length * 2 - 1])
      print_line("Type of station: #{type_of_station}")
    when '0202'
      name_of_station = hex_to_bin(block[4 * 2..4 * 2 + block_length * 2 - 1])
      print_line("Name of station: #{name_of_station}")
    when '0203'
      vendor_id = parse_vendorid(block[6 * 2..8 * 2 - 1])
      device_id = parse_deviceid(block[8 * 2..10 * 2 - 1])
      print_line("Vendor and Device Type: #{vendor_id}, #{device_id}")
    when '0204'
      device_role = parse_devicerole(block[6 * 2..7 * 2 - 1])
      print_line("Device Role: #{device_role}")
    when '0102'
      ip = hex_to_address(block[6 * 2..10 * 2 - 1])
      snm = hex_to_address(block[10 * 2..14 * 2 - 1])
      gw = hex_to_address(block[14 * 2..18 * 2 - 1])
      print_line("IP, Subnetmask and Gateway are: #{ip}, #{snm}, #{gw}")
    end
  end

  def parse_profinet(data)
    data_to_parse = data[24..-1]

    until data_to_parse.empty?
      block_length = data_to_parse[2 * 2..4 * 2 - 1].to_i(16)
      block = data_to_parse[0..(4 + block_length) * 2 - 1]

      parse_block(block, block_length)

      padding = block_length % 2
      data_to_parse = data_to_parse[(4 + block_length + padding) * 2..-1]
    end
  end

  def receive(iface, answertime)
    capture = PacketFu::Capture.new(iface: iface, start: true, filter: 'ether proto 0x8892')
    sleep answertime
    capture.save
    i = 0
    capture.array.each do |packet|
      data = bin_to_hex(packet).downcase
      mac = data[12..13] + ':' + data[14..15] + ':' + data[16..17] + ':' + data[18..19] + ':' + data[20..21] + ':' + data[22..23]
      next unless data[28..31] == 'feff'
      print_good("Parsing packet from #{mac}")
      parse_profinet(data[28..-1])
      print_line('')
      i += 1
    end
    if i.zero?
      print_warning('No devices found, maybe you are running virtually?')
    else
      print_good("I found #{i} devices for you!")
    end
  end

  def run
    iface = datastore['INTERFACE']
    answertime = datastore['ANSWERTIME']
    packet = "\x00\x00\x88\x92\xfe\xfe\x05\x00\x04\x00\x00\x03\x00\x80\x00\x04\xff\xff\x00\x00\x00\x00"
    packet += "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    eth_pkt = PacketFu::EthPacket.new
    begin
      eth_pkt.eth_src = PacketFu::Utils.whoami?(iface: iface)[:eth_src]
    rescue
      print_error("Error: interface #{iface} not active?")
      return
    end
    eth_pkt.eth_daddr = "01:0e:cf:00:00:00"
    eth_pkt.eth_proto = 0x8100
    eth_pkt.payload = packet
    print_status("Sending packet out to #{iface}")
    eth_pkt.to_w(iface)

    receive(iface, answertime)
  end
end
