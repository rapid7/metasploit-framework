##
## This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize(_info = {})
    super(
      'Name' => 'Extract zip from Modbus communication',
      'Description' => %q{
        This module is able to extract a zip file sent through Modbus from a pcap.
        Tested with Schneider TM221CE16R.
      },
      'Author' => [
        'José Diogo Monteiro <jdlopes[at]student.dei.uc.pt>',
        'Luis Rosa <lmrosa[at]dei.uc.pt)>'
      ],
      'License' => MSF_LICENSE,
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options [
      Opt::RPORT(502),
      OptEnum.new('MODE', [
        true, 'Extract zip from upload/download capture', 'UPLOAD',
        ['UPLOAD', 'DOWNLOAD']
      ]),
      OptString.new('PCAPFILE', [ true, 'Pcap to read', '' ]),
      OptString.new('FILENAME', [ false, 'Zip file output name'])
    ]
  end

  FIRST_BYTE_UPLOAD = 12
  FIRST_BYTE_DOWNLOAD = 16

  def extract_zip(packet, zip_packet, first_byte, data, packet_number)
    # ZIP start signature
    h = packet.payload.scan(/\x50\x4B\x03\x04.*/)
    if h.size.nonzero?
      print_status "Zip start on packet #{packet_number + 1}"
      data = h[0]
      zip_packet += 1
      return zip_packet, data
    end

    # ZIP end signature (central directory record)
    h = packet.payload.scan(/.*\x50\x4B\x05\x06................../)
    if h.size.nonzero?
      print_status "Zip end on packet #{packet_number + 1}"
      data += h[0][first_byte..]
      zip_packet += 1
      return zip_packet, data
    end

    # ZIP data
    if zip_packet == 1 && !packet.payload[first_byte..].nil?
      data += packet.payload[first_byte..]
    end
    return zip_packet, data
  end

  def run
    packets = PacketFu::PcapFile.read_packets datastore['PCAPFILE']
    zip_packet = 0
    data = ''
    packets.each_with_index do |packet, i|
      if datastore['MODE'] == 'UPLOAD'
        if packet.respond_to?(:tcp_src) && (packet.tcp_src == datastore['RPORT'])
          zip_packet, data = extract_zip(packet, zip_packet, FIRST_BYTE_UPLOAD, data, i)
        end
      elsif datastore['MODE'] == 'DOWNLOAD'
        if packet.respond_to?(:tcp_dst) && (packet.tcp_dst == datastore['RPORT'])
          zip_packet, data = extract_zip(packet, zip_packet, FIRST_BYTE_DOWNLOAD, data, i)
        end
      end
      break if zip_packet == 2
    end

    filename = datastore['FILENAME'] || 'project.zip'
    if data.empty?
      print_status "Zip file not found in #{datastore['PCAPFILE']}"
    else
      path = store_loot(filename, 'application/zip', datastore['RHOSTS'], data, filename, 'modbus.zip')
      print_good "Zip file saved in loot: #{path}"
    end
  end
end
