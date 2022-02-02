##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::UDPScanner

  def initialize
    super(
      'Name'        => 'GTP Echo Scanner',
      'Description' => %q{
        This module sends UDP GTP (GTP-U) echo requests to the target RHOSTS and
        reports on which ones respond, thus identifying General Packet Radio
        Service (GPRS) servers. This module does not support scanning with SCTP.
      },
      'References'  =>
        [
          ['URL', 'https://insinuator.net/tag/gtp/'],
          ['URL', 'https://www.etsi.org/deliver/etsi_ts/129200_129299/129281/08.00.00_60/ts_129281v080000p.pdf']
        ],
      'Author'      =>
        [
          'Daniel Mende',    # original gtp-scan.py script
          'Spencer McIntyre' # metasploit module
        ],
      'License'     => MSF_LICENSE
    )

    register_options([
      OptEnum.new('VERSION', [ true, 'The GTP version to use', '1', ['1', '2'] ]),
      Opt::RPORT(2152)
    ])
  end

  class GTPv1 < BinData::Record
    endian  :big

    default_parameter version: 1
    default_parameter protocol_type: 1
    default_parameter has_next_extension_header: 0
    default_parameter has_sequence_number: 0
    default_parameter has_n_pdu_number: 0
    default_parameter message_type: 0
    default_parameter data: ""

    # header
    bit3   :version, :initial_value => :version
    bit1   :protocol_type, :initial_value => :protocol_type
    bit1   :reserved
    bit1   :has_next_extension_header, :initial_value => :has_next_extension_header
    bit1   :has_sequence_number, :initial_value => :has_sequence_number
    bit1   :has_n_pdu_number, :initial_value => :has_n_pdu_number
    uint8  :message_type, :initial_value => :message_type
    uint16 :len, :value => :calc_length
    uint32 :teid

    # body
    uint16  :sequence_number, onlyif: -> { has_sequence_number.nonzero? }
    uint8   :n_pdu_number, onlyif: -> { has_n_pdu_number.nonzero? }
    uint8   :next_extension_header_type, onlyif: -> { has_next_extension_header.nonzero? }
    string :data, :initial_value => :data, :read_length => :calc_length_read

    def calc_length
      length = data.length
      length += 2 if has_sequence_number.nonzero?
      length += 1 if has_n_pdu_number.nonzero?
      length += 1 if has_next_extension_header.nonzero?
      length
    end

    def calc_length_read
      length = len
      length -= 2 if has_sequence_number.nonzero?
      length -= 1 if has_n_pdu_number.nonzero?
      length -= 1 if has_next_extension_header.nonzero?
      length
    end
  end

  class GTPv1EchoRequest < GTPv1
    default_parameter has_sequence_number: 1
    default_parameter message_type: 1
  end

  class GTPv2 < BinData::Record
    endian  :big

    default_parameter version: 2
    default_parameter piggybacking: 0
    default_parameter message_priority: 0
    default_parameter message_type: 0
    default_parameter data: ""

    # header
    bit3   :version, :initial_value => :version
    bit1   :piggybacking, :initial_value => :piggybacking
    bit1   :has_teid
    bit1   :message_priority, :initial_value => :message_priority
    uint8  :message_type, :initial_value => :message_type
    uint16 :len, :value => :calc_length

    # body
    uint32 :teid, onlyif: -> { has_teid.nonzero? }
    uint24 :sequence_number
    uint8  :spare
    string :data, :initial_value => :data, :read_length => :calc_length_read

    def calc_length
      length = data.length + 4
      length += 4 if has_teid.nonzero?
      length
    end

    def calc_length_read
      length = len - 4
      length -= 4 if has_teid.nonzero?
      length
    end
  end

  class GTPv2EchoRequest < GTPv2
    default_parameter message_type: 1
  end

  def build_probe
    # the tunnel endpoint identifier (TEID) field must be 0 for echo requests
    # per the specification
    if datastore['VERSION'] == '1'
      @probe = GTPv1EchoRequest.new.to_binary_s
    else
      @probe = GTPv2EchoRequest.new.to_binary_s
    end
  end

  def scanner_postscan(batch)
    @results.each do |rhost, data|
      next unless data.length == 1
      data = data[0]

      if datastore['VERSION'] == '1'
        gtp = GTPv1
      else
        gtp = GTPv2
      end
      begin
        response = gtp.read(data)
      rescue EOFError
        next
      end

      if datastore['VERSION'] == '1'
        next unless response.version == 1
        next unless response.teid == 0
      else
        next unless response.version == 2
        next unless response.sequence_number == 0
      end

      peer = "#{rhost}:#{rport}"
      print_good("GTP v#{datastore['VERSION']} echo response received from: #{peer}")

      report_service(
        :host  => rhost,
        :proto => 'udp',
        :port  => rport,
        :name  => 'gtp'
      )
    end
  end
end
