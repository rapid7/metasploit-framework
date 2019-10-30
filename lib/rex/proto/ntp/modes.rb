# -*- coding: binary -*-

require 'bindata'

module Rex
module Proto
module NTP

  # A very generic NTP message
  #
  # Uses the common/similar parts from versions 1-4 and considers everything
  # after to be just one big field.  For the particulars on the different versions,
  # see:
  #   http://tools.ietf.org/html/rfc958#appendix-B
  #   http://tools.ietf.org/html/rfc1059#appendix-B
  #   pages 45/48 of http://tools.ietf.org/pdf/rfc1119.pdf
  #   http://tools.ietf.org/html/rfc1305#appendix-D
  #   http://tools.ietf.org/html/rfc5905#page-19
  class NTPGeneric < BinData::Record
    alias size num_bytes
    #    0                   1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |LI | VN  | mode|    Stratum    |      Poll     |   Precision   |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    endian :big
    bit2   :li
    bit3   :version
    bit3   :mode
    uint8  :stratum
    uint8  :poll
    uint8  :precision
    rest   :payload
  end

  # An NTP control message.  Control messages are only specified for NTP
  # versions 2-4, but this is a fuzzer so why not try them all...
  class NTPControl < BinData::Record
    alias size num_bytes
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |00 | VN  |   6 |R E M|  op     |     Sequence                  |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |              status           |      association id           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |              offset           |     count                     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    endian :big
    bit2   :reserved
    bit3   :version
    bit3   :mode, initial_value: 6
    bit1   :response
    bit1   :error
    bit1   :more
    bit5   :operation
    uint16 :sequence
    uint16 :status
    uint16 :association_id
    # TODO: there *must* be bugs in the handling of these next two fields!
    uint16 :payload_offset
    uint16 :payload_size
    rest   :payload
  end

  # An NTP "private" message.  Private messages are only specified for NTP
  # versions 2-4, but this is a fuzzer so why not try them all...
  class NTPPrivate < BinData::Record
    alias size num_bytes
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |R M| VN  |   7 |A|  Sequence   | Implementation| Req code      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |  err  | Number of data items  |  MBZ   |   Size of data item  |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    endian :big
    bit1   :response
    bit1   :more
    bit3   :version
    bit3   :mode, initial_value: 7
    bit1   :auth
    bit7   :sequence
    uint8  :implementation
    uint8  :request_code
    bit4   :error
    bit12  :record_count
    bit4   :mbz
    bit12  :record_size
    rest   :payload

    def records
      records = []
      1.upto(record_count) do |record_num|
        records << payload[record_size * (record_num - 1), record_size]
      end
      records
    end
  end

  class NTPSymmetric < BinData::Record
    alias size num_bytes
    endian :big
    bit2   :li
    bit3   :version, initial_value: 3
    bit3   :mode
    uint8  :stratum
    uint8  :poll
    uint8  :precision
    uint32 :root_delay
    uint32 :root_dispersion
    uint32 :reference_id
    uint64 :reference_timestamp
    uint64 :origin_timestamp
    uint64 :receive_timestamp
    uint64 :transmit_timestamp
    rest   :payload
  end

  def self.ntp_control(version, operation, payload = nil)
    n = NTPControl.new
    n.version = version
    n.operation = operation
    if payload
      n.payload_offset = 0
      n.payload_size = payload.size
      n.payload = payload
    end
    n
  end

  def self.ntp_private(version, implementation, request_code, payload = nil)
    n = NTPPrivate.new
    n.version = version
    n.implementation = implementation
    n.request_code = request_code
    n.payload = payload if payload
    n
  end

  def self.ntp_generic(version, mode)
    n = NTPGeneric.new
    n.version = version
    n.mode = mode
    n
  end

  # Parses the given message and provides a description about the NTP message inside
  def self.describe(message)
    ntp = NTPGeneric.new.read(message)
    "#{message.size}-byte version #{ntp.version} mode #{ntp.mode} reply"
  end
end
end
end
