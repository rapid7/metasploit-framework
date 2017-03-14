# -*- coding: binary -*-

require 'bit-struct'

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
  class NTPGeneric < BitStruct
    #    0                   1                   2                   3
    #    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #   |LI | VN  | mode|    Stratum    |      Poll     |   Precision   |
    #   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    unsigned :li, 2,  default: 0
    unsigned :version, 3,  default: 0
    unsigned :mode, 3,  default: 0
    unsigned :stratum, 8,  default: 0
    unsigned :poll, 8,  default: 0
    unsigned :precision, 8,  default: 0
    rest :payload
  end

  # An NTP control message.  Control messages are only specified for NTP
  # versions 2-4, but this is a fuzzer so why not try them all...
  class NTPControl < BitStruct
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |00 | VN  |   6 |R E M|  op     |     Sequence                  |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |              status           |      association id           |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |              offset           |     count                     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    unsigned :reserved, 2, default: 0
    unsigned :version, 3,  default: 0
    unsigned :mode, 3,  default: 6
    unsigned :response, 1,  default: 0
    unsigned :error, 1,  default: 0
    unsigned :more, 1,  default: 0
    unsigned :operation, 5,  default: 0
    unsigned :sequence, 16,  default: 0
    unsigned :status, 16,  default: 0
    unsigned :association_id, 16,  default: 0
    # TODO: there *must* be bugs in the handling of these next two fields!
    unsigned :payload_offset, 16,  default: 0
    unsigned :payload_size, 16,  default: 0
    rest :payload
  end

  # An NTP "private" message.  Private messages are only specified for NTP
  # versions 2-4, but this is a fuzzer so why not try them all...
  class NTPPrivate < BitStruct
    #  0                   1                   2                   3
    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |R M| VN  |   7 |A|  Sequence   | Implementation| Req code      |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |  err  | Number of data items  |  MBZ   |   Size of data item  |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    unsigned :response, 1, default: 0
    unsigned :more, 1, default: 0
    unsigned :version, 3,  default: 0
    unsigned :mode, 3,  default: 7
    unsigned :auth, 1, default: 0
    unsigned :sequence, 7, default: 0
    unsigned :implementation, 8, default: 0
    unsigned :request_code, 8, default: 0
    unsigned :error, 4, default: 0
    unsigned :record_count, 12, default: 0
    unsigned :mbz, 4, default: 0
    unsigned :record_size, 12, default: 0
    rest :payload

    def records
      records = []
      1.upto(record_count) do |record_num|
        records << payload[record_size*(record_num-1), record_size]
      end
      records
    end
  end

  class NTPSymmetric < BitStruct
    unsigned :li, 2,  default: 0
    unsigned :version, 3,  default: 3
    unsigned :mode, 3,  default: 0
    unsigned :stratum, 8,  default: 0
    unsigned :poll, 8,  default: 0
    unsigned :precision, 8,  default: 0
    unsigned :root_delay, 32,  default: 0
    unsigned :root_dispersion, 32,  default: 0
    unsigned :reference_id, 32,  default: 0
    unsigned :reference_timestamp, 64,  default: 0
    unsigned :origin_timestamp, 64,  default: 0
    unsigned :receive_timestamp, 64,  default: 0
    unsigned :transmit_timestamp, 64,  default: 0
    rest :payload
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
    ntp = NTPGeneric.new(message)
    "#{message.size}-byte version #{ntp.version} mode #{ntp.mode} reply"
  end
end
end
end
