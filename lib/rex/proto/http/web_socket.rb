# -*- coding: binary -*-
require 'bindata'

module Rex
module Proto
module Http
module WebSocket

class WebSocketError < StandardError
end

module Interface
  def put_wsframe(frame, opts={})
    put(frame.to_binary_s, opts=opts)
  end

  def put_wsbinary(value, opts={})
    put_wsframe(Frame.from_binary(value), opts=opts)
  end

  def put_wstext(value, opts={})
    put_wsframe(Frame.from_text(value), opts=opts)
  end

  def get_wsframe(_opts={})
    Frame.read(self)
  rescue EOFError
    nil
  end

  # Run a loop to handle data from the remote end of the websocket. The loop will automatically handle fragmentation
  # (via continuation messages) and ping requests. When the remote connection is closed, the loop will exit. If
  # specified the block will be passed data chunks and their data types.
  def wsloop(&block)
    buffer = ''
    buffer_type = nil

    while (frame = get_wsframe)
      frame.unmask! if frame.masked

      case frame.opcode
      when Opcode::CONNECTION_CLOSE
        break
      when Opcode::CONTINUATION
        # a continuation frame can only be sent for a data frames
        # see: https://datatracker.ietf.org/doc/html/rfc6455#section-5.4
        raise WebSocketError, 'Received an unexpected continuation frame (uninitialized buffer)' if buffer_type.nil?
        buffer << frame.payload_data
      when Opcode::BINARY
        raise WebSocketError, 'Received an unexpected binary frame (unfinished buffer)' unless buffer_type.nil?
        buffer = frame.payload_data
        buffer_type = :binary
      when Opcode::TEXT
        raise WebSocketError, 'Received an unexpected text frame (unfinished buffer)' unless buffer_type.nil?
        buffer = frame.payload_data
        buffer_type = :text
      when Opcode::PING
        # see: https://datatracker.ietf.org/doc/html/rfc6455#section-5.5.2
        put_wsframe(frame.dup.tap { |pong| pong.opcode = Opcode::PONG })
      end

      if frame.fin == 1
        if block_given?
          buffer.force_encoding('UTF-8') if buffer_type == :text
          block.call(buffer, buffer_type)
        end

        buffer = ''
        buffer_type = nil
      end
    end
  end
end

class Opcode < BinData::Bit4
  CONTINUATION = 0
  TEXT = 1
  BINARY = 2
  CONNECTION_CLOSE = 8
  PING = 9
  PONG = 10

  default_parameter assert: -> { !Opcode.name(value).nil? }

  def self.name(value)
    constants.select { |c| c.upcase == c }.find { |c| const_get(c) == value }
  end

  def to_sym
    self.class.name(value)
  end
end

class Frame  < BinData::Record
  endian :big
  hide   :rsv1, :rsv2, :rsv3

  bit1   :fin
  bit1   :rsv1
  bit1   :rsv2
  bit1   :rsv3
  opcode :opcode
  bit1   :masked
  bit7   :payload_len_sm
  uint16 :payload_len_md, onlyif: -> { payload_len_sm == 126 }
  uint64 :payload_len_lg, onlyif: -> { payload_len_sm == 127 }
  uint32 :masking_key, onlyif: -> { masked == 1 }
  string :payload_data, read_length: -> { payload_len }

  class << self
    private

    def from_opcode(opcode, payload, last: true, mask: true)
      frame = Frame.new(fin: (last ? 1 : 0), opcode: opcode)
      frame.payload_len = payload.length
      frame.payload_data = payload

      case mask
      when TrueClass
        frame.mask!
      when Integer
        frame.mask!(mask)
      when FalseClass
      else
        raise ArgumentError, 'mask must be true, false or an integer (literal mask key)'
      end

      frame
    end
  end

  def self.apply_masking_key(data, mask)
    mask = [mask].pack('N').each_byte.to_a
    xored = ''
    data.each_byte.each_with_index do |byte, index|
      xored << (byte ^ mask[index % 4]).chr
    end

    xored
  end

  def self.from_binary(value, last: true, mask: true)
    from_opcode(Opcode::Binary, value, last: last, mask: mask)
  end

  def self.from_text(value, last: true, mask: true)
    from_opcode(Opcode::TEXT, value, last: last, mask: mask)
  end

  def mask!(key=nil)
    masked.assign(1)
    key = rand(0x100000000) if key.nil?
    masking_key.assign(key)
    payload_data.assign(self.class.apply_masking_key(payload_data, masking_key))
  end

  def unmask!
    payload_data.assign(self.class.apply_masking_key(payload_data, masking_key))
    masked.assign(0)
    payload_data
  end

  def payload_len
    case payload_len_sm
    when 127
      payload_len_lg
    when 126
      payload_len_md
    else
      payload_len_sm
    end
  end

  def payload_len=(value)
    if value < 126
      payload_len_sm.assign(value)
    elsif value < 0xffff
      payload_len_sm.assign(126)
      payload_len_md.assign(value)
    elsif value < 0x7fffffffffffffff
      payload_len_sm.assign(127)
      payload_len_lg.assign(value)
    else
      raise ArgumentError, 'payload length is outside the acceptable range'
    end
  end
end

end
end
end
end
