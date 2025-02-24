# -*- coding: binary -*-

module Msf::Exploit::Remote::X11::Read
  def x11_read_response(klass, timeout: 10)
    unless klass.fields.field_name?(:response_length)
      raise ::ArgumentError, 'X11 class must have the response_length field to be read'
    end

    remaining = timeout
    reply_instance = klass.new

    metalength = reply_instance.response_length.num_bytes
    buffer, elapsed_time = Rex::Stopwatch.elapsed_time do
      sock.read(reply_instance.response_length.abs_offset + metalength, remaining)
    end
    raise ::EOFError, 'X11: failed to read response' if buffer.nil?

    remaining -= elapsed_time

    # see: https://www.x.org/releases/X11R7.7/doc/xproto/x11protocol.html#request_format
    response_length = reply_instance.response_length.read(buffer[-metalength..]).value
    response_length *= 4 # field is in 4-byte units
    response_length += 32 # 32 byte header is not included

    while buffer.length < response_length && remaining > 0
      chunk, elapsed_time = Rex::Stopwatch.elapsed_time do
        sock.read(response_length - buffer.length, remaining)
      end

      remaining -= elapsed_time
      break if chunk.nil?

      buffer << chunk
    end

    unless buffer.length == response_length
      if remaining <= 0
        raise Rex::TimeoutError, 'X11: failed to read response due to timeout'
      end

      raise ::EOFError, 'X11: failed to read response'
    end

    reply_instance.read(buffer)
  end
end
