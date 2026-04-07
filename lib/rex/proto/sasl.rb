module Rex::Proto::Sasl
  # Wrap the data in a SASL structure, per RFC 4422 (basically just prepends a big-endian encoded 32-bit integer representing the length)
  def wrap_sasl(data)
    length = [data.length].pack('N')

    length + data
  end

  # Unwraps the data from a SASL structure, per RFC 4422
  def unwrap_sasl(data)
    length = data[0,4].unpack('N')[0]
    if length != data.length + 4
      raise ArgumentError.new('Invalid SASL structure')
    end

    data[4,length]
  end
end
