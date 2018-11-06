require 'base64'

module XDR::Concerns::ConvertsToXDR
  include XDR::Concerns::ReadsBytes

  # 
  # Serialized the provided `val` to xdr and writes it to `io`
  # 
  # @param val [Object] The object to serialize
  # @param io [IO] an IO object to write to
  # 
  def write(val, io)
    raise NotImplementedError, "implement in including class"
  end

  # 
  # Reads from the provided IO an instance of the implementing class
  # @param io [IO] the io to read from
  # 
  # @return [Object] the deserialized value
  def read(io)
    raise NotImplementedError, "implement in including class"
  end

  # 
  # Returns true if the value provided is compatible with this serializer class
  # 
  # @param value [Object] the value to test
  # 
  # @return [Boolean] true if valid, false otherwise
  def valid?(value)
    raise NotImplementedError, "implement in including class"
  end
  
  # 
  # Serialized the provided val to xdr, returning a string
  # of the serialized data
  # 
  # @param val [Object] the value to serialize
  # 
  # @return [String] the produced bytes
  def to_xdr(val, encoding='raw')
    raw = StringIO.
      new.
      tap{|io| write(val, io)}.
      string.force_encoding("ASCII-8BIT")

    case encoding
    when 'raw' ; raw
    when 'base64' ; Base64.strict_encode64(raw)
    when 'hex' ; raw.unpack("H*").first
    else
      raise  ArgumentError, "Invalid encoding #{encoding.inspect}: must be 'raw', 'base64', or 'hex'"
    end
  end
  
  # 
  # Deserializes an object from the provided string of bytes
  # 
  # @param string [String] the bytes to read from
  # 
  # @return [Object] the deserialized value
  def from_xdr(string, encoding='raw')
    raw = case encoding
          when 'raw' ; string
          when 'base64' ; Base64.strict_decode64(string)
          when 'hex' ; [string].pack("H*")
          else
            raise  ArgumentError, "Invalid encoding #{encoding.inspect}: must be 'raw', 'base64', or 'hex'"
          end

    io = StringIO.new(raw)
    result = read(io)

    if io.pos != io.length
      raise  ArgumentError, "Input string not fully consumed! are you decoding the right xdr type?"
    end

    result
  end

  private
  def padding_for(length)
    case length % 4
    when 0 ; 0
    when 1 ; 3
    when 2 ; 2
    when 3 ; 1
    end
  end
end
