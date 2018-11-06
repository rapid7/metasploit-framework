class XDR::RPC::RecordReader
  include XDR::Concerns::ReadsBytes

  LAST_MASK   = 0x80000000
  LENGTH_MASK = 0x7FFFFFFF

  def read(io)
    header      = read_bytes(io, 4).unpack("L>").first
    length      = header & LENGTH_MASK
    last        = (header & LAST_MASK) > 0
    raw_content = read_bytes(io, length)
    content     = StringIO.new(raw_content)
    
    XDR::RPC::Record.new(last, length, content)
  end
end