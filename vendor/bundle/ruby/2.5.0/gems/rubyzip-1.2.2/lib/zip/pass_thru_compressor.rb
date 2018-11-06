module Zip
  class PassThruCompressor < Compressor #:nodoc:all
    def initialize(outputStream)
      super()
      @output_stream = outputStream
      @crc = Zlib.crc32
      @size = 0
    end

    def <<(data)
      val = data.to_s
      @crc = Zlib.crc32(val, @crc)
      @size += val.bytesize
      @output_stream << val
    end

    attr_reader :size, :crc
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
