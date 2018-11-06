module Zip
  class Deflater < Compressor #:nodoc:all
    def initialize(output_stream, level = Zip.default_compression, encrypter = NullEncrypter.new)
      super()
      @output_stream = output_stream
      @zlib_deflater = ::Zlib::Deflate.new(level, -::Zlib::MAX_WBITS)
      @size          = 0
      @crc           = ::Zlib.crc32
      @encrypter     = encrypter
    end

    def <<(data)
      val   = data.to_s
      @crc  = Zlib.crc32(val, @crc)
      @size += val.bytesize
      buffer = @zlib_deflater.deflate(data)
      if buffer.empty?
        @output_stream
      else
        @output_stream << @encrypter.encrypt(buffer)
      end
    end

    def finish
      @output_stream << @encrypter.encrypt(@zlib_deflater.finish) until @zlib_deflater.finished?
    end

    attr_reader :size, :crc
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
