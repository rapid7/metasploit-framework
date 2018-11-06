module Zip
  class Inflater < Decompressor #:nodoc:all
    def initialize(input_stream, decrypter = NullDecrypter.new)
      super(input_stream)
      @zlib_inflater           = ::Zlib::Inflate.new(-Zlib::MAX_WBITS)
      @output_buffer           = ''
      @has_returned_empty_string = false
      @decrypter = decrypter
    end

    def sysread(number_of_bytes = nil, buf = '')
      readEverything = number_of_bytes.nil?
      while readEverything || @output_buffer.bytesize < number_of_bytes
        break if internal_input_finished?
        @output_buffer << internal_produce_input(buf)
      end
      return value_when_finished if @output_buffer.bytesize == 0 && input_finished?
      end_index = number_of_bytes.nil? ? @output_buffer.bytesize : number_of_bytes
      @output_buffer.slice!(0...end_index)
    end

    def produce_input
      if @output_buffer.empty?
        internal_produce_input
      else
        @output_buffer.slice!(0...(@output_buffer.length))
      end
    end

    # to be used with produce_input, not read (as read may still have more data cached)
    # is data cached anywhere other than @outputBuffer?  the comment above may be wrong
    def input_finished?
      @output_buffer.empty? && internal_input_finished?
    end

    alias :eof input_finished?
    alias :eof? input_finished?

    private

    def internal_produce_input(buf = '')
      retried = 0
      begin
        @zlib_inflater.inflate(@decrypter.decrypt(@input_stream.read(Decompressor::CHUNK_SIZE, buf)))
      rescue Zlib::BufError
        raise if retried >= 5 # how many times should we retry?
        retried += 1
        retry
      end
    end

    def internal_input_finished?
      @zlib_inflater.finished?
    end

    def value_when_finished # mimic behaviour of ruby File object.
      return if @has_returned_empty_string
      @has_returned_empty_string = true
      ''
    end
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
