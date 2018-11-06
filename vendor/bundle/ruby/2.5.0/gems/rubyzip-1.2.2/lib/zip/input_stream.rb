module Zip
  # InputStream is the basic class for reading zip entries in a
  # zip file. It is possible to create a InputStream object directly,
  # passing the zip file name to the constructor, but more often than not
  # the InputStream will be obtained from a File (perhaps using the
  # ZipFileSystem interface) object for a particular entry in the zip
  # archive.
  #
  # A InputStream inherits IOExtras::AbstractInputStream in order
  # to provide an IO-like interface for reading from a single zip
  # entry. Beyond methods for mimicking an IO-object it contains
  # the method get_next_entry for iterating through the entries of
  # an archive. get_next_entry returns a Entry object that describes
  # the zip entry the InputStream is currently reading from.
  #
  # Example that creates a zip archive with ZipOutputStream and reads it
  # back again with a InputStream.
  #
  #   require 'zip'
  #
  #   Zip::OutputStream.open("my.zip") do |io|
  #
  #     io.put_next_entry("first_entry.txt")
  #     io.write "Hello world!"
  #
  #     io.put_next_entry("adir/first_entry.txt")
  #     io.write "Hello again!"
  #   end
  #
  #
  #   Zip::InputStream.open("my.zip") do |io|
  #
  #     while (entry = io.get_next_entry)
  #       puts "Contents of #{entry.name}: '#{io.read}'"
  #     end
  #   end
  #
  # java.util.zip.ZipInputStream is the original inspiration for this
  # class.

  class InputStream
    include ::Zip::IOExtras::AbstractInputStream

    # Opens the indicated zip file. An exception is thrown
    # if the specified offset in the specified filename is
    # not a local zip entry header.
    #
    # @param context [String||IO||StringIO] file path or IO/StringIO object
    # @param offset [Integer] offset in the IO/StringIO
    def initialize(context, offset = 0, decrypter = nil)
      super()
      @archive_io = get_io(context, offset)
      @decompressor  = ::Zip::NullDecompressor
      @decrypter     = decrypter || ::Zip::NullDecrypter.new
      @current_entry = nil
    end

    def close
      @archive_io.close
    end

    # Returns a Entry object. It is necessary to call this
    # method on a newly created InputStream before reading from
    # the first entry in the archive. Returns nil when there are
    # no more entries.
    def get_next_entry
      @archive_io.seek(@current_entry.next_header_offset, IO::SEEK_SET) if @current_entry
      open_entry
    end

    # Rewinds the stream to the beginning of the current entry
    def rewind
      return if @current_entry.nil?
      @lineno = 0
      @pos    = 0
      @archive_io.seek(@current_entry.local_header_offset, IO::SEEK_SET)
      open_entry
    end

    # Modeled after IO.sysread
    def sysread(number_of_bytes = nil, buf = nil)
      @decompressor.sysread(number_of_bytes, buf)
    end

    def eof
      @output_buffer.empty? && @decompressor.eof
    end

    alias :eof? eof

    class << self
      # Same as #initialize but if a block is passed the opened
      # stream is passed to the block and closed when the block
      # returns.
      def open(filename_or_io, offset = 0, decrypter = nil)
        zio = new(filename_or_io, offset, decrypter)
        return zio unless block_given?
        begin
          yield zio
        ensure
          zio.close if zio
        end
      end

      def open_buffer(filename_or_io, offset = 0)
        puts 'open_buffer is deprecated!!! Use open instead!'
        open(filename_or_io, offset)
      end
    end

    protected

    def get_io(io_or_file, offset = 0)
      if io_or_file.respond_to?(:seek)
        io = io_or_file.dup
        io.seek(offset, ::IO::SEEK_SET)
        io
      else
        file = ::File.open(io_or_file, 'rb')
        file.seek(offset, ::IO::SEEK_SET)
        file
      end
    end

    def open_entry
      @current_entry = ::Zip::Entry.read_local_entry(@archive_io)
      if @current_entry && @current_entry.gp_flags & 1 == 1 && @decrypter.is_a?(NullEncrypter)
        raise Error, 'password required to decode zip file'
      end
      if @current_entry && @current_entry.gp_flags & 8 == 8 && @current_entry.crc == 0 \
        && @current_entry.compressed_size == 0 \
        && @current_entry.size == 0 && !@complete_entry
        raise GPFBit3Error,
              'General purpose flag Bit 3 is set so not possible to get proper info from local header.' \
              'Please use ::Zip::File instead of ::Zip::InputStream'
      end
      @decompressor = get_decompressor
      flush
      @current_entry
    end

    def get_decompressor
      if @current_entry.nil?
        ::Zip::NullDecompressor
      elsif @current_entry.compression_method == ::Zip::Entry::STORED
        if @current_entry.gp_flags & 8 == 8 && @current_entry.crc == 0 && @current_entry.size == 0 && @complete_entry
          ::Zip::PassThruDecompressor.new(@archive_io, @complete_entry.size)
        else
          ::Zip::PassThruDecompressor.new(@archive_io, @current_entry.size)
        end
      elsif @current_entry.compression_method == ::Zip::Entry::DEFLATED
        header = @archive_io.read(@decrypter.header_bytesize)
        @decrypter.reset!(header)
        ::Zip::Inflater.new(@archive_io, @decrypter)
      else
        raise ::Zip::CompressionMethodError,
              "Unsupported compression method #{@current_entry.compression_method}"
      end
    end

    def produce_input
      @decompressor.produce_input
    end

    def input_finished?
      @decompressor.input_finished?
    end
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
