module Zip
  # ZipOutputStream is the basic class for writing zip files. It is
  # possible to create a ZipOutputStream object directly, passing
  # the zip file name to the constructor, but more often than not
  # the ZipOutputStream will be obtained from a ZipFile (perhaps using the
  # ZipFileSystem interface) object for a particular entry in the zip
  # archive.
  #
  # A ZipOutputStream inherits IOExtras::AbstractOutputStream in order
  # to provide an IO-like interface for writing to a single zip
  # entry. Beyond methods for mimicking an IO-object it contains
  # the method put_next_entry that closes the current entry
  # and creates a new.
  #
  # Please refer to ZipInputStream for example code.
  #
  # java.util.zip.ZipOutputStream is the original inspiration for this
  # class.

  class OutputStream
    include ::Zip::IOExtras::AbstractOutputStream

    attr_accessor :comment

    # Opens the indicated zip file. If a file with that name already
    # exists it will be overwritten.
    def initialize(file_name, stream = false, encrypter = nil)
      super()
      @file_name = file_name
      @output_stream = if stream
                         iostream = @file_name.dup
                         iostream.reopen(@file_name)
                         iostream.rewind
                         iostream
                       else
                         ::File.new(@file_name, 'wb')
                       end
      @entry_set = ::Zip::EntrySet.new
      @compressor = ::Zip::NullCompressor.instance
      @encrypter = encrypter || ::Zip::NullEncrypter.new
      @closed = false
      @current_entry = nil
      @comment = nil
    end

    # Same as #initialize but if a block is passed the opened
    # stream is passed to the block and closed when the block
    # returns.
    class << self
      def open(file_name, encrypter = nil)
        return new(file_name) unless block_given?
        zos = new(file_name, false, encrypter)
        yield zos
      ensure
        zos.close if zos
      end

      # Same as #open but writes to a filestream instead
      def write_buffer(io = ::StringIO.new(''), encrypter = nil)
        zos = new(io, true, encrypter)
        yield zos
        zos.close_buffer
      end
    end

    # Closes the stream and writes the central directory to the zip file
    def close
      return if @closed
      finalize_current_entry
      update_local_headers
      write_central_directory
      @output_stream.close
      @closed = true
    end

    # Closes the stream and writes the central directory to the zip file
    def close_buffer
      return @output_stream if @closed
      finalize_current_entry
      update_local_headers
      write_central_directory
      @closed = true
      @output_stream
    end

    # Closes the current entry and opens a new for writing.
    # +entry+ can be a ZipEntry object or a string.
    def put_next_entry(entry_name, comment = nil, extra = nil, compression_method = Entry::DEFLATED, level = Zip.default_compression)
      raise Error, 'zip stream is closed' if @closed
      new_entry = if entry_name.kind_of?(Entry)
                    entry_name
                  else
                    Entry.new(@file_name, entry_name.to_s)
                  end
      new_entry.comment = comment unless comment.nil?
      unless extra.nil?
        new_entry.extra = extra.is_a?(ExtraField) ? extra : ExtraField.new(extra.to_s)
      end
      new_entry.compression_method = compression_method unless compression_method.nil?
      init_next_entry(new_entry, level)
      @current_entry = new_entry
    end

    def copy_raw_entry(entry)
      entry = entry.dup
      raise Error, 'zip stream is closed' if @closed
      raise Error, 'entry is not a ZipEntry' unless entry.is_a?(Entry)
      finalize_current_entry
      @entry_set << entry
      src_pos = entry.local_header_offset
      entry.write_local_entry(@output_stream)
      @compressor = NullCompressor.instance
      entry.get_raw_input_stream do |is|
        is.seek(src_pos, IO::SEEK_SET)
        ::Zip::Entry.read_local_entry(is)
        IOExtras.copy_stream_n(@output_stream, is, entry.compressed_size)
      end
      @compressor = NullCompressor.instance
      @current_entry = nil
    end

    private

    def finalize_current_entry
      return unless @current_entry
      finish
      @current_entry.compressed_size = @output_stream.tell - @current_entry.local_header_offset - @current_entry.calculate_local_header_size
      @current_entry.size = @compressor.size
      @current_entry.crc = @compressor.crc
      @output_stream << @encrypter.data_descriptor(@current_entry.crc, @current_entry.compressed_size, @current_entry.size)
      @current_entry.gp_flags |= @encrypter.gp_flags
      @current_entry = nil
      @compressor = ::Zip::NullCompressor.instance
    end

    def init_next_entry(entry, level = Zip.default_compression)
      finalize_current_entry
      @entry_set << entry
      entry.write_local_entry(@output_stream)
      @encrypter.reset!
      @output_stream << @encrypter.header(entry.mtime)
      @compressor = get_compressor(entry, level)
    end

    def get_compressor(entry, level)
      case entry.compression_method
      when Entry::DEFLATED then
        ::Zip::Deflater.new(@output_stream, level, @encrypter)
      when Entry::STORED then
        ::Zip::PassThruCompressor.new(@output_stream)
      else
        raise ::Zip::CompressionMethodError,
              "Invalid compression method: '#{entry.compression_method}'"
      end
    end

    def update_local_headers
      pos = @output_stream.pos
      @entry_set.each do |entry|
        @output_stream.pos = entry.local_header_offset
        entry.write_local_entry(@output_stream, true)
      end
      @output_stream.pos = pos
    end

    def write_central_directory
      cdir = CentralDirectory.new(@entry_set, @comment)
      cdir.write_to_stream(@output_stream)
    end

    protected

    def finish
      @compressor.finish
    end

    public

    # Modeled after IO.<<
    def <<(data)
      @compressor << data
      self
    end
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
