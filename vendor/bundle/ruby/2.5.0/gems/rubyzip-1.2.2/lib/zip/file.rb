module Zip
  # ZipFile is modeled after java.util.zip.ZipFile from the Java SDK.
  # The most important methods are those inherited from
  # ZipCentralDirectory for accessing information about the entries in
  # the archive and methods such as get_input_stream and
  # get_output_stream for reading from and writing entries to the
  # archive. The class includes a few convenience methods such as
  # #extract for extracting entries to the filesystem, and #remove,
  # #replace, #rename and #mkdir for making simple modifications to
  # the archive.
  #
  # Modifications to a zip archive are not committed until #commit or
  # #close is called. The method #open accepts a block following
  # the pattern from File.open offering a simple way to
  # automatically close the archive when the block returns.
  #
  # The following example opens zip archive <code>my.zip</code>
  # (creating it if it doesn't exist) and adds an entry
  # <code>first.txt</code> and a directory entry <code>a_dir</code>
  # to it.
  #
  #   require 'zip'
  #
  #   Zip::File.open("my.zip", Zip::File::CREATE) {
  #    |zipfile|
  #     zipfile.get_output_stream("first.txt") { |f| f.puts "Hello from ZipFile" }
  #     zipfile.mkdir("a_dir")
  #   }
  #
  # The next example reopens <code>my.zip</code> writes the contents of
  # <code>first.txt</code> to standard out and deletes the entry from
  # the archive.
  #
  #   require 'zip'
  #
  #   Zip::File.open("my.zip", Zip::File::CREATE) {
  #     |zipfile|
  #     puts zipfile.read("first.txt")
  #     zipfile.remove("first.txt")
  #   }
  #
  # ZipFileSystem offers an alternative API that emulates ruby's
  # interface for accessing the filesystem, ie. the File and Dir classes.

  class File < CentralDirectory
    CREATE               = true
    SPLIT_SIGNATURE      = 0x08074b50
    ZIP64_EOCD_SIGNATURE = 0x06064b50
    MAX_SEGMENT_SIZE     = 3_221_225_472
    MIN_SEGMENT_SIZE     = 65_536
    DATA_BUFFER_SIZE     = 8192
    IO_METHODS           = [:tell, :seek, :read, :close]

    attr_reader :name

    # default -> false
    attr_accessor :restore_ownership
    # default -> false
    attr_accessor :restore_permissions
    # default -> true
    attr_accessor :restore_times
    # Returns the zip files comment, if it has one
    attr_accessor :comment

    # Opens a zip archive. Pass true as the second parameter to create
    # a new archive if it doesn't exist already.
    def initialize(file_name, create = false, buffer = false, options = {})
      super()
      @name    = file_name
      @comment = ''
      @create  = create ? true : false # allow any truthy value to mean true
      if !buffer && ::File.size?(file_name)
        @create = false
        @file_permissions = ::File.stat(file_name).mode
        ::File.open(name, 'rb') do |f|
          read_from_stream(f)
        end
      elsif @create
        @entry_set = EntrySet.new
      elsif ::File.zero?(file_name)
        raise Error, "File #{file_name} has zero size. Did you mean to pass the create flag?"
      else
        raise Error, "File #{file_name} not found"
      end
      @stored_entries      = @entry_set.dup
      @stored_comment      = @comment
      @restore_ownership   = options[:restore_ownership]    || false
      @restore_permissions = options[:restore_permissions]  || true
      @restore_times       = options[:restore_times]        || true
    end

    class << self
      # Same as #new. If a block is passed the ZipFile object is passed
      # to the block and is automatically closed afterwards just as with
      # ruby's builtin File.open method.
      def open(file_name, create = false)
        zf = ::Zip::File.new(file_name, create)
        return zf unless block_given?
        begin
          yield zf
        ensure
          zf.close
        end
      end

      # Same as #open. But outputs data to a buffer instead of a file
      def add_buffer
        io = ::StringIO.new('')
        zf = ::Zip::File.new(io, true, true)
        yield zf
        zf.write_buffer(io)
      end

      # Like #open, but reads zip archive contents from a String or open IO
      # stream, and outputs data to a buffer.
      # (This can be used to extract data from a
      # downloaded zip archive without first saving it to disk.)
      def open_buffer(io, options = {})
        unless IO_METHODS.map { |method| io.respond_to?(method) }.all? || io.is_a?(String)
          raise "Zip::File.open_buffer expects a String or IO-like argument (responds to #{IO_METHODS.join(', ')}). Found: #{io.class}"
        end
        if io.is_a?(::String)
          require 'stringio'
          io = ::StringIO.new(io)
        elsif io.respond_to?(:binmode)
          # https://github.com/rubyzip/rubyzip/issues/119
          io.binmode
        end
        zf = ::Zip::File.new(io, true, true, options)
        zf.read_from_stream(io)
        return zf unless block_given?
        yield zf
        begin
          zf.write_buffer(io)
        rescue IOError => e
          raise unless e.message == 'not opened for writing'
        end
      end

      # Iterates over the contents of the ZipFile. This is more efficient
      # than using a ZipInputStream since this methods simply iterates
      # through the entries in the central directory structure in the archive
      # whereas ZipInputStream jumps through the entire archive accessing the
      # local entry headers (which contain the same information as the
      # central directory).
      def foreach(aZipFileName, &block)
        open(aZipFileName) do |zipFile|
          zipFile.each(&block)
        end
      end

      def get_segment_size_for_split(segment_size)
        if MIN_SEGMENT_SIZE > segment_size
          MIN_SEGMENT_SIZE
        elsif MAX_SEGMENT_SIZE < segment_size
          MAX_SEGMENT_SIZE
        else
          segment_size
        end
      end

      def get_partial_zip_file_name(zip_file_name, partial_zip_file_name)
        unless partial_zip_file_name.nil?
          partial_zip_file_name = zip_file_name.sub(/#{::File.basename(zip_file_name)}\z/,
                                                    partial_zip_file_name + ::File.extname(zip_file_name))
        end
        partial_zip_file_name ||= zip_file_name
        partial_zip_file_name
      end

      def get_segment_count_for_split(zip_file_size, segment_size)
        (zip_file_size / segment_size).to_i + (zip_file_size % segment_size == 0 ? 0 : 1)
      end

      def put_split_signature(szip_file, segment_size)
        signature_packed = [SPLIT_SIGNATURE].pack('V')
        szip_file << signature_packed
        segment_size - signature_packed.size
      end

      #
      # TODO: Make the code more understandable
      #
      def save_splited_part(zip_file, partial_zip_file_name, zip_file_size, szip_file_index, segment_size, segment_count)
        ssegment_size  = zip_file_size - zip_file.pos
        ssegment_size  = segment_size if ssegment_size > segment_size
        szip_file_name = "#{partial_zip_file_name}.#{format('%03d', szip_file_index)}"
        ::File.open(szip_file_name, 'wb') do |szip_file|
          if szip_file_index == 1
            ssegment_size = put_split_signature(szip_file, segment_size)
          end
          chunk_bytes = 0
          until ssegment_size == chunk_bytes || zip_file.eof?
            segment_bytes_left = ssegment_size - chunk_bytes
            buffer_size        = segment_bytes_left < DATA_BUFFER_SIZE ? segment_bytes_left : DATA_BUFFER_SIZE
            chunk              = zip_file.read(buffer_size)
            chunk_bytes += buffer_size
            szip_file << chunk
            # Info for track splitting
            yield segment_count, szip_file_index, chunk_bytes, ssegment_size if block_given?
          end
        end
      end

      # Splits an archive into parts with segment size
      def split(zip_file_name, segment_size = MAX_SEGMENT_SIZE, delete_zip_file = true, partial_zip_file_name = nil)
        raise Error, "File #{zip_file_name} not found" unless ::File.exist?(zip_file_name)
        raise Errno::ENOENT, zip_file_name unless ::File.readable?(zip_file_name)
        zip_file_size = ::File.size(zip_file_name)
        segment_size  = get_segment_size_for_split(segment_size)
        return if zip_file_size <= segment_size
        segment_count = get_segment_count_for_split(zip_file_size, segment_size)
        # Checking for correct zip structure
        open(zip_file_name) {}
        partial_zip_file_name = get_partial_zip_file_name(zip_file_name, partial_zip_file_name)
        szip_file_index       = 0
        ::File.open(zip_file_name, 'rb') do |zip_file|
          until zip_file.eof?
            szip_file_index += 1
            save_splited_part(zip_file, partial_zip_file_name, zip_file_size, szip_file_index, segment_size, segment_count)
          end
        end
        ::File.delete(zip_file_name) if delete_zip_file
        szip_file_index
      end
    end

    # Returns an input stream to the specified entry. If a block is passed
    # the stream object is passed to the block and the stream is automatically
    # closed afterwards just as with ruby's builtin File.open method.
    def get_input_stream(entry, &aProc)
      get_entry(entry).get_input_stream(&aProc)
    end

    # Returns an output stream to the specified entry. If entry is not an instance
    # of Zip::Entry, a new Zip::Entry will be initialized using the arguments
    # specified. If a block is passed the stream object is passed to the block and
    # the stream is automatically closed afterwards just as with ruby's builtin
    # File.open method.
    def get_output_stream(entry, permission_int = nil, comment = nil, extra = nil, compressed_size = nil, crc = nil, compression_method = nil, size = nil, time = nil, &aProc)
      new_entry =
        if entry.kind_of?(Entry)
          entry
        else
          Entry.new(@name, entry.to_s, comment, extra, compressed_size, crc, compression_method, size, time)
        end
      if new_entry.directory?
        raise ArgumentError,
              "cannot open stream to directory entry - '#{new_entry}'"
      end
      new_entry.unix_perms = permission_int
      zip_streamable_entry = StreamableStream.new(new_entry)
      @entry_set << zip_streamable_entry
      zip_streamable_entry.get_output_stream(&aProc)
    end

    # Returns the name of the zip archive
    def to_s
      @name
    end

    # Returns a string containing the contents of the specified entry
    def read(entry)
      get_input_stream(entry) { |is| is.read }
    end

    # Convenience method for adding the contents of a file to the archive
    def add(entry, src_path, &continue_on_exists_proc)
      continue_on_exists_proc ||= proc { ::Zip.continue_on_exists_proc }
      check_entry_exists(entry, continue_on_exists_proc, 'add')
      new_entry = entry.kind_of?(::Zip::Entry) ? entry : ::Zip::Entry.new(@name, entry.to_s)
      new_entry.gather_fileinfo_from_srcpath(src_path)
      new_entry.dirty = true
      @entry_set << new_entry
    end

    # Removes the specified entry.
    def remove(entry)
      @entry_set.delete(get_entry(entry))
    end

    # Renames the specified entry.
    def rename(entry, new_name, &continue_on_exists_proc)
      foundEntry = get_entry(entry)
      check_entry_exists(new_name, continue_on_exists_proc, 'rename')
      @entry_set.delete(foundEntry)
      foundEntry.name = new_name
      @entry_set << foundEntry
    end

    # Replaces the specified entry with the contents of srcPath (from
    # the file system).
    def replace(entry, srcPath)
      check_file(srcPath)
      remove(entry)
      add(entry, srcPath)
    end

    # Extracts entry to file dest_path.
    def extract(entry, dest_path, &block)
      block ||= proc { ::Zip.on_exists_proc }
      found_entry = get_entry(entry)
      found_entry.extract(dest_path, &block)
    end

    # Commits changes that has been made since the previous commit to
    # the zip archive.
    def commit
      return if name.is_a?(StringIO) || !commit_required?
      on_success_replace do |tmp_file|
        ::Zip::OutputStream.open(tmp_file) do |zos|
          @entry_set.each do |e|
            e.write_to_zip_output_stream(zos)
            e.dirty = false
            e.clean_up
          end
          zos.comment = comment
        end
        true
      end
      initialize(name)
    end

    # Write buffer write changes to buffer and return
    def write_buffer(io = ::StringIO.new(''))
      ::Zip::OutputStream.write_buffer(io) do |zos|
        @entry_set.each { |e| e.write_to_zip_output_stream(zos) }
        zos.comment = comment
      end
    end

    # Closes the zip file committing any changes that has been made.
    def close
      commit
    end

    # Returns true if any changes has been made to this archive since
    # the previous commit
    def commit_required?
      @entry_set.each do |e|
        return true if e.dirty
      end
      @comment != @stored_comment || @entry_set != @stored_entries || @create
    end

    # Searches for entry with the specified name. Returns nil if
    # no entry is found. See also get_entry
    def find_entry(entry_name)
      @entry_set.find_entry(entry_name)
    end

    # Searches for entries given a glob
    def glob(*args, &block)
      @entry_set.glob(*args, &block)
    end

    # Searches for an entry just as find_entry, but throws Errno::ENOENT
    # if no entry is found.
    def get_entry(entry)
      selected_entry = find_entry(entry)
      raise Errno::ENOENT, entry unless selected_entry
      selected_entry.restore_ownership   = @restore_ownership
      selected_entry.restore_permissions = @restore_permissions
      selected_entry.restore_times       = @restore_times
      selected_entry
    end

    # Creates a directory
    def mkdir(entryName, permissionInt = 0o755)
      raise Errno::EEXIST, "File exists - #{entryName}" if find_entry(entryName)
      entryName = entryName.dup.to_s
      entryName << '/' unless entryName.end_with?('/')
      @entry_set << ::Zip::StreamableDirectory.new(@name, entryName, nil, permissionInt)
    end

    private

    def directory?(newEntry, srcPath)
      srcPathIsDirectory = ::File.directory?(srcPath)
      if newEntry.directory? && !srcPathIsDirectory
        raise ArgumentError,
              "entry name '#{newEntry}' indicates directory entry, but " \
                  "'#{srcPath}' is not a directory"
      elsif !newEntry.directory? && srcPathIsDirectory
        newEntry.name += '/'
      end
      newEntry.directory? && srcPathIsDirectory
    end

    def check_entry_exists(entryName, continue_on_exists_proc, procedureName)
      continue_on_exists_proc ||= proc { Zip.continue_on_exists_proc }
      return unless @entry_set.include?(entryName)
      if continue_on_exists_proc.call
        remove get_entry(entryName)
      else
        raise ::Zip::EntryExistsError,
              procedureName + " failed. Entry #{entryName} already exists"
      end
    end

    def check_file(path)
      raise Errno::ENOENT, path unless ::File.readable?(path)
    end

    def on_success_replace
      dirname, basename = ::File.split(name)
      ::Dir::Tmpname.create(basename, dirname) do |tmp_filename|
        begin
          if yield tmp_filename
            ::File.rename(tmp_filename, name)
            ::File.chmod(@file_permissions, name) unless @create
          end
        ensure
          ::File.unlink(tmp_filename) if ::File.exist?(tmp_filename)
        end
      end
    end
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
