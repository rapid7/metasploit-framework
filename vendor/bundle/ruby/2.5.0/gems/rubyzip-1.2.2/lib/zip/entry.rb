module Zip
  class Entry
    STORED   = 0
    DEFLATED = 8
    # Language encoding flag (EFS) bit
    EFS = 0b100000000000

    attr_accessor :comment, :compressed_size, :crc, :extra, :compression_method,
                  :name, :size, :local_header_offset, :zipfile, :fstype, :external_file_attributes,
                  :internal_file_attributes,
                  :gp_flags, :header_signature, :follow_symlinks,
                  :restore_times, :restore_permissions, :restore_ownership,
                  :unix_uid, :unix_gid, :unix_perms,
                  :dirty
    attr_reader :ftype, :filepath # :nodoc:

    def set_default_vars_values
      @local_header_offset      = 0
      @local_header_size        = nil # not known until local entry is created or read
      @internal_file_attributes = 1
      @external_file_attributes = 0
      @header_signature         = ::Zip::CENTRAL_DIRECTORY_ENTRY_SIGNATURE

      @version_needed_to_extract = VERSION_NEEDED_TO_EXTRACT
      @version                   = VERSION_MADE_BY

      @ftype           = nil          # unspecified or unknown
      @filepath        = nil
      @gp_flags        = 0
      if ::Zip.unicode_names
        @gp_flags |= EFS
        @version = 63
      end
      @follow_symlinks = false

      @restore_times       = true
      @restore_permissions = false
      @restore_ownership   = false
      # BUG: need an extra field to support uid/gid's
      @unix_uid            = nil
      @unix_gid            = nil
      @unix_perms          = nil
      # @posix_acl = nil
      # @ntfs_acl = nil
      @dirty               = false
    end

    def check_name(name)
      return unless name.start_with?('/')
      raise ::Zip::EntryNameError, "Illegal ZipEntry name '#{name}', name must not start with /"
    end

    def initialize(*args)
      name = args[1] || ''
      check_name(name)

      set_default_vars_values
      @fstype = ::Zip::RUNNING_ON_WINDOWS ? ::Zip::FSTYPE_FAT : ::Zip::FSTYPE_UNIX

      @zipfile            = args[0] || ''
      @name               = name
      @comment            = args[2] || ''
      @extra              = args[3] || ''
      @compressed_size    = args[4] || 0
      @crc                = args[5] || 0
      @compression_method = args[6] || ::Zip::Entry::DEFLATED
      @size               = args[7] || 0
      @time               = args[8] || ::Zip::DOSTime.now

      @ftype = name_is_directory? ? :directory : :file
      @extra = ::Zip::ExtraField.new(@extra.to_s) unless @extra.is_a?(::Zip::ExtraField)
    end

    def time
      if @extra['UniversalTime']
        @extra['UniversalTime'].mtime
      elsif @extra['NTFS']
        @extra['NTFS'].mtime
      else
        # Standard time field in central directory has local time
        # under archive creator. Then, we can't get timezone.
        @time
      end
    end

    alias mtime time

    def time=(value)
      unless @extra.member?('UniversalTime') || @extra.member?('NTFS')
        @extra.create('UniversalTime')
      end
      (@extra['UniversalTime'] || @extra['NTFS']).mtime = value
      @time                         = value
    end

    def file_type_is?(type)
      raise InternalError, "current filetype is unknown: #{inspect}" unless @ftype
      @ftype == type
    end

    # Dynamic checkers
    %w[directory file symlink].each do |k|
      define_method "#{k}?" do
        file_type_is?(k.to_sym)
      end
    end

    def name_is_directory? #:nodoc:all
      @name.end_with?('/')
    end

    # Is the name a relative path, free of `..` patterns that could lead to
    # path traversal attacks? This does NOT handle symlinks; if the path
    # contains symlinks, this check is NOT enough to guarantee safety.
    def name_safe?
      cleanpath = Pathname.new(@name).cleanpath
      return false unless cleanpath.relative?
      root = ::File::SEPARATOR
      naive_expanded_path = ::File.join(root, cleanpath.to_s)
      cleanpath.expand_path(root).to_s == naive_expanded_path
    end

    def local_entry_offset #:nodoc:all
      local_header_offset + @local_header_size
    end

    def name_size
      @name ? @name.bytesize : 0
    end

    def extra_size
      @extra ? @extra.local_size : 0
    end

    def comment_size
      @comment ? @comment.bytesize : 0
    end

    def calculate_local_header_size #:nodoc:all
      LOCAL_ENTRY_STATIC_HEADER_LENGTH + name_size + extra_size
    end

    # check before rewriting an entry (after file sizes are known)
    # that we didn't change the header size (and thus clobber file data or something)
    def verify_local_header_size!
      return if @local_header_size.nil?
      new_size = calculate_local_header_size
      raise Error, "local header size changed (#{@local_header_size} -> #{new_size})" if @local_header_size != new_size
    end

    def cdir_header_size #:nodoc:all
      CDIR_ENTRY_STATIC_HEADER_LENGTH + name_size +
        (@extra ? @extra.c_dir_size : 0) + comment_size
    end

    def next_header_offset #:nodoc:all
      local_entry_offset + compressed_size + data_descriptor_size
    end

    # Extracts entry to file dest_path (defaults to @name).
    # NB: The caller is responsible for making sure dest_path is safe, if it
    # is passed.
    def extract(dest_path = nil, &block)
      if dest_path.nil? && !name_safe?
        puts "WARNING: skipped #{@name} as unsafe"
        return self
      end

      dest_path ||= @name
      block ||= proc { ::Zip.on_exists_proc }

      if directory? || file? || symlink?
        __send__("create_#{@ftype}", dest_path, &block)
      else
        raise "unknown file type #{inspect}"
      end

      self
    end

    def to_s
      @name
    end

    class << self
      def read_zip_short(io) # :nodoc:
        io.read(2).unpack('v')[0]
      end

      def read_zip_long(io) # :nodoc:
        io.read(4).unpack('V')[0]
      end

      def read_zip_64_long(io) # :nodoc:
        io.read(8).unpack('Q<')[0]
      end

      def read_c_dir_entry(io) #:nodoc:all
        path = if io.respond_to?(:path)
                 io.path
               else
                 io
               end
        entry = new(path)
        entry.read_c_dir_entry(io)
        entry
      rescue Error
        nil
      end

      def read_local_entry(io)
        entry = new(io)
        entry.read_local_entry(io)
        entry
      rescue Error
        nil
      end
    end

    public

    def unpack_local_entry(buf)
      @header_signature,
        @version,
        @fstype,
        @gp_flags,
        @compression_method,
        @last_mod_time,
        @last_mod_date,
        @crc,
        @compressed_size,
        @size,
        @name_length,
        @extra_length = buf.unpack('VCCvvvvVVVvv')
    end

    def read_local_entry(io) #:nodoc:all
      @local_header_offset = io.tell

      static_sized_fields_buf = io.read(::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH) || ''

      unless static_sized_fields_buf.bytesize == ::Zip::LOCAL_ENTRY_STATIC_HEADER_LENGTH
        raise Error, 'Premature end of file. Not enough data for zip entry local header'
      end

      unpack_local_entry(static_sized_fields_buf)

      unless @header_signature == ::Zip::LOCAL_ENTRY_SIGNATURE
        raise ::Zip::Error, "Zip local header magic not found at location '#{local_header_offset}'"
      end
      set_time(@last_mod_date, @last_mod_time)

      @name = io.read(@name_length)
      extra = io.read(@extra_length)

      @name.tr!('\\', '/')
      if ::Zip.force_entry_names_encoding
        @name.force_encoding(::Zip.force_entry_names_encoding)
      end

      if extra && extra.bytesize != @extra_length
        raise ::Zip::Error, 'Truncated local zip entry header'
      else
        if @extra.is_a?(::Zip::ExtraField)
          @extra.merge(extra) if extra
        else
          @extra = ::Zip::ExtraField.new(extra)
        end
      end
      parse_zip64_extra(true)
      @local_header_size = calculate_local_header_size
    end

    def pack_local_entry
      zip64 = @extra['Zip64']
      [::Zip::LOCAL_ENTRY_SIGNATURE,
       @version_needed_to_extract, # version needed to extract
       @gp_flags, # @gp_flags                  ,
       @compression_method,
       @time.to_binary_dos_time, # @last_mod_time              ,
       @time.to_binary_dos_date, # @last_mod_date              ,
       @crc,
       zip64 && zip64.compressed_size ? 0xFFFFFFFF : @compressed_size,
       zip64 && zip64.original_size ? 0xFFFFFFFF : @size,
       name_size,
       @extra ? @extra.local_size : 0].pack('VvvvvvVVVvv')
    end

    def write_local_entry(io, rewrite = false) #:nodoc:all
      prep_zip64_extra(true)
      verify_local_header_size! if rewrite
      @local_header_offset = io.tell

      io << pack_local_entry

      io << @name
      io << @extra.to_local_bin if @extra
      @local_header_size = io.tell - @local_header_offset
    end

    def unpack_c_dir_entry(buf)
      @header_signature,
        @version, # version of encoding software
        @fstype, # filesystem type
        @version_needed_to_extract,
        @gp_flags,
        @compression_method,
        @last_mod_time,
        @last_mod_date,
        @crc,
        @compressed_size,
        @size,
        @name_length,
        @extra_length,
        @comment_length,
        _, # diskNumberStart
        @internal_file_attributes,
        @external_file_attributes,
        @local_header_offset,
        @name,
        @extra,
        @comment = buf.unpack('VCCvvvvvVVVvvvvvVV')
    end

    def set_ftype_from_c_dir_entry
      @ftype = case @fstype
               when ::Zip::FSTYPE_UNIX
                 @unix_perms = (@external_file_attributes >> 16) & 0o7777
                 case (@external_file_attributes >> 28)
                 when ::Zip::FILE_TYPE_DIR
                   :directory
                 when ::Zip::FILE_TYPE_FILE
                   :file
                 when ::Zip::FILE_TYPE_SYMLINK
                   :symlink
                 else
                   # best case guess for whether it is a file or not
                   # Otherwise this would be set to unknown and that entry would never be able to extracted
                   if name_is_directory?
                     :directory
                   else
                     :file
                   end
                 end
               else
                 if name_is_directory?
                   :directory
                 else
                   :file
                 end
               end
    end

    def check_c_dir_entry_static_header_length(buf)
      return if buf.bytesize == ::Zip::CDIR_ENTRY_STATIC_HEADER_LENGTH
      raise Error, 'Premature end of file. Not enough data for zip cdir entry header'
    end

    def check_c_dir_entry_signature
      return if header_signature == ::Zip::CENTRAL_DIRECTORY_ENTRY_SIGNATURE
      raise Error, "Zip local header magic not found at location '#{local_header_offset}'"
    end

    def check_c_dir_entry_comment_size
      return if @comment && @comment.bytesize == @comment_length
      raise ::Zip::Error, 'Truncated cdir zip entry header'
    end

    def read_c_dir_extra_field(io)
      if @extra.is_a?(::Zip::ExtraField)
        @extra.merge(io.read(@extra_length))
      else
        @extra = ::Zip::ExtraField.new(io.read(@extra_length))
      end
    end

    def read_c_dir_entry(io) #:nodoc:all
      static_sized_fields_buf = io.read(::Zip::CDIR_ENTRY_STATIC_HEADER_LENGTH)
      check_c_dir_entry_static_header_length(static_sized_fields_buf)
      unpack_c_dir_entry(static_sized_fields_buf)
      check_c_dir_entry_signature
      set_time(@last_mod_date, @last_mod_time)
      @name = io.read(@name_length)
      if ::Zip.force_entry_names_encoding
        @name.force_encoding(::Zip.force_entry_names_encoding)
      end
      read_c_dir_extra_field(io)
      @comment = io.read(@comment_length)
      check_c_dir_entry_comment_size
      set_ftype_from_c_dir_entry
      parse_zip64_extra(false)
    end

    def file_stat(path) # :nodoc:
      if @follow_symlinks
        ::File.stat(path)
      else
        ::File.lstat(path)
      end
    end

    def get_extra_attributes_from_path(path) # :nodoc:
      return if Zip::RUNNING_ON_WINDOWS
      stat        = file_stat(path)
      @unix_uid   = stat.uid
      @unix_gid   = stat.gid
      @unix_perms = stat.mode & 0o7777
    end

    def set_unix_permissions_on_path(dest_path)
      # BUG: does not update timestamps into account
      # ignore setuid/setgid bits by default.  honor if @restore_ownership
      unix_perms_mask = 0o1777
      unix_perms_mask = 0o7777 if @restore_ownership
      ::FileUtils.chmod(@unix_perms & unix_perms_mask, dest_path) if @restore_permissions && @unix_perms
      ::FileUtils.chown(@unix_uid, @unix_gid, dest_path) if @restore_ownership && @unix_uid && @unix_gid && ::Process.egid == 0
      # File::utimes()
    end

    def set_extra_attributes_on_path(dest_path) # :nodoc:
      return unless file? || directory?

      case @fstype
      when ::Zip::FSTYPE_UNIX
        set_unix_permissions_on_path(dest_path)
      end
    end

    def pack_c_dir_entry
      zip64 = @extra['Zip64']
      [
        @header_signature,
        @version, # version of encoding software
        @fstype, # filesystem type
        @version_needed_to_extract, # @versionNeededToExtract           ,
        @gp_flags, # @gp_flags                          ,
        @compression_method,
        @time.to_binary_dos_time, # @last_mod_time                      ,
        @time.to_binary_dos_date, # @last_mod_date                      ,
        @crc,
        zip64 && zip64.compressed_size ? 0xFFFFFFFF : @compressed_size,
        zip64 && zip64.original_size ? 0xFFFFFFFF : @size,
        name_size,
        @extra ? @extra.c_dir_size : 0,
        comment_size,
        zip64 && zip64.disk_start_number ? 0xFFFF : 0, # disk number start
        @internal_file_attributes, # file type (binary=0, text=1)
        @external_file_attributes, # native filesystem attributes
        zip64 && zip64.relative_header_offset ? 0xFFFFFFFF : @local_header_offset,
        @name,
        @extra,
        @comment
      ].pack('VCCvvvvvVVVvvvvvVV')
    end

    def write_c_dir_entry(io) #:nodoc:all
      prep_zip64_extra(false)
      case @fstype
      when ::Zip::FSTYPE_UNIX
        ft = case @ftype
             when :file
               @unix_perms ||= 0o644
               ::Zip::FILE_TYPE_FILE
             when :directory
               @unix_perms ||= 0o755
               ::Zip::FILE_TYPE_DIR
             when :symlink
               @unix_perms ||= 0o755
               ::Zip::FILE_TYPE_SYMLINK
             end

        unless ft.nil?
          @external_file_attributes = (ft << 12 | (@unix_perms & 0o7777)) << 16
        end
      end

      io << pack_c_dir_entry

      io << @name
      io << (@extra ? @extra.to_c_dir_bin : '')
      io << @comment
    end

    def ==(other)
      return false unless other.class == self.class
      # Compares contents of local entry and exposed fields
      keys_equal = %w[compression_method crc compressed_size size name extra filepath].all? do |k|
        other.__send__(k.to_sym) == __send__(k.to_sym)
      end
      keys_equal && time.dos_equals(other.time)
    end

    def <=>(other)
      to_s <=> other.to_s
    end

    # Returns an IO like object for the given ZipEntry.
    # Warning: may behave weird with symlinks.
    def get_input_stream(&block)
      if @ftype == :directory
        yield ::Zip::NullInputStream if block_given?
        ::Zip::NullInputStream
      elsif @filepath
        case @ftype
        when :file
          ::File.open(@filepath, 'rb', &block)
        when :symlink
          linkpath = ::File.readlink(@filepath)
          stringio = ::StringIO.new(linkpath)
          yield(stringio) if block_given?
          stringio
        else
          raise "unknown @file_type #{@ftype}"
        end
      else
        zis = ::Zip::InputStream.new(@zipfile, local_header_offset)
        zis.instance_variable_set(:@complete_entry, self)
        zis.get_next_entry
        if block_given?
          begin
            yield(zis)
          ensure
            zis.close
          end
        else
          zis
        end
      end
    end

    def gather_fileinfo_from_srcpath(src_path) # :nodoc:
      stat   = file_stat(src_path)
      @ftype = case stat.ftype
               when 'file'
                 if name_is_directory?
                   raise ArgumentError,
                         "entry name '#{newEntry}' indicates directory entry, but " \
                             "'#{src_path}' is not a directory"
                 end
                 :file
               when 'directory'
                 @name += '/' unless name_is_directory?
                 :directory
               when 'link'
                 if name_is_directory?
                   raise ArgumentError,
                         "entry name '#{newEntry}' indicates directory entry, but " \
                             "'#{src_path}' is not a directory"
                 end
                 :symlink
               else
                 raise "unknown file type: #{src_path.inspect} #{stat.inspect}"
               end

      @filepath = src_path
      get_extra_attributes_from_path(@filepath)
    end

    def write_to_zip_output_stream(zip_output_stream) #:nodoc:all
      if @ftype == :directory
        zip_output_stream.put_next_entry(self, nil, nil, ::Zip::Entry::STORED)
      elsif @filepath
        zip_output_stream.put_next_entry(self, nil, nil, compression_method || ::Zip::Entry::DEFLATED)
        get_input_stream { |is| ::Zip::IOExtras.copy_stream(zip_output_stream, is) }
      else
        zip_output_stream.copy_raw_entry(self)
      end
    end

    def parent_as_string
      entry_name  = name.chomp('/')
      slash_index = entry_name.rindex('/')
      slash_index ? entry_name.slice(0, slash_index + 1) : nil
    end

    def get_raw_input_stream(&block)
      if @zipfile.respond_to?(:seek) && @zipfile.respond_to?(:read)
        yield @zipfile
      else
        ::File.open(@zipfile, 'rb', &block)
      end
    end

    def clean_up
      # By default, do nothing
    end

    private

    def set_time(binary_dos_date, binary_dos_time)
      @time = ::Zip::DOSTime.parse_binary_dos_format(binary_dos_date, binary_dos_time)
    rescue ArgumentError
      warn 'Invalid date/time in zip entry' if ::Zip.warn_invalid_date
    end

    def create_file(dest_path, _continue_on_exists_proc = proc { Zip.continue_on_exists_proc })
      if ::File.exist?(dest_path) && !yield(self, dest_path)
        raise ::Zip::DestinationFileExistsError,
              "Destination '#{dest_path}' already exists"
      end
      ::File.open(dest_path, 'wb') do |os|
        get_input_stream do |is|
          set_extra_attributes_on_path(dest_path)

          buf = ''
          while (buf = is.sysread(::Zip::Decompressor::CHUNK_SIZE, buf))
            os << buf
          end
        end
      end
    end

    def create_directory(dest_path)
      return if ::File.directory?(dest_path)
      if ::File.exist?(dest_path)
        if block_given? && yield(self, dest_path)
          ::FileUtils.rm_f dest_path
        else
          raise ::Zip::DestinationFileExistsError,
                "Cannot create directory '#{dest_path}'. " \
                    'A file already exists with that name'
        end
      end
      ::FileUtils.mkdir_p(dest_path)
      set_extra_attributes_on_path(dest_path)
    end

    # BUG: create_symlink() does not use &block
    def create_symlink(dest_path)
      # TODO: Symlinks pose security challenges. Symlink support temporarily
      # removed in view of https://github.com/rubyzip/rubyzip/issues/369 .
      puts "WARNING: skipped symlink #{dest_path}"
    end

    # apply missing data from the zip64 extra information field, if present
    # (required when file sizes exceed 2**32, but can be used for all files)
    def parse_zip64_extra(for_local_header) #:nodoc:all
      return if @extra['Zip64'].nil?
      if for_local_header
        @size, @compressed_size = @extra['Zip64'].parse(@size, @compressed_size)
      else
        @size, @compressed_size, @local_header_offset = @extra['Zip64'].parse(@size, @compressed_size, @local_header_offset)
      end
    end

    def data_descriptor_size
      (@gp_flags & 0x0008) > 0 ? 16 : 0
    end

    # create a zip64 extra information field if we need one
    def prep_zip64_extra(for_local_header) #:nodoc:all
      return unless ::Zip.write_zip64_support
      need_zip64 = @size >= 0xFFFFFFFF || @compressed_size >= 0xFFFFFFFF
      need_zip64 ||= @local_header_offset >= 0xFFFFFFFF unless for_local_header
      if need_zip64
        @version_needed_to_extract = VERSION_NEEDED_TO_EXTRACT_ZIP64
        @extra.delete('Zip64Placeholder')
        zip64 = @extra.create('Zip64')
        if for_local_header
          # local header always includes size and compressed size
          zip64.original_size = @size
          zip64.compressed_size = @compressed_size
        else
          # central directory entry entries include whichever fields are necessary
          zip64.original_size = @size if @size >= 0xFFFFFFFF
          zip64.compressed_size = @compressed_size if @compressed_size >= 0xFFFFFFFF
          zip64.relative_header_offset = @local_header_offset if @local_header_offset >= 0xFFFFFFFF
        end
      else
        @extra.delete('Zip64')

        # if this is a local header entry, create a placeholder
        # so we have room to write a zip64 extra field afterward
        # (we won't know if it's needed until the file data is written)
        if for_local_header
          @extra.create('Zip64Placeholder')
        else
          @extra.delete('Zip64Placeholder')
        end
      end
    end
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
