# encoding: ASCII-8BIT
require 'delegate'
require 'singleton'
require 'tempfile'
require 'fileutils'
require 'stringio'
require 'zlib'
require 'zip/stdrubyext'
require 'zip/ioextras'

if Tempfile.superclass == SimpleDelegator
  require 'zip/tempfile_bugfixed'
  Tempfile = BugFix::Tempfile
end

module Zlib  #:nodoc:all
  if ! const_defined? :MAX_WBITS
    MAX_WBITS = Zlib::Deflate.MAX_WBITS
  end
end

module Zip

  VERSION = '0.9.4'

  RUBY_MINOR_VERSION = RUBY_VERSION.split(".")[1].to_i

  RUNNING_ON_WINDOWS = /mswin32|cygwin|mingw|bccwin/ =~ RUBY_PLATFORM

  # Ruby 1.7.x compatibility
  # In ruby 1.6.x and 1.8.0 reading from an empty stream returns 
  # an empty string the first time and then nil.
  #  not so in 1.7.x
  EMPTY_FILE_RETURNS_EMPTY_STRING_FIRST = RUBY_MINOR_VERSION != 7

  # ZipInputStream is the basic class for reading zip entries in a 
  # zip file. It is possible to create a ZipInputStream object directly, 
  # passing the zip file name to the constructor, but more often than not 
  # the ZipInputStream will be obtained from a ZipFile (perhaps using the 
  # ZipFileSystem interface) object for a particular entry in the zip 
  # archive.
  #
  # A ZipInputStream inherits IOExtras::AbstractInputStream in order
  # to provide an IO-like interface for reading from a single zip 
  # entry. Beyond methods for mimicking an IO-object it contains 
  # the method get_next_entry for iterating through the entries of 
  # an archive. get_next_entry returns a ZipEntry object that describes
  # the zip entry the ZipInputStream is currently reading from.
  #
  # Example that creates a zip archive with ZipOutputStream and reads it 
  # back again with a ZipInputStream.
  #
  #   require 'zip/zip'
  #   
  #   Zip::ZipOutputStream::open("my.zip") { 
  #     |io|
  #   
  #     io.put_next_entry("first_entry.txt")
  #     io.write "Hello world!"
  #   
  #     io.put_next_entry("adir/first_entry.txt")
  #     io.write "Hello again!"
  #   }
  #
  #   
  #   Zip::ZipInputStream::open("my.zip") {
  #     |io|
  #   
  #     while (entry = io.get_next_entry)
  #       puts "Contents of #{entry.name}: '#{io.read}'"
  #     end
  #   }
  #
  # java.util.zip.ZipInputStream is the original inspiration for this 
  # class.

  class ZipInputStream 
    include IOExtras::AbstractInputStream

    # Opens the indicated zip file. An exception is thrown
    # if the specified offset in the specified filename is
    # not a local zip entry header.
    def initialize(filename, offset = 0)
      super()
      @archiveIO = File.open(filename, "rb")
      @archiveIO.seek(offset, IO::SEEK_SET)
      @decompressor = NullDecompressor.instance
      @currentEntry = nil
    end
    
    def close
      @archiveIO.close
    end

    # Same as #initialize but if a block is passed the opened
    # stream is passed to the block and closed when the block
    # returns.    
    def ZipInputStream.open(filename)
      return new(filename) unless block_given?
      
      zio = new(filename)
      yield zio
    ensure
      zio.close if zio
    end

    # Returns a ZipEntry object. It is necessary to call this
    # method on a newly created ZipInputStream before reading from 
    # the first entry in the archive. Returns nil when there are 
    # no more entries.

    def get_next_entry
      @archiveIO.seek(@currentEntry.next_header_offset, 
                      IO::SEEK_SET) if @currentEntry
      open_entry
    end

    # Rewinds the stream to the beginning of the current entry
    def rewind
      return if @currentEntry.nil?
      @lineno = 0
      @archiveIO.seek(@currentEntry.localHeaderOffset, 
          IO::SEEK_SET)
      open_entry
    end

    # Modeled after IO.sysread
    def sysread(numberOfBytes = nil, buf = nil)
      @decompressor.sysread(numberOfBytes, buf)
    end

    def eof
      @outputBuffer.empty? && @decompressor.eof
    end
    alias :eof? :eof

    protected

    def open_entry
      @currentEntry = ZipEntry.read_local_entry(@archiveIO)
      if (@currentEntry == nil) 
        @decompressor = NullDecompressor.instance
      elsif @currentEntry.compression_method == ZipEntry::STORED
        @decompressor = PassThruDecompressor.new(@archiveIO, @currentEntry.size)
      elsif @currentEntry.compression_method == ZipEntry::DEFLATED
        @decompressor = Inflater.new(@archiveIO)
      else
        raise ZipCompressionMethodError, "Unsupported compression method #{@currentEntry.compression_method}"
      end
      flush
      return @currentEntry
    end

    def produce_input
      @decompressor.produce_input
    end

    def input_finished?
      @decompressor.input_finished?
    end
  end
  
  
  
  class Decompressor  #:nodoc:all
    CHUNK_SIZE=32768
    def initialize(inputStream)
      super()
      @inputStream=inputStream
    end
  end
  
  class Inflater < Decompressor  #:nodoc:all
    def initialize(inputStream)
      super
      @zlibInflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)
      @outputBuffer=""
      @hasReturnedEmptyString = ! EMPTY_FILE_RETURNS_EMPTY_STRING_FIRST
    end
    
    def sysread(numberOfBytes = nil, buf = nil)
      readEverything = (numberOfBytes == nil)
      while (readEverything || @outputBuffer.length < numberOfBytes)
        break if internal_input_finished?
        @outputBuffer << internal_produce_input(buf)
      end
      return value_when_finished if @outputBuffer.length==0 && input_finished?
      endIndex= numberOfBytes==nil ? @outputBuffer.length : numberOfBytes
      return @outputBuffer.slice!(0...endIndex)
    end
    
    def produce_input
      if (@outputBuffer.empty?)
        return internal_produce_input
      else
        return @outputBuffer.slice!(0...(@outputBuffer.length))
      end
    end

    # to be used with produce_input, not read (as read may still have more data cached)
    # is data cached anywhere other than @outputBuffer?  the comment above may be wrong
    def input_finished?
      @outputBuffer.empty? && internal_input_finished?
    end
    alias :eof :input_finished?
    alias :eof? :input_finished?

    private

    def internal_produce_input(buf = nil)
      retried = 0
      begin
        @zlibInflater.inflate(@inputStream.read(Decompressor::CHUNK_SIZE, buf))
      rescue Zlib::BufError
        raise if (retried >= 5) # how many times should we retry?
        retried += 1
        retry
      end
    end

    def internal_input_finished?
      @zlibInflater.finished?
    end

    # TODO: Specialize to handle different behaviour in ruby > 1.7.0 ?
    def value_when_finished   # mimic behaviour of ruby File object.
      return nil if @hasReturnedEmptyString
      @hasReturnedEmptyString=true
      return ""
    end
  end
  
  class PassThruDecompressor < Decompressor  #:nodoc:all
    def initialize(inputStream, charsToRead)
      super inputStream
      @charsToRead = charsToRead
      @readSoFar = 0
      @hasReturnedEmptyString = ! EMPTY_FILE_RETURNS_EMPTY_STRING_FIRST
    end
    
    # TODO: Specialize to handle different behaviour in ruby > 1.7.0 ?
    def sysread(numberOfBytes = nil, buf = nil)
      if input_finished?
        hasReturnedEmptyStringVal=@hasReturnedEmptyString
        @hasReturnedEmptyString=true
        return "" unless hasReturnedEmptyStringVal
        return nil
      end
      
      if (numberOfBytes == nil || @readSoFar+numberOfBytes > @charsToRead)
        numberOfBytes = @charsToRead-@readSoFar
      end
      @readSoFar += numberOfBytes
      @inputStream.read(numberOfBytes, buf)
    end
    
    def produce_input
      sysread(Decompressor::CHUNK_SIZE)
    end
    
    def input_finished?
      (@readSoFar >= @charsToRead)
    end
    alias :eof :input_finished?
    alias :eof? :input_finished?
  end
  
  class NullDecompressor  #:nodoc:all
    include Singleton
    def sysread(numberOfBytes = nil, buf = nil)
      nil
    end
    
    def produce_input
      nil
    end
    
    def input_finished?
      true
    end

    def eof
      true
    end
    alias :eof? :eof
  end
  
  class NullInputStream < NullDecompressor  #:nodoc:all
    include IOExtras::AbstractInputStream
  end
  
  class ZipEntry
    STORED = 0
    DEFLATED = 8

    FSTYPE_FAT = 0
    FSTYPE_AMIGA = 1
    FSTYPE_VMS = 2
    FSTYPE_UNIX = 3
    FSTYPE_VM_CMS = 4
    FSTYPE_ATARI = 5
    FSTYPE_HPFS = 6
    FSTYPE_MAC = 7
    FSTYPE_Z_SYSTEM = 8 
    FSTYPE_CPM = 9
    FSTYPE_TOPS20 = 10
    FSTYPE_NTFS = 11
    FSTYPE_QDOS = 12
    FSTYPE_ACORN = 13
    FSTYPE_VFAT = 14
    FSTYPE_MVS = 15
    FSTYPE_BEOS = 16
    FSTYPE_TANDEM = 17
    FSTYPE_THEOS = 18
    FSTYPE_MAC_OSX = 19
    FSTYPE_ATHEOS = 30

    FSTYPES = {
      FSTYPE_FAT => 'FAT'.freeze,
      FSTYPE_AMIGA => 'Amiga'.freeze,
      FSTYPE_VMS => 'VMS (Vax or Alpha AXP)'.freeze,
      FSTYPE_UNIX => 'Unix'.freeze,
      FSTYPE_VM_CMS => 'VM/CMS'.freeze,
      FSTYPE_ATARI => 'Atari ST'.freeze,
      FSTYPE_HPFS => 'OS/2 or NT HPFS'.freeze,
      FSTYPE_MAC => 'Macintosh'.freeze,
      FSTYPE_Z_SYSTEM => 'Z-System'.freeze,
      FSTYPE_CPM => 'CP/M'.freeze,
      FSTYPE_TOPS20 => 'TOPS-20'.freeze,
      FSTYPE_NTFS => 'NTFS'.freeze,
      FSTYPE_QDOS => 'SMS/QDOS'.freeze,
      FSTYPE_ACORN => 'Acorn RISC OS'.freeze,
      FSTYPE_VFAT => 'Win32 VFAT'.freeze,
      FSTYPE_MVS => 'MVS'.freeze,
      FSTYPE_BEOS => 'BeOS'.freeze,
      FSTYPE_TANDEM => 'Tandem NSK'.freeze,
      FSTYPE_THEOS => 'Theos'.freeze,
      FSTYPE_MAC_OSX => 'Mac OS/X (Darwin)'.freeze,
      FSTYPE_ATHEOS => 'AtheOS'.freeze,
    }.freeze
    
    attr_accessor  :comment, :compressed_size, :crc, :extra, :compression_method, 
      :name, :size, :localHeaderOffset, :zipfile, :fstype, :externalFileAttributes, :gp_flags, :header_signature

    attr_accessor :follow_symlinks
    attr_accessor :restore_times, :restore_permissions, :restore_ownership
    attr_accessor :unix_uid, :unix_gid, :unix_perms

    attr_reader :ftype, :filepath # :nodoc:
    
    # Returns the character encoding used for name and comment
    def name_encoding
      (@gp_flags & 0b100000000000) != 0 ? "utf8" : "CP437//"
    end


    # Converts string encoding
    def encode_string(str, src, dst)
      str.encode(dst, { :invalid => :replace, :undef => :replace, :replace => '' })
    end

    # Returns the name in the encoding specified by enc
    def name_in(enc)
      encode_string(@name, name_encoding, enc)
    end

    # Returns the comment in the encoding specified by enc
    def comment_in(enc)
      encode_string(@comment, name_encoding, enc)
    end

    def initialize(zipfile = "", name = "", comment = "", extra = "", 
                   compressed_size = 0, crc = 0, 
       compression_method = ZipEntry::DEFLATED, size = 0,
       time  = Time.now)
      super()
      if name.starts_with("/")
        raise ZipEntryNameError, "Illegal ZipEntry name '#{name}', name must not start with /" 
      end
      @localHeaderOffset = 0
      @local_header_size = 0
      @internalFileAttributes = 1
      @externalFileAttributes = 0
      @version = 52 # this library's version
      @ftype = nil # unspecified or unknown
      @filepath = nil
      if Zip::RUNNING_ON_WINDOWS
        @fstype = FSTYPE_FAT
      else
        @fstype = FSTYPE_UNIX
      end
      @zipfile = zipfile
      @comment = comment
      @compressed_size = compressed_size
      @crc = crc
      @extra = extra
      @compression_method = compression_method
      @name = name
      @size = size
      @time = time

      @follow_symlinks = false

      @restore_times = true
      @restore_permissions = false
      @restore_ownership = false

# BUG: need an extra field to support uid/gid's
      @unix_uid = nil
      @unix_gid = nil
      @unix_perms = nil
#      @posix_acl = nil
#      @ntfs_acl = nil

      if name_is_directory?
        @ftype = :directory
      else
        @ftype = :file
      end

      unless ZipExtraField === @extra
        @extra = ZipExtraField.new(@extra.to_s)
      end
    end

    def time
      if @extra["UniversalTime"]
        @extra["UniversalTime"].mtime
      else
        # Atandard time field in central directory has local time
        # under archive creator. Then, we can't get timezone.
        @time
      end
    end
    alias :mtime :time
    
    def time=(aTime)
      unless @extra.member?("UniversalTime")
        @extra.create("UniversalTime")
      end
      @extra["UniversalTime"].mtime = aTime
      @time = aTime
    end

    # Returns +true+ if the entry is a directory.
    def directory?
      raise ZipInternalError, "current filetype is unknown: #{self.inspect}" unless @ftype
      @ftype == :directory
    end
    alias :is_directory :directory?

    # Returns +true+ if the entry is a file.
    def file?
      raise ZipInternalError, "current filetype is unknown: #{self.inspect}" unless @ftype
      @ftype == :file
    end

    # Returns +true+ if the entry is a symlink.
    def symlink?
      raise ZipInternalError, "current filetype is unknown: #{self.inspect}" unless @ftype
      @ftype == :symlink
    end

    def name_is_directory?  #:nodoc:all
      (%r{\/$} =~ @name) != nil
    end

    def local_entry_offset  #:nodoc:all
      localHeaderOffset + @local_header_size
    end
    
    def calculate_local_header_size  #:nodoc:all
      LOCAL_ENTRY_STATIC_HEADER_LENGTH + (@name ?  @name.size : 0) + (@extra ? @extra.local_size : 0)
    end

    def cdir_header_size  #:nodoc:all
      CDIR_ENTRY_STATIC_HEADER_LENGTH  + (@name ?  @name.size : 0) + 
  (@extra ? @extra.c_dir_size : 0) + (@comment ? @comment.size : 0)
    end
    
    def next_header_offset  #:nodoc:all
      local_entry_offset + self.compressed_size
    end

    # Extracts entry to file destPath (defaults to @name).
    def extract(destPath = @name, &onExistsProc)
      onExistsProc ||= proc { false }

      if directory?
        create_directory(destPath, &onExistsProc)
      elsif file?
        write_file(destPath, &onExistsProc) 
      elsif symlink?
        create_symlink(destPath, &onExistsProc)
      else
        raise RuntimeError, "unknown file type #{self.inspect}"
      end

      self
    end

    def to_s
      @name
    end
    
    protected
    
    def ZipEntry.read_zip_short(io) # :nodoc:
      io.read(2).unpack('v')[0]
    end
    
    def ZipEntry.read_zip_long(io) # :nodoc:
      io.read(4).unpack('V')[0]
    end
    public
    
    LOCAL_ENTRY_SIGNATURE = 0x04034b50
    LOCAL_ENTRY_STATIC_HEADER_LENGTH = 30
    LOCAL_ENTRY_TRAILING_DESCRIPTOR_LENGTH = 4+4+4
    VERSION_NEEDED_TO_EXTRACT = 10

    def read_local_entry(io)  #:nodoc:all
      @localHeaderOffset = io.tell
      staticSizedFieldsBuf = io.read(LOCAL_ENTRY_STATIC_HEADER_LENGTH)
      unless (staticSizedFieldsBuf.size==LOCAL_ENTRY_STATIC_HEADER_LENGTH)
        raise ZipError, "Premature end of file. Not enough data for zip entry local header"
      end
      
      @header_signature       ,
      @version          ,
      @fstype           ,
      @gp_flags          ,
      @compression_method,
      lastModTime       ,
      lastModDate       ,
      @crc              ,
      @compressed_size   ,
      @size             ,
      nameLength        ,
      extraLength       = staticSizedFieldsBuf.unpack('VCCvvvvVVVvv') 

      unless (@header_signature == LOCAL_ENTRY_SIGNATURE)
        raise ZipError, "Zip local header magic not found at location '#{localHeaderOffset}'"
      end
      set_time(lastModDate, lastModTime)

      
      @name              = io.read(nameLength)
      extra              = io.read(extraLength)

      if (extra && extra.length != extraLength)
        raise ZipError, "Truncated local zip entry header"
      else
        if ZipExtraField === @extra
          @extra.merge(extra)
        else
          @extra = ZipExtraField.new(extra)
        end
      end
      @local_header_size = calculate_local_header_size
    end
    
    def ZipEntry.read_local_entry(io)
      entry = new(io.path)
      entry.read_local_entry(io)
      return entry
    rescue ZipError
      return nil
    end
  
    def write_local_entry(io)   #:nodoc:all
      @localHeaderOffset = io.tell
      
      io << 
        [LOCAL_ENTRY_SIGNATURE    ,
        VERSION_NEEDED_TO_EXTRACT , # version needed to extract
        0                         , # @gp_flags                  ,
        @compression_method        ,
        @time.to_binary_dos_time     , # @lastModTime              ,
        @time.to_binary_dos_date     , # @lastModDate              ,
        @crc                      ,
        @compressed_size           ,
        @size                     ,
        @name ? @name.length   : 0,
        @extra? @extra.local_length : 0 ].pack('VvvvvvVVVvv')
      io << @name
      io << (@extra ? @extra.to_local_bin : "")
    end
    
    CENTRAL_DIRECTORY_ENTRY_SIGNATURE = 0x02014b50
    CDIR_ENTRY_STATIC_HEADER_LENGTH = 46
    
    def read_c_dir_entry(io)  #:nodoc:all
      staticSizedFieldsBuf = io.read(CDIR_ENTRY_STATIC_HEADER_LENGTH)
      unless (staticSizedFieldsBuf.size == CDIR_ENTRY_STATIC_HEADER_LENGTH)
        raise ZipError, "Premature end of file. Not enough data for zip cdir entry header"
      end

      @header_signature          ,
      @version               , # version of encoding software
      @fstype                , # filesystem type
      @versionNeededToExtract,
      @gp_flags               ,
      @compression_method     ,
      lastModTime            ,
      lastModDate            ,
      @crc                   ,
      @compressed_size        ,
      @size                  ,
      nameLength             ,
      extraLength            ,
      commentLength          ,
      diskNumberStart        ,
      @internalFileAttributes,
      @externalFileAttributes,
      @localHeaderOffset     ,
      @name                  ,
      @extra                 ,
      @comment               = staticSizedFieldsBuf.unpack('VCCvvvvvVVVvvvvvVV')

      unless (@header_signature == CENTRAL_DIRECTORY_ENTRY_SIGNATURE)
        raise ZipError, "Zip local header magic not found at location '#{localHeaderOffset}'"
      end
      set_time(lastModDate, lastModTime)
      
      @name                  = io.read(nameLength)
      if ZipExtraField === @extra
        @extra.merge(io.read(extraLength))
      else
        @extra = ZipExtraField.new(io.read(extraLength))
      end
      @comment               = io.read(commentLength)
      unless (@comment && @comment.length == commentLength)
        raise ZipError, "Truncated cdir zip entry header"
      end

      case @fstype
      when FSTYPE_UNIX
        @unix_perms = (@externalFileAttributes >> 16) & 07777

        case (@externalFileAttributes >> 28)
        when 04
          @ftype = :directory
        when 010
          @ftype = :file
        when 012
          @ftype = :symlink
        else
          raise ZipInternalError, "unknown file type #{'0%o' % (@externalFileAttributes >> 28)}"
        end
      else
        if name_is_directory?
          @ftype = :directory
        else
          @ftype = :file
        end
      end
      @local_header_size = calculate_local_header_size
    end
    
    def ZipEntry.read_c_dir_entry(io)  #:nodoc:all
      entry = new(io.path)
      entry.read_c_dir_entry(io)
      return entry
    rescue ZipError
      return nil
    end

    def file_stat(path)	# :nodoc:
      if @follow_symlinks
        return File::stat(path)
      else
        return File::lstat(path)
      end
    end

    def get_extra_attributes_from_path(path)	# :nodoc:
      unless Zip::RUNNING_ON_WINDOWS
        stat = file_stat(path)
        @unix_uid = stat.uid
        @unix_gid = stat.gid
        @unix_perms = stat.mode & 07777
      end
    end

    def set_extra_attributes_on_path(destPath)	# :nodoc:
      return unless (file? or directory?)

      case @fstype
      when FSTYPE_UNIX
        # BUG: does not update timestamps into account
        # ignore setuid/setgid bits by default.  honor if @restore_ownership
        unix_perms_mask = 01777
        unix_perms_mask = 07777 if (@restore_ownership)
        FileUtils::chmod(@unix_perms & unix_perms_mask, destPath) if (@restore_permissions && @unix_perms)
        FileUtils::chown(@unix_uid, @unix_gid, destPath) if (@restore_ownership && @unix_uid && @unix_gid && Process::egid == 0)
        # File::utimes()
      end
    end

    def write_c_dir_entry(io)  #:nodoc:all
      case @fstype
      when FSTYPE_UNIX
        ft = nil
        case @ftype
        when :file
          ft = 010
          @unix_perms ||= 0644
        when :directory
          ft = 004
          @unix_perms ||= 0755
        when :symlink
          ft = 012
          @unix_perms ||= 0755
        else
          raise ZipInternalError, "unknown file type #{self.inspect}"
        end

        @externalFileAttributes = (ft << 12 | (@unix_perms & 07777)) << 16
      end

      io << 
  [CENTRAL_DIRECTORY_ENTRY_SIGNATURE,
        @version                          , # version of encoding software
  @fstype                           , # filesystem type
  VERSION_NEEDED_TO_EXTRACT         , # @versionNeededToExtract           ,
  0                                 , # @gp_flags                          ,
  @compression_method                ,
        @time.to_binary_dos_time             , # @lastModTime                      ,
  @time.to_binary_dos_date             , # @lastModDate                      ,
  @crc                              ,
  @compressed_size                   ,
  @size                             ,
  @name  ?  @name.length  : 0       ,
  @extra ? @extra.c_dir_length : 0  ,
  @comment ? comment.length : 0     ,
  0                                 , # disk number start
  @internalFileAttributes           , # file type (binary=0, text=1)
  @externalFileAttributes           , # native filesystem attributes
  @localHeaderOffset                ,
  @name                             ,
  @extra                            ,
  @comment                          ].pack('VCCvvvvvVVVvvvvvVV')

      io << @name
      io << (@extra ? @extra.to_c_dir_bin : "")
      io << @comment
    end
    
    def == (other)
      return false unless other.class == self.class
      # Compares contents of local entry and exposed fields
      (@compression_method == other.compression_method &&
       @crc               == other.crc		     &&
       @compressed_size   == other.compressed_size   &&
       @size              == other.size	             &&
       @name              == other.name	             &&
       @extra             == other.extra             &&
       @filepath          == other.filepath          &&
       self.time.dos_equals(other.time))
    end

    def <=> (other)
      return to_s <=> other.to_s
    end

    # Returns an IO like object for the given ZipEntry.
    # Warning: may behave weird with symlinks.
    def get_input_stream(&aProc)
      if @ftype == :directory
          return yield(NullInputStream.instance) if block_given?
          return NullInputStream.instance
      elsif @filepath
        case @ftype
        when :file
          return File.open(@filepath, "rb", &aProc)

        when :symlink
          linkpath = File::readlink(@filepath)
          stringio = StringIO.new(linkpath)
          return yield(stringio) if block_given?
          return stringio
        else
          raise "unknown @ftype #{@ftype}"
        end
      else
        zis = ZipInputStream.new(@zipfile, localHeaderOffset)
        zis.get_next_entry
        if block_given?
          begin
      return yield(zis)
    ensure
      zis.close
    end
        else
    return zis
        end
      end
    end

    def gather_fileinfo_from_srcpath(srcPath) # :nodoc:
      stat = file_stat(srcPath)
      case stat.ftype
      when 'file'
        if name_is_directory?
          raise ArgumentError,
      "entry name '#{newEntry}' indicates directory entry, but "+
      "'#{srcPath}' is not a directory"
        end
        @ftype = :file
      when 'directory'
        if ! name_is_directory?
          @name += "/"
        end
        @ftype = :directory
      when 'link'
        if name_is_directory?
          raise ArgumentError,
      "entry name '#{newEntry}' indicates directory entry, but "+
      "'#{srcPath}' is not a directory"
        end
        @ftype = :symlink
      else
      	raise RuntimeError, "unknown file type: #{srcPath.inspect} #{stat.inspect}"
      end

      @filepath = srcPath
      get_extra_attributes_from_path(@filepath)
    end

    def write_to_zip_output_stream(aZipOutputStream)  #:nodoc:all
      if @ftype == :directory
        aZipOutputStream.put_next_entry(self)
      elsif @filepath
        aZipOutputStream.put_next_entry(self)
        get_input_stream { |is| IOExtras.copy_stream(aZipOutputStream, is) } 
      else
        aZipOutputStream.copy_raw_entry(self)
      end
    end

    def parent_as_string
      entry_name = name.chomp("/")
      slash_index = entry_name.rindex("/")
      slash_index ? entry_name.slice(0, slash_index+1) : nil
    end

    def get_raw_input_stream(&aProc)
      File.open(@zipfile, "rb", &aProc)
    end

    private

    def set_time(binaryDosDate, binaryDosTime)
      @time = Time.parse_binary_dos_format(binaryDosDate, binaryDosTime)
    rescue ArgumentError
      puts "Invalid date/time in zip entry"
    end

    def write_file(destPath, continueOnExistsProc = proc { false })
      if File.exists?(destPath) && ! yield(self, destPath)
  raise ZipDestinationFileExistsError,
    "Destination '#{destPath}' already exists"
      end
      File.open(destPath, "wb") do |os|
        get_input_stream do |is|
          set_extra_attributes_on_path(destPath)

          buf = ''
          while buf = is.sysread(Decompressor::CHUNK_SIZE, buf)
            os << buf
          end
        end
      end
    end
    
    def create_directory(destPath)
      if File.directory? destPath
  return
      elsif File.exists? destPath
  if block_given? && yield(self, destPath)
    FileUtils::rm_f destPath
  else
    raise ZipDestinationFileExistsError,
      "Cannot create directory '#{destPath}'. "+
      "A file already exists with that name"
  end
      end
      Dir.mkdir destPath
      set_extra_attributes_on_path(destPath)
    end

# BUG: create_symlink() does not use &onExistsProc
    def create_symlink(destPath)
      stat = nil
      begin
        stat = File::lstat(destPath)
      rescue Errno::ENOENT
      end

      io = get_input_stream
      linkto = io.read

      if stat
        if stat.symlink?
          if File::readlink(destPath) == linkto
            return
          else
            raise ZipDestinationFileExistsError,
              "Cannot create symlink '#{destPath}'. "+
              "A symlink already exists with that name"
          end
        else
    raise ZipDestinationFileExistsError,
      "Cannot create symlink '#{destPath}'. "+
      "A file already exists with that name"
        end
      end

      File::symlink(linkto, destPath)
    end
  end


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

  class ZipOutputStream
    include IOExtras::AbstractOutputStream

    attr_accessor :comment

    # Opens the indicated zip file. If a file with that name already
    # exists it will be overwritten.
    def initialize(fileName)
      super()
      @fileName = fileName
      @outputStream = File.new(@fileName, "wb")
      @entrySet = ZipEntrySet.new
      @compressor = NullCompressor.instance
      @closed = false
      @currentEntry = nil
      @comment = nil
    end

    # Same as #initialize but if a block is passed the opened
    # stream is passed to the block and closed when the block
    # returns.    
    def ZipOutputStream.open(fileName)
      return new(fileName) unless block_given?
      zos = new(fileName)
      yield zos
    ensure
      zos.close if zos
    end

    # Closes the stream and writes the central directory to the zip file
    def close
      return if @closed
      finalize_current_entry
      update_local_headers
      write_central_directory
      @outputStream.close
      @closed = true
    end

    # Closes the current entry and opens a new for writing.
    # +entry+ can be a ZipEntry object or a string.
    def put_next_entry(entryname, comment = nil, extra = nil, compression_method = ZipEntry::DEFLATED,  level = Zlib::DEFAULT_COMPRESSION)
      raise ZipError, "zip stream is closed" if @closed
      new_entry = ZipEntry.new(@fileName, entryname.to_s)
      new_entry.comment = comment if !comment.nil?
      if (!extra.nil?)
        new_entry.extra = ZipExtraField === extra ? extra : ZipExtraField.new(extra.to_s)
      end
      new_entry.compression_method = compression_method
      init_next_entry(new_entry, level)
      @currentEntry = new_entry
    end

    def copy_raw_entry(entry)
      entry = entry.dup
      raise ZipError, "zip stream is closed" if @closed
      raise ZipError, "entry is not a ZipEntry" if !entry.kind_of?(ZipEntry)
      finalize_current_entry
      @entrySet << entry
      src_pos = entry.local_entry_offset
      entry.write_local_entry(@outputStream)
      @compressor = NullCompressor.instance
      entry.get_raw_input_stream { 
  |is| 
  is.seek(src_pos, IO::SEEK_SET)
        IOExtras.copy_stream_n(@outputStream, is, entry.compressed_size)
      }
      @compressor = NullCompressor.instance
      @currentEntry = nil
    end

    private
    def finalize_current_entry
      return unless @currentEntry
      finish
      @currentEntry.compressed_size = @outputStream.tell - @currentEntry.localHeaderOffset - 
  @currentEntry.calculate_local_header_size
      @currentEntry.size = @compressor.size
      @currentEntry.crc = @compressor.crc
      @currentEntry = nil
      @compressor = NullCompressor.instance
    end
    
    def init_next_entry(entry, level = Zlib::DEFAULT_COMPRESSION)
      finalize_current_entry
      @entrySet << entry
      entry.write_local_entry(@outputStream)
      @compressor = get_compressor(entry, level)
    end

    def get_compressor(entry, level)
      case entry.compression_method
  when ZipEntry::DEFLATED then Deflater.new(@outputStream, level)
  when ZipEntry::STORED   then PassThruCompressor.new(@outputStream)
      else raise ZipCompressionMethodError, 
    "Invalid compression method: '#{entry.compression_method}'"
      end
    end

    def update_local_headers
      pos = @outputStream.tell
      @entrySet.each {
  |entry|
  @outputStream.pos = entry.localHeaderOffset
  entry.write_local_entry(@outputStream)
      }
      @outputStream.pos = pos
    end

    def write_central_directory
      cdir = ZipCentralDirectory.new(@entrySet, @comment)
      cdir.write_to_stream(@outputStream)
    end

    protected

    def finish
      @compressor.finish
    end

    public
    # Modeled after IO.<<
    def << (data)
      @compressor << data
    end
  end
  
  
  class Compressor #:nodoc:all
    def finish
    end
  end
  
  class PassThruCompressor < Compressor #:nodoc:all
    def initialize(outputStream)
      super()
      @outputStream = outputStream
      @crc = Zlib::crc32
      @size = 0
    end
    
    def << (data)
      val = data.to_s
      @crc = Zlib::crc32(val, @crc)
      @size += val.size
      @outputStream << val
    end

    attr_reader :size, :crc
  end

  class NullCompressor < Compressor #:nodoc:all
    include Singleton

    def << (data)
      raise IOError, "closed stream"
    end

    attr_reader :size, :compressed_size
  end

  class Deflater < Compressor #:nodoc:all
    def initialize(outputStream, level = Zlib::DEFAULT_COMPRESSION)
      super()
      @outputStream = outputStream
      @zlibDeflater = Zlib::Deflate.new(level, -Zlib::MAX_WBITS)
      @size = 0
      @crc = Zlib::crc32
    end
    
    def << (data)
      val = data.to_s
      @crc = Zlib::crc32(val, @crc)
      @size += val.size
      @outputStream << @zlibDeflater.deflate(data)
    end

    def finish
      until @zlibDeflater.finished?
  @outputStream << @zlibDeflater.finish
      end
    end

    attr_reader :size, :crc
  end
  

  class ZipEntrySet #:nodoc:all
    include Enumerable
    
    def initialize(anEnumerable = [])
      super()
      @entrySet = {}
      anEnumerable.each { |o| push(o) }
    end

    def include?(entry)
      @entrySet.include?(entry.to_s)
    end

    def <<(entry)
      @entrySet[entry.to_s] = entry
    end
    alias :push :<<

    def size
      @entrySet.size
    end
    alias :length :size

    def delete(entry)
      @entrySet.delete(entry.to_s) ? entry : nil
    end

    def each(&aProc)
      @entrySet.values.each(&aProc)
    end

    def entries
      @entrySet.values
    end

    # deep clone
    def dup
      newZipEntrySet = ZipEntrySet.new(@entrySet.values.map { |e| e.dup })
    end

    def == (other)
      return false unless other.kind_of?(ZipEntrySet)
      return @entrySet == other.entrySet      
    end

    def parent(entry)
      @entrySet[entry.parent_as_string]
    end

    def glob(pattern, flags = File::FNM_PATHNAME|File::FNM_DOTMATCH)
      entries.select { 
  |entry| 
  File.fnmatch(pattern, entry.name.chomp('/'), flags) 
      } 
    end	

#TODO    attr_accessor :auto_create_directories
    protected
    attr_accessor :entrySet
  end


  class ZipCentralDirectory
    include Enumerable
    
    END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054b50
    MAX_END_OF_CENTRAL_DIRECTORY_STRUCTURE_SIZE = 65536 + 18
    STATIC_EOCD_SIZE = 22

    attr_reader :comment

    # Returns an Enumerable containing the entries.
    def entries
      @entrySet.entries
    end

    def initialize(entries = ZipEntrySet.new, comment = "")  #:nodoc:
      super()
      @entrySet = entries.kind_of?(ZipEntrySet) ? entries : ZipEntrySet.new(entries)
      @comment = comment
    end

    def write_to_stream(io)  #:nodoc:
      offset = io.tell
      @entrySet.each { |entry| entry.write_c_dir_entry(io) }
      write_e_o_c_d(io, offset)
    end

    def write_e_o_c_d(io, offset)  #:nodoc:
      io <<
  [END_OF_CENTRAL_DIRECTORY_SIGNATURE,
        0                                  , # @numberOfThisDisk
  0                                  , # @numberOfDiskWithStartOfCDir
  @entrySet? @entrySet.size : 0        ,
  @entrySet? @entrySet.size : 0        ,
  cdir_size                           ,
  offset                             ,
  @comment ? @comment.length : 0     ].pack('VvvvvVVv')
      io << @comment
    end
    private :write_e_o_c_d

    def cdir_size  #:nodoc:
      # does not include eocd
      @entrySet.inject(0) { |value, entry| entry.cdir_header_size + value }
    end
    private :cdir_size

    def read_e_o_c_d(io) #:nodoc:
      buf = get_e_o_c_d(io)
      @numberOfThisDisk                     = ZipEntry::read_zip_short(buf)
      @numberOfDiskWithStartOfCDir          = ZipEntry::read_zip_short(buf)
      @totalNumberOfEntriesInCDirOnThisDisk = ZipEntry::read_zip_short(buf)
      @size                                 = ZipEntry::read_zip_short(buf)
      @sizeInBytes                          = ZipEntry::read_zip_long(buf)
      @cdirOffset                           = ZipEntry::read_zip_long(buf)
      commentLength                         = ZipEntry::read_zip_short(buf)
      @comment                              = buf.read(commentLength)
      # remove trailing \n symbol
      buf.chomp!
      raise ZipError, "Zip consistency problem while reading eocd structure" unless buf.size == 0
    end
    
    def read_central_directory_entries(io)  #:nodoc:
      begin
  io.seek(@cdirOffset, IO::SEEK_SET)
      rescue Errno::EINVAL
  raise ZipError, "Zip consistency problem while reading central directory entry"
      end
      @entrySet = ZipEntrySet.new
      @size.times {
  @entrySet << ZipEntry.read_c_dir_entry(io)
      }
    end
    
    def read_from_stream(io)  #:nodoc:
      read_e_o_c_d(io)
      read_central_directory_entries(io)
    end
    
    def get_e_o_c_d(io)  #:nodoc:
      begin
  io.seek(-MAX_END_OF_CENTRAL_DIRECTORY_STRUCTURE_SIZE, IO::SEEK_END)
      rescue Errno::EINVAL
  io.seek(0, IO::SEEK_SET)
      rescue Errno::EFBIG # FreeBSD 4.9 raise Errno::EFBIG instead of Errno::EINVAL
  io.seek(0, IO::SEEK_SET)
      end
      
      # 'buf = io.read' substituted with lump of code to work around FreeBSD 4.5 issue
      retried = false
      buf = nil
      begin
        buf = io.read
      rescue Errno::EFBIG # FreeBSD 4.5 may raise Errno::EFBIG
        raise if (retried)
        retried = true
  
        io.seek(0, IO::SEEK_SET)
        retry
      end

      sigIndex = buf.rindex([END_OF_CENTRAL_DIRECTORY_SIGNATURE].pack('V'))
      raise ZipError, "Zip end of central directory signature not found" unless sigIndex
      buf=buf.slice!((sigIndex+4)...(buf.size))
      def buf.read(count)
  slice!(0, count)
      end
      return buf
    end

    # For iterating over the entries.
    def each(&proc)
      @entrySet.each(&proc)
    end

    # Returns the number of entries in the central directory (and 
    # consequently in the zip archive).
    def size
      @entrySet.size
    end

    def ZipCentralDirectory.read_from_stream(io)  #:nodoc:
      cdir  = new
      cdir.read_from_stream(io)
      return cdir
    rescue ZipError
      return nil
    end

    def == (other) #:nodoc:
      return false unless other.kind_of?(ZipCentralDirectory)
      @entrySet.entries.sort == other.entries.sort && comment == other.comment
    end
  end
  
  
  class ZipError < StandardError ; end

  class ZipEntryExistsError            < ZipError; end
  class ZipDestinationFileExistsError  < ZipError; end
  class ZipCompressionMethodError      < ZipError; end
  class ZipEntryNameError              < ZipError; end
  class ZipInternalError               < ZipError; end

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
  #   require 'zip/zip'
  #   
  #   Zip::ZipFile.open("my.zip", Zip::ZipFile::CREATE) {
  #    |zipfile|
  #     zipfile.get_output_stream("first.txt") { |f| f.puts "Hello from ZipFile" }
  #     zipfile.mkdir("a_dir")
  #   }
  #
  # The next example reopens <code>my.zip</code> writes the contents of
  # <code>first.txt</code> to standard out and deletes the entry from 
  # the archive.
  #
  #   require 'zip/zip'
  #   
  #   Zip::ZipFile.open("my.zip", Zip::ZipFile::CREATE) {
  #     |zipfile|
  #     puts zipfile.read("first.txt")
  #     zipfile.remove("first.txt")
  #   }
  #
  # ZipFileSystem offers an alternative API that emulates ruby's 
  # interface for accessing the filesystem, ie. the File and Dir classes.
  
  class ZipFile < ZipCentralDirectory

    CREATE = 1

    attr_reader :name

    # default -> false
    attr_accessor :restore_ownership
    # default -> false
    attr_accessor :restore_permissions
    # default -> true
    attr_accessor :restore_times

    # Opens a zip archive. Pass true as the second parameter to create
    # a new archive if it doesn't exist already.
    def initialize(fileName, create = nil)
      super()
      @name = fileName
      @comment = ""
      if (File.exists?(fileName))
  File.open(name, "rb") { |f| read_from_stream(f) }
      elsif (create)
  @entrySet = ZipEntrySet.new
      else
  raise ZipError, "File #{fileName} not found"
      end
      @create = create
      @storedEntries = @entrySet.dup

      @restore_ownership = false
      @restore_permissions = false
      @restore_times = true
    end

    # Same as #new. If a block is passed the ZipFile object is passed
    # to the block and is automatically closed afterwards just as with
    # ruby's builtin File.open method.
    def ZipFile.open(fileName, create = nil)
      zf = ZipFile.new(fileName, create)
      if block_given?
  begin
    yield zf
  ensure
    zf.close
  end
      else
  zf
      end
    end

    # Returns the zip files comment, if it has one
    attr_accessor :comment

    # Iterates over the contents of the ZipFile. This is more efficient
    # than using a ZipInputStream since this methods simply iterates
    # through the entries in the central directory structure in the archive
    # whereas ZipInputStream jumps through the entire archive accessing the
    # local entry headers (which contain the same information as the 
    # central directory).
    def ZipFile.foreach(aZipFileName, &block)
      ZipFile.open(aZipFileName) {
  |zipFile|
  zipFile.each(&block)
      }
    end
    
    # Returns an input stream to the specified entry. If a block is passed
    # the stream object is passed to the block and the stream is automatically
    # closed afterwards just as with ruby's builtin File.open method.
    def get_input_stream(entry, &aProc)
      get_entry(entry).get_input_stream(&aProc)
    end

    # Returns an output stream to the specified entry. If a block is passed
    # the stream object is passed to the block and the stream is automatically
    # closed afterwards just as with ruby's builtin File.open method.
    def get_output_stream(entry, &aProc)
      newEntry = entry.kind_of?(ZipEntry) ? entry : ZipEntry.new(@name, entry.to_s)
      if newEntry.directory?
  raise ArgumentError,
    "cannot open stream to directory entry - '#{newEntry}'"
      end
      zipStreamableEntry = ZipStreamableStream.new(newEntry)
      @entrySet << zipStreamableEntry
      zipStreamableEntry.get_output_stream(&aProc)      
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
    def add(entry, srcPath, &continueOnExistsProc)
      continueOnExistsProc ||= proc { false }
      check_entry_exists(entry, continueOnExistsProc, "add")
      newEntry = entry.kind_of?(ZipEntry) ? entry : ZipEntry.new(@name, entry.to_s)
      newEntry.gather_fileinfo_from_srcpath(srcPath)
      @entrySet << newEntry
    end
    
    # Removes the specified entry.
    def remove(entry)
      @entrySet.delete(get_entry(entry))
    end
    
    # Renames the specified entry.
    def rename(entry, newName, &continueOnExistsProc)
      foundEntry = get_entry(entry)
      check_entry_exists(newName, continueOnExistsProc, "rename")
      @entrySet.delete(foundEntry)
      foundEntry.name = newName
      @entrySet << foundEntry
    end

    # Replaces the specified entry with the contents of srcPath (from 
    # the file system).
    def replace(entry, srcPath)
      check_file(srcPath)
      add(remove(entry), srcPath)
    end

    # Extracts entry to file destPath.
    def extract(entry, destPath, &onExistsProc)
      onExistsProc ||= proc { false }
      foundEntry = get_entry(entry)
      foundEntry.extract(destPath, &onExistsProc)
    end

    # Commits changes that has been made since the previous commit to 
    # the zip archive.
    def commit
     return if ! commit_required?
      on_success_replace(name) {
  |tmpFile|
  ZipOutputStream.open(tmpFile) {
    |zos|

    @entrySet.each { |e| e.write_to_zip_output_stream(zos) }
    zos.comment = comment
  }
  true
      }
      initialize(name)
    end

    # Closes the zip file committing any changes that has been made.
    def close
      commit
    end

    # Returns true if any changes has been made to this archive since
    # the previous commit
    def commit_required?
      return @entrySet != @storedEntries || @create == ZipFile::CREATE
    end

    # Searches for entry with the specified name. Returns nil if 
    # no entry is found. See also get_entry
    def find_entry(entry)
      @entrySet.detect { 
  |e| 
  e.name.sub(/\/$/, "") == entry.to_s.sub(/\/$/, "")
      }
    end

    # Searches for an entry just as find_entry, but throws Errno::ENOENT
    # if no entry is found.
    def get_entry(entry)
      selectedEntry = find_entry(entry)
      unless selectedEntry
  raise Errno::ENOENT, entry
      end
      selectedEntry.restore_ownership = @restore_ownership
      selectedEntry.restore_permissions = @restore_permissions
      selectedEntry.restore_times = @restore_times

      return selectedEntry
    end

    # Creates a directory
    def mkdir(entryName, permissionInt = 0755)
      if find_entry(entryName)
        raise Errno::EEXIST, "File exists - #{entryName}"
      end
      @entrySet << ZipStreamableDirectory.new(@name, entryName.to_s.ensure_end("/"), nil, permissionInt)
    end

    private

    def is_directory(newEntry, srcPath)
      srcPathIsDirectory = File.directory?(srcPath)
      if newEntry.is_directory && ! srcPathIsDirectory
  raise ArgumentError,
    "entry name '#{newEntry}' indicates directory entry, but "+
    "'#{srcPath}' is not a directory"
      elsif ! newEntry.is_directory && srcPathIsDirectory
  newEntry.name += "/"
      end
      return newEntry.is_directory && srcPathIsDirectory
    end

    def check_entry_exists(entryName, continueOnExistsProc, procedureName)
      continueOnExistsProc ||= proc { false }
      if @entrySet.detect { |e| e.name == entryName }
  if continueOnExistsProc.call
    remove get_entry(entryName)
  else
    raise ZipEntryExistsError, 
      procedureName+" failed. Entry #{entryName} already exists"
  end
      end
    end

    def check_file(path)
      unless File.readable? path
  raise Errno::ENOENT, path
      end
    end
    
    def on_success_replace(aFilename)
      tmpfile = get_tempfile
      tmpFilename = tmpfile.path
      tmpfile.close
      if yield tmpFilename
  File.rename(tmpFilename, name)
      end
    end
    
    def get_tempfile
      tempFile = Tempfile.new(File.basename(name), File.dirname(name))
      tempFile.binmode
      tempFile
    end
    
  end

  class ZipStreamableDirectory < ZipEntry
    def initialize(zipfile, entry, srcPath = nil, permissionInt = nil)
      super(zipfile, entry)

      @ftype = :directory
      entry.get_extra_attributes_from_path(srcPath) if (srcPath)
      @unix_perms = permissionInt if (permissionInt)
    end
  end

  class ZipStreamableStream < DelegateClass(ZipEntry) #nodoc:all
    def initialize(entry)
      super(entry)
      @tempFile = Tempfile.new(File.basename(name), File.dirname(zipfile))
      @tempFile.binmode
    end

    def get_output_stream
      if block_given?
        begin
          yield(@tempFile)
        ensure
          @tempFile.close
        end
      else
        @tempFile
      end
    end

    def get_input_stream
      if ! @tempFile.closed?
        raise StandardError, "cannot open entry for reading while its open for writing - #{name}"
      end
      @tempFile.open # reopens tempfile from top
      @tempFile.binmode
      if block_given?
        begin
          yield(@tempFile)
        ensure
          @tempFile.close
        end
      else
        @tempFile
      end
    end
    
    def write_to_zip_output_stream(aZipOutputStream)
      aZipOutputStream.put_next_entry(self)
      get_input_stream { |is| IOExtras.copy_stream(aZipOutputStream, is) } 
    end
  end

  class ZipExtraField < Hash
    ID_MAP = {}

    # Meta class for extra fields
    class Generic
      def self.register_map
        if self.const_defined?(:HEADER_ID)
          ID_MAP[self.const_get(:HEADER_ID)] = self
        end
      end

      def self.name
        self.to_s.split("::")[-1]
      end

      # return field [size, content] or false
      def initial_parse(binstr)
        if ! binstr
          # If nil, start with empty.
          return false
        elsif binstr[0,2] != self.class.const_get(:HEADER_ID)
          $stderr.puts "Warning: weired extra feild header ID. skip parsing"
          return false
        end
        [binstr[2,2].unpack("v")[0], binstr[4..-1]]
      end

      def ==(other)
        self.class != other.class and return false
        each { |k, v|
          v != other[k] and return false
        }
        true
      end

      def to_local_bin
        s = pack_for_local
        self.class.const_get(:HEADER_ID) + [s.length].pack("v") + s
      end

      def to_c_dir_bin
        s = pack_for_c_dir
        self.class.const_get(:HEADER_ID) + [s.length].pack("v") + s
      end
    end

    # Info-ZIP Additional timestamp field
    class UniversalTime < Generic
      HEADER_ID = "UT"
      register_map

      def initialize(binstr = nil)
        @ctime = nil
        @mtime = nil
        @atime = nil
        @flag  = nil
        binstr and merge(binstr)
      end
      attr_accessor :atime, :ctime, :mtime, :flag

      def merge(binstr)
        binstr == "" and return
        size, content = initial_parse(binstr)
        size or return
        @flag, mtime, atime, ctime = content.unpack("CVVV")
        mtime and @mtime ||= Time.at(mtime)
        atime and @atime ||= Time.at(atime)
        ctime and @ctime ||= Time.at(ctime)
      end

      def ==(other)
        @mtime == other.mtime &&
        @atime == other.atime &&
        @ctime == other.ctime
      end

      def pack_for_local
        s = [@flag].pack("C")
        @flag & 1 != 0 and s << [@mtime.to_i].pack("V")
        @flag & 2 != 0 and s << [@atime.to_i].pack("V")
        @flag & 4 != 0 and s << [@ctime.to_i].pack("V")
        s
      end

      def pack_for_c_dir
        s = [@flag].pack("C")
        @flag & 1 == 1 and s << [@mtime.to_i].pack("V")
        s
      end
    end

    # Info-ZIP Extra for UNIX uid/gid
    class IUnix < Generic
      HEADER_ID = "Ux"
      register_map

      def initialize(binstr = nil)
        @uid = 0
        @gid = 0
        binstr and merge(binstr)
      end
      attr_accessor :uid, :gid

      def merge(binstr)
        binstr == "" and return
        size, content = initial_parse(binstr)
        # size: 0 for central direcotry. 4 for local header
        return if(! size || size == 0)
        uid, gid = content.unpack("vv")
        @uid ||= uid
        @gid ||= gid
      end

      def ==(other)
        @uid == other.uid &&
        @gid == other.gid
      end

      def pack_for_local
        [@uid, @gid].pack("vv")
      end

      def pack_for_c_dir
        ""
      end
    end

    ## start main of ZipExtraField < Hash
    def initialize(binstr = nil)
      binstr and merge(binstr)
    end

    def merge(binstr)
      binstr == "" and return
      i = 0 
      while i < binstr.length
        id = binstr[i,2]
        len = binstr[i+2,2].to_s.unpack("v")[0] 
        if id && ID_MAP.member?(id)
          field_name = ID_MAP[id].name
          if self.member?(field_name)
            self[field_name].mergea(binstr[i, len+4])
          else
            field_obj = ID_MAP[id].new(binstr[i, len+4])
            self[field_name] = field_obj
          end
        elsif id
          unless self["Unknown"]
            s = ""
            class << s
              alias_method :to_c_dir_bin, :to_s
              alias_method :to_local_bin, :to_s
            end
            self["Unknown"] = s
          end
          if ! len || len+4 > binstr[i..-1].length
            self["Unknown"] << binstr[i..-1]
            break;
          end
          self["Unknown"] << binstr[i, len+4]
        end
        i += len+4
      end
    end

    def create(name)
      field_class = nil
      ID_MAP.each { |id, klass|
        if klass.name == name
          field_class = klass
          break
        end
      }
      if ! field_class
  raise ZipError, "Unknown extra field '#{name}'"
      end
      self[name] = field_class.new()
    end

    def to_local_bin
      s = ""
      each { |k, v|
        s << v.to_local_bin
      }
      s
    end
    alias :to_s :to_local_bin

    def to_c_dir_bin
      s = ""
      each { |k, v|
        s << v.to_c_dir_bin
      }
      s
    end

    def c_dir_length
      to_c_dir_bin.length
    end
    def local_length
      to_local_bin.length
    end
    alias :c_dir_size :c_dir_length
    alias :local_size :local_length
    alias :length     :local_length
    alias :size       :local_length
  end # end ZipExtraField

end # Zip namespace module



# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
