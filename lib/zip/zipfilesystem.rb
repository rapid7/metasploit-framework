# encoding: ASCII-8BIT
require 'zip/zip'

module Zip

  # The ZipFileSystem API provides an API for accessing entries in 
  # a zip archive that is similar to ruby's builtin File and Dir 
  # classes.
  #
  # Requiring 'zip/zipfilesystem' includes this module in ZipFile
  # making the methods in this module available on ZipFile objects.
  #
  # Using this API the following example creates a new zip file 
  # <code>my.zip</code> containing a normal entry with the name
  # <code>first.txt</code>, a directory entry named <code>mydir</code>
  # and finally another normal entry named <code>second.txt</code>
  #
  #   require 'zip/zipfilesystem'
  #   
  #   Zip::ZipFile.open("my.zip", Zip::ZipFile::CREATE) {
  #     |zipfile|
  #     zipfile.file.open("first.txt", "w") { |f| f.puts "Hello world" }
  #     zipfile.dir.mkdir("mydir")
  #     zipfile.file.open("mydir/second.txt", "w") { |f| f.puts "Hello again" }
  #   }
  #
  # Reading is as easy as writing, as the following example shows. The 
  # example writes the contents of <code>first.txt</code> from zip archive
  # <code>my.zip</code> to standard out.
  #
  #   require 'zip/zipfilesystem'
  #   
  #   Zip::ZipFile.open("my.zip") {
  #     |zipfile|
  #     puts zipfile.file.read("first.txt")
  #   }

  module ZipFileSystem

    def initialize # :nodoc:
      mappedZip = ZipFileNameMapper.new(self)
      @zipFsDir  = ZipFsDir.new(mappedZip)
      @zipFsFile = ZipFsFile.new(mappedZip)
      @zipFsDir.file = @zipFsFile
      @zipFsFile.dir = @zipFsDir
    end

    # Returns a ZipFsDir which is much like ruby's builtin Dir (class)
    # object, except it works on the ZipFile on which this method is
    # invoked
    def dir
      @zipFsDir
    end
    
    # Returns a ZipFsFile which is much like ruby's builtin File (class)
    # object, except it works on the ZipFile on which this method is
    # invoked
    def file
      @zipFsFile
    end

    # Instances of this class are normally accessed via the accessor
    # ZipFile::file. An instance of ZipFsFile behaves like ruby's
    # builtin File (class) object, except it works on ZipFile entries.
    #
    # The individual methods are not documented due to their
    # similarity with the methods in File
    class ZipFsFile

      attr_writer :dir
#      protected :dir

      class ZipFsStat
        def initialize(zipFsFile, entryName)
          @zipFsFile = zipFsFile
          @entryName = entryName
        end
        
        def forward_invoke(msg)
          @zipFsFile.send(msg, @entryName)
        end

        def kind_of?(t)
          super || t == ::File::Stat 
        end
        
        forward_message :forward_invoke, :file?, :directory?, :pipe?, :chardev?
        forward_message :forward_invoke, :symlink?, :socket?, :blockdev?
        forward_message :forward_invoke, :readable?, :readable_real?
        forward_message :forward_invoke, :writable?, :writable_real?
        forward_message :forward_invoke, :executable?, :executable_real?
        forward_message :forward_invoke, :sticky?, :owned?, :grpowned?
        forward_message :forward_invoke, :setuid?, :setgid?
        forward_message :forward_invoke, :zero?
        forward_message :forward_invoke, :size, :size?
        forward_message :forward_invoke, :mtime, :atime, :ctime
        
        def blocks; nil; end

        def get_entry
          @zipFsFile.__send__(:get_entry, @entryName)
        end
        private :get_entry

        def gid
          e = get_entry
          if e.extra.member? "IUnix"
            e.extra["IUnix"].gid || 0
          else
            0
          end
        end

        def uid
          e = get_entry
          if e.extra.member? "IUnix"
            e.extra["IUnix"].uid || 0
          else
            0
          end
        end

        def ino; 0; end

        def dev; 0; end

        def rdev; 0; end

        def rdev_major; 0; end

        def rdev_minor; 0; end

        def ftype
          if file?
            return "file"
          elsif directory?
            return "directory"
          else
            raise StandardError, "Unknown file type"
          end
        end

        def nlink; 1; end
        
        def blksize; nil; end

        def mode
          e = get_entry
          if e.fstype == 3
            e.externalFileAttributes >> 16
          else
            33206 # 33206 is equivalent to -rw-rw-rw-
          end
        end
      end

      def initialize(mappedZip)
  @mappedZip = mappedZip
      end

      def get_entry(fileName)
        if ! exists?(fileName)
          raise Errno::ENOENT, "No such file or directory - #{fileName}"
        end
        @mappedZip.find_entry(fileName)
      end
      private :get_entry

      def unix_mode_cmp(fileName, mode)
        begin
          e = get_entry(fileName)
          e.fstype == 3 && ((e.externalFileAttributes >> 16) & mode ) != 0
        rescue Errno::ENOENT
          false
        end
      end
      private :unix_mode_cmp
      
      def exists?(fileName)
        expand_path(fileName) == "/" || @mappedZip.find_entry(fileName) != nil
      end
      alias :exist? :exists?
      
      # Permissions not implemented, so if the file exists it is accessible
      alias owned?           exists?
      alias grpowned?        exists?

      def readable?(fileName)
        unix_mode_cmp(fileName, 0444)
      end
      alias readable_real?   readable?

      def writable?(fileName)
        unix_mode_cmp(fileName, 0222)
      end
      alias writable_real?   writable?

      def executable?(fileName)
        unix_mode_cmp(fileName, 0111)
      end
      alias executable_real? executable?

      def setuid?(fileName)
        unix_mode_cmp(fileName, 04000)
      end

      def setgid?(fileName)
        unix_mode_cmp(fileName, 02000)
      end
      
      def sticky?(fileName)
        unix_mode_cmp(fileName, 01000)
      end

      def umask(*args)
        ::File.umask(*args)
      end

      def truncate(fileName, len)
        raise StandardError, "truncate not supported"
      end

      def directory?(fileName)
  entry = @mappedZip.find_entry(fileName)
  expand_path(fileName) == "/" || (entry != nil && entry.directory?)
      end
      
      def open(fileName, openMode = "r", &block)
        openMode.gsub!("b", "") # ignore b option
        case openMode
        when "r" 
          @mappedZip.get_input_stream(fileName, &block)
        when "w"
          @mappedZip.get_output_stream(fileName, &block)
        else
          raise StandardError, "openmode '#{openMode} not supported" unless openMode == "r"
        end
      end

      def new(fileName, openMode = "r")
  open(fileName, openMode)
      end
      
      def size(fileName)
  @mappedZip.get_entry(fileName).size
      end
      
      # Returns nil for not found and nil for directories
      def size?(fileName)
  entry = @mappedZip.find_entry(fileName)
  return (entry == nil || entry.directory?) ? nil : entry.size
      end
      
      def chown(ownerInt, groupInt, *filenames)
        filenames.each { |fileName|
          e = get_entry(fileName)
          unless e.extra.member?("IUnix")
            e.extra.create("IUnix")
          end
          e.extra["IUnix"].uid = ownerInt
          e.extra["IUnix"].gid = groupInt
        }
        filenames.size
      end

      def chmod (modeInt, *filenames)
        filenames.each { |fileName|
          e = get_entry(fileName)
          e.fstype = 3 # force convertion filesystem type to unix
          e.externalFileAttributes = modeInt << 16
        }
        filenames.size
      end

      def zero?(fileName)
  sz = size(fileName)
  sz == nil || sz == 0
      rescue Errno::ENOENT
  false
      end
      
      def file?(fileName)
  entry = @mappedZip.find_entry(fileName)
  entry != nil && entry.file?
      end      
      
      def dirname(fileName)
  ::File.dirname(fileName)
      end
      
      def basename(fileName)
  ::File.basename(fileName)
      end
      
      def split(fileName)
  ::File.split(fileName)
      end
      
      def join(*fragments)
  ::File.join(*fragments)
      end
      
      def utime(modifiedTime, *fileNames)
        fileNames.each { |fileName|
          get_entry(fileName).time = modifiedTime
        }
      end

      def mtime(fileName)
  @mappedZip.get_entry(fileName).mtime
      end
      
      def atime(fileName)
        e = get_entry(fileName)
        if e.extra.member? "UniversalTime"
          e.extra["UniversalTime"].atime
        else
          nil
        end
      end
      
      def ctime(fileName)
        e = get_entry(fileName)
        if e.extra.member? "UniversalTime"
          e.extra["UniversalTime"].ctime
        else
          nil
        end
      end

      def pipe?(filename)
  false
      end
      
      def blockdev?(filename)
  false
      end
      
      def chardev?(filename)
  false
      end
      
      def symlink?(fileName)
  false
      end
      
      def socket?(fileName)
  false
      end
      
      def ftype(fileName)
  @mappedZip.get_entry(fileName).directory? ? "directory" : "file"
      end
      
      def readlink(fileName)
  raise NotImplementedError, "The readlink() function is not implemented"
      end
      
      def symlink(fileName, symlinkName)
  raise NotImplementedError, "The symlink() function is not implemented"
      end

      def link(fileName, symlinkName)
  raise NotImplementedError, "The link() function is not implemented"
      end

      def pipe
  raise NotImplementedError, "The pipe() function is not implemented"
      end

      def stat(fileName)
        if ! exists?(fileName)
          raise Errno::ENOENT, fileName
        end
        ZipFsStat.new(self, fileName)
      end

      alias lstat stat

      def readlines(fileName)
  open(fileName) { |is| is.readlines }
      end

      def read(fileName)
        @mappedZip.read(fileName)
      end

      def popen(*args, &aProc)
  File.popen(*args, &aProc)
      end

      def foreach(fileName, aSep = $/, &aProc)
  open(fileName) { |is| is.each_line(aSep, &aProc) }
      end

      def delete(*args)
  args.each { 
    |fileName|
    if directory?(fileName)
      raise Errno::EISDIR, "Is a directory - \"#{fileName}\""
    end
    @mappedZip.remove(fileName) 
  }
      end

      def rename(fileToRename, newName)
        @mappedZip.rename(fileToRename, newName) { true }
      end

      alias :unlink :delete

      def expand_path(aPath)
        @mappedZip.expand_path(aPath)
      end
    end

    # Instances of this class are normally accessed via the accessor
    # ZipFile::dir. An instance of ZipFsDir behaves like ruby's
    # builtin Dir (class) object, except it works on ZipFile entries.
    #
    # The individual methods are not documented due to their
    # similarity with the methods in Dir
    class ZipFsDir
      
      def initialize(mappedZip)
        @mappedZip = mappedZip
      end
      
      attr_writer :file

      def new(aDirectoryName)
        ZipFsDirIterator.new(entries(aDirectoryName))
      end

      def open(aDirectoryName)
        dirIt = new(aDirectoryName)
        if block_given?
          begin
            yield(dirIt)
            return nil
          ensure
            dirIt.close
          end
        end
        dirIt
      end

      def pwd; @mappedZip.pwd; end
      alias getwd pwd
      
      def chdir(aDirectoryName)
        unless @file.stat(aDirectoryName).directory?
          raise Errno::EINVAL, "Invalid argument - #{aDirectoryName}"
        end
        @mappedZip.pwd = @file.expand_path(aDirectoryName)
      end
      
      def entries(aDirectoryName)
        entries = []
        foreach(aDirectoryName) { |e| entries << e }
        entries
      end

      def foreach(aDirectoryName)
        unless @file.stat(aDirectoryName).directory?
          raise Errno::ENOTDIR, aDirectoryName
        end
        path = @file.expand_path(aDirectoryName).ensure_end("/")

        subDirEntriesRegex = Regexp.new("^#{path}([^/]+)$")
        @mappedZip.each { 
          |fileName|
          match = subDirEntriesRegex.match(fileName)
          yield(match[1]) unless match == nil
        }
      end

      def delete(entryName)
        unless @file.stat(entryName).directory?
          raise Errno::EINVAL, "Invalid argument - #{entryName}"
        end
        @mappedZip.remove(entryName)
      end
      alias rmdir  delete
      alias unlink delete
      
      def mkdir(entryName, permissionInt = 0755)
        @mappedZip.mkdir(entryName, permissionInt)
      end
      
      def chroot(*args)
      	raise NotImplementedError, "The chroot() function is not implemented"
      end

    end

    class ZipFsDirIterator # :nodoc:all
      include Enumerable

      def initialize(arrayOfFileNames)
        @fileNames = arrayOfFileNames
        @index = 0
      end

      def close
        @fileNames = nil
      end

      def each(&aProc)
        raise IOError, "closed directory" if @fileNames == nil
        @fileNames.each(&aProc)
      end

      def read
        raise IOError, "closed directory" if @fileNames == nil
        @fileNames[(@index+=1)-1]
      end

      def rewind
        raise IOError, "closed directory" if @fileNames == nil
        @index = 0
      end

      def seek(anIntegerPosition)
        raise IOError, "closed directory" if @fileNames == nil
        @index = anIntegerPosition
      end

      def tell
        raise IOError, "closed directory" if @fileNames == nil
        @index
      end
    end

    # All access to ZipFile from ZipFsFile and ZipFsDir goes through a
    # ZipFileNameMapper, which has one responsibility: ensure
    class ZipFileNameMapper # :nodoc:all
      include Enumerable

      def initialize(zipFile)
        @zipFile = zipFile
        @pwd = "/"
      end
      
      attr_accessor :pwd
      
      def find_entry(fileName)
        @zipFile.find_entry(expand_to_entry(fileName))
      end
      
      def get_entry(fileName)
        @zipFile.get_entry(expand_to_entry(fileName))
      end

      def get_input_stream(fileName, &aProc)
        @zipFile.get_input_stream(expand_to_entry(fileName), &aProc)
      end
      
      def get_output_stream(fileName, &aProc)
        @zipFile.get_output_stream(expand_to_entry(fileName), &aProc)
      end

      def read(fileName)
        @zipFile.read(expand_to_entry(fileName))
      end
      
      def remove(fileName)
        @zipFile.remove(expand_to_entry(fileName))
      end

      def rename(fileName, newName, &continueOnExistsProc)
        @zipFile.rename(expand_to_entry(fileName), expand_to_entry(newName), 
                        &continueOnExistsProc)
      end

      def mkdir(fileName, permissionInt = 0755)
        @zipFile.mkdir(expand_to_entry(fileName), permissionInt)
      end

      # Turns entries into strings and adds leading /
      # and removes trailing slash on directories
      def each
        @zipFile.each {
          |e|
          yield("/"+e.to_s.chomp("/"))
        }
      end
      
      def expand_path(aPath)
        expanded = aPath.starts_with("/") ? aPath : @pwd.ensure_end("/") + aPath
        expanded.gsub!(/\/\.(\/|$)/, "")
        expanded.gsub!(/[^\/]+\/\.\.(\/|$)/, "")
        expanded.empty? ? "/" : expanded
      end

      private

      def expand_to_entry(aPath)
        expand_path(aPath).lchop
      end
    end
  end

  class ZipFile
    include ZipFileSystem
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
