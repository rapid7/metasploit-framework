# encoding: utf-8

require 'pathname'
require 'active_support/core_ext/string/multibyte'

module CarrierWave

  ##
  # SanitizedFile is a base class which provides a common API around all
  # the different quirky Ruby File libraries. It has support for Tempfile,
  # File, StringIO, Merb-style upload Hashes, as well as paths given as
  # Strings and Pathnames.
  #
  # It's probably needlessly comprehensive and complex. Help is appreciated.
  #
  class SanitizedFile

    attr_accessor :file

    class << self
      attr_writer :sanitize_regexp

      def sanitize_regexp
        @sanitize_regexp ||= /[^a-zA-Z0-9\.\-\+_]/
      end
    end

    def initialize(file)
      self.file = file
    end

    ##
    # Returns the filename as is, without sanizting it.
    #
    # === Returns
    #
    # [String] the unsanitized filename
    #
    def original_filename
      return @original_filename if @original_filename
      if @file and @file.respond_to?(:original_filename)
        @file.original_filename
      elsif path
        File.basename(path)
      end
    end

    ##
    # Returns the filename, sanitized to strip out any evil characters.
    #
    # === Returns
    #
    # [String] the sanitized filename
    #
    def filename
      sanitize(original_filename) if original_filename
    end

    alias_method :identifier, :filename

    ##
    # Returns the part of the filename before the extension. So if a file is called 'test.jpeg'
    # this would return 'test'
    #
    # === Returns
    #
    # [String] the first part of the filename
    #
    def basename
      split_extension(filename)[0] if filename
    end

    ##
    # Returns the file extension
    #
    # === Returns
    #
    # [String] the extension
    #
    def extension
      split_extension(filename)[1] if filename
    end

    ##
    # Returns the file's size.
    #
    # === Returns
    #
    # [Integer] the file's size in bytes.
    #
    def size
      if is_path?
        exists? ? File.size(path) : 0
      elsif @file.respond_to?(:size)
        @file.size
      elsif path
        exists? ? File.size(path) : 0
      else
        0
      end
    end

    ##
    # Returns the full path to the file. If the file has no path, it will return nil.
    #
    # === Returns
    #
    # [String, nil] the path where the file is located.
    #
    def path
      unless @file.blank?
        if is_path?
          File.expand_path(@file)
        elsif @file.respond_to?(:path) and not @file.path.blank?
          File.expand_path(@file.path)
        end
      end
    end

    ##
    # === Returns
    #
    # [Boolean] whether the file is supplied as a pathname or string.
    #
    def is_path?
      !!((@file.is_a?(String) || @file.is_a?(Pathname)) && !@file.blank?)
    end

    ##
    # === Returns
    #
    # [Boolean] whether the file is valid and has a non-zero size
    #
    def empty?
      @file.nil? || self.size.nil? || (self.size.zero? && ! self.exists?)
    end

    ##
    # === Returns
    #
    # [Boolean] Whether the file exists
    #
    def exists?
      return File.exists?(self.path) if self.path
      return false
    end

    ##
    # Returns the contents of the file.
    #
    # === Returns
    #
    # [String] contents of the file
    #
    def read
      if is_path?
        File.open(@file, "rb") {|file| file.read}
      else
        @file.rewind if @file.respond_to?(:rewind)
        @file.read
      end
    end

    ##
    # Moves the file to the given path
    #
    # === Parameters
    #
    # [new_path (String)] The path where the file should be moved.
    # [permissions (Integer)] permissions to set on the file in its new location.
    #
    def move_to(new_path, permissions=nil)
      return if self.empty?
      new_path = File.expand_path(new_path)

      mkdir!(new_path)
      if exists?
        FileUtils.mv(path, new_path) unless new_path == path
      else
        File.open(new_path, "wb") { |f| f.write(read) }
      end
      chmod!(new_path, permissions)
      self.file = new_path
      self
    end

    ##
    # Creates a copy of this file and moves it to the given path. Returns the copy.
    #
    # === Parameters
    #
    # [new_path (String)] The path where the file should be copied to.
    # [permissions (Integer)] permissions to set on the copy
    #
    # === Returns
    #
    # @return [CarrierWave::SanitizedFile] the location where the file will be stored.
    #
    def copy_to(new_path, permissions=nil)
      return if self.empty?
      new_path = File.expand_path(new_path)

      mkdir!(new_path)
      if exists?
        FileUtils.cp(path, new_path) unless new_path == path
      else
        File.open(new_path, "wb") { |f| f.write(read) }
      end
      chmod!(new_path, permissions)
      self.class.new({:tempfile => new_path, :content_type => content_type})
    end

    ##
    # Removes the file from the filesystem.
    #
    def delete
      FileUtils.rm(self.path) if exists?
    end

    ##
    # Returns a File object, or nil if it does not exist.
    #
    # === Returns
    #
    # [File] a File object representing the SanitizedFile
    #
    def to_file
      return @file if @file.is_a?(File)
      File.open(path) if exists?
    end

    ##
    # Returns the content type of the file.
    #
    # === Returns
    #
    # [String] the content type of the file
    #
    def content_type
      return @content_type if @content_type
      @file.content_type.to_s.chomp if @file.respond_to?(:content_type) and @file.content_type
    end

    ##
    # Sets the content type of the file.
    #
    # === Returns
    #
    # [String] the content type of the file
    #
    def content_type=(type)
      @content_type = type
    end

    ##
    # Used to sanitize the file name. Public to allow overriding for non-latin characters.
    #
    # === Returns
    #
    # [Regexp] the regexp for sanitizing the file name
    #
    def sanitize_regexp
      CarrierWave::SanitizedFile.sanitize_regexp
    end

  private

    def file=(file)
      if file.is_a?(Hash)
        @file = file["tempfile"] || file[:tempfile]
        @original_filename = file["filename"] || file[:filename]
        @content_type = file["content_type"] || file[:content_type]
      else
        @file = file
        @original_filename = nil
        @content_type = nil
      end
    end

    # create the directory if it doesn't exist
    def mkdir!(path)
      FileUtils.mkdir_p(File.dirname(path)) unless File.exists?(File.dirname(path))
    end

    def chmod!(path, permissions)
      File.chmod(permissions, path) if permissions
    end

    # Sanitize the filename, to prevent hacking
    def sanitize(name)
      name = name.gsub("\\", "/") # work-around for IE
      name = File.basename(name)
      name = name.gsub(sanitize_regexp,"_")
      name = "_#{name}" if name =~ /\A\.+\z/
      name = "unnamed" if name.size == 0
      return name.mb_chars.to_s
    end

    def split_extension(filename)
      # regular expressions to try for identifying extensions
      extension_matchers = [
        /\A(.+)\.(tar\.gz)\z/, # matches "something.tar.gz"
        /\A(.+)\.([^\.]+)\z/ # matches "something.jpg"
      ]

      extension_matchers.each do |regexp|
        if filename =~ regexp
          return $1, $2
        end
      end
      return filename, "" # In case we weren't able to split the extension
    end

  end # SanitizedFile
end # CarrierWave
