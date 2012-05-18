require 'sprockets/asset'
require 'fileutils'
require 'zlib'

module Sprockets
  # `StaticAsset`s are used for files that are served verbatim without
  # any processing or concatenation. These are typical images and
  # other binary files.
  class StaticAsset < Asset
    # Returns file contents as its `source`.
    def source
      # File is read everytime to avoid memory bloat of large binary files
      pathname.open('rb') { |f| f.read }
    end

    # Implemented for Rack SendFile support.
    def to_path
      pathname.to_s
    end

    # Save asset to disk.
    def write_to(filename, options = {})
      # Gzip contents if filename has '.gz'
      options[:compress] ||= File.extname(filename) == '.gz'

      if options[:compress]
        # Open file and run it through `Zlib`
        pathname.open('rb') do |rd|
          File.open("#{filename}+", 'wb') do |wr|
            gz = Zlib::GzipWriter.new(wr, Zlib::BEST_COMPRESSION)
            buf = ""
            while rd.read(16384, buf)
              gz.write(buf)
            end
            gz.close
          end
        end
      else
        # If no compression needs to be done, we can just copy it into place.
        FileUtils.cp(pathname, "#{filename}+")
      end

      # Atomic write
      FileUtils.mv("#{filename}+", filename)

      # Set mtime correctly
      File.utime(mtime, mtime, filename)

      nil
    ensure
      # Ensure tmp file gets cleaned up
      FileUtils.rm("#{filename}+") if File.exist?("#{filename}+")
    end
  end
end
