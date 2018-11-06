#!/usr/bin/env ruby

$VERBOSE = true

$: << '../lib'

require 'zip'
require 'find'

module Zip
  module ZipFind
    def self.find(path, zipFilePattern = /\.zip$/i)
      Find.find(path) do |fileName|
        yield(fileName)
        next unless zipFilePattern.match(fileName) && File.file?(fileName)
        begin
          Zip::File.foreach(fileName) do |zipEntry|
            yield(fileName + File::SEPARATOR + zipEntry.to_s)
          end
        rescue Errno::EACCES => ex
          puts ex
        end
      end
    end

    def self.find_file(path, fileNamePattern, zipFilePattern = /\.zip$/i)
      find(path, zipFilePattern) do |fileName|
        yield(fileName) if fileNamePattern.match(fileName)
      end
    end
  end
end

if $0 == __FILE__
  module ZipFindConsoleRunner
    PATH_ARG_INDEX = 0
    FILENAME_PATTERN_ARG_INDEX = 1
    ZIPFILE_PATTERN_ARG_INDEX = 2

    def self.run(args)
      check_args(args)
      Zip::ZipFind.find_file(args[PATH_ARG_INDEX],
                             args[FILENAME_PATTERN_ARG_INDEX],
                             args[ZIPFILE_PATTERN_ARG_INDEX]) do |fileName|
        report_entry_found fileName
      end
    end

    def self.check_args(args)
      if args.size != 3
        usage
        exit
      end
    end

    def self.usage
      puts "Usage: #{$0} PATH ZIPFILENAME_PATTERN FILNAME_PATTERN"
    end

    def self.report_entry_found(fileName)
      puts fileName
    end
  end

  ZipFindConsoleRunner.run(ARGV)
end
