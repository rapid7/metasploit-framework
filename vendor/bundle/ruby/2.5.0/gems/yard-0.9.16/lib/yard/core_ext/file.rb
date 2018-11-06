# frozen_string_literal: true
require 'fileutils'

class File
  RELATIVE_PARENTDIR = '..'
  RELATIVE_SAMEDIR = '.'

  # @group Manipulating Paths

  # Turns a path +to+ into a relative path from starting
  # point +from+. The argument +from+ is assumed to be
  # a filename. To treat it as a directory, make sure it
  # ends in +File::SEPARATOR+ ('/' on UNIX filesystems).
  #
  # @param [String] from the starting filename
  #   (or directory with +from_isdir+ set to +true+).
  # @param [String] to the final path that should be made relative.
  # @return [String] the relative path from +from+ to +to+.
  def self.relative_path(from, to)
    from = expand_path(from).split(SEPARATOR)
    to = expand_path(to).split(SEPARATOR)
    from.length.times do
      break if from[0] != to[0]
      from.shift; to.shift
    end
    from.pop
    join(*(from.map { RELATIVE_PARENTDIR } + to))
  end

  # Cleans a path by removing extraneous '..', '.' and '/' characters
  #
  # @example Clean a path
  #   File.cleanpath('a/b//./c/../e') # => "a/b/e"
  # @param [String] path the path to clean
  # @param [Boolean] rel_root allows relative path above root value
  # @return [String] the sanitized path
  def self.cleanpath(path, rel_root = false)
    path = path.split(SEPARATOR)
    path = path.inject([]) do |acc, comp|
      next acc if comp == RELATIVE_SAMEDIR
      if comp == RELATIVE_PARENTDIR && !acc.empty? && acc.last != RELATIVE_PARENTDIR
        acc.pop
        next acc
      elsif !rel_root && comp == RELATIVE_PARENTDIR && acc.empty?
        next acc
      end
      acc << comp
    end
    File.join(*path)
  end

  # @group Reading Files

  # Forces opening a file (for writing) by first creating the file's directory
  # @param [String] file the filename to open
  # @since 0.5.2
  def self.open!(file, *args, &block)
    dir = dirname(file)
    FileUtils.mkdir_p(dir) unless directory?(dir)
    open(file, *args, &block)
  end

  # Reads a file with binary encoding
  # @return [String] the ascii-8bit encoded data
  # @since 0.5.3
  def self.read_binary(file)
    File.open(file, 'rb', &:read)
  end
end
