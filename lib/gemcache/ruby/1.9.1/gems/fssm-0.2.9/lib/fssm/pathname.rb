require 'fileutils'
require 'find'
require 'pathname'

module FSSM
  class Pathname < ::Pathname
    VIRTUAL_REGEX = /^file:([^!]*)!/

    class << self
      def for(path)
        path.is_a?(::FSSM::Pathname) ? path : new(path)
      end

      alias :[] :glob
    end

    def is_virtual?
      !!(VIRTUAL_REGEX =~ to_s)
    end

    def segments
      path  = to_s
      array = path.split(File::SEPARATOR)
      array.delete('')
      array.insert(0, File::SEPARATOR) if path[0, 1] == File::SEPARATOR
      array[0] += File::SEPARATOR if path[0, 3] =~ SEPARATOR_PAT
      array
    end

    def glob(pattern, flags = 0, &block)
      patterns = [pattern].flatten
      patterns.map! { |p| self.class.glob(to_s + p, flags, &block) }
      patterns.flatten
    end
  end
end
