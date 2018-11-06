require_relative 'subset/unicode'
require_relative 'subset/unicode_8bit'
require_relative 'subset/mac_roman'
require_relative 'subset/windows_1252'

module TTFunk
  module Subset
    def self.for(original, encoding)
      case encoding.to_sym
      when :unicode      then Unicode.new(original)
      when :unicode_8bit then Unicode8Bit.new(original)
      when :mac_roman    then MacRoman.new(original)
      when :windows_1252 then Windows1252.new(original)
      else raise NotImplementedError, "encoding #{encoding} is not supported"
      end
    end
  end
end
