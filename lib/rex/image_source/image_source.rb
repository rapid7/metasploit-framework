#!/usr/bin/env ruby
# -*- coding: binary -*-

module Rex
module ImageSource
class ImageSource

  #
  # Um, just some abstract class stuff I guess, this is the interface
  # that any image sources should subscribe to...
  #

  def subsource(offset, len)
    raise "do something"
  end

  def size
    raise "do something"
  end

  def file_offset
    raise "do something"
  end

  def close
    raise "do something"
  end

  def read_asciiz(offset)
    # FIXME, make me better
    string = ''
    loop do
      char = read(offset, 1)
      break if char == "\x00"
      offset += 1
      string << char
    end
    return string
  end


end

end
end
