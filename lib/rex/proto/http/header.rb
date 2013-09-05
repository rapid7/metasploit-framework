# -*- coding: binary -*-
require 'rex/proto/http'

module Rex
module Proto
module Http

###
#
# Represents the logical HTTP header portion of an HTTP packet (request or
# response).
#
###
class Packet::Header < Hash

  #
  # Initializes an HTTP packet header class that inherits from a Hash base
  # class.
  #
  def initialize
    self.dcase_hash = {}

    reset
  end

  #
  # Parses a header from a string.
  #
  # XXX - Putting : in a header value breaks this badly
  def from_s(header)
    reset

    # ghettoooooo!
    # If we don't have any newlines..., put one there.
    if (header.size > 0 && header !~ /\r\n/)
      header << "\r\n"
    end

    # put the non-standard line terminations back to normal
    # gah.  not having look behinds suck,
    header.gsub!(/([^\r])\n/n,'\1' + "\r\n")

    # undo folding, kinda ugly but works for now.
    header.gsub!(/:\s*\r\n\s+/smni,': ')

    # Extract the command string
    self.cmd_string = header.slice!(/.+\r\n/)

    # Extract each header value pair
    header.split(/\r\n/mn).each { |str|
      if (md = str.match(/^(.+?)\s*:\s*(.+?)\s*$/))
        if (self[md[1]])
          self[md[1]] << ", " + md[2]
        else
          self[md[1]] = md[2]
        end
      end
    }
  end

  #
  # More advanced [] that does downcase comparison.
  #
  def [](key)
    begin
      rv = self.fetch(key)
    rescue IndexError
      rv = nil
    end
    if (rv == nil)
      begin
        rv = self.dcase_hash[key.downcase]
      rescue IndexError
        rv = nil
      end
    end

    return rv
  end

  #
  # More advanced []= that does downcase storage.
  #
  def []=(key, value)
    stored = false

    self.each_key { |k|
      if (k.downcase == key.downcase)
        self.store(k, value)
        stored = true
      end
    }

    self.store(key, value) if (stored == false)
    self.dcase_hash[key.downcase] = value
  end

  #
  # Converts the header to a string.
  #
  def to_s(prefix = '')
    str = prefix

    if self.junk_headers
      while str.length < 4096
        if self.fold
          str << "X-#{Rex::Text.rand_text_alphanumeric(rand(30) + 5)}:\r\n\t#{Rex::Text.rand_text_alphanumeric(rand(1024) + 1)}\r\n"
        else
          str << "X-#{Rex::Text.rand_text_alphanumeric(rand(30) + 5)}: #{Rex::Text.rand_text_alphanumeric(rand(1024) + 1)}\r\n"
        end
      end
    end

    each_pair { |var, val|
      if self.fold
        str << "#{var}:\r\n\t#{val}\r\n"
      else
        str << "#{var}: #{val}\r\n"
      end
    }

    str << "\r\n"

    return str
  end

  #
  # Brings in from an array like yo.
  #
  def from_a(ary)
    ary.each { |e|
      self[e[0]] = e[1]
    }
  end

  #
  # Flushes all header pairs.
  #
  def reset
    self.cmd_string = ''
    self.clear
    self.dcase_hash.clear
  end

  #
  # Overrides the builtin 'each' operator to avoid the following exception on Ruby 1.9.2+
  #    "can't add a new key into hash during iteration"
  #
  def each(&block)
    list = []
    self.keys.sort.each do |sidx|
      list << [sidx, self[sidx]]
    end
    list.each(&block)
  end

  #
  # The raw command string associated with the header which will vary between
  # requests and responses.
  #
  attr_accessor :junk_headers
  attr_accessor :cmd_string
  attr_accessor :fold

protected

  attr_accessor :dcase_hash # :nodoc:

end

end
end
end
