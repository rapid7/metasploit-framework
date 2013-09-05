# -*- coding: binary -*-
module Rex
module MIME
class Header

  require 'rex/text'

  attr_accessor :headers

  def initialize(data='')
    self.headers = []
    parse(data)
  end

  def parse(data)
    prev = nil
    data.gsub("\r", '').split("\n").each do |line|

      # Handle header folding
      if (line =~ /^\s+/)
        # Ignore if there is no previous header
        next if not prev
        next if not self.headers[prev]
        self.headers[prev][1] << line.strip
        next
      end

      var,val = line.split(':')
      next if not val
      self.headers << [ var.to_s.strip, val.to_s.strip ]
      prev = self.headers.length - 1
    end
  end

  def to_s
    self.headers.map{ |pair| "#{pair[0]}: #{pair[1]}\r\n" }.join
  end

  def find(idx)
    if (idx.class == ::Fixnum)
      return self.headers[idx]
    else
      self.headers.each do |pair|
        if (pair[0] == idx.to_s)
          return pair
        end
      end
    end
    nil
  end

  def set(var, val)
    hdr = self.find(var) || self.add(var, '')
    hdr[1] = val
  end

  def add(var, val)
    self.headers << [var, val]
    self.headers[-1]
  end

  def remove(idx)
    if (idx.class == ::Fixnum)
      self.headers.delete_at(idx)
    else
      self.headers.each_index do |i|
        pair = self.headers[i]
        if (pair[0] == idx.to_s)
          self.headers.delete_at(i)
        end
      end
    end
  end

end
end
end

