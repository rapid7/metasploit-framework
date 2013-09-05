# -*- coding: binary -*-
###
#
# framework-util-svn
# --------------
#
# The class provides methods for parsing the SVN information in the framework directory
#
###

require 'date'

module Msf
module Util
class SVN

  def self.load_root
    info = {}
    path = ::File.join(::File.dirname(__FILE__), "..", "..", "..", ".svn", "entries")
    if !::File.exists?(path)
      return info
    end
    contents = ''
    File.open(path, "rb") do |fd|
      contents = fd.read(::File.size(path))
    end
    if contents.include? "<?xml"
      require 'rexml/document'
      rd = REXML::Document.new(contents).root
      rd.elements.each { |e|
        if e.attributes['name'] == ""
          info[:root] = e.attributes['url']
          info[:revision] = e.attributes['revision']
          info[:updated] = e.attributes['committed-date']
          break
        end
      }
    else
      ents = contents.split("\x0c")
      ents[0].split("\n").each do |line|
        line.strip!
        next if line.empty?
        case line
        when /framework3/
          info[:root] = line
        when /^\d+$/
          info[:revision] = line.to_i
        when /^\d{4}-\d.*T/
          info[:updated] = line
        end
        break if (info[:root] and info[:revision] and info[:updated])
      end
    end
    info
  end

  def self.revision
    @@info ||= load_root
    @@info[:revision]
  end

  def self.updated
    @@info ||= load_root
    @@info[:updated]
  end

  def self.root
    @@info ||= load_root
    @@info[:root]
  end

  def self.days_since_update
    @@info ||= load_root
    svnt = @@info[:updated]
    if(not svnt)
      return
    end

    # Date.parse and Date.strptime are both broken beyond repair in
    # ruby 1.8.6 and older.  Just bail if the parsing doesn't work.
    begin
      diff = (Date.parse(Time.now.to_s) - Date.parse(svnt)).to_f
    rescue ArgumentError
    end
  end

  def self.last_updated_friendly
    diff = self.days_since_update
    case diff
    when nil
      "at an unknown date"
    when -2.0 .. 1.0
      "today"
    when 1.0 .. 2.0
      "yesterday"
    else
      if (diff.to_i > 7)
        "%red#{diff.to_i} days ago%clr"
      else
        "#{diff.to_i} days ago"
      end
    end
  end

  def self.last_updated_date
    @@info ||= load_root
                svnt = @@info[:updated]
                if(not svnt)
                        return
                end
    begin
      Date.parse(@@info[:updated])
    rescue ArgumentError
    end
  end

end
end
end

