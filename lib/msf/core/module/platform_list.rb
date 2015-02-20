#!/usr/bin/env ruby
# -*- coding: binary -*-

#
# This is a helper to a easy way to specify support platforms.  It will take a
# list of strings or Msf::Module::Platform objects and build them into a list
# of Msf::Module::Platform objects.  It also supports ranges based on relative
# ranks...
#

require 'msf/core/module/platform'

class Msf::Module::PlatformList
  attr_accessor :platforms

  #
  # Returns the win32 platform list.
  #
  def self.win32
    transform('win')
  end

  #
  # Transformation method, just accept an array or a single entry.
  # This is just to make defining platform lists in a module more
  # convenient, skape's a girl like that.
  #
  def self.transform(src)
    if (src.kind_of?(Array))
      from_a(src)
    else
      from_a([src])
    end
  end

  #
  # Create an instance from an array
  #
  def self.from_a(ary)
    self.new(*ary)
  end

  def index(needle)
    self.platforms.index(needle)
  end

  #
  # Constructor, takes the entries are arguments
  #
  def initialize(*args)
    self.platforms = [ ]

    args.each { |a|
      if a.kind_of?(String)
        platforms << Msf::Module::Platform.find_platform(a)
      elsif a.kind_of?(Range)
        b = Msf::Module::Platform.find_platform(a.begin)
        e = Msf::Module::Platform.find_platform(a.end)

        children = b.superclass.find_children
        r        = (b::Rank .. e::Rank)
        children.each { |c|
          platforms << c if r.include?(c::Rank)
        }
      else
        platforms << a
      end

    }

  end

  #
  # Checks to see if the platform list is empty.
  #
  def empty?
    return platforms.empty?
  end

  #
  # Returns an array of names contained within this platform list.
  #
  def names
    platforms.map { |m| m.realname }
  end

  #
  # Symbolic check to see if this platform list represents 'all' platforms.
  #
  def all?
    names.include? ''
  end

  #
  # Do I support plist (do I support all of they support?)
  # use for matching say, an exploit and a payload
  #
  def supports?(plist)
    plist.platforms.each { |pl|
      supported = false
      platforms.each { |p|
        if p >= pl
          supported = true
          break
        end
      }
      return false if !supported
    }

    return true
  end

  #
  # used for say, building a payload from a stage and stager
  # finds common subarchitectures between the arguments
  #
  def &(plist)
    l1 = platforms
    l2 = plist.platforms
    total = l1.find_all { |m| l2.find { |mm| m <= mm } } |
          l2.find_all { |m| l1.find { |mm| m <= mm } }
    Msf::Module::PlatformList.from_a(total)
  end
end
