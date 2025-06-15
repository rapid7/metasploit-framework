# -*- coding: binary -*-

#
# This is a helper to an easy way to specify support platforms.  It will take a
# list of strings or Msf::Module::Platform objects and build them into a list
# of Msf::Module::Platform objects.  It also supports ranges based on relative
# ranks...
#
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
  # convenient.
  #
  def self.transform(src)
    from_a(Array.wrap(src))
  end

  #
  # Create an instance from an array
  #
  def self.from_a(ary)
    new(*ary)
  end

  def index(needle)
    platforms.index(needle)
  end

  #
  # Constructor, takes the entries as arguments
  #
  def initialize(*args)
    self.platforms = []

    args.each do |a|
      if a.is_a?(String)
        platforms << Msf::Module::Platform.find_platform(a)
      elsif a.is_a?(Range)
        a_begin = Msf::Module::Platform.find_platform(a.begin)
        a_end = Msf::Module::Platform.find_platform(a.end)
        range = (a_begin::Rank..a_end::Rank)

        a_begin.superclass.find_children.each do |c|
          platforms << c if range.include?(c::Rank)
        end
      else
        platforms << a
      end
    end
  end

  #
  # Checks to see if the platform list is empty.
  #
  def empty?
    platforms.empty?
  end

  #
  # Returns an array of names contained within this platform list.
  #
  def names
    platforms.map(&:realname)
  end

  #
  # Symbolic check to see if this platform list represents 'all' platforms.
  #
  def all?
    names.include?('')
  end

  #
  # Do I support platform list (do I support all of they support?)
  # use for matching say, an exploit and a payload
  #
  def supports?(platform_list)
    platform_list.platforms.each do |pl|
      supported = false
      platforms.each do |p|
        if p >= pl
          supported = true
          break
        end
      end
      return false unless supported
    end

    true
  end

  #
  # used for say, building a payload from a stage and stager
  # finds common subarchitectures between the arguments
  #
  def &(other)
    l1 = platforms
    l2 = other.platforms
    total = l1.find_all { |m| l2.find { |mm| m <= mm } } |
            l2.find_all { |m| l1.find { |mm| m <= mm } }
    Msf::Module::PlatformList.from_a(total)
  end
end
