#!/usr/bin/env ruby
# -*- coding: binary -*-

#
# This is a helper to a easy way to specify support platforms.  It will take a
# list of strings or Msf::Module::Platform objects and build them into a list
# of Msf::Module::Platform objects.  It also supports ranges based on relative
# ranks...
#

class Msf::Module::PlatformList
  #
  # Attributes
  #

  # @!attribute [rw] platforms
  #   Platforms declared for this list.
  #
  #   @return [Array<Metasploit::Framework::Platform>]
  attr_accessor :platforms

  #
  # Methods
  #

  # Intersection of {#platforms} in this platform list and `other_platform_list`.
  #
  # @param other_platform_list [Msf::Module::PlatformList]
  # @return [Msf::Module::PlatformList] a new platform list
  def &(other_platform_list)
    # tree intersection across all nodes in all trees.
    common_platform_and_descendant_set = platform_and_descendant_set & other_platform_list.platform_and_descendant_set

    # common_platform_and_descendant_set needs to be first as Array & Set does not work, but Set & Array does.

    # grabs all platforms that were the max common platform/descendant
    preserved_platforms = common_platform_and_descendant_set & platforms
    # grabs all other platforms that were the max common platform/descendant
    preserved_platforms |= common_platform_and_descendant_set & other_platform_list.platforms

    self.class.from_a(preserved_platforms)
  end

  def each(&block)
    platforms.each(&block)
  end

  #
  # Checks to see if the platform list is empty.
  #
  def empty?
    platforms.empty?
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
    self.platforms = args.collect_concat { |a|
      case a
        when Metasploit::Framework::Platform
          a
        # empty string is used to indicate all platforms and must be before the more general String
        when ''
          Metasploit::Framework::Platform.all
        # must be after the more specific empty String, ''.
        when String
          Metasploit::Framework::Platform.closest(a)
        when Range
          raise ArgumentError, "Platform ranges no longer supported"
        else
          raise ArgumentError, "Don't know how to convert #{a.inspect} to a Metasploit::Framework::Platform"
      end
    }
  end

  #
  # Returns an array of names contained within this platform list.
  #
  def names
    platforms.map { |m| m.realname }
  end

  # The set of all {Metasploit::Framework::Platform} in {#platforms} and their
  # {Metasploit::Framework::Platform#descendant_set}.
  #
  # @return [Set<Metasploit::Framework::Platform]
  def platform_and_descendant_set
    @platform_and_descendant_set ||= platforms.each_with_object(Set.new) { |platform, set|
      set.merge platform.self_and_descendant_set
    }
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
  # Returns the win32 platform list.
  #
  def self.win32
    transform('win')
  end
end
