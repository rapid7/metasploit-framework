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

  # @!attribute [rw] module_class_full_names
  #   `Mdm::Module::Class#full_name`s for module classes that declared this platform list.  {#&} will combine the
  #   {#module_class_full_names} from `self` and the `other_platform_list`.
  #
  #   @return [Array<String>] `Mdm::Module::Class#full_name`s
  attr_writer :module_class_full_names

  # @!attribute [rw] platforms
  #   Platforms declared for this list.
  #
  #   @return [Array<Metasploit::Framework::Platform>]

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

    module_class_full_names_union = module_class_full_names | other_platform_list.module_class_full_names

    self.class.new(
        module_class_full_names: module_class_full_names_union,
        platforms: preserved_platforms
    )
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
  def self.from_a(array, options={})
    options.assert_valid_keys(:module_class_full_names)

    unless array.is_a? Array
      raise TypeError,
            "#{array.inspect} is not an Array"
    end

    new(
        module_class_full_names: options[:module_class_full_names],
        platforms: array
    )
  end

  # @param attributes [Hash{Symbol => Array}]
  # @option attributes [Array<String>] :module_class_full_names The `Mdm::Module::Class#full_name`s of the modules that
  #   declared this platform list or combined to form this platform list when using {#&}.
  # @option attributes [Array<Metasploit::Framework::Platform, '', String>] :platforms List of platforms.
  #   {Metasploit::Framework::Platform} are used directly.  `''` is treated as {Metasploit::Framework::Platform.all}
  def initialize(attributes={})
    attributes.assert_valid_keys(:module_class_full_names, :platforms)

    # MUST be set before {#platforms} so errors and deprecation warnings are reported against the correct module
    # class(es).
    self.module_class_full_names = attributes[:module_class_full_names]
    self.platforms = attributes[:platforms]
  end

  # `Mdm::Module::Class#full_name`s of modules that declared this list directly or contributed to this unioned platform
  # list.
  #
  # @return [Array<String>] Defaults to []
  def module_class_full_names
    @module_class_full_names ||= []
  end

  def platforms
    @platforms ||= []
  end

  def platforms=(platforms)
    # Array.wrap doesn't handle Enumerable other than Array, such as Set correctly, so check for Enumerable before
    # wrapping to prevent Array(Set) when it should just be Array with Set's elements.
    if platforms.is_a? Enumerable
      enumerable_platforms = platforms
    else
      enumerable_platforms = Array.wrap(platforms)
    end

    @platforms = enumerable_platforms.collect_concat { |platform|
      case platform
        when Metasploit::Framework::Platform
          platform
        # empty string is used to indicate all platforms and must be before the more general String
        when ''
          Metasploit::Framework::Platform.all
        # must be after the more specific empty String, ''.
        when String
          Metasploit::Framework::Platform.closest(
              platform,
              module_class_full_names: module_class_full_names
          )
        when Range
          raise ArgumentError, "Platform ranges no longer supported"
        else
          raise ArgumentError, "Don't know how to convert #{platform.inspect} to a Metasploit::Framework::Platform"
      end
    }

    # reset caches derived from platforms
    @platform_and_descendant_set = nil

    @platforms
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
  # @param src [String, nil, Array<String>] A platform or list of platforms as declared in a module.
  def self.transform(src, options={})
    options.assert_valid_keys(:module_class_full_names)

    array = Array.wrap(src)
    from_a(
        array,
        module_class_full_names: options[:module_class_full_names]
    )
  end

  #
  # Returns the win32 platform list.
  #
  def self.win32
    transform('win')
  end
end
