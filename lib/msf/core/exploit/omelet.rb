# -*- coding: binary -*-

require 'rex/exploitation/omelet'

module Msf

###
#
# This mixin provides an interface to generating eggs-to-omelet hunters for win/x86
# platforms using the Rex::Exploitation::Omelet class.
#
# written by corelanc0d3r <peter.ve [at] corelan.be>
#
###
module Exploit::Omelet

  #
  # Creates an instance of an exploit that uses an Omelet overwrite.
  #
  def initialize(info = {})
    super
  end


  #
  # Generates an omelet hunter stub and eggs
  #
  def generate_omelet(payload, badchars = nil, opts = {})
    # Prefer the target's platform/architecture information, but use
    # the module's if no target specific information exists
    los   = target_platform
    larch = target_arch || ARCH_X86

    # If we found a platform list, then take the first platform
    los   = los.names[0] if (los.kind_of?(Msf::Module::PlatformList))

    # Use the first architecture if one was specified
    larch = larch[0] if (larch.kind_of?(Array))

    if los.nil?
      raise RuntimeError, "No platform restrictions were specified -- cannot select omelet hunter"
    end

    badchars ||= payload_badchars

    omelet   = Rex::Exploitation::Omelet.new(los, larch)
    scrambledeggs = omelet.generate(payload, badchars, opts)

    if (scrambledeggs.nil?)
      print_error("The omelet hunter could not be generated")
      raise ArgumentError
    end

    return scrambledeggs
  end

end

end
