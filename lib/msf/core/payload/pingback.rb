# -*- coding => binary -*-

require 'msf/core'
require 'msf/core/module/platform'
require 'rex/text'

#
# This class provides methods for calculating, extracting, and parsing
# unique ID values used by payloads.
#
class Msf::Payload::Pingback


  #
  # Constants
  #

  def self.generate_raw(opts={})

    puid ||= SecureRandom.uuid
    puid

  end

  #
  # Instance methods
  #

  def initialize(opts=nil)
    if opts.nil?
      puid ||= SecureRandom.uuid()
    end
  end

  #
  # Return a string that represents the Meterpreter arch/platform
  #
  def session_type
    # mini-patch for x86 so that it renders x64 instead. This is
    # mostly to keep various external modules happy.
    arch = self.arch
    if arch == ARCH_X86_64
        arch = ARCH_X64
    end
    "#{arch}/#{self.platform}"
  end

  attr_accessor :puid
end
