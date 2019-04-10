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
    puts("Initializing pingback_uuid")
    puts("uuid = " + self.uuid.to_s) if not uuid.nil?
    puts("uuid is nil") if self.uuid.nil?
    self.uuid ||= SecureRandom.uuid()
    opts[:pingback_uuid] = self.uuid
    puts("uuid = " + self.uuid.to_s)
    puts("opts = " + opts.to_s)
  end

  attr_accessor :uuid
end
