# -*- coding => binary -*-

require 'msf/core'
require 'msf/core/module/platform'
require 'rex/text'

#
# This class provides methods for calculating, extracting, and parsing
# unique ID values used by payloads.
#
module Msf::Payload::Pingback

  #
  # Instance methods
  #
  #
  # Generates a URI with a given checksum and optionally with an embedded UUID if
  # the desired length can accommodate it.
  #
  # @param mode [Symbol] The type of checksum to generate (:connect, :init_native, :init_python, :init_java)
  # @param len [Integer] The length of the URI not including the leading slash, optionally nil for random
  # @return [String] A URI with a leading slash that hashes to the checksum, with an optional UUID
  #

  # Generate a Payload UUID
  def generate_pingback_uuid
    self.pingback_uuid ||= SecureRandom.uuid()
    print_status("PingbackUUID = #{self.pingback_uuid}")
    if framework.db.active
      print_status("Writing UUID #{datastore['PingbackUUID']} to database...")
      Mdm::Payload.create!(name: datastore['PayloadUUIDName'],
                           uuid: datastore['PingbackUUID'].gsub('-',''),
                           description: 'pingback',
                           platform: platform.platforms.first.realname.downcase)
    else
      print_warning("Unable to save UUID to database -- database support not active")
    end
    self.pingback_uuid
  end

  def initialize(info = {})
    ret = super(info)
    self.can_cleanup = false
    self
  end

  attr_accessor :pingback_uuid
  attr_accessor :can_cleanup
end
