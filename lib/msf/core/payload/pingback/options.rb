# -*- coding => binary -*-

require 'msf/core'
require 'msf/core/payload/pingback'

#
# This module provides datastore option definitions and helper methods for payload modules that support UUIDs
#
module Msf::Payload::Pingback::Options

  def initialize(info = {})
    super
    register_advanced_options(
      [
        Msf::OptString.new('PingbackUUID', [ false, 'A pingback UUID to use']),
        Msf::OptBool.new('PingbackUUIDDatabase', [ true, 'save the pingback UUID to the database', false]),
      ], self.class)
  end

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
    conf = {}
    if datastore['PingbackUUID'].to_s.length > 0
      #
      # TODO- Make this not terrible
      #
      conf[:pingback_uuid] = datastore['PingbackUUID'].to_s
    end
    conf[:pingback_store] = datastore['PingbackUUIDDatabase']
    pingback = Msf::Payload::Pingback.new(conf)
    datastore['PingbackUUID'] ||= pingback.uuid

    if framework.db.active
      vprint_status("Writing UUID #{datastore['PingbackUUID']} to database...")
      Mdm::Payload.create!(name: datastore['PayloadUUIDName'],
                           uuid: datastore['PingbackUUID'].gsub('-',''),
                           description: 'pingback',
                           platform: platform.platforms.first.realname.downcase,
                           workspace: framework.db.workspace)
    else
      print_warning("Unable to save UUID to database -- database support not active")
    end

    pingback.uuid
  end
end
