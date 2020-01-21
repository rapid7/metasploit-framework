# -*- coding => binary -*-

require 'msf/core'
require 'msf/core/payload/uuid'
require 'rex/payloads/meterpreter/uri_checksum'

#
# This module provides datastore option definitions and helper methods for payload modules that support UUIDs
#
module Msf::Payload::UUID::Options

  include Rex::Payloads::Meterpreter::UriChecksum

  def initialize(info = {})
    super
    register_advanced_options(
      [
        Msf::OptString.new('PayloadUUIDSeed', [ false, 'A string to use when generating the payload UUID (deterministic)']),
        Msf::OptString.new('PayloadUUIDRaw', [ false, 'A hex string representing the raw 8-byte PUID value for the UUID']),
        Msf::OptString.new('PayloadUUIDName', [ false, 'A human-friendly name to reference this unique payload (requires tracking)']),
        Msf::OptBool.new('PayloadUUIDTracking', [ true, 'Whether or not to automatically register generated UUIDs', false]),
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
  def generate_uri_uuid_mode(mode, len = nil, uuid: nil)
    sum = uri_checksum_lookup(mode)

    # The URI length may not have room for an embedded UUID
    if len && len < URI_CHECKSUM_UUID_MIN_LEN
      # Throw an error if the user set a seed, but there is no room for it
      if datastore['PayloadUUIDSeed'].to_s.length > 0 || datastore['PayloadUUIDRaw'].to_s.length > 0
        raise ArgumentError, "A PayloadUUIDSeed or PayloadUUIDRaw value was specified, but this payload doesn't have enough room for a UUID"
      end
      return "/" + generate_uri_checksum(sum, len, prefix="")
    end

    uuid ||= generate_payload_uuid
    uri  = generate_uri_uuid(sum, uuid, len)
    record_payload_uuid_url(uuid, uri)

    uri
  end

  # Generate a Payload UUID
  def generate_payload_uuid

    conf = {
      arch:     self.arch,
      platform: self.platform
    }

    # Handle user-specified seed values
    if datastore['PayloadUUIDSeed'].to_s.length > 0
      conf[:seed] = datastore['PayloadUUIDSeed'].to_s
    end

    # Handle user-specified raw payload UID values
    if datastore['PayloadUUIDRaw'].to_s.length > 0
      puid_raw = [datastore['PayloadUUIDRaw'].to_s].pack("H*")
      if puid_raw.length != 8
        raise ArgumentError, "The PayloadUUIDRaw value must be exactly 16 bytes of hex"
      end
      conf.delete(:seed)
      conf[:puid] = puid_raw
    end

    if datastore['PayloadUUIDName'].to_s.length > 0 && ! datastore['PayloadUUIDTracking']
      raise ArgumentError, "The PayloadUUIDName value is ignored unless PayloadUUIDTracking is enabled"
    end

    # Generate the UUID object
    uuid = Msf::Payload::UUID.new(conf)
    record_payload_uuid(uuid)

    uuid
  end

  # Store a UUID in the JSON database if tracking is enabled
  def record_payload_uuid(uuid, info={})
    return unless datastore['PayloadUUIDTracking']
    # skip if there is no active database
    return if !(framework.db && framework.db.active)

    uuid_info = info.merge({
      uuid:  uuid.puid_hex,
      arch: uuid.arch,
      platform: uuid.platform,
      timestamp: uuid.timestamp,
    })

    if datastore['PayloadUUIDSeed'].to_s.length > 0
      uuid_info[:seed] = datastore['PayloadUUIDSeed']
    end

    if datastore['PayloadUUIDName'].to_s.length > 0
      uuid_info[:name] = datastore['PayloadUUIDName']
    end

    framework.db.create_payload(uuid_info)
  end

  # Store a UUID URL in the database if tracking is enabled
  def record_payload_uuid_url(uuid, url)
    return unless datastore['PayloadUUIDTracking']
    # skip if there is no active database
    return if !(framework.db && framework.db.active)

    payload_info = {
        uuid: uuid.puid_hex,
    }
    payload = framework.db.payloads(payload_info).first
    unless payload.nil?
      urls = payload.urls.nil? ? [] : payload.urls
      urls << url
      urls.uniq!
      framework.db.update_payload({id: payload.id, urls: urls})
    end
  end

end

