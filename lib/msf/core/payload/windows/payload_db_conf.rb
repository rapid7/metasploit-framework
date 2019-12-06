# -*- coding: binary -*-

require 'msf/core'

module Msf::Payload::Windows::PayloadDBConf
  def initialize(*args)
    super
  end

  #
  # Saves a payload configuration to the db
  #
  # @param conf [Hash]
  #   accepts a uuid, which will be used as
  #   the payload identifier. Additional
  #   hash values will be saved within `build_opts`
  def save_conf_to_db(conf={})
    return nil unless (framework.db && framework.db.active)

    return nil unless conf['uuid']
    payload_uuid = conf['uuid']
    conf.delete('uuid')

    saved_payload = framework.db.get_payload(uuid: payload_uuid)
    if saved_payload
      framework.db.update_payload(id: saved_payload.id, build_opts: conf)
    else
      print_status('Payload does not exist in database. Attempting to save it now.')
      framework.db.create_payload(uuid: payload_uuid, build_opts: conf)
    end
  rescue
    print_error('Failed to save payload info to database')
  end

  # Retrieve payload configuration from db
  #
  # @param uuid [String]
  #   accepts the payload uuid and
  #   a hash of the payload information will
  #   be returned
  def retrieve_conf_from_db(uuid=nil)
    return nil unless (framework.db && framework.db.active)

    curr_payload = framework.db.get_payload(uuid: uuid)
    return nil unless curr_payload && curr_payload[:build_opts]

    return curr_payload[:build_opts]
  end

  #
  # @param uuid [String]
  #   retrieves the key and nonce for
  #   payloads using the chacha cipher
  #   from the database
  def retrieve_chacha_creds(uuid=nil)
    return nil unless uuid

    build_opts = retrieve_conf_from_db(uuid)
    return nil unless build_opts['key'] && build_opts['nonce']

    return build_opts['key'], build_opts['nonce']
  end
end
