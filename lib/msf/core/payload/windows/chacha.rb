# -*- coding: binary -*-

require 'msf/core'

module Msf::Payload::Windows::Chacha
  def initialize(*args)
    super
  end

  def save_to_db(conf)
    print_warning('Database is not connected. Cannot Save payload info!') unless (framework.db && framework.db.active)

    b_opts = { 'key' => conf[:key], 'nonce' => conf[:nonce] }
    saved_payload = framework.db.get_payload(uuid: conf[:uuid])
    if saved_payload
      framework.db.update_payload(id: saved_payload.id, build_opts: b_opts)
    else
      print_status('Payload does not exist in database. Attempting to save it now.')
      framework.db.create_payload(uuid: conf[:uuid], build_opts: b_opts)
    end
  rescue
    print_error('Failed to save payload info to database')
  end

  def get_key_nonce(p_uuid)
    return nil unless (framework.db && framework.db.active)

    curr_payload = framework.db.get_payload(uuid: p_uuid)
    return nil unless curr_payload && curr_payload[:build_opts]

    key = curr_payload[:build_opts]['key']
    nonce = curr_payload[:build_opts]['nonce']

    return key, nonce
  rescue
    print_warning("Failed to retrieve key and nonce for uuid: #{p_uuid}")
  end
end
