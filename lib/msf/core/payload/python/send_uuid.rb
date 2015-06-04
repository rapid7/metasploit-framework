# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/python'
require 'msf/core/payload/uuid'

module Msf

###
#
# Basic send_uuid stub for Python payloads
#
###

module Payload::Python::SendUUID

  #
  # Generate python code that writes the UUID to the socket.
  #
  def py_send_uuid(opts={})
    sock_var = opts[:sock_var] || 's'

    uuid = opts[:uuid] || generate_payload_uuid
    uuid_raw = uuid.to_raw.chars.map { |c| '\x%.2x' % c.ord }.join('')

    "#{sock_var}.send(\"#{uuid_raw}\")\n"
  end

end

end

