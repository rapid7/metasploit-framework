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
    uuid_hex = Rex::Text.to_hex(uuid.to_raw, prefix = '')

    uuid_stub = "import binascii\n"
    uuid_stub << "#{sock_var}.send(binascii.a2b_hex('#{uuid_hex}'))\n"
    uuid_stub
  end

end

end

