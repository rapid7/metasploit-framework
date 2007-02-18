##
# $Id:$
##

##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##


require 'msf/core'
require 'msf/core/payload/windows/exec'

module Msf
module Payloads
module Singles
module Windows

###
#
# Executes a command on the target machine
#
###
module Exec

	include Msf::Payload::Windows::Exec

end

end end end end
