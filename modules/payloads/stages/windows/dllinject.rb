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
require 'msf/core/payload/windows/dllinject'

module Msf
module Payloads
module Stages
module Windows

###
#
# Injects an arbitrary DLL in the exploited process.
#
###
module DllInject

	include Msf::Payload::Windows::DllInject

end

end end end end
