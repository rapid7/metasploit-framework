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
