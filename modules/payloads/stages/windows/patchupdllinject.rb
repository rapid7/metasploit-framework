##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/payload/windows/dllinject'

###
#
# Injects an arbitrary DLL in the exploited process.
#
###
module Metasploit3

  include Msf::Payload::Windows::DllInject

end
