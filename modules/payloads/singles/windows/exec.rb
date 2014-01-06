##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/payload/windows/exec'

###
#
# Executes a command on the target machine
#
###
module Metasploit3

  include Msf::Payload::Windows::Exec

end
