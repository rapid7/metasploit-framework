##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/windows/loadlibrary'

###
#
# Executes a command on the target machine
#
###
module MetasploitModule

  CachedSize = 230

  include Msf::Payload::Windows::LoadLibrary

end
