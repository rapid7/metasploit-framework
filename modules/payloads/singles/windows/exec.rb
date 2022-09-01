##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


###
#
# Executes a command on the target machine
#
###
module MetasploitModule

  CachedSize = 192

  include Msf::Payload::Windows::Exec

end
