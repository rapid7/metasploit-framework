##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


###
#
# Injects an arbitrary DLL in the exploited process.
#
###
module MetasploitModule

  include Msf::Payload::Osx::BundleInject

end
