##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/osx/bundleinject'

###
#
# Injects an arbitrary DLL in the exploited process.
#
###
module MetasploitModule

  include Msf::Payload::Osx::BundleInject

end
