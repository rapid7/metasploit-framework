##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# Copyright (c) 2008 Stephen Fewer of Harmony Security (www.harmonysecurity.com)


###
#
# Injects an arbitrary DLL in the exploited process via a reflective loader.
#
###
module MetasploitModule

  include Msf::Payload::Windows::ReflectiveDllInject

end
