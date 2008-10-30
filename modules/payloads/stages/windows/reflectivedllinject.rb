# Copyright (c) 2008 Stephen Fewer of Harmony Security (www.harmonysecurity.com)

require 'msf/core'
require 'msf/core/payload/windows/reflectivedllinject'


###
#
# Injects an arbitrary DLL in the exploited process via a reflective loader.
#
###
module Metasploit3

	include Msf::Payload::Windows::ReflectiveDllInject

end

