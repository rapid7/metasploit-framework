##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

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
