##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/payload/generic'
require 'msf/core/handler/bind_tcp'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Payload::Generic

  handler module_name: 'Msf::Handler::BindTcp'

  def initialize(info = {})
    super(merge_info(info,
      'Name'          => 'Generic Command Shell, Bind TCP Inline',
      'Description'   => 'Listen for a connection and spawn a command shell',
      'Author'        => 'skape',
      'License'       => MSF_LICENSE,
      'Session'       => Msf::Sessions::CommandShell
      ))
  end

end
