##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
		super(update_info(info,
	    'Name'           => "Check Test",
	  	'Description'    => %q{
		   This module ensures that 'check' actually functions for Auxiilary modules.
      },
      'References'     =>
        [
          [ 'OSVDB', '0' ]
        ],
      'Author'         =>
        [
          'todb'
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(80)
      ], self.class)
  end

  def check
    print_debug "Check is successful"
    return Msf::Exploit::CheckCode::Vulnerable
  end

  def run
    print_debug "Run is successful."
  end

end
