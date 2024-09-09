##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  Rank = ExcellentRanking

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Multi Manage the screensaver of the target computer',
        'Description' => %q{
          This module allows you to turn on or off the screensaver of the target computer and also
          lock the current session.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Eliott Teissonniere', # Metasploit module
          'Julien Voisin' # Linux improvements
        ],
        'Platform' => [ 'linux', 'osx', 'win', 'unix', 'solaris' ],
        'SessionTypes' => [ 'shell', 'meterpreter' ],
        'Actions' => [
          [ 'LOCK', { 'Description' => 'Lock the current session' } ],
          [ 'UNLOCK', { 'Description' => 'Unlock the current session' } ],
          [ 'START', { 'Description' => 'Start the screensaver, may lock the current session' } ],
          [ 'STOP', { 'Description' => 'Stop the screensaver, user may be prompted for its password' }],
        ],
        'References' => [
          ['URL', 'https://gitlab.gnome.org/GNOME/gnome-shell/-/issues/7530']
        ],
        'Notes' => {
          'Reliability' => [ ],
          'Stability' => [ ],
          'SideEffects' => [ ]
        }
      )
    )
  end

  #
  # cmd_exec but returning a boolean
  #
  def cmd_vexec(cmd)
    vprint_status("Executing '#{cmd}'")

    begin
      cmd_exec(cmd)
    rescue StandardError
      return false
    end

    true
  end

  def lock_session
    case session.platform
    when 'linux', 'solaris'
      ret = false
      if command_exists?('xdg-screensaver-lock')
        ret |= cmd_vexec('xdg-screensaver lock')
      end
      if command_exists?('qdbus')
        ret |= cmd_vexec('qdbus org.freedesktop.ScreenSaver /ScreenSaver Lock')
      end
      if command_exists?('dbus-send')
        ret |= cmd_exec('dbus-send --type=method_call --print-reply --dest=org.gnome.ScreenSaver /org/gnome/ScreenSaver org.gnome.ScreenSaver.SetActive boolean:true')
      end
      if command_exists?('loginctl')
        self.class.include Msf::Post::Linux::Priv
        if is_root?
          ret |= cmd_vexec('loginctl lock-sessions')
        else
          ret |= cmd_vexec('loginctl lock-session')
        end
      end
      print_error('Unable to lock session.') unless ret
      return ret
    when 'osx'
      cmd_vexec('pmset displaysleepnow')
    when 'windows'
      cmd_vexec('rundll32 user32.dll,LockWorkStation')
    end

    true
  end

  def unlock_session
    case session.platform
    when 'linux', 'solaris'
      ret = false
      if command_exists?('xdg-screensaver')
        ret |= cmd_vexec('xdg-screensaver reset')
      end
      if command_exists?('qdbus')
        ret |= cmd_vexec('qdbus org.freedesktop.ScreenSaver /ScreenSaver Unlock')
      end
      if command_exists?('dbus-send')
        ret |= cmd_exec('dbus-send --type=method_call --print-reply --dest=org.gnome.ScreenSaver /org/gnome/ScreenSaver org.gnome.ScreenSaver.SetActive boolean:false')
      end
      if command_exists?('loginctl')
        self.class.include Msf::Post::Linux::Priv
        if is_root?
          ret |= cmd_vexec('loginctl unlock-sessions')
        else
          ret |= cmd_vexec('loginctl unlock-session')
        end
      end
      print_error('Unable to unlock session.') unless ret
      return ret
    when 'osx'
      fail_with(Msf::Exploit::Failure::NoTarget, 'Not supported on Mac OSX, you can still lock the screen or start the screensaver')
    when 'windows'
      fail_with(Msf::Exploit::Failure::NoTarget, 'Not supported on Windows, you can still lock the screen or start the screensaver')
    end

    true
  end

  def start_screensaver
    case session.platform
    when 'linux', 'solaris'
      cmd_vexec('xdg-screensaver activate')
    when 'osx'
      cmd_vexec('open -a ScreenSaverEngine')
    when 'windows'
      cmd_vexec('powershell -w hidden -nop -c "Start-Process C:\\Windows\\System32\\scrnsave.scr"')
    end

    true
  end

  def stop_screensaver
    case session.platform
    when 'linux', 'solaris'
      cmd_vexec('xdg-screensaver reset') if command_exists?('xdg-screensaver')
    when 'osx'
      fail_with(Msf::Exploit::Failure::NoTarget, 'Not supported on Mac OSX, you can still lock the screen or start the screensaver')
    when 'windows'
      fail_with(Msf::Exploit::Failure::NoTarget, 'Not supported on Windows, you can still lock the screen or start the screensaver')
    end

    true
  end

  def run
    print_error('Please specify an action') if action.nil?

    case action.name
    when 'LOCK'
      return lock_session
    when 'UNLOCK'
      return unlock_session
    when 'START'
      return start_screensaver
    when 'STOP'
      return stop_screensaver
    end
  end
end
