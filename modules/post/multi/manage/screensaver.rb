##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Multi Manage the screensaver of the target computer',
      'Description'   => %q{
        This module allows you to turn on or off the screensaver of the target computer and also
        lock the current session.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Eliott Teissonniere'],
      'Platform'      => [ 'linux', 'osx', 'win' ],
      'SessionTypes'  => [ 'shell', 'meterpreter' ],
      'Actions'       =>
        [
          [ 'LOCK',  { 'Description' => 'Lock the current session' } ],
          [ 'START', { 'Description' => 'Start the screensaver, may lock the current session' } ],
          [ 'STOP',  { 'Description' => 'Stop the screensaver, user may be prompted for its password' }]
        ]
    ))
  end

  #
  # cmd_exec but with some controls and verbosity
  #
  def cmd_vexec(cmd)
    print_status("Executing '#{cmd}'")

    begin
      cmd_exec(cmd)
    rescue EOFError
      print_error('Command failed')
      return false
    end

    true
  end

  def lock_session
    case session.platform
    when 'linux'
      cmd_vexec('xdg-screensaver lock')
    when 'osx'
      cmd_vexec('pmset displaysleepnow')
    when 'windows'
      cmd_vexec('rundll32 user32.dll,LockWorkStation')
    end

    true
  end

  def start_screensaver
    case session.platform
    when 'linux'
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
    when 'linux'
      cmd_vexec('xdg-screensaver reset')
    when 'osx'
      print_error('Not supported on Mac OSX, you can still lock the screen or start the screensaver')
      return false
    when 'windows'
      print_error('Not supported on Windows, you can still lock the screen or start the screensaver')
      return false
    end

    true
  end

  def run
    if action.nil?
      print_error('Please specify an action')
    end

    case action.name
     when 'LOCK'
       return lock_session
     when 'START'
       return start_screensaver
     when 'STOP'
       return stop_screensaver
    end
  end
end
