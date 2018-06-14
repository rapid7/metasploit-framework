##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Linux::System

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Linux XDG screensaver',
      'Description'   => %q{
          This module allows you to control the screensaver of the target system.
      },
      'License'       => MSF_LICENSE,
      'Author'        => ['DeveloppSoft'],
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell', 'meterpreter'],
      'Actions'       =>
        [
          ['STATUS',   { 'Description' => 'Print if the screensaver is enabled to turn on after a period of inactivity' } ],
          ['LOCK',     { 'Description' => 'Lock current session' } ],
          ['ACTIVATE', { 'Description' => 'Start the screensaver, session might be locked' } ],
          ['RESET',    { 'Description' => 'Deactivate screensaver, user might have to unlock its session'}]
        ],
      'DefaultAction' => 'STATUS'
    ))
  end

  def run
    if action.nil?
      print_error("Please specify an action")
      return
    end

    case action.name
      when 'STATUS'
        output = cmd_exec('xdg-screensaver status')
        print_status output
      when 'LOCK'
        cmd_exec('xdg-screensaver lock')
      when 'ACTIVATE'
        cmd_exec('xdg-screensaver activate')
      when 'RESET'
        cmd_exec('xdg-screensaver reset')
    end
  end
end
