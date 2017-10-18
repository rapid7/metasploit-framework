##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/windows/powershell'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Powershell
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'         => 'Windows \'Run As\' Using Powershell',
        'Description'  => %q( This module will start a process as another user using powershell. ),
        'License'      => MSF_LICENSE,
        'Author'       => ['p3nt4'],
        'Platform'     => ['win'],
        'SessionTypes' => ['meterpreter']
      )
    )
    register_options(
      [
        OptString.new('USER', [true, 'User to run executable as', nil]),
        OptString.new('PASS', [true, 'Password of user', nil]),
        OptString.new('DOMAIN', [false, 'Domain of user', '']),
        OptString.new('EXE', [true, 'Executable to run', 'cmd.exe']),
        OptString.new('ARGS', [false, 'Arguments', nil]),
        OptString.new('PATH', [true, 'Working Directory', 'C:\\']),
        OptBool.new('CHANNELIZE', [true, 'Chanelize output, required for reading output or interracting', true]),
        OptBool.new('INTERACTIVE', [true, 'Run interactively', true]),
        OptBool.new('HIDDEN', [true, 'Hide the window', true])
      ])
  end

  def run
    raise "Powershell is required" if !have_powershell?
    # Variable Setup
    user = datastore['user']
    pass = datastore['pass']
    domain = datastore['domain']
    exe = datastore['exe'].gsub('\\', '\\\\\\\\')
    inter = datastore['interactive']
    args = datastore['args']
    path = datastore['path'].gsub('\\', '\\\\\\\\')
    channelized = datastore['channelize']
    hidden = datastore['hidden']
    if user.include? '\\'
      domain = user.split('\\')[0]
      user = user.split('\\')[1]
    end
    # Check if session is interactive
    if !session.interacting && inter
      print_error('Interactive mode can only be used in a meterpreter console')
      print_error("Use 'run post/windows/manage/run_as_psh USER=x PASS=X EXE=X' or 'SET INTERACTIVE false'")
      raise 'Invalide console'
    end
    # Prepare powershell script
    scr = "$pw = convertto-securestring '#{pass}' -asplaintext -force; "
    scr << "$pp = new-object -typename System.Management.Automation.PSCredential -argumentlist '#{domain}\\#{user}',$pw; "
    scr << "Start-process '#{exe}' -WorkingDirectory '#{path}' -Credential $pp"
    if args && args != ''
      scr << " -argumentlist '#{args}' "
    end
    if hidden
      print_status('Hidden mode may not work on older powershell versions, if it fails, try HIDDEN=false')
      scr << ' -WindowStyle hidden'
    end
    scr = " -c \"#{scr}\""
    # Execute script
    p = client.sys.process.execute("powershell.exe", scr,
      'Channelized' => channelized,
      'Desktop'     => false,
      'Session'     => false,
      'Hidden'      => true,
      'Interactive' => inter,
      'InMemory'    => false,
      'UseThreadToken' => false)
    print_status("Process #{p.pid} created.")
    print_status("Channel #{p.channel.cid} created.") if p.channel
    # Process output
    if inter && p.channel
      client.console.interact_with_channel(p.channel)
    elsif p.channel
      data = p.channel.read
      print_line(data) if data
    end
  end
end
