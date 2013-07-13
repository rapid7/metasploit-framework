##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/registry'
require 'time'


class Metasploit3 < Msf::Post
        include Msf::Post::Windows::Priv
	
        def initialize(info={})
                super(update_info(info,
                        'Name'          =>      'Windows Gather Prefetch File Information',
                        'Description'   =>       %q{This module gathers prefetch file information from WinXP & Win7 systems.},
                        'License'       =>      MSF_LICENSE,
                        'Author'        =>      ['TJ Glad <fraktaali[at]gmail.com>'],
                        'Platform'      =>      ['win'],
                        'SessionType'   =>      ['meterpreter']
                ))

        end


	# Checks if Prefetch registry key exists and what value it has.

	
	def prefetch_key_value()

		reg_key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session\ Manager\\Memory\ Management\\PrefetchParameters", KEY_READ)
    key_value = reg_key.query_value("EnablePrefetcher").data


                        if key_value == 0
                                print_error("EnablePrefetcher Value: (0) = Disabled (Non-Default).")
                        elsif key_value == 1
                                print_good("EnablePrefetcher Value: (1) = Application launch prefetching enabled (Non-Default).")
                        elsif key_value == 2
                                print_good("EnablePrefetcher Value: (2) = Boot prefetching enabled (Non-Default).")
                        elsif key_value == 3
                                print_good("EnablePrefetcher Value: (3) = Applaunch and boot enabled (Default Value).")
                        else
                                print_error("No proper value set so information should be taken with a grain of salt.")

                        end
      reg_key.close
	end

	
	def gather_info(name_offset, hash_offset, lastrun_offset, runcount_offset, filename)

		# This function seeks and gathers information from specific offsets.

		h = client.railgun.kernel32.CreateFileA(filename, "GENERIC_READ", "FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE", nil, "OPEN_EXISTING", "FILE_ATTRIBUTE_NORMAL", 0)

    if h['GetLastError'] != 0

      print_error("Error opening a file handle.")
      return nil
    else

      handle = h['return']

      # Finds the filename from the prefetch file
      client.railgun.kernel32.SetFilePointer(handle, name_offset, 0, nil)
      name = client.railgun.kernel32.ReadFile(handle, 60, 60, 4, nil)
      x = name['lpBuffer']
      pname = x.slice(0..x.index("\x00\x00"))

      # Finds the run count from the prefetch file 
      client.railgun.kernel32.SetFilePointer(handle, runcount_offset, 0, nil)
      count = client.railgun.kernel32.ReadFile(handle, 4, 4, 4, nil)
      prun = count['lpBuffer'].unpack('L*')

      # FIXME: Finds the FILETIME offset and converts it.
      # The time conversion is currently a bit confusing.
      # ATM You have to add/substract your timezone from the
      # time it prints out. That time is the one from the pf
      # file and represents the time on your timezone
      # i.e. if timestamp is 2013-07-13 21:00:13 and i'm on +2
      # then the correct time is 2013-07-13 19:00:13
      client.railgun.kernel32.SetFilePointer(handle, lastrun_offset, 0, 0)
      tm = client.railgun.kernel32.ReadFile(handle, 8, 8, 4, nil)
      filetime = tm['lpBuffer'].unpack('h*')[0].reverse.to_i(16)
      xtime = ((filetime.to_i - 116444556000000000) / 10000000)
      ptime = Time.at(xtime).utc.to_s

      # Finds the hash.
      client.railgun.kernel32.SetFilePointer(handle, hash_offset, 0, 0)
      hh = client.railgun.kernel32.ReadFile(handle, 4, 4, 4, nil)
      phash = hh['lpBuffer'].unpack('h*')[0].reverse


      print_line("%s\t\t %s\t\t %08s\t %-29s" % [ptime[0..-4], prun[0], phash, pname])
      client.railgun.kernel32.CloseHandle(handle)
		end

	end


	def run

    print_status("Prefetch Gathering started.")

    if not is_admin?

      print_error("You don't have enough privileges. Try getsystem.")

      return nil
    end


	begin

		sysnfo = client.sys.config.sysinfo['OS']

		# Check to see what Windows Version is running.
		# Needed for offsets.
    # Tested on WinXP and Win7 systems. Should work on WinVista & Win2k3..
		# http://www.forensicswiki.org/wiki/Prefetch
    # http://www.forensicswiki.org/wiki/Windows_Prefetch_File_Format

		if sysnfo =~/(Windows XP)/ # Offsets for WinXP

			  print_good("Detected Windows XP")
			  name_offset = 0x10
			  hash_offset = 0x4C
			  lastrun_offset = 0x78
			  runcount_offset = 0x90

    elsif sysnfo =~/(Windows 7)/ # Offsets for Win7

        print_good("Detected Windows 7")
        name_offset = 0x10
        hash_offset = 0x4C
        lastrun_offset = 0x80
        runcount_offset = 0x98

		else

			print_error("No offsets for the target Windows version.")

        return nil
		end

    print_status("Searching for Prefetch Hive Value.")
		prefetch_key_value

		sysroot = client.fs.file.expand_path("%SYSTEMROOT%")
		full_path = sysroot + "\\Prefetch\\"
		file_type = "*.pf"
		
		print_line("\nLatest Run Time\t\t\tRun Count\tHash\t\tFilename\n")

				
		getfile_prefetch_filenames = client.fs.file.search(full_path,file_type,recurse=false,timeout=-1)
                getfile_prefetch_filenames.each do |file|
                        if file.empty? or file.nil?

				print_error("No files or not enough privileges.")

        return nil

			else

				filename = File.join(file['path'], file['name'])
				
				gather_info(name_offset, hash_offset, lastrun_offset, runcount_offset, filename)

			end

		end

	end


		print_good("Finished gathering information from prefetch files.")	


	end
end
