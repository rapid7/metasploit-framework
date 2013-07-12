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
                        'Name'          =>      'Prefetch Tool',
                        'Description'   =>       %q{ Gathers information from Windows Prefetch files.},
                        'License'       =>      MSF_LICENSE,
                        'Author'        =>      ['Timo Glad <fraktaali[at]gmail.com>'],
                        'Platform'      =>      ['win'],
                        'SessionType'   =>      ['meterpreter']
                ))

        end




	# Checks if Prefetch registry key exists and what value it has.

	
	def prefetch_key_value()

		reg_key = session.sys.registry.open_key(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session\ Manager\\Memory\ Management\\PrefetchParameters", KEY_READ)
                key_value = reg_key.query_value("EnablePrefetcher").data

		
		 print_status("EnablePrefetcher Value: #{key_value}")

                        if key_value == 0
                                print_error("(0) = Disabled (Non-Default).")
                        elsif key_value == 1
                                print_good("(1) = Application launch prefetching enabled (Non-Default).")
                        elsif key_value == 2
                                print_good("(2) = Boot prefetching enabled (Non-Default).")
                        elsif key_value == 3
                                print_good("(3) = Applaunch and boot enabled (Default Value).")
                        else
                                print_error("No proper value.")

                        end

	end

	
	
	def gather_info(name_offset, hash_offset, lastrun_offset, runcount_offset, filename)

		# This function seeks and gathers information from specific offsets.

		h = client.railgun.kernel32.CreateFileA(filename, "GENERIC_READ", "FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE", nil, "OPEN_EXISTING", "FILE_ATTRIBUTE_NORMAL", 0)

		if h['GetLastError'] != 0

                                print_error("Error opening a file handle.")
                                return nil
                        else

				                        handle = h['return']

				                        # Looks for the FILENAME offset

				                        client.railgun.kernel32.SetFilePointer(handle, name_offset, 0, nil)
                                name = client.railgun.kernel32.ReadFile(handle, 60, 60, 4, nil)
                                x = name['lpBuffer']
				                        pname = x.slice(0..x.index("\x00\x00"))

                                # Finds the run count from the prefetch file    

                                client.railgun.kernel32.SetFilePointer(handle, runcount_offset, 0, nil)
                                count = client.railgun.kernel32.ReadFile(handle, 4, 4, 4, nil)
                                prun = count['lpBuffer'].unpack('L*')


				                        # Looks for the FILETIME offset / WORKS, sort of at least..
				                        # Need to find a way to convert FILETIME to LOCAL TIME etc...
				                        client.railgun.kernel32.SetFilePointer(handle, lastrun_offset, 0, 0)
                                tm1 = client.railgun.kernel32.ReadFile(handle, 8, 8, 4, nil)
                                time1 = tm1['lpBuffer']
				                        time = time1.unpack('h*')[0].reverse.to_i(16)
				

				                        # Finding the HASH      
                                client.railgun.kernel32.SetFilePointer(handle, hash_offset, 0, 0)
                                hh = client.railgun.kernel32.ReadFile(handle, 4, 4, 4, nil)
                                y = hh['lpBuffer']
				                        hash = y.unpack('h*')[0].reverse


				print_line("%20s\t %8s\t %08s\t %-60s\t\t %s" % [time,prun[0], hash, pname, filename[20..-1]])


		client.railgun.kernel32.CloseHandle(handle)
		
		end

	end

	

	def run

		print_status("Searching for Prefetch Hive Value.")

		if not is_admin?
			
			print_error("You don't have enough privileges. Try getsystem.")
      return nil
		end


	begin


		sysnfo = client.sys.config.sysinfo['OS']

		# Check to see what Windows Version is running.
		# Needed for offsets.
		
		if sysnfo =~/(Windows XP|2003)/

			print_status("Detected Windows XP/2003")

			name_offset = 0x10 # Offset for EXE name in XP / 2003
			hash_offset = 0x4C # Offset for hash in XP / 2003
			lastrun_offset = 0x78 # Offset for LastRun in XP / 2003
			runcount_offset = 0x90 # Offset for RunCount in XP / 2003


    elsif sysnfo =~/(Windows 7)/ # Offsets for Win7, should work on Vista too but couldn't test it.

        print_status("Detected Windows 7")

        name_offset = 0x10
        hash_offset = 0x4C
        lastrun_offset = 0x80
        runcount_offset = 0x98
		else
			print_error("No offsets for the target Windows version.")
        return nil
		end



		prefetch_key_value
		



		# FIX: Needs to add a check if the path is found or not
		
		sysroot = client.fs.file.expand_path("%SYSTEMROOT%")
		full_path = sysroot + "\\Prefetch\\"
		file_type = "*.pf"
		
		print_line("\n\tFiletime\tRunCount\tHash\t\tFilename (from prefetch file)\t\t\t\t\tFilename (from prefetch directory)\n")

				
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
