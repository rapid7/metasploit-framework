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

	include Msf::Post::File
	include Msf::Post::Windows::Priv
	include Msf::Post::Windows::Registry

	def initialize(info={})
		super(update_info(info,
			'Name'          => 'Windows Gather Prefetch File Information',
			'Description'   => %q{
								This module gathers prefetch file information from WinXP, Win2k3 and Win7 systems.
								File offset reads for run count, hash and filename are collected from each prefetch file
								while Last Modified and Create times are file MACE values.
													},
			'License'       =>      MSF_LICENSE,
			'Author'        =>      ['TJ Glad <fraktaali[at]gmail.com>'],
			'Platform'      =>      ['win'],
			'SessionType'   =>      ['meterpreter']))
	end

	def print_prefetch_key_value()
		# Checks if Prefetch registry key exists and what value it has.
		prefetch_key_value = registry_getvaldata("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters", "EnablePrefetcher")
		if prefetch_key_value == 0
			print_error("EnablePrefetcher Value: (0) = Disabled (Non-Default).")
		elsif prefetch_key_value == 1
			print_good("EnablePrefetcher Value: (1) = Application launch prefetching enabled (Non-Default).")
		elsif prefetch_key_value == 2
			print_good("EnablePrefetcher Value: (2) = Boot prefetching enabled (Non-Default, excl. Win2k3).")
		elsif prefetch_key_value == 3
			print_good("EnablePrefetcher Value: (3) = Applaunch and boot enabled (Default Value, excl. Win2k3).")
		else
			print_error("No value or unknown value. Results might vary.")
		end
	end

	def print_timezone_key_values(key_value)
		# Looks for timezone from registry
		timezone = registry_getvaldata("HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation", key_value)
		tz_bias = registry_getvaldata("HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation", "Bias")
		if timezone.nil? or tz_bias.nil?
			print_line("Couldn't find key/value for timezone from registry.")
		else
			print_good("Remote: Timezone is %s." % timezone)
			if tz_bias < 0xfff
				print_good("Remote: Localtime bias to UTC: -%s minutes." % tz_bias)
			else
				offset = 0xffffffff
				bias = offset - tz_bias
				print_good("Remote: Localtime bias to UTC: +%s minutes." % bias)
			end
		end
	end

	def gather_pf_info(name_offset, hash_offset, runcount_offset, filename)
		# We'll load the file and parse information from the offsets
		prefetch_file = read_file(filename)
		if prefetch_file.empty? or prefetch_file.nil?
			print_error("Couldn't read file: #{filename}")
			return nil
		else
			# First we'll get the filename
			pf_filename = prefetch_file[name_offset..name_offset+60]
			idx = pf_filename.index("\x00\x00")
			name = Rex::Text.to_ascii(pf_filename.slice(0..idx))
			# Next we'll get the run count
			run_count = prefetch_file[runcount_offset..runcount_offset+4].unpack('L*')[0].to_s
			# Then file path hash
			path_hash = prefetch_file[hash_offset..hash_offset+4].unpack('h8')[0].reverse.upcase.to_s
			# Last is mace value for timestamps
			mtimes = client.priv.fs.get_file_mace(filename)
			if mtimes.nil? or mtimes.empty?
				last_modified = "Error reading value"
				created = "Error reading value"
			else
				last_modified = mtimes['Modified'].utc.to_s
				created = mtimes['Created'].utc.to_s
			end
			return [last_modified, created, run_count, path_hash, name]
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
			# For some reason we need system privileges to read file
			# mace time on XP/2003 while we can do the same only
			# as admin on Win7.
			if not is_system?
				print_error(error_msg)
				return nil
			end
			# Offsets for WinXP & Win2k3
			print_good("Detected #{sysnfo} (max 128 entries)")
			name_offset = 0x10
			hash_offset = 0x4C
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
		print_prefetch_key_value
		print_timezone_key_values(key_value)
		print_good("Current UTC Time: %s" % Time.now.utc)
		sys_root = expand_path("%SYSTEMROOT%")
		full_path = sys_root + "\\Prefetch\\"
		file_type = "*.pf"
		print_status("Gathering information from remote system. This will take awhile..")

		# Goes through the files in Prefetch directory, creates file paths for the
		# gather_pf_info function that enumerates all the pf info

		getfile_prefetch_filenames = client.fs.file.search(full_path, file_type)
		if getfile_prefetch_filenames.empty? or getfile_prefetch_filenames.nil?
			print_error("Could not find/access any .pf files. Can't continue. (Might be temporary error..)")
			return nil
		else
			getfile_prefetch_filenames.each do |file|
				if file.empty? or file.nil?
					next
				else
					filename = File.join(file['path'], file['name'])
					pf_entry = gather_pf_info(name_offset, hash_offset, runcount_offset, filename)
					if not pf_entry.nil?
						table << pf_entry
					end
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
