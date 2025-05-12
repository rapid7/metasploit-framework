##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# Forensic byte-for-byte imaging of remote disks and volumes
#
# R. Wesley McGrew wesley@mcgrewsecurity.com
#    http://mcgrewsecurity.com
# Mississippi State University National Forensics Training Center
#    http://msu-nftc.org

require 'digest/md5'
require 'digest/sha1'

class MetasploitModule < Msf::Post

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Forensic Imaging',
        'Description' => %q{This module will perform byte-for-byte imaging of remote disks and volumes.},
        'License' => MSF_LICENSE,
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter'],
        'Author' => ['Wesley McGrew <wesley[at]mcgrewsecurity.com>'],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_railgun_api
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
    register_options(
      [
        OptString.new('DEVICE', [true, 'Device to image (use enum_drives for possible names)', nil]),
        OptString.new('OUTFILE', [false, 'Output filename without extension', 'image']),
        OptInt.new('SPLIT', [false, 'Split image size, in bytes', 1610612736]),
        OptInt.new('BLOCKSIZE', [false, 'Block size, in bytes (multiples of 512)', 1048576]),
        OptInt.new('SKIP', [false, 'Skip this many blocks before beginning', 0]),
        OptInt.new('COUNT', [false, 'Image only this many blocks (0 - read till end)', 0])
      ]
    )
  end

  def run
    devname = datastore['DEVICE']
    base_filename = datastore['OUTFILE']
    split = datastore['SPLIT']
    block_size = datastore['BLOCKSIZE']
    skip = datastore['SKIP']
    num_to_read = datastore['COUNT']

    invalid_handle_value = 0xFFFFFFFF
    invalid_set_file_pointer = 0xFFFFFFFF
    fsctl_allow_extended_dasd_io = 0x00090083
    ioctl_disk_get_drive_geometry_ex = 0x000700A0

    r = client.railgun.kernel32.CreateFileA(
      devname,
      'GENERIC_READ',
      0x3,
      nil,
      'OPEN_EXISTING',
      'FILE_ATTRIBUTE_READONLY',
      0
    )
    handle = r['return']

    if handle == invalid_handle_value
      print_error("Could not open #{devname}")
      raise Rex::Script::Completed
    end

    r = client.railgun.kernel32.DeviceIoControl(handle, fsctl_allow_extended_dasd_io, nil, 0, 0, 0, 4, nil)

    ioctl = client.railgun.kernel32.DeviceIoControl(
      handle,
      ioctl_disk_get_drive_geometry_ex,
      '',
      0,
      200,
      200,
      4,
      ''
    )
    if ioctl['GetLastError'] == 6
      ioctl = client.railgun.kernel32.DeviceIoControl(
        handle, ioctl_disk_get_drive_geometry_ex,
        '', 0, 200, 200, 4, ''
      )
    end
    geometry = ioctl['lpOutBuffer']

    disk_size = geometry[24, 31].unpack('Q')[0]

    finished = false
    skip_counter = 0
    if num_to_read != 0
      count = 0
    end
    file_number = 1
    file_data_count = 0
    disk_bytes_count = 0
    fname = base_filename.to_s + format('.%<file_number>03i', file_number: file_number)
    fp = ::File.new(fname, 'w')
    print_line("Started imaging #{devname} to #{fname}")

    md5_hash = Digest::MD5.new
    sha1_hash = Digest::SHA1.new

    while finished != true
      if skip_counter < skip
        print_line("Skipped #{block_size} bytes")
        r = client.railgun.kernel32.SetFilePointer(handle, block_size, 0, 1)
        if r['return'] == invalid_set_file_pointer && (r['GetLastError'] != 0)
          print_error('Skipped past the end of file?')
          raise Rex::Script::Completed
        end
        skip_counter += 1
        next
      end

      if (disk_size - disk_bytes_count) < block_size
        block_size = disk_size - disk_bytes_count
        finished = true
      end
      r = client.railgun.kernel32.ReadFile(handle, block_size, block_size, 4, nil)
      disk_bytes_count += block_size
      if disk_bytes_count == disk_size
        finished = true
      end

      data = r['lpBuffer'][0, r['lpNumberOfBytesRead']]

      if num_to_read != 0
        count += 1
        if count == num_to_read
          finished = true
        end
      end

      md5_hash << data
      sha1_hash << data

      fp.syswrite(data)
      file_data_count += data.length
      next unless file_data_count >= split

      fp.close
      next unless finished != true

      file_number += 1
      file_data_count = 0
      fname = base_filename.to_s + format('.%<file_number>03i', file_number: file_number)
      fp = ::File.new(fname, 'w')
      print_line("...continuing with #{fname}")
    end
    fp.close

    print_line('Finished!')
    print_line("MD5  : #{md5_hash}")
    print_line("SHA1 : #{sha1_hash}")

    client.railgun.kernel32.CloseHandle(handle)
  end
end
