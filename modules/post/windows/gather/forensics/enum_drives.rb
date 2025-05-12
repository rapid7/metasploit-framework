##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# List physical drives and logical volumes on the remote system
#
# R. Wesley McGrew wesley@mcgrewsecurity.com
#    http://mcgrewsecurity.com
# Mississippi State University National Forensics Training Center
#    http://msu-nftc.org

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::FileSystem

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Physical Drives and Logical Volumes',
        'Description' => %q{This module will list physical drives and logical volumes},
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
        OptInt.new('MAXDRIVES', [false, 'Maximum physical drive number', 10])
      ]
    )
  end

  def print_device(devname)
    ioctl_disk_get_drive_geometry_ex = 0x000700A0
    removable = 0x0b
    fixed = 0x0c
    invalid_handle_value = 0xFFFFFFFF
    result = client.railgun.kernel32.CreateFileA(
      devname,
      'GENERIC_READ',
      0x3,
      nil,
      'OPEN_EXISTING',
      'FILE_ATTRIBUTE_READONLY',
      0
    )
    handle = result['return']

    return if handle == invalid_handle_value

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
        handle,
        ioctl_disk_get_drive_geometry_ex,
        '',
        0,
        200,
        200,
        4,
        ''
      )
    end

    geometry = ioctl['lpOutBuffer']

    if geometry[8] == removable
      type = 'Removable'
    elsif geometry[8] == fixed
      type = 'Fixed'
    else
      type = ''
    end

    size = geometry[24, 31].unpack('Q')

    if size.to_s == '4702111234474983745'
      size = 'N/A'
    end

    print_line('%<devname>-25s%<type>12s%<size>15i', devname: devname, type: type, size: size[0])
    client.railgun.kernel32.CloseHandle(handle)
  end

  def run
    print_line('Device Name:                    Type:   Size (bytes):')
    print_line('------------                    -----   -------------')
    print_line('<Physical Drives:>')
    max_physical = datastore['MAXDRIVES']
    (0..max_physical).each do |i|
      devname = "\\\\.\\PhysicalDrive#{i}"
      print_device(devname)
    end

    print_line('<Logical Drives:>')
    get_drives.each do |i|
      devname = "\\\\.\\#{i}:"
      print_device(devname)
    end
  end
end
