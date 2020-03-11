# -*- coding: binary -*-

require 'msf/core/exploit/windows_constants'
require 'msf/core/post/windows/error'

module Msf
class Post
module Windows

module FileSystem
  include Msf::Exploit::Windows_Constants
  include Msf::Post::Windows::Error



  class String16 < BinData::String
    def assign(val)
      super(val.encode('utf-16le'))
    end

    def snapshot
      super.force_encoding('utf-16le')
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
    choice :p_root_directory, selection: -> { arch } do
      uint32 ARCH_X86
      uint64 ARCH_X64
    end
    choice :p_object_name, selection: -> { arch } do
      uint32 ARCH_X86
      uint64 ARCH_X64
    end
    uint32 :attributes
    choice :p_security_descriptor, selection: -> { arch } do
      uint32 ARCH_X86
      uint64 ARCH_X64
    end
    choice :p_security_quality_of_service, selection: -> { arch } do
      uint32 ARCH_X86
      uint64 ARCH_X64
    end
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

  FSCTL_SET_REPARSE_POINT = 0x000900a4
  SYMBOLIC_LINK_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | 0x1


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
      return false
    end

    vprint_good("Successfuly opened #{path}")
    handle
  end

  def build_mount_point(target, print_name)
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

  def fixup_path(str)
    return str.prepend('\\??\\') unless str.start_with?('\\')
    str
  end

  def create_mount_point_internal(path, buffer)
    handle = open_reparse_point(path, true)
    return nil unless handle
    set_reparse_point(handle, buffer.to_binary_s)
    #result = session.railgun.kernel32.CloseHandle(handle)
  end

  def create_symlink(root, link_name, target_name)
    object_attributes = ObjectAttributes.new(
      arch: client.native_arch == ARCH_X64 ? ObjectAttributes::ARCH_X64 : ObjectAttributes::ARCH_X86
    )
    object_attributes.p_root_directory = 0 # root argument is nil, otherwise, we need to get a valid handle to root (TODO later)
    object_attributes.attributes = ObjectAttributes::OBJ_CASE_INSENSITIVE
    object_attributes.p_security_descriptor = 0
    object_attributes.p_security_quality_of_service = 0

    result = session.railgun.ntdll.RtlInitUnicodeString(
      client.native_arch == ARCH_X64 ? 8 : 4,
      link_name
    )
    unless result['GetLastError'] == SUCCESS
      print_error("Error init unicode string #{link_name}. Windows Error Code: #{result['GetLastError']} - #{result['ErrorMessage']}")
      return nil
    end
    object_attributes.p_object_name.read(result['DestinationString'])

    result = session.railgun.ntdll.RtlInitUnicodeString(
      client.native_arch == ARCH_X64 ? 8 : 4,
      target_name
    )
    unless result['GetLastError'] == SUCCESS
      print_error("Error init unicode string #{target_name}. Windows Error Code: #{result['GetLastError']} - #{result['ErrorMessage']}")
      return nil
    end
    target = result['DestinationString']

    result = session.railgun.ntdll.NtCreateSymbolicLinkObject(
      client.native_arch == ARCH_X64 ? 8 : 4,
      SYMBOLIC_LINK_ALL_ACCESS,
      object_attributes.to_binary_s,
      target
    )
    unless result['return'] == SUCCESS
      print_error("Error creating the symlink. Windows Error Code: #{result['GetLastError']} - #{result['ErrorMessage']}")
      return nil
    end
  end

end # FileSystem
end # Windows
end # Post
end # Msf
