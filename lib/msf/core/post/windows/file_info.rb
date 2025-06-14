# -*- coding: binary -*-
module Msf
class Post
module Windows

module FileInfo

  def initialize(info = {})
    super(
      update_info(
        info,
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_railgun_api
              stdapi_railgun_memread
            ]
          }
        }
      )
    )
  end

  def hiword(num)
    (num >> 16) & 0xffff
  end

  def loword(num)
    num & 0xffff
  end

  # Returns the file version information such as: major, minor, build, revision, branch.
  #
  # @param filepath [String] The path of the file you are targeting.
  # @return [String] Returns the file version information of the file.

  def file_version(filepath)
    file_version_info_size = client.railgun.version.GetFileVersionInfoSizeA(
      filepath,
      nil
    )['return']

    if file_version_info_size == 0
      # Indicates an error - should not continue
      return nil
    end

    buffer = session.railgun.kernel32.VirtualAlloc(
      nil,
      file_version_info_size,
      MEM_COMMIT|MEM_RESERVE,
      PAGE_READWRITE
    )['return']

    client.railgun.version.GetFileVersionInfoA(
      filepath,
      0,
      file_version_info_size,
      buffer
    )

    result = client.railgun.version.VerQueryValueA(buffer, "\\", 4, 4)
    ffi = client.railgun.memread(result['lplpBuffer'], result['puLen'])

    vs_fixed_file_info = ffi.unpack('V13')

    unless vs_fixed_file_info and (vs_fixed_file_info.length == 13)	and
(vs_fixed_file_info[0] = 0xfeef04bd)
      return nil
    end

    major = hiword(vs_fixed_file_info[2])
    minor = loword(vs_fixed_file_info[2])
    build = hiword(vs_fixed_file_info[3])
    revision = loword(vs_fixed_file_info[3])
    branch = revision.to_s[0..1].to_i

    return major, minor, build, revision, branch
  end
end # FileInfo
end # Windows
end # Post
end # Msf
