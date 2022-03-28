# -*- coding: binary -*-

module Msf::Post::Windows::FileInfo
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
    return unless file_exist?(filepath)

    if session.type == 'meterpreter'
      file_version_info_size = client.railgun.version.GetFileVersionInfoSizeA(
        filepath,
        nil
      )['return']

      buffer = session.railgun.kernel32.VirtualAlloc(
        nil,
        file_version_info_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
      )['return']

      client.railgun.version.GetFileVersionInfoA(
        filepath,
        0,
        file_version_info_size,
        buffer
      )

      result = client.railgun.version.VerQueryValueA(buffer, '\\', 4, 4)
      ffi = client.railgun.memread(result['lplpBuffer'], result['puLen'])

      vs_fixed_file_info = ffi.unpack('V13')

      unless vs_fixed_file_info && (vs_fixed_file_info.length == 13) &&
             (vs_fixed_file_info[0] = 0xfeef04bd)
        return nil
      end

      major = hiword(vs_fixed_file_info[2])
      minor = loword(vs_fixed_file_info[2])
      build = hiword(vs_fixed_file_info[3])
      revision = loword(vs_fixed_file_info[3])
      branch = revision.to_s[0..1].to_i
    elsif session.type == 'powershell'
      result = cmd_exec("([System.Diagnostics.FileVersionInfo]::GetVersionInfo(\"#{filepath}\") | Select-Object FileMajorPart,FileMinorPart,FileBuildPart,FilePrivatePart) -join ''")
      return unless result

      major = result.scan(/FileMajorPart=(\d+)/).flatten.first.to_i
      minor = result.scan(/FileMinorPart=(\d+)/).flatten.first.to_i
      build = result.scan(/FileBuildPart=(\d+)/).flatten.first.to_i
      revision = result.scan(/FilePrivatePart=(\d+)/).flatten.first.to_i
      branch = revision.to_s[0..1].to_i
    else
      result = cmd_exec("wmic datafile where name=\"#{filepath.gsub('\\', '\\\\\\')}\" get Version /value")
      return unless result
      return unless result.to_s.include?('Version=')

      major = result.scan(/Version=(\d+).\d+.\d+.\d+/).flatten.first.to_i
      minor = result.scan(/Version=\d+.(\d+).\d+.\d+/).flatten.first.to_i
      build = result.scan(/Version=\d+.\d+.(\d+).\d+/).flatten.first.to_i
      revision = result.scan(/Version=\d+.\d+.\d+.(\d+)/).flatten.first.to_i
      branch = revision.to_s[0..1].to_i
    end

    return major, minor, build, revision, branch
  end
end
