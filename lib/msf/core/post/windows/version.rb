# -*- coding: binary -*-

module Msf::Post::Windows::Version
  include Msf::Post::Windows::Registry

  class Error < RuntimeError
  end

  def initialize(info = {})
    super(
      update_info(
        info,
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_railgun_api
            ]
          }
        }
      )
    )
  end

  def get_version_info
    result = get_version_info_impl
    if result.nil?
      print_error("Couldn't retrieve the target's build number!")
      raise Error, "Couldn't retrieve the target's build number!"
    end

    result
  end

  def get_version_info_fallback_impl
    build_num_raw = cmd_exec('cmd.exe /c ver')
    groups = build_num_raw.match(/Version\s+(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?/)
    if groups.nil?
      return nil
    end

    major, minor, build, revision = groups.captures
    # Default to workstation, since it'll likely be an older OS - pre Server editions
    return Msf::WindowsVersion.new(major.to_i, minor.to_i, build.to_i, 0, revision, Msf::WindowsVersion::VER_NT_WORKSTATION)
  end

  def get_version_info_impl
    if session.type == 'meterpreter'
      result = session.railgun.ntdll.RtlGetVersion(input_os_version_info_ex)
      os_version_info_ex = unpack_version_info(result['VersionInformation'])
      major = os_version_info_ex[1]
      minor = os_version_info_ex[2]
      build = os_version_info_ex[3]
      service_pack = os_version_info_ex[6]
      product_type = os_version_info_ex[9]
    
      revision = 0
      if (major >= 10)
        revision = registry_getvaldata('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'UBR', Msf::Post::Windows::Registry::REGISTRY_VIEW_NATIVE)
      end

      Msf::WindowsVersion.new(major, minor, build, service_pack, revision, product_type)
    else
      # Command shell - we'll try reg commands, and fall back to `ver`
      build_str = shell_registry_getvaldata('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'CurrentBuildNumber', Msf::Post::Windows::Registry::REGISTRY_VIEW_NATIVE)
      if build_str.nil?
        return get_version_info_fallback_impl
      end

      version_str = shell_registry_getvaldata('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'CurrentVersion', Msf::Post::Windows::Registry::REGISTRY_VIEW_NATIVE)
      if version_str.nil?
        return get_version_info_fallback_impl
      end

      build_num = build_str.to_i
      version_match = version_str.match(/(\d+)\.(\d+)/)
      if version_match.nil?
        return get_version_info_fallback_impl
      end

      major, minor = version_match.captures
      major = major.to_i
      minor = minor.to_i

      product = shell_registry_getvaldata('HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions', 'ProductType', Msf::Post::Windows::Registry::REGISTRY_VIEW_NATIVE)
      case product
      when 'WinNT'
        product_type = Msf::WindowsVersion::VER_NT_WORKSTATION
      when 'LanmanNT'
        product_type = Msf::WindowsVersion::VER_NT_DOMAIN_CONTROLLER
      when 'ServerNT'
        product_type = Msf::WindowsVersion::VER_NT_SERVER
      else
        product_type = Msf::WindowsVersion::VER_NT_WORKSTATION
      end

      if (major == 6) && (minor == 3) && (build_num > 9600) # 9600 is Windows 8.1 build number
        # This is Windows 10+ - the version numbering is calculated differently
        major = shell_registry_getvaldata('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'CurrentMajorVersionNumber', Msf::Post::Windows::Registry::REGISTRY_VIEW_NATIVE)
        minor = shell_registry_getvaldata('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'CurrentMinorVersionNumber', Msf::Post::Windows::Registry::REGISTRY_VIEW_NATIVE)
        ubr = shell_registry_getvaldata('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'UBR', Msf::Post::Windows::Registry::REGISTRY_VIEW_NATIVE)
        if major.nil? || minor.nil? || ubr.nil?
          return get_version_info_fallback_impl
        end

        Msf::WindowsVersion.new(major, minor, build_num, 0, ubr, product_type)
      else
        # Pre-Windows 10
        service_pack_raw = shell_registry_getvaldata('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'CSDVersion', Msf::Post::Windows::Registry::REGISTRY_VIEW_NATIVE)
        if service_pack_raw.nil? && (major >= 6)
          # Some older versions didn't put the Service Pack value in both 32 and 64-bit versions of the registry - look there specifically
          service_pack_raw = shell_registry_getvaldata('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'CSDVersion', Msf::Post::Windows::Registry::REGISTRY_VIEW_32_BIT)
        end
        service_pack = 0
        unless service_pack_raw.nil?
          match = service_pack_raw.match(/Service Pack (\d+)/)
          unless match.nil?
            service_pack = match[1].to_i
          end
        end

        Msf::WindowsVersion.new(major, minor, build_num, service_pack, 0, product_type)
      end
    end
  end

  private

  def empty_os_version_info_ex
    [
      0,
      0,
      0,
      0,
      0,
      '',
      0,
      0,
      0,
      0,
      0
    ]
  end

  def pack_version_info(info)
    info.pack('VVVVVa256vvvCC')
  end

  def unpack_version_info(bytes)
    bytes.unpack('VVVVVa256vvvCC')
  end

  def input_os_version_info_ex
    input = empty_os_version_info_ex
    size = pack_version_info(input).size
    input[0] = size

    pack_version_info(input)
  end
end
