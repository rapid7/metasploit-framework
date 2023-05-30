# -*- coding: binary -*-

module Msf::Post::Windows::Version

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

  def registry_query(key, value)
    cmd = 'reg query "' + key + '" /v ' + value
    vprint_line("Running registry query: #{cmd}")
    raw_output = cmd_exec(cmd)
    vprint_line("Output: #{raw_output}")
    regexp = "#{value}\\s+REG_\\w+\\s+(.*)"
    groups = raw_output.match(regexp)
    if groups.nil?
      return nil
    end

    groups[1]
  end

  def get_version_info
    result = get_version_info_impl
    if result.nil?
      print_error("Couldn't retrieve the target's build number!")
      raise RuntimeError.new("Couldn't retrieve the target's build number!")
    end

    result
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

      Msf::WindowsVersion.new(major, minor, build, service_pack, product_type)
    else
      # Command shell - we'll try reg commands, and fall back to `ver`
      build_str = registry_query('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'CurrentBuildNumber')
      if build_str.nil?
        # May be pre-XP, which doesn't have `reg`. If we're in a CMD shell, we'll hopefully have `ver`
        # This seems to be language-pack-independent
        build_num_raw = cmd_exec('ver')
        groups = build_num_raw.match(/.*Version\s+(\d+)\.(\d+)\.(\d+)(\.(\d+))?/)
        if groups.nil?
          return nil
        end

        major, minor, build, unused, revision = groups.captures
        revision = 0 if revision.nil?
        return Msf::WindowsVersion.new(major.to_i, minor.to_i, build.to_i, 0, Msf::WindowsVersion::UnknownProduct)
      end

      version_str = registry_query('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'CurrentVersion')
      if version_str.nil?
        return nil
      end

      build_num = build_str.to_i
      version_match = version_str.match(/(\d+)\.(\d+)/)
      if version_match.nil?
        return nil
      end

      major, minor = version_match.captures
      major = major.to_i
      minor = minor.to_i
        
      product = registry_query('HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions', 'ProductType')
      case product
      when /WinNT/
        product_type = Msf::WindowsVersion::VER_NT_WORKSTATION
      when /LanmanNT/
        product_type = Msf::WindowsVersion::VER_NT_DOMAIN_CONTROLLER
      when /ServerNT/
        product_type = Msf::WindowsVersion::VER_NT_SERVER
      else
        product_type = Msf::WindowsVersion::UnknownProduct
      end

      if major == 6 and minor == 3 and build_num > 9600 # 9600 is Windows 8.1 build number
        # This is Windows 10+ - the version numbering is calculated differently
        major = registry_query('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'CurrentMajorVersionNumber')
        minor = registry_query('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'CurrentMinorVersionNumber')
        if major.nil? or minor.nil?
          return nil
        end

        major = major.to_i(16)
        minor = minor.to_i(16)
        Msf::WindowsVersion.new(major, minor, build_num, 0, product_type)
      else
        # Pre-Windows 10
        service_pack_raw = registry_query('HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion', 'CSDVersion')
        service_pack = 0
        unless service_pack_raw.nil?
          match = service_pack_raw.match(/Service Pack (\d+)/)
          unless match.nil?
            service_pack = match[1].to_i
          end
        end

        Msf::WindowsVersion.new(major, minor, build_num, service_pack, product_type)
      end
    end
  end

  private

  def empty_os_version_info_ex
    result = [0,
     0,
     0,
     0,
     0,
     "",
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
