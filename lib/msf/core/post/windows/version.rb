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

  def get_version_info
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
      build_num_raw = cmd_exec('systeminfo')
      bn_groups = build_num_raw.match(/OS Version:\s+(\d+)\.(\d+)\.(\d+).*((Service Pack\s+(\d+))|N\/A)/)
      if bn_groups.nil?
        print_error("Couldn't retrieve the target's build number!")
        raise RuntimeError.new("Couldn't retrieve the target's build number!")
      else
        sp = bn_groups[6]
        sp = 0 if sp.nil?
        workstation = 'Standalone Workstation'
        dc = 'Domain Controller'
        server = 'Standalone Server'
        product_regex_output = build_num_raw.match(/((#{workstation})|(#{dc})|(#{server}))/)
        if product_regex_output.nil?
          product_type = Msf::WindowsVersion::UnknownProduct
        else
          case product_regex_output[1]
          when workstation
            product_type = Msf::WindowsVersion::VER_NT_WORKSTATION
          when dc
            product_type = Msf::WindowsVersion::VER_NT_DOMAIN_CONTROLLER
          when server
            product_type = Msf::WindowsVersion::VER_NT_SERVER
          end
        end
        Msf::WindowsVersion.new(bn_groups[1].to_i, bn_groups[2].to_i, bn_groups[3].to_i, sp, product_type)
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
